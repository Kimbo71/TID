#!/usr/bin/env python3
import sys
import os
import argparse
import csv
import time
import json
import random
import ipaddress
from datetime import datetime

# --- TRex API path ---
TREX_API_PATH = "/opt/trex-core/scripts/automation/trex_control_plane/interactive"
if TREX_API_PATH not in sys.path:
    sys.path.insert(0, TREX_API_PATH)

from trex_stl_lib.api import (
    STLClient, STLStream, STLPktBuilder, STLTXCont, STLTXMultiBurst,
    STLScVmRaw, STLVmFixIpv4, STLVmFixChecksumHw, STLVmFlowVar, STLVmWrFlowVar
)
from scapy.all import Ether, Dot1Q, IP, UDP, TCP, Raw, wrpcap


# ---------------------------------------------------------
# QinQ Packet Builder (outer_tpid supports 0x88a8 or 0x8100)
# ---------------------------------------------------------

def build_qinq_packet(src_mac, dst_mac, src_ip, dst_ip,
                      src_port, dst_port, s_vlan, c_vlan, pkt_size,
                      outer_tpid=0x88a8, l4_proto="udp", tcp_flags="S", stamp_head_bytes=0):
    """
    Build a QinQ (double-tagged) IP packet (UDP or TCP) and ensure space for optional
    payload stamping. Returns a tuple (packet, payload_offset).
    """
    if stamp_head_bytes not in (0, 8, 16):
        raise ValueError("stamp_head_bytes must be 0, 8, or 16")

    ether = Ether(src=src_mac, dst=dst_mac, type=outer_tpid)
    s_tag = Dot1Q(vlan=s_vlan, type=0x8100)
    c_tag = Dot1Q(vlan=c_vlan)

    ip = IP(src=src_ip, dst=dst_ip)
    l4p = str(l4_proto).lower()
    if l4p == "tcp":
        tcp = TCP(sport=src_port, dport=dst_port,
                  flags=tcp_flags, seq=random.randint(0, 0xffffffff))
        l4 = tcp
    else:
        udp = UDP(sport=src_port, dport=dst_port)
        l4 = udp

    base = ether / s_tag / c_tag / ip / l4
    payload_off = len(base)
    pad = pkt_size - payload_off
    if pad < stamp_head_bytes:
        raise ValueError(f"Packet size too small for headers+stamp ({payload_off}+{stamp_head_bytes} > {pkt_size})")

    stamp_region = b"\x00" * stamp_head_bytes
    random_tail = os.urandom(pad - stamp_head_bytes) if pad > stamp_head_bytes else b""
    pkt = base / Raw(stamp_region + random_tail)
    return pkt, payload_off



# ---------------------------------------------------------
# Field Engine helpers (sequence/timestamp stamping + checksum fix)
# ---------------------------------------------------------
def build_vm_program(payload_off, l4_proto="udp", stamp_head_bytes=16, fix_checksums=True):
    cmds = []
    MAX64 = (1 << 63) - 1
    if stamp_head_bytes >= 8:
        cmds.append(STLVmFlowVar(name="seq64", init_value=0, min_value=0,
                                 max_value=MAX64, size=8, op="inc"))
        cmds.append(STLVmWrFlowVar(fv_name="seq64", pkt_offset=int(payload_off)))
    if stamp_head_bytes >= 16:
        cmds.append(STLVmFlowVar(name="tick64", init_value=0, min_value=0,
                                 max_value=MAX64, size=8, op="inc"))
        cmds.append(STLVmWrFlowVar(fv_name="tick64", pkt_offset=int(payload_off) + 8))

    if fix_checksums:
        l4p = str(l4_proto).lower()
        l4_name = "UDP" if l4p == "udp" else "TCP"
        l4_type_int = 17 if l4p == "udp" else 6
        try:
            cmds.extend([
                STLVmFixIpv4(offset="IP"),
                STLVmFixChecksumHw(l3_offset="IP", l4_offset=l4_name, l4_type=l4_type_int),
            ])
        except TypeError:
            cmds.extend([
                STLVmFixIpv4(offset="IP"),
                STLVmFixChecksumHw(l3_offset="IP", l4_offset=l4_name),
            ])

    return STLScVmRaw(cmds) if cmds else None

# ---------------------------------------------------------
# Stats Collection (CSV)
# ---------------------------------------------------------
def collect_and_log_stats(client, ports, csv_file):
    fields = [
        "timestamp", "port", "tx_pps", "rx_pps", "tx_bps", "rx_bps",
        "tx_pkts", "rx_pkts", "tx_dropped", "rx_dropped"
    ]
    with open(csv_file, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(fields)
        start = time.time()
        while client.is_traffic_active(ports=ports):
            stats = client.get_stats()
            t = round(time.time() - start, 2)
            for p in ports:
                s = stats[p]
                w.writerow([
                    t, p,
                    s.get("tx_pps", 0), s.get("rx_pps", 0),
                    s.get("tx_bps", 0), s.get("rx_bps", 0),
                    s.get("tx_pkts", 0), s.get("rx_pkts", 0),
                    s.get("tx_dropped", 0), s.get("rx_dropped", 0)
                ])
            time.sleep(1)


# ---------------------------------------------------------
# Port Mapping
# ---------------------------------------------------------
def determine_ports(tx_mode, rx_mode, ports):
    # TX
    if tx_mode == "same_port":
        tx_ports = [ports[0]]
    elif tx_mode == "dual_port":
        tx_ports = ports if len(ports) > 1 else [0, 1]
    else:
        raise ValueError(f"Invalid tx_mode: {tx_mode}")

    # RX
    if rx_mode == "same_port":
        rx_ports = tx_ports
    elif rx_mode == "dual_port":
        if len(ports) > 1:
            rx_ports = ports[::-1] if tx_mode == "dual_port" else [ports[1]]
        else:
            rx_ports = [tx_ports[0]]
    elif rx_mode == "off":
        rx_ports = []
    else:
        raise ValueError(f"Invalid rx_mode: {rx_mode}")

    return tx_ports, rx_ports


# ---------------------------------------------------------
# Safe file helpers
# ---------------------------------------------------------
def safe_path(path_str):
    if not path_str:
        return path_str
    if not os.path.exists(path_str):
        return path_str
    root, ext = os.path.splitext(path_str)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{root}_{stamp}{ext}"

def ensure_parent_writable(path_str):
    if not path_str:
        return
    parent = os.path.dirname(path_str) or "."
    if not os.path.isdir(parent):
        raise RuntimeError(f"[capture] Directory does not exist: {parent}")
    if not os.access(parent, os.W_OK):
        raise RuntimeError(f"[capture] Directory not writable: {parent}")

def stop_capture_write_or_fetch(client, cap_id, outfile):
    try:
        client.stop_capture(cap_id, output=outfile)
        return outfile
    except TypeError:
        try:
            client.stop_capture(cap_id)
            if hasattr(client, "fetch_capture_file"):
                client.fetch_capture_file(cap_id, outfile)
                return outfile
        except Exception as e2:
            print(f"[capture] stop/fetch fallback failed: {e2}")
            return None
    except Exception as e:
        print(f"[capture] stop with output failed: {e}")
        return None


# ---------------------------------------------------------
# TRex Port MAC helpers
# ---------------------------------------------------------
def get_port_mac(client, port_id):
    """Return MAC string for a TRex port across API variants."""
    attr = client.get_port_attr(port_id)
    if isinstance(attr, dict):
        return (attr.get("mac") or attr.get("src_mac") or
                (attr.get("layer_cfg", {}).get("ether", {}).get("src")) or
                (attr.get("ether", {}).get("src")))
    for key in ("mac", "src_mac"):
        if hasattr(attr, key):
            return getattr(attr, key)
    return None


def expand_ip_range(range_str):
    """Return list of IPv4 strings covering inclusive start-end (handles single value)."""
    range_str = str(range_str or "").strip()
    if not range_str:
        return []
    if "-" not in range_str:
        addr = ipaddress.IPv4Address(range_str.strip())
        return [str(addr)]
    start_s, end_s = [part.strip() for part in range_str.split("-", 1)]
    start_ip = int(ipaddress.IPv4Address(start_s))
    end_ip = int(ipaddress.IPv4Address(end_s))
    if end_ip < start_ip:
        raise ValueError(f"IP range end {end_s} precedes start {start_s}")
    if end_ip - start_ip > 65536:
        raise ValueError("IP range too large; limit to <= 65537 addresses")
    return [str(ipaddress.IPv4Address(val)) for val in range(start_ip, end_ip + 1)]


def expand_port_range(range_str, default):
    range_str = str(range_str or "").strip()
    if not range_str:
        return []
    if "-" not in range_str:
        val = int(range_str)
        if not (0 <= val <= 65535):
            raise ValueError(f"Port {val} out of range 0-65535")
        return [val]
    start_s, end_s = [part.strip() for part in range_str.split("-", 1)]
    start = int(start_s)
    end = int(end_s)
    if not (0 <= start <= 65535) or not (0 <= end <= 65535):
        raise ValueError("Port range values must be between 0 and 65535")
    if end < start:
        raise ValueError(f"Port range end {end} precedes start {start}")
    if end - start > 65535:
        raise ValueError("Port range too large; limit to <= 65536 ports")
    return list(range(start, end + 1))

def print_port_macs(client, ports):
    macs = {}
    print("[mac] TRex port MACs:")
    for p in ports:
        mac = get_port_mac(client, p)
        macs[p] = mac
        print(f"  - port {p}: {mac if mac else 'UNKNOWN'}")
    return macs

def build_peer_mac_map(ports, macs, mode):
    """
    For dual_port: map each TX port to the *other* port's MAC.
    For same_port: map each TX port to its *own* MAC (loopback).
    """
    mapping = {}
    if mode == "dual_port" and len(ports) >= 2:
        for i, p in enumerate(ports):
            peer = ports[(i + 1) % len(ports)]  # simple ring
            mapping[p] = macs.get(peer)
    else:
        for p in ports:
            mapping[p] = macs.get(p)
    return mapping


# ---------------------------------------------------------
# Load profile parsing & auto builder
# ---------------------------------------------------------
def parse_load_profile(profile_str):
    """
    Parse strings like: '30Gbps@5,60Gbps@5,95Gbps@20,50Gbps@10,95Gbps@15'
    Returns list of (mult_string, seconds_int).
    """
    phases = []
    if not profile_str:
        return phases
    for chunk in profile_str.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "@" not in chunk:
            raise ValueError(f"Bad load phase '{chunk}'. Use format '<mult>@<seconds>' e.g. '95Gbps@20'")
        mult, sec = chunk.split("@", 1)
        mult = mult.strip()
        sec = int(float(sec.strip()))
        if sec <= 0:
            raise ValueError(f"Phase duration must be >0: '{chunk}'")
        phases.append((mult, sec))
    return phases

def _parse_ratios(s):
    parts = [float(x.strip()) for x in s.split(",") if x.strip()]
    total = sum(parts)
    if total <= 0:
        raise ValueError("pattern_ratios must sum to > 0")
    return [x / total for x in parts]

def _linspace_loads(a, b, steps):
    if steps < 2:
        return [b]
    delta = (b - a) / float(steps - 1)
    return [a + i * delta for i in range(steps)]

def _string_to_pair(start, end, steps):
    import re
    num = re.compile(r'^\s*([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z%]*)\s*$')
    m1, m2 = num.match(start), num.match(end)
    if not (m1 and m2):
        return [end] * steps
    v1, u1 = float(m1.group(1)), (m1.group(2) or "")
    v2, u2 = float(m2.group(1)), (m2.group(2) or "")
    if u1 != u2:
        return [end] * steps
    vals = _linspace_loads(v1, v2, steps)
    return [f"{v:.6g}{u1}" for v in vals]

def build_auto_load_profile(duration_sec, start_load, max_load,
                            pattern="up-hold-down-hold-up",
                            ratios="0.3,0.2,0.3,0.2", ramp_steps=20):
    tokens = [t.strip().lower() for t in pattern.split("-") if t.strip()]

    # parse ratios, filter empties, normalize to 1.0
    parts = [x.strip() for x in ratios.split(",")]
    parts = [p for p in parts if p not in ("", None)]
    try:
        r = [float(p) for p in parts]
    except ValueError:
        raise ValueError(f"pattern_ratios has a non-numeric value: '{ratios}'")
    total = sum(r) or 0.0
    if total <= 0.0:
        # default evenly if ratios unusable
        r = [1.0 / max(1, len(tokens))] * max(1, len(tokens))
    else:
        r = [x / total for x in r]

    # align lengths: trim extra ratios or repeat last to fill
    if len(r) > len(tokens):
        r = r[:len(tokens)]
    elif len(r) < len(tokens):
        last = r[-1] if r else (1.0 / len(tokens))
        r = r + [last] * (len(tokens) - len(r))
        # renormalize
        s = sum(r)
        r = [x / s for x in r]

    # map to seconds, rounding to match duration exactly
    secs_float = [duration_sec * x for x in r]
    secs = [max(1, int(round(x))) for x in secs_float]
    diff = sum(secs) - int(duration_sec)
    if diff != 0:
        # adjust the longest segment
        idx = max(range(len(secs)), key=lambda i: secs[i])
        secs[idx] = max(1, secs[idx] - diff)

    phases = []
    last = start_load
    for tok, s in zip(tokens, secs):
        if tok == "hold":
            phases.append((last, s))
        elif tok in ("up", "down"):
            src = last
            dst = max_load if tok == "up" else start_load
            steps = max(2, min(int(ramp_steps), s))
            step_loads = _string_to_pair(src, dst, steps)
            base = s // steps
            rem = s - base * steps
            for i, mult in enumerate(step_loads):
                span = base + (1 if i < rem else 0)
                if span > 0:
                    phases.append((mult, span))
            last = dst
        else:
            raise ValueError(f"Unknown token in profile_pattern: '{tok}'")
    return phases
# ---------------------------------------------------------
# Run-time rate changer
# ---------------------------------------------------------
def run_load_profile(client, tx_ports, phases, force=False):
    """
    Start with phases[0] and update rate through remaining phases.
    """
    if not phases:
        return 0
    total = sum(sec for _, sec in phases)
    first_mult, first_sec = phases[0]
    client.start(ports=tx_ports, duration=total, mult=first_mult, force=force)

    elapsed = 0
    time.sleep(first_sec)
    elapsed += first_sec
    for mult, sec in phases[1:]:
        client.update(ports=tx_ports, mult=mult)
        time.sleep(sec)
        elapsed += sec
    return elapsed


# ---------------------------------------------------------
# Argument parsing (two-stage: JSON defaults then CLI overrides)
# ---------------------------------------------------------
def build_arg_parser():
    p = argparse.ArgumentParser(
        description="QinQ VarSize Runner with VLAN ranges, TX/RX mode, CSV logging, RX capture, checksum fix, and load profile"
    )
    p.set_defaults(fix_checksums=True)  # default: ON

    p.add_argument("--input_file", help="JSON file with all arguments", required=False)

    # Traffic pattern
    p.add_argument("--src_mac", default="bc:d0:74:59:9b:9e")
    p.add_argument("--dst_mac", default="00:e0:4c:77:8d:e0")
    p.add_argument("--src_ip_base", default="192.168.0.")
    p.add_argument("--src_ip_range", default="",
                   help="Optional inclusive range 'start-end' to roll source IPs (overrides src_ip_base)")
    p.add_argument("--dst_ip", default="20.0.0.1")
    p.add_argument("--dst_ip_range", default="",
                   help="Optional inclusive range 'start-end' to build destination list")
    p.add_argument("--dst_ip_list", default="",
                   help="Comma list of destination IPs to roll across per stream")
    p.add_argument("--src_port", type=int, default=1234,
                   help="Base source port (used if no range provided)")
    p.add_argument("--dst_port", type=int, default=443,
                   help="Base destination port (used if no range provided)")
    p.add_argument("--src_port_range", default="",
                   help="Optional inclusive range 'start-end' for source ports")
    p.add_argument("--dst_port_range", default="",
                   help="Optional inclusive range 'start-end' for destination ports")
    p.add_argument("--min_size", type=int, default=64)
    p.add_argument("--max_size", type=int, default=1500)
    p.add_argument("--num_streams", type=int, default=300)
    p.add_argument("--pps_per_stream", type=int, default=50)
    p.add_argument("--dup_factor", type=int, default=2,
                   help="Number of identical packets transmitted back-to-back per stream (>=1).")

    # Ports & modes
    p.add_argument("--ports", type=int, nargs="+", default=[0, 1])
    p.add_argument("--tx_mode", choices=["same_port", "dual_port"], default="same_port")
    p.add_argument("--rx_mode", choices=["same_port", "dual_port", "off"], default="same_port")

    # VLAN ranges
    p.add_argument("--s_vlan_start", type=int, default=100)
    p.add_argument("--s_vlan_count", type=int, default=10)
    p.add_argument("--c_vlan_start", type=int, default=200)
    p.add_argument("--c_vlan_count", type=int, default=20)

    # QinQ flavor: outer TPID (0x88a8 or 0x8100)
    p.add_argument("--outer_tpid", default="0x88a8",
                   help="Outer VLAN TPID: 0x88a8 (802.1ad) or 0x8100 (stacked 802.1Q)")

    # Duration & outputs
    p.add_argument("--duration", type=int, default=30,
                   help="If --load_profile or --auto_profile is set, duration comes from the profile builder")
    p.add_argument("--csv_out", help="CSV output file for stats logging", required=False)
    p.add_argument("--pcap_out", help="Optional PCAP output path (generated packets)", required=False)

    # Capture
    p.add_argument("--capture_rx", action="store_true", help="Enable RX capture on RX port(s)")
    p.add_argument("--capture_file", help="Path to save RX capture PCAP", required=False)
    p.add_argument("--capture_limit", type=int, default=1000, help="Max packets to capture")
    p.add_argument("--capture_bpf", default="", help="BPF filter, e.g. 'vlan and vlan' or ''")

    # Peer MAC automation
    p.add_argument("--auto_peer_mac", action="store_true",
                   help="Use peer port MAC as dst_mac per TX port (prints mapping)")

    # Checksum fix
    p.add_argument("--fix_checksums", action="store_true",
                   help="Fix IP and L4 checksums on transmit (default: on; use --no-fix-checksums to disable)")
    p.add_argument("--no-fix-checksums", action="store_true",
                   help="Disable checksum fixing (overrides --fix_checksums)")
    p.add_argument("--l4_protos", default="udp",
                   help="Comma list of protocols per stream (e.g. 'udp,tcp,udp'). Accepted values: udp, tcp.")
    p.add_argument("--tcp_flags", default="S",
                   help="TCP flags sequence matching TCP streams (single value or comma list)")
    p.add_argument("--stamp-head-bytes", type=int, choices=[0, 8, 16], default=16,
                   help="Bytes reserved at start of payload for stamping (0 disables)")

    # TRex server
    p.add_argument("--trex_server", default="127.0.0.1")

    # Load profile (explicit or auto-generated)
    p.add_argument("--load_profile", default=None,
                   help="Comma-separated phases '<mult>@<sec>', e.g. '95Gbps@20,50Gbps@10,95Gbps@15'. "
                        "Units supported: %, pps, mpps, bps, kbps, mbps, gbps.")
    p.add_argument("--auto_profile", action="store_true",
                   help="Auto-build a load profile from start/max/duration (ramps + holds)")
    p.add_argument("--start_load", default=None,
                   help="Starting load for auto profile (e.g. '30Gbps', '25%%', '10mpps')")
    p.add_argument("--max_load", default=None,
                   help="Max load for auto profile (e.g. '95Gbps', '80%%', '15mpps')")
    p.add_argument("--profile_pattern", default="up-hold-down-hold-up",
                   help="Pattern of phases: e.g. 'up-hold-down-hold-up', 'up-hold', 'up-down-up'")
    p.add_argument("--pattern_ratios", default="0.3,0.2,0.3,0.2",
                   help="Comma ratios totaling 1.0 matching pattern phases (e.g. '0.3,0.2,0.3,0.2')")
    p.add_argument("--ramp_steps", type=int, default=20,
                   help="Number of linear steps for each ramp in the auto profile")

    return p

def parse_args_2stage():
    parser = build_arg_parser()

    # Stage 1: read --input_file first
    partial, _ = parser.parse_known_args()
    json_defaults = {}
    if partial.input_file:
        try:
            with open(partial.input_file) as f:
                loaded = json.load(f) or {}
            if isinstance(loaded, dict):
                json_defaults = loaded
        except FileNotFoundError:
            print(f"ERROR: Input file '{partial.input_file}' not found. Exiting.")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: Failed to parse JSON '{partial.input_file}': {e}")
            sys.exit(1)

    # Apply JSON keys as defaults
    defaults_probe = parser.parse_args([])
    for k, v in json_defaults.items():
        if hasattr(defaults_probe, k):
            parser.set_defaults(**{k: v})

    # Stage 2: final parse — CLI overrides JSON defaults
    args = parser.parse_args()

    # Normalize outer_tpid to int (accepts "0x88a8" or 34984)
    if isinstance(args.outer_tpid, str):
        args.outer_tpid = int(args.outer_tpid, 0)

    if getattr(args, "no_fix_checksums", False):
        args.fix_checksums = False

    proto_tokens = [tok.strip().lower() for tok in str(args.l4_protos).split(',') if tok.strip()]
    if not proto_tokens:
        proto_tokens = ['udp']
    valid = {'udp', 'tcp'}
    for tok in proto_tokens:
        if tok not in valid:
            raise ValueError(f"Unsupported protocol '{tok}'. Allowed: udp,tcp")

    tcp_flags_seq = [tok.strip() for tok in str(args.tcp_flags).split(',') if tok.strip()]
    if not tcp_flags_seq:
        tcp_flags_seq = ['S']

    args._l4_proto_list = proto_tokens
    args._tcp_flags_list = tcp_flags_seq

    src_range = expand_ip_range(args.src_ip_range)
    args._src_ip_list = src_range if src_range else None

    if args.dst_ip_range:
        dst_list = expand_ip_range(args.dst_ip_range)
    else:
        dst_list = [ip.strip() for ip in str(args.dst_ip_list).split(',') if ip.strip()]
    if not dst_list:
        dst_list = [args.dst_ip]
    args._dst_ip_list = dst_list

    src_ports = expand_port_range(args.src_port_range, args.src_port)
    dst_ports = expand_port_range(args.dst_port_range, args.dst_port)
    args._src_port_list = src_ports if src_ports else None
    args._dst_port_list = dst_ports if dst_ports else None
    args._stamp_head_bytes = args.stamp_head_bytes
    if args.dup_factor < 1:
        raise ValueError("--dup_factor must be >= 1")

    return args


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
def main():
    args = parse_args_2stage()
    dup_factor = max(1, args.dup_factor)

    client = STLClient(server=args.trex_server)
    client.connect()
    client.reset()

    # Determine ports
    tx_ports, rx_ports = determine_ports(args.tx_mode, args.rx_mode, args.ports)
    all_ports = sorted(set(tx_ports + rx_ports))

    # Print MACs and, if requested, compute per-port dst_mac
    trex_macs = print_port_macs(client, all_ports)
    peer_map = build_peer_mac_map(tx_ports, trex_macs, args.tx_mode) if args.auto_peer_mac else {}
    if peer_map:
        print("[mac] TX port -> dst_mac mapping (auto_peer_mac):")
        for p in tx_ports:
            print(f"  - TX port {p} dst_mac => {peer_map.get(p)}")
    else:
        print(f"[mac] Using provided dst_mac for all TX ports: {args.dst_mac}")

    # Build streams per TX port
    first_port_sample = True
    pcap_path = safe_path(args.pcap_out) if args.pcap_out else None
    scapy_sample = []

    proto_cycle = args._l4_proto_list
    tcp_flag_cycle = args._tcp_flags_list
    dst_ip_cycle = args._dst_ip_list
    src_cycle = args._src_ip_list

    for txp in tx_ports:
        dst_mac_for_port = peer_map.get(txp, args.dst_mac)
        streams = []
        for i in range(args.num_streams):
            if src_cycle:
                user_ip = src_cycle[i % len(src_cycle)]
            else:
                user_ip = args.src_ip_base + str(1 + (i % 254))
            s_vlan = args.s_vlan_start + (i % args.s_vlan_count)
            c_vlan = args.c_vlan_start + (i % args.c_vlan_count)
            pkt_size = random.randint(args.min_size, args.max_size)

            proto = proto_cycle[i % len(proto_cycle)]
            tcp_flag = tcp_flag_cycle[i % len(tcp_flag_cycle)]
            dst_ip = dst_ip_cycle[i % len(dst_ip_cycle)]

            if args._src_port_list:
                src_port = args._src_port_list[i % len(args._src_port_list)]
            else:
                src_port = args.src_port + i

            if args._dst_port_list:
                dst_port = args._dst_port_list[i % len(args._dst_port_list)]
            else:
                dst_port = args.dst_port

            stamp_head_bytes = args._stamp_head_bytes if dup_factor == 1 else 0
            scapy_pkt, payload_off = build_qinq_packet(
                args.src_mac, dst_mac_for_port, user_ip, dst_ip,
                src_port, dst_port,
                s_vlan, c_vlan, pkt_size,
                outer_tpid=args.outer_tpid,
                l4_proto=proto,
                tcp_flags=tcp_flag,
                stamp_head_bytes=stamp_head_bytes
            )

            if pcap_path and first_port_sample:
                scapy_sample.append(scapy_pkt.copy())

            vm = build_vm_program(payload_off,
                                  l4_proto=proto,
                                  stamp_head_bytes=stamp_head_bytes,
                                  fix_checksums=args.fix_checksums)
            pkt_builder = STLPktBuilder(pkt=scapy_pkt, vm=vm)
            if dup_factor > 1:
                mode = STLTXMultiBurst(
                    pkts_per_burst=dup_factor,
                    ibg=0.0,
                    count=0,
                    pps=args.pps_per_stream
                )
            else:
                mode = STLTXCont(pps=args.pps_per_stream)
            streams.append(STLStream(packet=pkt_builder, mode=mode))

        client.add_streams(streams, ports=[txp])
        first_port_sample = False

    if dup_factor > 1:
        print(f"[dup] Burst mode enabled: each stream transmits {dup_factor} identical packets")

    # Save a small sample PCAP of generated packets (from first TX port)
    if pcap_path and scapy_sample:
        wrpcap(pcap_path, scapy_sample)
        print(f"[pcap] Wrote sample of generated packets to: {pcap_path}")

    # Optional RX capture
    capture_id = None
    capture_file = None
    service_ports = []
    if args.capture_rx:
        cap_ports = rx_ports if rx_ports else tx_ports
        if not cap_ports:
            print("[capture] No ports available for capture; skipping.")
        else:
            try:
                capture_file = safe_path(args.capture_file or "qinq_rx_capture.pcap")
                ensure_parent_writable(capture_file)

                service_ports = sorted(set(cap_ports))
                client.set_service_mode(ports=service_ports, enabled=True)
                print(f"[capture] Service mode ON for ports {service_ports}")

                cap_args = dict(
                    rx_ports=cap_ports,
                    limit=int(args.capture_limit),
                    bpf_filter=str(args.capture_bpf or "")
                )
                if "tx_ports" in client.start_capture.__code__.co_varnames:
                    cap_args["tx_ports"] = cap_ports

                try:
                    cap = client.start_capture(**cap_args)
                except Exception as e:
                    print(f"[capture] start failed with filter '{cap_args.get('bpf_filter','')}': {e}")
                    try:
                        cap_args["bpf_filter"] = "vlan and vlan"
                        print("[capture] retrying with BPF: 'vlan and vlan'")
                        cap = client.start_capture(**cap_args)
                    except Exception:
                        cap_args["bpf_filter"] = ""
                        print("[capture] retrying with no BPF")
                        cap = client.start_capture(**cap_args)

                capture_id = cap.get("id", cap.get("capture_id", None))
                print(f"[capture] Started on ports {cap_ports}, id={capture_id}, "
                      f"limit={cap_args['limit']}, bpf='{cap_args.get('bpf_filter','')}', "
                      f"tx_capture={'yes' if 'tx_ports' in cap_args else 'no'}")
            except Exception as e:
                print(f"[capture] Start failed ({e}); continuing without capture.")
                service_ports = []

    # ---------- Traffic start + load profile / or fixed duration ----------
    phases = None

    if args.load_profile:
        phases = parse_load_profile(args.load_profile)
        print(f"[load] Profile (explicit): {phases}")
    elif args.auto_profile or (args.start_load and args.max_load):
        if not args.duration or args.duration <= 0:
            raise ValueError("When using auto_profile, --duration must be > 0")
        phases = build_auto_load_profile(
            duration_sec=int(args.duration),
            start_load=str(args.start_load or "30Gbps"),
            max_load=str(args.max_load or "95Gbps"),
            pattern=args.profile_pattern,
            ratios=args.pattern_ratios,
            ramp_steps=int(args.ramp_steps)
        )
        print(f"[load] Auto profile ({args.profile_pattern}): {phases}")

    if phases:
        run_load_profile(client, tx_ports, phases, force=bool(args.capture_rx))
        if args.csv_out:
            collect_and_log_stats(client, sorted(set(tx_ports + rx_ports)), args.csv_out)
        client.wait_on_traffic(ports=sorted(set(tx_ports + rx_ports)))
    else:
        client.start(ports=tx_ports, duration=args.duration, force=bool(args.capture_rx))
        if args.csv_out:
            collect_and_log_stats(client, sorted(set(tx_ports + rx_ports)), args.csv_out)
        client.wait_on_traffic(ports=sorted(set(tx_ports + rx_ports)))
    # ---------------------------------------------------------------------

    # Stop capture and write PCAP
    if capture_id is not None and capture_file:
        try:
            saved = stop_capture_write_or_fetch(client, capture_id, capture_file)
            if saved:
                print(f"[capture] Saved RX capture to: {saved}")
            else:
                print("[capture] Capture stopped but file not saved (API variant?).")
        except Exception as e:
            print(f"[capture] Stop failed ({e}); capture not saved.")

    # Always disable service mode
    if service_ports:
        try:
            client.set_service_mode(ports=service_ports, enabled=False)
            print(f"[capture] Service mode OFF for ports {service_ports}")
        except Exception as e:
            print(f"[capture] Failed to disable service mode: {e}")

    client.disconnect()


if __name__ == "__main__":
    main()
