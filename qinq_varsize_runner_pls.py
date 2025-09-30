#!/usr/bin/env python3
import sys
import os
import argparse
import csv
import time
import json
import random
from datetime import datetime

# --- TRex API path ---
TREX_API_PATH = "/opt/trex-core/scripts/automation/trex_control_plane/interactive"
if TREX_API_PATH not in sys.path:
    sys.path.insert(0, TREX_API_PATH)

from trex_stl_lib.api import (
    STLClient, STLStream, STLPktBuilder, STLTXCont,
    STLScVmRaw, STLVmFixIpv4, STLVmFixChecksumHw,
    STLVmFlowVar, STLVmWrFlowVar
)
from scapy.all import Ether, Dot1Q, IP, UDP, Raw, wrpcap


# ---------------------------------------------------------
# QinQ Packet Builder (outer_tpid supports 0x88a8 or 0x8100)
# ---------------------------------------------------------
def build_qinq_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                      s_vlan, c_vlan, pkt_size, outer_tpid=0x88a8,
                      stamp_head_bytes=0):
    """
    Build a QinQ (double-tagged) IP/UDP frame and return:
      (packet_with_payload, payload_offset)

    - stamp_head_bytes: 0, 8, or 16. Ensures there is at least this many bytes
      available at the *start of the UDP payload* for stamping.
    """
    # Outer TPID sits in Ethernet.type
    ether = Ether(src=src_mac, dst=dst_mac, type=outer_tpid)

    # First Dot1Q is the OUTER tag; 'type=0x8100' indicates another VLAN follows.
    s_tag = Dot1Q(vlan=s_vlan, type=0x8100)

    # Second Dot1Q is the INNER tag (its type will be set by next layer, e.g. IPv4 0x0800)
    c_tag = Dot1Q(vlan=c_vlan)

    ip = IP(src=src_ip, dst=dst_ip)      # leave checksums as None (Scapy default)
    udp = UDP(sport=src_port, dport=dst_port)

    base = ether / s_tag / c_tag / ip / udp
    payload_offset = len(base)

    # Guarantee enough room for requested head-stamp (and meet 64B min without FCS)
    min_needed = payload_offset + max(0, int(stamp_head_bytes))
    pkt_size = max(int(pkt_size), min_needed, 64)

    pad = pkt_size - len(base)
    if pad < 0:
        raise ValueError(f"Packet size too small for QinQ headers. min={len(base)} got={pkt_size}")

    return (base / Raw(b"Q" * pad), payload_offset)


# ---------------------------------------------------------
# Build Field-Engine program: payload stamp + checksum fix
# ---------------------------------------------------------
def build_vm_program(payload_off, l4_proto="udp", stamp_head_bytes=16, fix_checksums=True):
    """
    Creates a single STLScVmRaw with:
      - 8B sequence counter at payload_off (always big-endian)
      - Optional 8B monotonic tick at payload_off+8
      - IPv4 + L4 checksum fix via HW offload (if enabled)

    Returns None if no VM commands are needed.
    """
    vm_cmds = []
    # 64-bit safe upper-bound to avoid signed/overflow issues in some TRex builds
    MAX64_SAFE = (1 << 63) - 1

    # 8 bytes: sequence counter (monotonic increment)
    if stamp_head_bytes >= 8:
        vm_cmds += [
            STLVmFlowVar(name="seq64", init_value=0, min_value=0,
                         max_value=MAX64_SAFE, size=8, op="inc"),
            STLVmWrFlowVar(fv_name="seq64", pkt_offset=int(payload_off))
        ]

    # next optional 8 bytes: a second monotonic counter ("ticks")
    if stamp_head_bytes >= 16:
        vm_cmds += [
            STLVmFlowVar(name="tick64", init_value=0, min_value=0,
                         max_value=MAX64_SAFE, size=8, op="inc"),
            STLVmWrFlowVar(fv_name="tick64", pkt_offset=int(payload_off) + 8)
        ]

    if fix_checksums:
        # Prefer symbolic constants; fall back gracefully if not available
        l4p = str(l4_proto).lower()
        l4_name = "UDP" if l4p == "udp" else "TCP"
        try:
            # Provided by trex.stl.trex_stl_packet_builder_scapy
            from trex.stl.trex_stl_packet_builder_scapy import CTRexVmInsFixHwCs
            l4_type = CTRexVmInsFixHwCs.L4_TYPE_UDP if l4_name == "UDP" else CTRexVmInsFixHwCs.L4_TYPE_TCP
            vm_cmds += [
                STLVmFixIpv4(offset="IP"),
                STLVmFixChecksumHw(l3_offset="IP", l4_offset=l4_name, l4_type=l4_type),
            ]
        except Exception:
            # Older Python client: accept no l4_type (server infers)
            vm_cmds += [
                STLVmFixIpv4(offset="IP"),
                STLVmFixChecksumHw(l3_offset="IP", l4_offset=l4_name),
            ]

    return STLScVmRaw(vm_cmds) if vm_cmds else None


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
        description="QinQ VarSize Runner with VLAN ranges, TX/RX mode, CSV logging, RX capture, checksum fix, load profile, and payload head stamp"
    )
    p.set_defaults(fix_checksums=True)  # default: ON

    p.add_argument("--input_file", help="JSON file with all arguments", required=False)

    # Traffic pattern
    p.add_argument("--src_mac", default="bc:d0:74:59:9b:9e")
    p.add_argument("--dst_mac", default="00:e0:4c:77:8d:e0")
    p.add_argument("--src_ip_base", default="192.168.0.")
    p.add_argument("--dst_ip", default="20.0.0.1")
    p.add_argument("--src_port", type=int, default=1234)
    p.add_argument("--dst_port", type=int, default=443)
    p.add_argument("--min_size", type=int, default=64)
    p.add_argument("--max_size", type=int, default=1500)
    p.add_argument("--num_streams", type=int, default=300)
    p.add_argument("--pps_per_stream", type=int, default=50)

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
    p.add_argument("--l4_proto", choices=["udp", "tcp"], default="udp",
                   help="L4 protocol for checksum fix (affects VM l4_offset)")

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

    # Payload head stamping
    p.add_argument("--stamp_head_bytes", type=int, choices=[0, 8, 16], default=16,
                   help="Write 8 or 16 bytes at the *start* of the UDP payload: "
                        "first 8B=seq counter (big-endian), next 8B=monotonic tick. 0=disable.")

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

    # Resolve checksum toggles (default True; --no-fix-checksums forces False)
    if getattr(args, "no_fix_checksums", False):
        args.fix_checksums = False

    return args


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
def main():
    args = parse_args_2stage()

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

    for txp in tx_ports:
        dst_mac_for_port = peer_map.get(txp, args.dst_mac)
        streams = []
        for i in range(args.num_streams):
            user_ip = args.src_ip_base + str(1 + (i % 254))
            s_vlan = args.s_vlan_start + (i % args.s_vlan_count)
            c_vlan = args.c_vlan_start + (i % args.c_vlan_count)

            # Random size, but ensure header+stamp fits
            requested_size = random.randint(args.min_size, args.max_size)

            # Build packet and compute payload offset (start of UDP payload)
            scapy_pkt, payload_off = build_qinq_packet(
                args.src_mac, dst_mac_for_port, user_ip, args.dst_ip,
                args.src_port + i, args.dst_port,
                s_vlan, c_vlan, requested_size,
                outer_tpid=args.outer_tpid,
                stamp_head_bytes=args.stamp_head_bytes
            )

            if pcap_path and first_port_sample:
                scapy_sample.append(scapy_pkt)

            # Field-Engine program: payload stamp + checksum fix
            vm = build_vm_program(
                payload_off=payload_off,
                l4_proto=args.l4_proto,
                stamp_head_bytes=args.stamp_head_bytes,
                fix_checksums=bool(args.fix_checksums),
            )

            pkt_builder = STLPktBuilder(pkt=scapy_pkt, vm=vm)
            streams.append(STLStream(packet=pkt_builder, mode=STLTXCont(pps=args.pps_per_stream)))

        client.add_streams(streams, ports=[txp])
        first_port_sample = False

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
