#!/usr/bin/env python3
"""
TRex Firewall Block Tester (UDP/TCP)
------------------------------------
Goal: Make it dead-simple to send specific UDP/TCP test packets through a firewall (with TAPs on both sides)
      and print a clear end-of-run report of what was sent vs what arrived (estimated blocked).

Highlights
- Reads a JSON input file for parameters (flows, ports, duration, etc.)
- Generates UDP and/or TCP traffic (you choose per-flow)
- Uses your specified source/destination IPs and ports
- Counts packets per-stream (TX) and aggregates RX at port-level
- Prints a friendly end-of-run summary (per flow + totals + estimated blocked)
- Optional CSV of live stats and optional RX capture PCAP
- Backwards-compatible with your existing QinQ helpers & checksum VM

Example minimal input JSON (save as firewall_test.json):
{
  "ports": [0, 1],
  "tx_mode": "dual_port",           
  "rx_mode": "dual_port",           
  "duration": 10,
  "flows": [
    {"name": "allow-udp-53", "l4_proto": "udp", "src_ip": "10.0.0.10", "dst_ip": "8.8.8.8", "src_port": 53000, "dst_port": 53,  "size": 128,  "pps": 500},
    {"name": "block-tcp-22", "l4_proto": "tcp", "src_ip": "10.0.0.20", "dst_ip": "198.51.100.10", "src_port": 40022, "dst_port": 22, "size": 256,  "pps": 500}
  ]
}
Run:
  python3 trex_firewall_block_tester.py --input_file firewall_test.json --trex_server 192.0.2.5 --csv_out run.csv --capture_rx --capture_file rx.pcap
"""

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
    STLScVmRaw, STLVmFixIpv4, STLVmFixChecksumHw
)
from scapy.all import Ether, Dot1Q, IP, UDP, TCP, Raw, wrpcap

# ===========================
# Packet builders & checksum
# ===========================

def build_qinq_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                      pkt_size, l4_proto="udp", s_vlan=None, c_vlan=None, outer_tpid=0x88a8):
    """Build single or double-tagged IPv4 UDP/TCP Ethernet frame.
       If s_vlan/c_vlan are None -> untagged. If only c_vlan -> single tag. If both -> QinQ.
    """
    ether = Ether(src=src_mac, dst=dst_mac)
    layers = [ether]

    # VLAN tagging
    if s_vlan is not None and c_vlan is not None:
        # QinQ: put outer Dot1Q with TPID=outer_tpid
        layers[0].type = outer_tpid
        layers += [Dot1Q(vlan=int(s_vlan), type=0x8100), Dot1Q(vlan=int(c_vlan))]
    elif c_vlan is not None and s_vlan is None:
        layers += [Dot1Q(vlan=int(c_vlan))]

    ip = IP(src=src_ip, dst=dst_ip)

    l4p = (l4_proto or "udp").lower()
    if l4p == "tcp":
        l4 = TCP(sport=int(src_port), dport=int(dst_port), flags="PA")
    else:
        l4 = UDP(sport=int(src_port), dport=int(dst_port))

    base = layers[0]
    for lay in layers[1:]:
        base = base / lay
    base = base / ip / l4

    pad = pkt_size - len(base)
    if pad < 0:
        raise ValueError(f"Packet size too small for headers. min={len(base)} got={pkt_size}")

    # Include a tiny payload marker: magic + flow name space (filled later by builder)
    payload = b"FWTEST" + b"\x00" * max(0, pad - 6)
    return base / Raw(payload)


def build_checksum_vm(l4_proto="udp"):
    """Fix IPv4 + L4 checksums on transmit (new/old API compatible)."""
    l4p = str(l4_proto).lower()
    l4_name = "UDP" if l4p == "udp" else "TCP"
    l4_type_int = 17 if l4p == "udp" else 6
    try:
        return STLScVmRaw([
            STLVmFixIpv4(offset="IP"),
            STLVmFixChecksumHw(l3_offset="IP", l4_offset=l4_name, l4_type=l4_type_int),
        ])
    except TypeError:
        return STLScVmRaw([
            STLVmFixIpv4(offset="IP"),
            STLVmFixChecksumHw(l3_offset="IP", l4_offset=l4_name),
        ])

# =====================
# Stats / capture utils
# =====================

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
                s = stats.get(p, {})
                w.writerow([
                    t, p,
                    s.get("tx_pps", 0), s.get("rx_pps", 0),
                    s.get("tx_bps", 0), s.get("rx_bps", 0),
                    s.get("tx_pkts", 0), s.get("rx_pkts", 0),
                    s.get("tx_dropped", 0), s.get("rx_dropped", 0)
                ])
            time.sleep(1)

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

# -------------
# Port handling
# -------------

def determine_ports(tx_mode, rx_mode, ports):
    if tx_mode == "same_port":
        tx_ports = [ports[0]]
    elif tx_mode == "dual_port":
        tx_ports = ports if len(ports) > 1 else [0, 1]
    else:
        raise ValueError(f"Invalid tx_mode: {tx_mode}")

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

# TRex Port MAC helpers

def get_port_mac(client, port_id):
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

# ========================
# CLI + input file parsing
# ========================

def build_arg_parser():
    p = argparse.ArgumentParser(description="TRex Firewall Block Tester (UDP/TCP)")
    p.set_defaults(fix_checksums=True)

    p.add_argument("--input_file", help="JSON file with all arguments")

    # Global defaults (can be overridden per-flow)
    p.add_argument("--src_mac", default="02:00:00:00:00:aa")
    p.add_argument("--dst_mac", default="02:00:00:00:00:bb")
    p.add_argument("--min_size", type=int, default=64)
    p.add_argument("--max_size", type=int, default=256)

    # Ports & modes
    p.add_argument("--ports", type=int, nargs="+", default=[0, 1])
    p.add_argument("--tx_mode", choices=["same_port", "dual_port"], default="dual_port")
    p.add_argument("--rx_mode", choices=["same_port", "dual_port", "off"], default="dual_port")

    # VLANs (optional): if only c_vlan provided -> single tag; if s_vlan & c_vlan -> QinQ
    p.add_argument("--s_vlan", type=int)
    p.add_argument("--c_vlan", type=int)
    p.add_argument("--outer_tpid", default="0x88a8")

    # Duration & outputs
    p.add_argument("--duration", type=int, default=10)
    p.add_argument("--csv_out", help="CSV output file for port stats logging")
    p.add_argument("--pcap_out", help="Optional PCAP sample of generated packets")

    # Capture
    p.add_argument("--capture_rx", action="store_true")
    p.add_argument("--capture_file", help="Path to save RX capture PCAP")
    p.add_argument("--capture_limit", type=int, default=10000)
    p.add_argument("--capture_bpf", default="")

    # Checksum fix
    p.add_argument("--fix_checksums", action="store_true")
    p.add_argument("--no-fix-checksums", action="store_true")

    # TRex server
    p.add_argument("--trex_server", default="127.0.0.1")

    return p


def parse_args_2stage():
    parser = build_arg_parser()

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

    args = parser.parse_args()

    # Normalize outer_tpid
    if isinstance(args.outer_tpid, str):
        try:
            args.outer_tpid = int(args.outer_tpid, 0)
        except Exception:
            args.outer_tpid = 0x88a8

    if getattr(args, "no_fix_checksums", False):
        args.fix_checksums = False

    # Pull flows list from JSON (if provided), else empty
    flows = []
    if partial.input_file and isinstance(json_defaults.get("flows"), list):
        flows = json_defaults["flows"]
    args.flows = flows

    return args

# =====================
# Main program
# =====================

def main():
    args = parse_args_2stage()

    client = STLClient(server=args.trex_server)
    client.connect()
    client.reset()

    # Determine ports
    tx_ports, rx_ports = determine_ports(args.tx_mode, args.rx_mode, args.ports)
    all_ports = sorted(set(tx_ports + rx_ports))

    # Print MACs
    trex_macs = print_port_macs(client, all_ports)

    # Build streams (per flow) for each TX port
    stream_meta = []   # list of dicts describing each stream -> for end-of-run report
    stream_ids_by_port = {p: [] for p in tx_ports}

    # Sample PCAP of the first few packets / first port
    pcap_path = safe_path(args.pcap_out) if args.pcap_out else None
    scapy_sample = []

    if not args.flows:
        # Fallback: create two simple default flows for convenience
        args.flows = [
            {
                "name": "udp-allow-default", "l4_proto": "udp",
                "src_ip": "10.0.0.1", "dst_ip": "10.0.1.1",
                "src_port": 40001, "dst_port": 53, "size": max(64, args.min_size), "pps": 1000
            },
            {
                "name": "tcp-block-default", "l4_proto": "tcp",
                "src_ip": "10.0.0.2", "dst_ip": "10.0.1.2",
                "src_port": 40022, "dst_port": 22, "size": max(64, args.min_size), "pps": 1000
            }
        ]

    # Create streams
    sid_counter = 1
    first_port_sample = True

    for txp in tx_ports:
        for f in args.flows:
            name = str(f.get("name", f"flow-{sid_counter}"))
            l4p = (f.get("l4_proto") or "udp").lower()
            src_ip = f.get("src_ip")
            dst_ip = f.get("dst_ip")
            src_port = int(f.get("src_port", 12345))
            dst_port = int(f.get("dst_port", 80))
            size = int(f.get("size", max(64, args.min_size)))
            pps = int(f.get("pps", 1000))

            # Per-flow VLAN override or use global
            s_vlan = f.get("s_vlan", args.s_vlan)
            c_vlan = f.get("c_vlan", args.c_vlan)

            pkt = build_qinq_packet(
                src_mac=args.src_mac,
                dst_mac=args.dst_mac,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                pkt_size=size,
                l4_proto=l4p,
                s_vlan=s_vlan,
                c_vlan=c_vlan,
                outer_tpid=args.outer_tpid,
            )

            # Replace payload marker with name (truncated) to help pcap readability
            payload_bytes = bytes(name.encode("ascii", errors="ignore"))[:32]
            # find marker start (after 'FWTEST') and patch by rebuilding last Raw
            base_len = len(pkt) - len(pkt[Raw].load)
            head = bytes(pkt)[:base_len + 6]  # up to 'FWTEST'
            tail_len = size - len(head)
            payload = payload_bytes + b"\x00" * max(0, tail_len - len(payload_bytes))
            pkt = Ether(head) / Raw(payload)  # Ether() will parse the rest accordingly

            vm = build_checksum_vm(l4p) if args.fix_checksums else None
            stream = STLStream(
                name=f"{name}@port{txp}",
                packet=STLPktBuilder(pkt=pkt, vm=vm),
                mode=STLTXCont(pps=pps),
                stream_id=sid_counter
            )

            client.add_streams([stream], ports=[txp])
            stream_ids_by_port[txp].append(sid_counter)

            if pcap_path and first_port_sample and len(scapy_sample) < 10:
                scapy_sample.append(pkt)

            stream_meta.append({
                "stream_id": sid_counter,
                "tx_port": txp,
                "name": name,
                "l4_proto": l4p,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "size": size,
                "pps": pps,
                "s_vlan": s_vlan,
                "c_vlan": c_vlan,
            })

            sid_counter += 1
        first_port_sample = False

    if pcap_path and scapy_sample:
        wrpcap(pcap_path, scapy_sample)
        print(f"[pcap] Wrote sample of generated packets to: {pcap_path}")

    # Optional RX capture
    capture_id = None
    capture_file = None
    service_ports = []
    if args.capture_rx:
        cap_ports = rx_ports if rx_ports else tx_ports
        try:
            capture_file = safe_path(args.capture_file or "rx_capture.pcap")
            ensure_parent_writable(capture_file)
            service_ports = sorted(set(cap_ports))
            client.set_service_mode(ports=service_ports, enabled=True)
            cap_args = dict(rx_ports=cap_ports, limit=int(args.capture_limit), bpf_filter=str(args.capture_bpf or ""))
            if "tx_ports" in client.start_capture.__code__.co_varnames:
                cap_args["tx_ports"] = cap_ports
            cap = client.start_capture(**cap_args)
            capture_id = cap.get("id", cap.get("capture_id", None))
            print(f"[capture] Started on ports {cap_ports}, id={capture_id}")
        except Exception as e:
            print(f"[capture] Start failed: {e}")
            service_ports = []

    # Start traffic
    tx_set = sorted(set(tx_ports))
    rx_set = sorted(set(rx_ports))

    client.start(ports=tx_set, duration=int(args.duration), force=bool(args.capture_rx))

    # CSV logging in a side thread-like loop (simple, blocking via poll)
    if args.csv_out:
        collect_and_log_stats(client, sorted(set(tx_set + rx_set)), args.csv_out)

    client.wait_on_traffic(ports=sorted(set(tx_set + rx_set)))

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

    if service_ports:
        try:
            client.set_service_mode(ports=service_ports, enabled=False)
        except Exception as e:
            print(f"[capture] Failed to disable service mode: {e}")

    # =============================
    # Build end-of-run easy report
    # =============================

    # Per-stream TX packets
    per_stream = []
    total_tx = 0

    for meta in stream_meta:
        sid = meta["stream_id"]
        txp = meta["tx_port"]
        try:
            sstats = client.get_stream_stats(ports=[txp], stream_id=sid)
            # sstats is a dict keyed by port
            s = sstats.get(txp) or {}
            tx_pkts = int(s.get("opackets", 0) or s.get("tx_packets", 0) or 0)
        except Exception:
            tx_pkts = 0
        meta_out = dict(meta)
        meta_out["tx_pkts"] = tx_pkts
        per_stream.append(meta_out)
        total_tx += tx_pkts

    # Aggregate RX packets at port-level
    stats = client.get_stats()
    total_rx = 0
    rx_detail = {}
    for p in rx_set:
        sp = stats.get(p, {})
        rx_pkts = int(sp.get("rx_pkts", 0) or sp.get("ipackets", 0) or 0)
        rx_detail[p] = rx_pkts
        total_rx += rx_pkts

    # Friendly printout
    print("\n================ FIREWALL TEST REPORT ================")
    print(f"Duration: {args.duration}s | TX ports: {tx_set} | RX ports: {rx_set}")
    print("----------------------------------------------------")
    print("Per-flow transmitted packets (by stream):")
    for m in per_stream:
        tag_vlan = ""
        if m.get("s_vlan") is not None and m.get("c_vlan") is not None:
            tag_vlan = f" qinq({m['s_vlan']},{m['c_vlan']})"
        elif m.get("c_vlan") is not None:
            tag_vlan = f" vlan({m['c_vlan']})"
        print(
            f"  - [{m['name']}] {m['l4_proto'].upper()} "
            f"{m['src_ip']}:{m['src_port']} -> {m['dst_ip']}:{m['dst_port']}"
            f" size={m['size']} pps={m['pps']}{tag_vlan} | TX={m['tx_pkts']}"
        )
    print("----------------------------------------------------")
    print("RX packets by port:")
    for p, v in rx_detail.items():
        print(f"  - port {p}: RX={v}")
    est_blocked = max(0, total_tx - total_rx)
    print("----------------------------------------------------")
    print(f"TOTAL TX={total_tx} | TOTAL RX={total_rx} | ESTIMATED BLOCKED={est_blocked}")
    if total_tx > 0:
        blocked_pct = 100.0 * est_blocked / float(total_tx)
        print(f"Blocked % (approx): {blocked_pct:.2f}%")
    print("====================================================\n")

    client.disconnect()


if __name__ == "__main__":
    main()
