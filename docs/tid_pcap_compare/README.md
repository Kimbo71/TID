# Traffic PCAP Compare (`tid_pcap_compare`)

## Overview

`tid_pcap_compare` compares two PCAP sources—either direct file paths or rolling
capture directories—and reports packet mismatches. It is tailored for verifying
that ingress/egress taps see identical traffic when running Napatech-based
capture, but works with any libpcap-compatible files.

Features:

- Text dashboard showing packet counts, file sizes, and difference summaries.
- Directory scanning mode (`--scan-all`) for rolling capture folders; can emit
  per-pair diff reports.
- Timestamp-window matching (`--window-us`) to tolerate small reorderings.
- Optional auto-generated diff reports with hex dumps of the first mismatching
  packets.

## Build

```bash
gcc -O2 -g src/c/tid_pcap_compare.c \
    -I/opt/napatech3/include \
    -L/opt/napatech3/lib \
    -lpcap -lntapi \
    -o bin/tid_pcap_compare
```

The Napatech headers are only required when you build with NT timestamp support;
omit `-lntapi` if you do not use the Napatech SDK.

## Common Workflows

### Compare Two Specific Files

```
bin/tid_pcap_compare \
    --pcap0 /path/to/port0.pcap \
    --pcap1 /path/to/port1.pcap \
    --offset1 1 \
    --window-us 1000 \
    --print-first-diff
```

- `--offset*` skips the first N packets in either file.
- `--window-us` defines the timestamp tolerance for windowed matching.

### Follow Rolling Capture Directories

```
bin/tid_pcap_compare \
    --pcap0-dir /dev/shm \
    --pcap1-dir /dev/shm \
    --scan-all \
    --window-us 1000 \
    --auto-report-dir /tmp/diff_reports
```

- `--scan-all` aligns files by timestamp suffix and compares each pair.
- `--auto-report-dir` writes textual reports with hex dumps for mismatching
  pairs (limited by `--auto-report-limit`).

Press `Ctrl+C` to exit the live view. Use `--once` for a single comparison.

## Matching Logic and Timestamp Window

At its core, `tid_pcap_compare` walks the packets in `pcap0` in order and, for
each packet, searches for an unused counterpart in `pcap1` whose timestamp falls
within a configured tolerance. The matching process is summarised below:

1. Load all packets from each PCAP (or from the latest pair of files when using
   rolling directories). For every packet the tool records:
   - Capture timestamp (converted to microseconds).
   - Captured length (`caplen`).
   - Layer‑2 payload digest (FNV‑1a hash across the captured bytes).
2. Iterate across packets from `pcap0` (after applying `--offset0`). For each
   packet `i` the tool searches the `pcap1` vector (after `--offset1`) for the
   first *unused* packet whose timestamp delta is within `--window-us` and whose
   `caplen` and digest match.
3. If a match is found the packet in `pcap1` is marked as used and the pair is
   counted as identical. Otherwise the packet is flagged as a difference.
4. After the scan, any unused packets remaining in `pcap1` represent packets that
   were not matched from `pcap0` (useful when one capture saw extra traffic).

### Why the Timestamp Window Matters

Packet captures from separate ports often show the same frame with slight
arrival differences. Setting `--window-us` allows the matcher to look past
microsecond-level skew. The default (`0`) enforces strict index-by-index matching.

- **Too small a window** (e.g. 0 µs) → reorderings are treated as differences
  because the first unmatched packet is compared against the wrong peer.
- **Too large a window** (e.g. > 1 000 000 µs) → packets in unrelated time periods
  might be paired if the streams diverge significantly. In practice the ideal
  range is just above the maximum observed skew (for inline taps this is usually
  in the 500–2000 µs range).

### Example: Impact of `--window-us`

| Scenario | window-us | Port 0 capture | Port 1 capture | Result |
|----------|-----------|----------------|----------------|--------|
| A: Perfect alignment | 0 | P0 timestamps: `t`, `t+1µs`, `t+2µs` | Identical order | 0 differences |
| B: Alternating order | 0 | Frames alternate `A,B,A,B,…` | Frames alternate `B,A,B,A,…` | 100% of comparisons flagged |
| B: Alternating order | 1000 | Same as above | Same as above | All matched (timestamps within 1 ms) |
| C: Extra packet on port 1 | 1000 | Sequence `A,B,C` | Sequence `A,B,X,C` (`X` arrives between B and C) | `X` unmatched; others match |

In Scenario B the timestamps differ by ~600 µs. Without `--window-us` the tool
compares packet 0 in port 0 against packet 0 in port 1 and sees different
payloads, reporting a mismatch for every pair. With a 1000 µs window the tool is
free to skip an already matched packet and align on timestamps, recognising the
frames are identical even though their order differs.

Tip: start by measuring the maximum timestamp skew between your taps (for
example with `tcpdump -tt`) and add a safety margin when setting `--window-us`.
