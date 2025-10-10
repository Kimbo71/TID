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
