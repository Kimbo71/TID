# Traffic Impact Monitor (`tid`)

## Overview

`tid` polls Napatech adapter statistics while simultaneously sampling packets
to PCAP. It is designed to monitor a pair of inline ports (typically ingress
and egress of a tap) and highlight deduplication behaviour, bandwidth, and
extended counters.

Key capabilities:

- Periodic screen refresh showing per‑port throughput, packet counters, and
  deduplication statistics.
- Optional PCAP sampling. Supports single capture files or rolling capture
  directories with file/time quotas.
- Inline NTPL management. The `--ntpl-*` options can clear and push the
  deduplication configuration required for the monitor.

## Build

```bash
gcc -O2 -g -pthread src/c/tid.c \
    -I/opt/napatech3/include \
    -L/opt/napatech3/lib \
    -lpcap -lntapi \
    -o bin/tid
```

Adjust the include/library paths if your Napatech SDK is installed elsewhere.

## Expected NTPL Configuration

If you do not use the inline `--ntpl-*` options, preload the following NTPL
rules (Stream ID 0 shown; substitute the appropriate port numbers):

```
Delete = All
DeduplicationConfig[ColorBit=7; Retransmit=Duplicate] = GroupID == 0
Define ckFull = CorrelationKey(Begin=StartOfFrame[0], End=EndOfFrame[0], DeduplicationGroupID=0)
Setup[State=Active] = StreamId == 0
Assign[StreamId=0; Descriptor=DYN3; CorrelationKey=ckFull] = Port == <port0>
Assign[StreamId=0; Descriptor=DYN3; CorrelationKey=ckFull] = Port == <port1>
```

## Usage Highlights

```
bin/tid --adapter 0 --rx-stream-id 0 --interval 0.5 \
        --roll-seconds 60 --roll-count 500 \
        --pcap0-dir /dev/shm --pcap1-dir /dev/shm \
        --window-us 1000
```

Useful options:

- `--pcap0/--pcap1` for fixed sample files.
- `--pcap*-dir`, `--roll-seconds`, `--roll-count`, `--roll-max-mib` for rolling
  captures.
- `--ntpl-duplicate`, `--ntpl-drop`, `--ntpl-clear` to manage NTPL automatically.
- `--sample-count`, `--sample-seconds` to limit sampling.

Press `Ctrl+C` to exit; use `--once` for a single snapshot.
