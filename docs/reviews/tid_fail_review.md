# Code Review: `tid_fail.c`

## Summary
The revised `tid_fail.c` still fails to build cleanly and contains runtime defects that prevent the sampling thread from behaving as intended. The most critical observations are listed below with proposed fixes.

## Findings & Recommendations

1. **Rolling capture stops after the first packet**  
   In rolling mode both `SC.path0` and `SC.path1` remain `NULL`, so the termination guard at the end of `cap_fn` immediately evaluates to true once any packet is written, causing the capture thread to flip `running = 0` and exit as soon as traffic arrives.【F:tid_fail.c†L258-L375】  As a result, long-lived rolling captures never rotate and the monitoring UI loses `port_seen` updates. Tie the stop condition to the actual rolling writers (e.g., require `SC.rolling == 0` or check the `d0`/`d1` handles) so that rolling sessions continue until an explicit time or size limit is hit.

2. **Nested helper functions break C portability**  
   `warn_nt` and `cap_fn` are declared as nested helpers inside `main` using `auto`, which is not valid ISO C and is only accepted by GNU C as a non-portable extension.【F:tid_fail.c†L195-L299】  Move these helpers to file scope (`static`) and pass the necessary context as parameters to keep the translation unit standards-compliant.

3. **Sample thread races during shutdown**  
   The shutdown path flips `SC.running = 0` and immediately tears down the RX stream and PCAP handles without waiting for `cap_fn` to stop, leaving the worker potentially blocked inside `NT_NetRxGet`.【F:tid_fail.c†L472-L479】  Signal the thread, break any pending reads, and `pthread_join(cap_thread, NULL)` before destroying shared resources.

4. **Bounds checking missing for `port_seen` bookkeeping**  
   `cap_fn` increments `C->port_seen[rxp]` with the descriptor-reported port index, but never verifies that `rxp` is within the 0..255 array bounds.【F:tid_fail.c†L316-L323】  Validate the index (or clamp to an "unknown" bucket) before touching the counter to avoid buffer corruption on malformed descriptors.

5. **Time conversion can yield invalid `timespec`**  
   `sleep_interval` derives `tv_nsec` using floating point subtraction, which regularly produces values equal to or above `1e9`, triggering `EINVAL` from `nanosleep` on some intervals.【F:tid_fail.c†L62-L66】  Use `modf`/`llround` and explicitly clamp to the legal nanosecond range.

6. **Directory pruning silently drops files when >1024 matches**  
   `prune_dir_budget` stores entries in a fixed 1024-element array; additional files are ignored, so the directory may remain above the requested budget without warning.【F:tid_fail.c†L24-L49】  Switch to a dynamically resized container or emit a warning when the cap is hit to preserve the pruning guarantee.

Addressing these issues will keep the tool running continuously, restore portability, and prevent hard-to-debug data corruption during long captures.
