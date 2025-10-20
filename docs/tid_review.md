diff --git a//dev/null b/reviews/tid_fail_review.md
index 0000000000000000000000000000000000000000..d031e2c8b0178906eaccd777c842740326c584c0 100644
--- a//dev/null
+++ b/reviews/tid_fail_review.md
@@ -0,0 +1,23 @@
+# Code Review: `tid_fail.c`
+
+## Summary
+`tid_fail.c` has a number of portability and robustness issues that are likely to cause build failures or runtime instability. The most critical observations are called out below, together with suggested improvements.
+
+## Findings & Recommendations
+
+1. **Nested helper functions break C portability**  
+   The file defines `warn_nt` and `cap_fn` as nested functions inside `main` using the `auto` storage-class keyword.【F:tid_fail.c†L190-L220】【F:tid_fail.c†L296-L379】  Nested functions are a non-standard GNU C extension and the use of `auto` before a function declaration is not valid ISO C. Most compilers (including MSVC and clang in default modes) will reject this, which explains why the translation unit cannot be built in a portable environment. Move both helpers to file scope (e.g., `static void warn_nt(...)` and `static void* cap_fn(void*)`) and pass any required context via parameters.
+
+2. **Sample thread races during shutdown**  
+   At exit the code sets `SC.running = 0` and immediately closes the NetRx stream and libpcap handles without waiting for the sampling thread to observe the flag.【F:tid_fail.c†L472-L479】  This can leave `cap_fn` blocked inside `NT_NetRxGet` while the underlying stream is destroyed, leading to undefined behavior or crashes. Signal the thread to stop, call `pthread_join(cap_thread, NULL)`, and only then close the hardware and PCAP resources. Adding a timeout-aware wake-up (e.g., `pthread_cancel` or `NT_NetRxBreak`) would make the shutdown path more predictable.
+
+3. **Bounds checking missing for `port_seen` bookkeeping**  
+   The thread increments `C->port_seen[rxp]` without validating that `rxp` is within 0..255.【F:tid_fail.c†L316-L323】  On malformed descriptors the decode helper can return values beyond the size of the array, corrupting adjacent memory. Add a guard (`if (rxp < NT_PORT_SEEN_MAX)`) before touching the counter or fall back to a dedicated "unknown" bucket.
+
+4. **Time conversion can yield invalid `timespec`**  
+   `sleep_interval` converts a `double` to a `timespec` using `(seconds - ts.tv_sec) * 1e9`, which is sensitive to floating-point rounding and may generate a `tv_nsec` outside the legal `[0, 999,999,999]` range (e.g., `0.1` often turns into `99999997x`).【F:tid_fail.c†L62-L66】  Use `modf` (or integer math via `struct timespec ts = { .tv_sec = (time_t)seconds, .tv_nsec = (long)llround((seconds - floor) * 1e9) }`) and clamp with `if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }` to avoid spurious `EINVAL` failures from `nanosleep`.
+
+5. **Directory pruning silently drops files when >1024 matches**  
+   `prune_dir_budget` keeps at most 1024 entries in a fixed-size stack array; additional files are ignored, so the function may fail to reduce the directory size below the configured budget.【F:tid_fail.c†L24-L49】  Consider dynamically allocating the entry list (e.g., grow an array with `realloc`) or, at minimum, detect when `n` reaches the limit and report a warning so the operator knows the pruning guarantee is not met.
+
+Implementing the above adjustments should resolve the immediate build failure and improve the resilience of the sampling pipeline.
