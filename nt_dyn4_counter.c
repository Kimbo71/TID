// nt_dyn4_counter.c — Aggregate first/duplicate counters for one or two SIDs.
// The tool polls Napatech RX streams and reports total packets, bytes, and
// deduplication statistics over a user-selected duration. It is intended for
// high-rate testing where per-packet logging is impractical.
//
// Command-line parameters:
//   --adapter=N        Napatech adapter index passed to NT_NetRxOpen (default 0).
//   --sid0=S           Primary stream ID to monitor (default 0).
//   --sid1=S           Optional secondary stream ID; omit or set to -1 to disable.
//   --descriptor=Dyn4|Dyn3  Expected descriptor layout on the stream (default Dyn4).
//   --dup_bit=N        Deduplication color bit to inspect (default 7, set -1 to ignore).
//   --duration=SEC     Measurement window in seconds (default 10, minimum 1).
//   --timeout_ms=MS    Poll timeout supplied to NT_NetRxGet (default 50 ms).
//
// Output summary:
//   For each monitored SID a line is printed with packet/byte totals. The
//   "first" column counts frames where the deduplication color bit was clear
//   (i.e. the FPGA treated the packet as the first observation within the
//   correlation key/window). The "duplicates" column counts frames where the
//   selected color bit was set, meaning the hardware recognised the packet as
//   a duplicate of an earlier frame. "dup_ratio" is duplicates / packets, so
//   0.0 means no duplicates observed and 1.0 means every frame arrived as a
//   duplicate. Derived throughput metrics (Mpps, Gbps) are also included. An
//   aggregate line follows when two SIDs are active. CTRL+C interrupts early
//   and prints the statistics collected so far.
//
/* Build:
 *   gcc -O2 -Wall -Wextra 
 *     -I/opt/napatech3/include -I/opt/napatech3/include/ntapi 
 *     -L/opt/napatech3/lib -Wl,-rpath,/opt/napatech3/lib 
 *     nt_dyn4_counter.c -lntapi -o nt_dyn4_counter
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include <nt.h>
#include <ntapi/stream_net.h>
#include <ntapi/pktdescr_dyn3.h>
#include <ntapi/pktdescr_dyn4.h>

typedef enum {
  DESC_DYN4,
  DESC_DYN3
} descriptor_t;

typedef struct {
  uint64_t packets;
  uint64_t bytes;
  uint64_t first;
  uint64_t duplicates;
  uint64_t last_ts_ns;
} counters_t;

static volatile sig_atomic_t g_stop = 0;

static void on_sigint(int sig) {
  (void)sig;
  g_stop = 1;
}

static void die_err(const char* where, int status) {
  char buf[NT_ERRBUF_SIZE];
  NT_ExplainError(status, buf, sizeof buf);
  fprintf(stderr, "%s failed: %s (0x%08X)\n", where, buf, status);
  exit(EXIT_FAILURE);
}

static inline uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline void update_counters(counters_t* c, uint64_t wire_len, int dup_flag, uint64_t ts) {
  c->packets++;
  c->bytes += wire_len;
  c->last_ts_ns = ts;
  if (dup_flag)
    c->duplicates++;
  else
    c->first++;
}

static int run_counter(int sid_index,
                       NtNetStreamRx_t stream,
                       descriptor_t desc,
                       int dup_bit,
                       int timeout_ms,
                       counters_t* counters,
                       int* warned_descriptor) {
  NtNetBuf_t nb = NULL;
  int status = NT_NetRxGet(stream, &nb, timeout_ms);
  if (status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN)
    return 0;
  if (status != NT_SUCCESS)
    die_err("NT_NetRxGet", status);

  int dtype = NT_NET_GET_PKT_DESCRIPTOR_TYPE(nb);
  if (dtype != NT_PACKET_DESCRIPTOR_TYPE_DYNAMIC && !*warned_descriptor) {
    fprintf(stderr, "[warn sid%d] descriptor=%d (expected DYN)\n", sid_index, dtype);
    *warned_descriptor = 1;
  }

  const uint8_t* l2 = (const uint8_t*)NT_NET_GET_PKT_L2_PTR(nb);
  (void)l2;  // we do not use the payload, but keep for completeness
  uint32_t wire = NT_NET_GET_PKT_WIRE_LENGTH(nb);
  uint64_t ts;
  uint64_t color_val = 0;

  if (desc == DESC_DYN4) {
    const NtDyn4Descr_t* d4 = _NT_NET_GET_PKT_DESCR_PTR_DYN4(nb);
    ts = d4->timestamp;
    color_val = ((uint64_t)d4->color1 << 8) | (uint64_t)d4->color0;
  } else {
    const NtDyn3Descr_t* d3 = _NT_NET_GET_PKT_DESCR_PTR_DYN3(nb);
    ts = d3->timestamp;
    color_val = ((uint64_t)d3->color_hi << 14) | (uint64_t)d3->color_lo;
  }

  int dup = dup_bit >= 0 ? (int)((color_val >> dup_bit) & 0x1ULL) : 0;
  update_counters(counters, wire, dup, ts);

  NT_NetRxRelease(stream, nb);
  return 1;
}

static void print_summary(int sid, const counters_t* c, double seconds) {
  double mpps = seconds > 0.0 ? ((double)c->packets / seconds) / 1e6 : 0.0;
  double gbps = seconds > 0.0 ? ((double)c->bytes * 8.0) / seconds / 1e9 : 0.0;
  double dup_ratio = c->packets ? (double)c->duplicates / (double)c->packets : 0.0;

  printf("SID %d summary: packets=%" PRIu64 " bytes=%" PRIu64
         " first=%" PRIu64 " duplicates=%" PRIu64
         " dup_ratio=%.6f mpps=%.3f gbps=%.3f\n",
         sid, c->packets, c->bytes, c->first, c->duplicates,
         dup_ratio, mpps, gbps);
}

int main(int argc, char** argv) {
  int adapter = 0;
  int sid0 = 0;
  int sid1 = -1;
  int timeout_ms = 50;
  int duration_sec = 10;
  int dup_bit = 7;
  descriptor_t desc = DESC_DYN4;

  for (int i = 1; i < argc; ++i) {
    if (!strncmp(argv[i], "--adapter=", 10))
      adapter = atoi(argv[i] + 10);
    else if (!strncmp(argv[i], "--sid0=", 7))
      sid0 = atoi(argv[i] + 7);
    else if (!strncmp(argv[i], "--sid1=", 7))
      sid1 = atoi(argv[i] + 7);
    else if (!strncmp(argv[i], "--timeout_ms=", 13))
      timeout_ms = atoi(argv[i] + 13);
    else if (!strncmp(argv[i], "--duration=", 11))
      duration_sec = atoi(argv[i] + 11);
    else if (!strncmp(argv[i], "--dup_bit=", 10))
      dup_bit = atoi(argv[i] + 10);
    else if (!strncmp(argv[i], "--descriptor=", 13)) {
      const char* v = argv[i] + 13;
      if (!strcasecmp(v, "dyn4")) desc = DESC_DYN4;
      else if (!strcasecmp(v, "dyn3")) desc = DESC_DYN3;
      else {
        fprintf(stderr, "unknown descriptor: %s\n", v);
        return EXIT_FAILURE;
      }
    } else {
      fprintf(stderr,
              "Usage: %s --adapter=N --sid0=S [--sid1=S] [--duration=SEC]\n"
              "          [--timeout_ms=MS] [--descriptor=Dyn4|Dyn3] [--dup_bit=N]\n",
              argv[0]);
      return EXIT_FAILURE;
    }
  }

  if (duration_sec <= 0)
    duration_sec = 5;

  signal(SIGINT, on_sigint);

  int status = NT_Init(NTAPI_VERSION);
  if (status != NT_SUCCESS)
    die_err("NT_Init", status);

  NtNetStreamRx_t s0 = NULL, s1 = NULL;
  status = NT_NetRxOpen(&s0, "dup_counter0", NT_NET_INTERFACE_PACKET, sid0, -1);
  if (status != NT_SUCCESS)
    die_err("NT_NetRxOpen(sid0)", status);

  if (sid1 >= 0) {
    status = NT_NetRxOpen(&s1, "dup_counter1", NT_NET_INTERFACE_PACKET, sid1, -1);
    if (status != NT_SUCCESS)
      die_err("NT_NetRxOpen(sid1)", status);
  }

  printf("[counter] adapter=%d sid0=%d sid1=%d duration=%ds dup_bit=%d descriptor=%s\n",
         adapter, sid0, sid1, duration_sec, dup_bit,
         desc == DESC_DYN4 ? "DYN4" : "DYN3");

  counters_t cnt0 = {0}, cnt1 = {0};
  int warned0 = 0, warned1 = 0;

  uint64_t start_ns = now_ns();
  uint64_t stop_ns = start_ns + (uint64_t)duration_sec * 1000000000ULL;

  while (!g_stop && now_ns() < stop_ns) {
    int got = 0;
    got += run_counter(0, s0, desc, dup_bit, timeout_ms, &cnt0, &warned0);
    if (sid1 >= 0)
      got += run_counter(1, s1, desc, dup_bit, timeout_ms, &cnt1, &warned1);

    if (!got)
      usleep(1000);
  }

  uint64_t end_ns = now_ns();
  double seconds = (double)(end_ns - start_ns) / 1e9;
  if (seconds <= 0.0)
    seconds = (double)duration_sec;

  printf("\n=== Deduplication counters ===\n");
  print_summary(sid0, &cnt0, seconds);
  if (sid1 >= 0)
    print_summary(sid1, &cnt1, seconds);

  double total_packets = (double)cnt0.packets + (double)cnt1.packets;
  double total_bytes = (double)cnt0.bytes + (double)cnt1.bytes;
  double total_duplicates = (double)cnt0.duplicates + (double)cnt1.duplicates;
  if (seconds > 0.0 && total_packets > 0.0) {
    printf("Aggregate: packets=%.0f bytes=%.0f Mpps=%.3f Gbps=%.3f dup_ratio=%.6f\n",
           total_packets,
           total_bytes,
           total_packets / seconds / 1e6,
           (total_bytes * 8.0) / seconds / 1e9,
           total_duplicates / total_packets);
  }

  NT_NetRxClose(s0);
  if (s1)
    NT_NetRxClose(s1);
  NT_Done();
  return 0;
}
