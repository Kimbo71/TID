#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

#include <nt.h>
#include <ntapi/stream_statistics.h>

static volatile sig_atomic_t g_running = 1;
static void on_sigint(int sig) { (void)sig; g_running = 0; }

static void die_nt(const char* where, int status) {
  char buf[NT_ERRBUF_SIZE];
  NT_ExplainError(status, buf, sizeof buf);
  fprintf(stderr, "%s failed: %s (0x%08X)\n", where, buf, status);
  exit(EXIT_FAILURE);
}

static void sleep_interval(double seconds) {
  if (seconds <= 0.0) return;
  struct timespec ts; ts.tv_sec = (time_t)seconds; ts.tv_nsec = (long)((seconds - ts.tv_sec) * 1e9);
  if (ts.tv_nsec < 0) ts.tv_nsec = 0; nanosleep(&ts, NULL);
}

static void clear_screen(void) { fputs("\033[2J\033[H", stdout); }

static const char* now_str(char* buf, size_t len) {
  struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
  struct tm tm; localtime_r(&ts.tv_sec, &tm);
  strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm);
  return buf;
}

static void print_bw_row(const char* label, double gbps0, double gbps1) {
  printf("%-18s | %8.3f Gbps        | %8.3f Gbps\n", label, gbps0, gbps1);
}

static void print_side_row(const char* label, uint64_t v0, uint64_t v1){
  printf("%-18s | #%018" PRIu64 " | #%018" PRIu64 "\n", label, v0, v1);
}

// Single-value row to match Stage-2 spec lines like "Port 1 = Port 2"
static void print_single_row(const char* label, uint64_t v){
  // Render only one numeric value in the first value column; second left blank
  printf("%-18s | #%018" PRIu64 " |\n", label, v);
}

int main(int argc, char** argv) {
  int adapter = 0;
  double interval = 0.5;
  double summary_period = 2.0;
  int color_bit = 7;
  int once = 0;

  static struct option long_opts[] = {
    {"adapter",   required_argument, NULL, 'a'},
    {"interval",  required_argument, NULL, 'i'},
    {"summary",   required_argument, NULL, 's'},
    {"color-bit", required_argument, NULL, 'b'},
    {"once",      no_argument,       NULL, 'o'},
    {NULL, 0, NULL, 0}
  };
  int opt;
  while ((opt = getopt_long(argc, argv, "a:i:s:b:o", long_opts, NULL)) != -1) {
    switch (opt) {
      case 'a': adapter = atoi(optarg); break;
      case 'i': interval = atof(optarg); if (interval <= 0.0) interval = 0.5; break;
      case 's': summary_period = atof(optarg); if (summary_period <= 0.0) summary_period = 2.0; break;
      case 'b': color_bit = atoi(optarg); if (color_bit < 0) color_bit = 0; if (color_bit > 63) color_bit = 63; break;
      case 'o': once = 1; break;
      default:
        fprintf(stderr, "Usage: %s [--adapter=N] [--interval=SEC] [--summary=SEC] [--color-bit=N] [--once]\n", argv[0]);
        return EXIT_FAILURE;
    }
  }

  int status = NT_Init(NTAPI_VERSION);
  if (status != NT_SUCCESS) die_nt("NT_Init", status);

  NtStatStream_t stat_stream = NULL;
  status = NT_StatOpen(&stat_stream, "tid");
  if (status != NT_SUCCESS) die_nt("NT_StatOpen", status);

  signal(SIGINT, on_sigint);
  setvbuf(stdout, NULL, _IONBF, 0);

  double since_summary = summary_period;
  uint64_t prev_octets[64] = {0};
  uint64_t dedup_tot_pkts[64] = {0};
  uint64_t dedup_tot_octets[64] = {0};
  uint64_t dedup_delta_pkts[64] = {0};
  uint64_t dedup_delta_octets[64] = {0};

  while (g_running) {
    sleep_interval(interval);

    NtStatistics_t stat; memset(&stat, 0, sizeof stat);
    stat.cmd = NT_STATISTICS_READ_CMD_QUERY_V4; stat.u.query_v4.poll = 1; stat.u.query_v4.clear = 0;
    status = NT_StatRead(stat_stream, &stat);
    if (status != NT_SUCCESS) die_nt("NT_StatRead", status);

    const struct NtStatisticsQueryPortResult_v4_s* port_res = &stat.u.query_v4.data.port;
    const struct NtStatisticsQueryAdapterResult_v4_s* adapter_res = &stat.u.query_v4.data.adapter;

    const struct NtPortStatistics_v3_s* p0 = port_res->numPorts > 0 ? &port_res->aPorts[0].rx : NULL;
    const struct NtPortStatistics_v3_s* p1 = port_res->numPorts > 1 ? &port_res->aPorts[1].rx : NULL;

    uint64_t v0_pkts = p0 ? p0->RMON1.pkts : 0;
    uint64_t v1_pkts = p1 ? p1->RMON1.pkts : 0;
    uint64_t d1_pkts = (p1 && p1->valid.extDrop) ? p1->extDrop.pktsDedup : 0;

    double gbps0 = 0.0, gbps1 = 0.0;
    if (p0) { gbps0 = (double)(p0->RMON1.octets - prev_octets[0]) * 8.0 / interval; prev_octets[0] = p0->RMON1.octets; }
    if (p1) { gbps1 = (double)(p1->RMON1.octets - prev_octets[1]) * 8.0 / interval; prev_octets[1] = p1->RMON1.octets; }

    since_summary += interval;
    if (since_summary >= summary_period) {
      for (uint8_t p = 0; p < port_res->numPorts && p < 64; ++p) {
        const struct NtPortStatistics_v3_s* rx = &port_res->aPorts[p].rx;
        if (rx->valid.extDrop) {
          uint64_t pkts = rx->extDrop.pktsDedup;
          uint64_t octs = rx->extDrop.octetsDedup;
          dedup_delta_pkts[p] = pkts >= dedup_tot_pkts[p] ? pkts - dedup_tot_pkts[p] : pkts;
          dedup_delta_octets[p] = octs >= dedup_tot_octets[p] ? octs - dedup_tot_octets[p] : octs;
          dedup_tot_pkts[p] = pkts; dedup_tot_octets[p] = octs;
        }
      }
      since_summary = 0.0;
    }

    clear_screen();
    char ts[64];
    printf("Traffic Impact Monitor            %s\n\n", now_str(ts, sizeof ts));
    printf("Adapter %d  Interval %.1fs  Summary %.1fs  Color bit %d\n\n", adapter, interval, summary_period, color_bit);

    // Stage-1 interface per tid-reqs-stage1.pdf
    // Stage-2 header: remove leading port indices in column labels
    printf("%-18s | %-22s | %-22s\n", "Metric", "Ingress Port 1 TAP", "Egress Port 2 TAP");
    printf("------------------+----------------------+----------------------\n");
    print_bw_row("RX Speed", gbps0, gbps1);
    print_side_row("Packets", v0_pkts, v1_pkts);

    // Derived rows per Stage-2: explicitly show both equal and not-equal counts
    // Port 1 = Port 2 is the dedup packet counter on Port 1
    print_single_row("Port 1 = Port 2", d1_pkts);
    // Port 1 != Port 2 is Port0 packets minus dedup pkts; render single-value row (second column removed)
    uint64_t forwarded_est = (v0_pkts >= d1_pkts) ? (v0_pkts - d1_pkts) : 0;
    print_single_row("Port 1 != Port 2", forwarded_est);

    // Extended counters subset
    if (p0 || p1) {
      const struct NtExtendedRMONCounters_v1_s* e0 = p0 && p0->valid.extRMON ? &p0->extRMON : NULL;
      const struct NtExtendedRMONCounters_v1_s* e1 = p1 && p1->valid.extRMON ? &p1->extRMON : NULL;
      print_side_row("Unicast", e0 ? e0->unicastPkts : v0_pkts, e1 ? e1->unicastPkts : v1_pkts);
      print_side_row("Multicast", p0 ? p0->RMON1.multicastPkts : 0, p1 ? p1->RMON1.multicastPkts : 0);
      print_side_row("Broadcast", p0 ? p0->RMON1.broadcastPkts : 0, p1 ? p1->RMON1.broadcastPkts : 0);
      print_side_row("Octets", p0 ? p0->RMON1.octets : 0, p1 ? p1->RMON1.octets : 0);
      print_side_row("512-1023 octets", p0 ? p0->RMON1.pkts512to1023Octets : 0, p1 ? p1->RMON1.pkts512to1023Octets : 0);
      print_side_row("1024-1518 octets", p0 ? p0->RMON1.pkts1024to1518Octets : 0, p1 ? p1->RMON1.pkts1024to1518Octets : 0);
    }

    // Stage-2 removes Drop counters, Dedup summary table, and adapter color totals

    printf("\nPress Ctrl+C to exit\n");
    if (once) break;
  }

  NT_StatClose(stat_stream);
  NT_Done();
  return 0;
}
