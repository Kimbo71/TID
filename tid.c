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
#include <pthread.h>

#include <nt.h>
#include <ntapi/stream_statistics.h>
// Optional packet sampling support
#include <ntapi/pktdescr.h>
#include <ntapi/pktdescr_dyn3.h>
#include <ntapi/pktdescr_dyn4.h>
#include <pcap/pcap.h>

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
  if (ts.tv_nsec < 0) ts.tv_nsec = 0;
  nanosleep(&ts, NULL);
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
  /* summary window removed in this simplified tool */
  int color_bit = 7;
  int once = 0;

  // Sampling options
  const char* pcap0_path = NULL;
  const char* pcap1_path = NULL;
  uint32_t snaplen = 128;
  uint32_t sample_count = 256;    // per port target
  double sample_seconds = 0.0;    // 0 = disabled
  int rx_stream_id = -1;          // capture stream id (any)
  int port0_index = 0;            // match rxPort for Port 0 (default 0)
  int port1_index = 1;            // match rxPort for Port 1 (default 1)

  static struct option long_opts[] = {
    {"adapter",   required_argument, NULL, 'a'},
    {"interval",  required_argument, NULL, 'i'},
    {"color-bit", required_argument, NULL, 'b'},
    {"once",      no_argument,       NULL, 'o'},
    {"pcap0",     required_argument, NULL, 1001},
    {"pcap1",     required_argument, NULL, 1002},
    {"snaplen",   required_argument, NULL, 1003},
    {"sample-count", required_argument, NULL, 1004},
    {"sample-seconds", required_argument, NULL, 1005},
    {"rx-stream-id", required_argument, NULL, 1006},
    {"port0",     required_argument, NULL, 1007},
    {"port1",     required_argument, NULL, 1008},
    {NULL, 0, NULL, 0}
  };
  int opt;
  while ((opt = getopt_long(argc, argv, "a:i:b:o", long_opts, NULL)) != -1) {
    switch (opt) {
      case 'a': adapter = atoi(optarg); break;
      case 'i': interval = atof(optarg); if (interval <= 0.0) interval = 0.5; break;
      case 'b': color_bit = atoi(optarg); if (color_bit < 0) color_bit = 0; if (color_bit > 63) color_bit = 63; break;
      case 'o': once = 1; break;
      case 1001: pcap0_path = optarg; break;
      case 1002: pcap1_path = optarg; break;
      case 1003: snaplen = (uint32_t)atoi(optarg); if (snaplen < 64) snaplen = 64; break;
      case 1004: sample_count = (uint32_t)atoi(optarg); if ((int)sample_count < 0) sample_count = 0; break;
      case 1005: sample_seconds = atof(optarg); if (sample_seconds < 0.0) sample_seconds = 0.0; break;
      case 1006: rx_stream_id = atoi(optarg); break;
      case 1007: port0_index = atoi(optarg); break;
      case 1008: port1_index = atoi(optarg); break;
      default:
        fprintf(stderr, "Usage: %s [--adapter=N] [--interval=SEC] [--color-bit=N] [--once]\n"
                        "            [--pcap0=PATH] [--pcap1=PATH] [--snaplen=B] [--sample-count=N] [--sample-seconds=S]\n"
                        "            [--rx-stream-id=N] [--port0=N] [--port1=N] (defaults: port0=0, port1=1)\n", argv[0]);
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

  // Optional PCAP sampling context
  typedef struct {
    volatile sig_atomic_t running;
    NtNetStreamRx_t rx;
    pcap_t* p_dead;
    pcap_dumper_t* d0;
    pcap_dumper_t* d1;
    const char* path0;
    const char* path1;
    uint32_t snaplen;
    uint32_t target;
    uint32_t wrote0;
    uint32_t wrote1;
    int port0;
    int port1;
    double max_sec;
    struct timespec t0;
    uint64_t port_seen[256];
  } sample_ctx_t;

  sample_ctx_t SC = {0};
  pthread_t cap_thread;

  int sampling_enabled = (pcap0_path || pcap1_path) ? 1 : 0;
  if (sampling_enabled) {
    SC.running = 1; SC.snaplen = snaplen; SC.target = sample_count; SC.max_sec = sample_seconds;
    SC.path0 = pcap0_path; SC.path1 = pcap1_path; SC.port0 = port0_index; SC.port1 = port1_index;
    clock_gettime(CLOCK_REALTIME, &SC.t0);
    SC.p_dead = pcap_open_dead(DLT_EN10MB, SC.snaplen);
    if (!SC.p_dead) { fprintf(stderr, "pcap_open_dead failed\n"); sampling_enabled = 0; }
    if (sampling_enabled && SC.path0) { SC.d0 = pcap_dump_open(SC.p_dead, SC.path0); if (!SC.d0) { fprintf(stderr, "pcap_dump_open %s: %s\n", SC.path0, pcap_geterr(SC.p_dead)); } }
    if (sampling_enabled && SC.path1) { SC.d1 = pcap_dump_open(SC.p_dead, SC.path1); if (!SC.d1) { fprintf(stderr, "pcap_dump_open %s: %s\n", SC.path1, pcap_geterr(SC.p_dead)); } }
    // Open a capture RX stream
    if (sampling_enabled) {
      int rc = NT_NetRxOpen(&SC.rx, "tid_cap", NT_NET_INTERFACE_PACKET, adapter, rx_stream_id);
      if (rc != NT_SUCCESS) { die_nt("NT_NetRxOpen", rc); }
    }
    // Thread to pull and write samples
    if (sampling_enabled) {
      auto void* cap_fn(void* arg) {
        sample_ctx_t* C = (sample_ctx_t*)arg;
        while (C->running) {
          NtNetBuf_t nb = NULL; int st = NT_NetRxGet(C->rx, &nb, 1000);
          if (st==NT_STATUS_TIMEOUT || st==NT_STATUS_TRYAGAIN) {
            // check time limit
            if (C->max_sec > 0.0) {
              struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
              double dt = (now.tv_sec - C->t0.tv_sec) + (now.tv_nsec - C->t0.tv_nsec)/1e9;
              if (dt >= C->max_sec) C->running = 0;
            }
            continue;
          }
          if (st!=NT_SUCCESS) continue;
          unsigned dtp = NT_NET_GET_PKT_DESCRIPTOR_TYPE(nb);
          uint8_t* l2 = (uint8_t*)NT_NET_GET_PKT_L2_PTR(nb);
          uint32_t cap = NT_NET_GET_PKT_CAP_LENGTH(nb);
          uint32_t wire= NT_NET_GET_PKT_WIRE_LENGTH(nb);
          uint8_t rxp = 255;
          if (dtp == 4)      rxp = _NT_NET_GET_PKT_DESCR_PTR_DYN4(nb)->rxPort;
          else if (dtp == 3 || dtp == NT_PACKET_DESCRIPTOR_TYPE_DYNAMIC)
                              rxp = _NT_NET_GET_PKT_DESCR_PTR_DYN3(nb)->rxPort;
          C->port_seen[rxp]++;
          // timestamp: host realtime for PCAP
          struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
          struct pcap_pkthdr h; memset(&h, 0, sizeof h);
          h.caplen = cap < C->snaplen ? cap : C->snaplen; h.len = wire ? wire : h.caplen;
          h.ts.tv_sec = ts.tv_sec; h.ts.tv_usec = (suseconds_t)(ts.tv_nsec/1000);
          if (C->d0 && rxp == (uint8_t)C->port0 && C->wrote0 < C->target) { pcap_dump((u_char*)C->d0, &h, l2); C->wrote0++; }
          if (C->d1 && rxp == (uint8_t)C->port1 && C->wrote1 < C->target) { pcap_dump((u_char*)C->d1, &h, l2); C->wrote1++; }
          NT_NetRxRelease(C->rx, nb);
          if ((C->path0?C->wrote0>=C->target:1) && (C->path1?C->wrote1>=C->target:1)) {
            if (C->max_sec <= 0.0) C->running = 0; // stop when reached targets (unless a time window specified)
          }
        }
        return (void*)0;
      }
      ;
      pthread_create(&cap_thread, NULL, cap_fn, &SC);
    }
  }

  /* no summary window */
  uint64_t prev_octets[64] = {0};

  while (g_running) {
    sleep_interval(interval);

    NtStatistics_t stat; memset(&stat, 0, sizeof stat);
    stat.cmd = NT_STATISTICS_READ_CMD_QUERY_V4; stat.u.query_v4.poll = 1; stat.u.query_v4.clear = 0;
    status = NT_StatRead(stat_stream, &stat);
    if (status != NT_SUCCESS) die_nt("NT_StatRead", status);

    const struct NtStatisticsQueryPortResult_v4_s* port_res = &stat.u.query_v4.data.port;
    // Adapter scope not used in Stage-3 interface

    const struct NtPortStatistics_v3_s* p0 = port_res->numPorts > 0 ? &port_res->aPorts[0].rx : NULL;
    const struct NtPortStatistics_v3_s* p1 = port_res->numPorts > 1 ? &port_res->aPorts[1].rx : NULL;

    uint64_t v0_pkts = p0 ? p0->RMON1.pkts : 0;
    uint64_t v1_pkts = p1 ? p1->RMON1.pkts : 0;
    uint64_t d1_pkts = (p1 && p1->valid.extDrop) ? p1->extDrop.pktsDedup : 0;

    double gbps0 = 0.0, gbps1 = 0.0;
    if (p0) { gbps0 = ((double)(p0->RMON1.octets - prev_octets[0]) * 8.0 / interval) / 1e9; prev_octets[0] = p0->RMON1.octets; }
    if (p1) { gbps1 = ((double)(p1->RMON1.octets - prev_octets[1]) * 8.0 / interval) / 1e9; prev_octets[1] = p1->RMON1.octets; }

    /* no summary window */

    clear_screen();
    char ts[64];
    printf("Traffic Impact Monitor            %s\n\n", now_str(ts, sizeof ts));
    printf("Adapter %d  Interval %.1fs  Color bit %d\n\n", adapter, interval, color_bit);

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

    // Extended Counters
    printf("\nExtended Counters\n\n");
    printf("------------------+----------------------+----------------------\n");
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

    if (sampling_enabled) {
      printf("\nPCAP sample: p0=%u/%u p1=%u/%u (port0=%d seen=%" PRIu64 ", port1=%d seen=%" PRIu64 ")\n",
             SC.wrote0, SC.path0?SC.target:0, SC.wrote1, SC.path1?SC.target:0,
             SC.port0, SC.port_seen[(unsigned)SC.port0], SC.port1, SC.port_seen[(unsigned)SC.port1]);
      if (SC.path0) printf("pcap0=%s\n", SC.path0);
      if (SC.path1) printf("pcap1=%s\n", SC.path1);
    }

    printf("\nPress Ctrl+C to exit\n");
    if (once) break;
  }

  NT_StatClose(stat_stream);
  if (sampling_enabled) {
    SC.running = 0;
    if (SC.rx) NT_NetRxClose(SC.rx);
    if (SC.d0) { pcap_dump_close(SC.d0); }
    if (SC.d1) { pcap_dump_close(SC.d1); }
    if (SC.p_dead) { pcap_close(SC.p_dead); }
  }
  NT_Done();
  return 0;
}
