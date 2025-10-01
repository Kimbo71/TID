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
#include <dirent.h>
#include <sys/stat.h>
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
static void clear_screen_full(void) { fputs("\033[3J\033[2J\033[H", stdout); }

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

// Render a shell-quoted argument (safe for copy/paste)
static void fprint_shell_quoted(FILE* f, const char* s){
  if (!s){ fputs("''", f); return; }
  // Use single-quote style and escape internal single quotes: ' -> '\''
  fputc('\'', f);
  for (const char* p = s; *p; ++p){
    if (*p == '\''){ fputs("'\\''", f); }
    else fputc(*p, f);
  }
  fputc('\'', f);
}

// Delete oldest files with given prefix in dir until total size <= max_bytes
static void prune_dir_budget(const char* dir, const char* prefix, uint64_t max_bytes){
  if (!dir || max_bytes==0) return;
  DIR* d = opendir(dir); if (!d) return;
  typedef struct { char path[768]; time_t mt; off_t sz; } ent_t;
  ent_t list[512]; size_t n=0; uint64_t total=0;
  struct dirent* e;
  while ((e = readdir(d)) != NULL){
    if (e->d_name[0]=='.') continue;
    size_t len = strlen(e->d_name);
    if (strncmp(e->d_name, prefix, strlen(prefix))!=0) continue;
    if (len < 5 || strcmp(e->d_name+len-5, ".pcap")!=0) continue;
    ent_t it; snprintf(it.path, sizeof it.path, "%s/%s", dir, e->d_name);
    struct stat st; if (stat(it.path, &st)!=0) continue;
    it.mt = st.st_mtime; it.sz = st.st_size; total += (uint64_t)st.st_size;
    if (n < sizeof(list)/sizeof(list[0])) list[n++] = it;
  }
  closedir(d);
  if (total <= max_bytes) return;
  // insertion sort by mtime asc
  for (size_t i=1;i<n;i++){
    ent_t key=list[i]; size_t j=i; while (j>0 && list[j-1].mt > key.mt){ list[j]=list[j-1]; j--; } list[j]=key;
  }
  size_t i=0; while (total > max_bytes && i<n){
    unlink(list[i].path); if (total >= (uint64_t)list[i].sz) total -= (uint64_t)list[i].sz; else total = 0; i++;
  }
}

int main(int argc, char** argv) {
  int adapter = 0;
  double interval = 0.5;
  /* summary window removed in this simplified tool */
  /* color bit removed from simplified UI */
  int once = 0;
  int no_clear = 0;      // do not clear screen between refreshes
  int alt_screen = 0;    // use terminal alternate screen buffer
  int full_clear = 0;    // clear scrollback too (if supported)

  // Sampling options
  const char* pcap0_path = NULL;
  const char* pcap1_path = NULL;
  const char* pcap0_dir  = NULL;  // rolling: directory for port0 files
  const char* pcap1_dir  = NULL;  // rolling: directory for port1 files
  uint32_t snaplen = 128;
  uint32_t sample_count = 256;    // per port target
  double sample_seconds = 0.0;    // 0 = disabled
  // Rolling file sampling
  int rolling = 0;                // enable rolling rotation
  uint32_t roll_count = 500;      // packets per rolling file
  double roll_seconds = 60.0;     // seconds per rolling file
  uint64_t roll_max_bytes = 0;    // 0 = unlimited; enforce budget per dir
  int rx_stream_id = -1;          // capture stream id (-1:any); NTPL often uses 0
  int host_buffer_allow = -1;     // hostBufferAllowance for NT_NetRxOpen (-1 disables drop-level)
  int auto_ports = 0;             // detect two most active rxPorts initially
  double auto_seconds = 1.0;      // probe window for auto-port detection
  int port0_index = 0;            // match rxPort for Port 0 (default 0)
  int port1_index = 1;            // match rxPort for Port 1 (default 1)

  static struct option long_opts[] = {
    {"adapter",   required_argument, NULL, 'a'},
    {"interval",  required_argument, NULL, 'i'},
    {"once",      no_argument,       NULL, 'o'},
    {"no-clear",  no_argument,       NULL, 1101},
    {"alt-screen",no_argument,       NULL, 1102},
    {"full-clear",no_argument,       NULL, 1103},
    {"pcap0",     required_argument, NULL, 1001},
    {"pcap1",     required_argument, NULL, 1002},
    {"pcap0-dir", required_argument, NULL, 1003},
    {"pcap1-dir", required_argument, NULL, 1004},
    {"snaplen",   required_argument, NULL, 1005},
    {"sample-count", required_argument, NULL, 1006},
    {"sample-seconds", required_argument, NULL, 1007},
    {"rx-stream-id", required_argument, NULL, 1008},
    {"host-allowance", required_argument, NULL, 1008+100},
    {"auto-ports", no_argument, NULL, 1110},
    {"auto-seconds", required_argument, NULL, 1111},
    {"port0",     required_argument, NULL, 1009},
    {"port1",     required_argument, NULL, 1010},
    {"roll",      no_argument,       NULL, 1011},
    {"roll-count",required_argument, NULL, 1012},
    {"roll-seconds", required_argument, NULL, 1013},
    {"roll-max-mib", required_argument, NULL, 1014},
    {NULL, 0, NULL, 0}
  };
  int opt;
  while ((opt = getopt_long(argc, argv, "a:i:o", long_opts, NULL)) != -1) {
    switch (opt) {
      case 'a': adapter = atoi(optarg); break;
      case 'i': interval = atof(optarg); if (interval <= 0.0) interval = 0.5; break;
      case 'o': once = 1; break;
      case 1101: no_clear = 1; break;
      case 1102: alt_screen = 1; break;
      case 1103: full_clear = 1; break;
      case 1001: pcap0_path = optarg; break;
      case 1002: pcap1_path = optarg; break;
      case 1003: pcap0_dir = optarg; break;
      case 1004: pcap1_dir = optarg; break;
      case 1005: snaplen = (uint32_t)atoi(optarg); if (snaplen < 64) snaplen = 64; break;
      case 1006: sample_count = (uint32_t)atoi(optarg); if ((int)sample_count < 0) sample_count = 0; break;
      case 1007: sample_seconds = atof(optarg); if (sample_seconds < 0.0) sample_seconds = 0.0; break;
      case 1008: rx_stream_id = atoi(optarg); break;
      case 1108: host_buffer_allow = atoi(optarg); break;
      case 1110: auto_ports = 1; break;
      case 1111: auto_seconds = atof(optarg); if (auto_seconds <= 0.0) auto_seconds = 0.5; break;
      case 1009: port0_index = atoi(optarg); break;
      case 1010: port1_index = atoi(optarg); break;
      case 1011: rolling = 1; break;
      case 1012: roll_count = (uint32_t)atoi(optarg); if (roll_count==0) roll_count = 1; break;
      case 1013: roll_seconds = atof(optarg); if (roll_seconds<=0.0) roll_seconds=1.0; break;
      case 1014: { long long mib = atoll(optarg); if (mib < 0) mib = 0; roll_max_bytes = (uint64_t)mib * 1024ULL * 1024ULL; } break;
      default:
        fprintf(stderr, "Usage: %s [--adapter=N] [--interval=SEC] [--once] [--no-clear] [--alt-screen] [--full-clear]\n"
                        "            [--pcap0=PATH] [--pcap1=PATH] [--pcap0-dir=DIR] [--pcap1-dir=DIR] [--roll]\n"
                        "            [--snaplen=B] [--sample-count=N] [--sample-seconds=S]\n"
                        "            [--rx-stream-id=N] [--host-allowance=N] [--port0=N] [--port1=N] (defaults: port0=0, port1=1)\n"
                        "            [--roll] [--roll-count=N] [--roll-seconds=S] [--roll-max-mib=MB]\n", argv[0]);
        return EXIT_FAILURE;
    }
  }

  if (alt_screen) { fputs("\033[?1049h", stdout); fflush(stdout); }

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
    // rolling capture
    int rolling;
    uint32_t roll_count;
    double roll_seconds;
    const char* dir0;
    const char* dir1;
    struct timespec roll0_t0;
    struct timespec roll1_t0;
    char cur0[512];
    char cur1[512];
    uint64_t roll_max_bytes;
    // auto-port selection
    int auto_ports;
    double auto_seconds;
    int auto_done;
    struct timespec auto_t0;
  } sample_ctx_t;

  

  sample_ctx_t SC = {0};
  pthread_t cap_thread;
  int tried_reopen_sid0 = 0;

  int sampling_enabled = (pcap0_path || pcap1_path || ((pcap0_dir || pcap1_dir))) ? 1 : 0;
  if (sampling_enabled) {
    SC.running = 1; SC.snaplen = snaplen; SC.target = sample_count; SC.max_sec = sample_seconds;
    SC.path0 = pcap0_path; SC.path1 = pcap1_path; SC.port0 = port0_index; SC.port1 = port1_index;
    SC.rolling = rolling; SC.roll_count = roll_count; SC.roll_seconds = roll_seconds; SC.dir0 = pcap0_dir; SC.dir1 = pcap1_dir; SC.roll_max_bytes = roll_max_bytes;
    SC.auto_ports = auto_ports; SC.auto_seconds = auto_seconds; SC.auto_done = auto_ports ? 0 : 1; clock_gettime(CLOCK_REALTIME, &SC.auto_t0);
    clock_gettime(CLOCK_REALTIME, &SC.t0);
    SC.p_dead = pcap_open_dead(DLT_EN10MB, SC.snaplen);
    if (!SC.p_dead) { fprintf(stderr, "pcap_open_dead failed\n"); sampling_enabled = 0; }
    if (sampling_enabled) {
      if (SC.rolling) {
        if (SC.dir0) {
          struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
          if (SC.d0) { pcap_dump_close(SC.d0); SC.d0=NULL; }
          char tsbuf[32]; time_t t=now.tv_sec; struct tm tm; gmtime_r(&t,&tm); strftime(tsbuf,sizeof tsbuf, "%Y-%m-%dT%H-%M-%SZ", &tm);
          snprintf(SC.cur0, sizeof SC.cur0, "%s/port0_%s.pcap", SC.dir0, tsbuf);
          SC.d0 = pcap_dump_open(SC.p_dead, SC.cur0);
          SC.wrote0 = 0; SC.roll0_t0 = now;
          prune_dir_budget(SC.dir0, "port0_", SC.roll_max_bytes);
        }
        if (SC.dir1) {
          struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
          if (SC.d1) { pcap_dump_close(SC.d1); SC.d1=NULL; }
          char tsbuf[32]; time_t t=now.tv_sec; struct tm tm; gmtime_r(&t,&tm); strftime(tsbuf,sizeof tsbuf, "%Y-%m-%dT%H-%M-%SZ", &tm);
          snprintf(SC.cur1, sizeof SC.cur1, "%s/port1_%s.pcap", SC.dir1, tsbuf);
          SC.d1 = pcap_dump_open(SC.p_dead, SC.cur1);
          SC.wrote1 = 0; SC.roll1_t0 = now;
          prune_dir_budget(SC.dir1, "port1_", SC.roll_max_bytes);
        }
      } else {
        if (SC.path0) { SC.d0 = pcap_dump_open(SC.p_dead, SC.path0); if (!SC.d0) { fprintf(stderr, "pcap_dump_open %s: %s\n", SC.path0, pcap_geterr(SC.p_dead)); } }
        if (SC.path1) { SC.d1 = pcap_dump_open(SC.p_dead, SC.path1); if (!SC.d1) { fprintf(stderr, "pcap_dump_open %s: %s\n", SC.path1, pcap_geterr(SC.p_dead)); } }
      }
    }
    // Open a capture RX stream
    if (sampling_enabled) {
      // Per NTAPI docs: NT_NetRxOpen(hStream, name, netIntf, streamId, hostBufferAllowance)
      // Use user-provided --rx-stream-id if specified (>=0) else open ANY (-1).
      int sid_to_open = (rx_stream_id >= 0) ? rx_stream_id : -1;
      int rc = NT_NetRxOpen(&SC.rx, "tid_cap", NT_NET_INTERFACE_PACKET,
                            (uint32_t)sid_to_open, host_buffer_allow);
      if (rc != NT_SUCCESS) { die_nt("NT_NetRxOpen", rc); }
      rx_stream_id = sid_to_open; // reflect in status
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
          // Optional auto-detect of two most active rxPorts during initial window
          if (C->auto_ports && !C->auto_done) {
            struct timespec nowp; clock_gettime(CLOCK_REALTIME, &nowp);
            double dtap = (nowp.tv_sec - C->auto_t0.tv_sec) + (nowp.tv_nsec - C->auto_t0.tv_nsec)/1e9;
            if (dtap >= C->auto_seconds) {
              // pick top-2 seen ports
              int best=-1, next=-1; uint64_t bv=0, nv=0;
              for (int i=0;i<256;i++){
                uint64_t v=C->port_seen[i];
                if (v>bv){ next=best; nv=bv; best=i; bv=v; }
                else if (v>nv){ next=i; nv=v; }
              }
              if (best>=0) C->port0 = best;
              if (next>=0) C->port1 = next;
              C->auto_done = 1;
            }
          }
          if (rxp == (uint8_t)C->port0 && C->d0) { pcap_dump((u_char*)C->d0, &h, l2); C->wrote0++; }
          if (rxp == (uint8_t)C->port1 && C->d1) { pcap_dump((u_char*)C->d1, &h, l2); C->wrote1++; }
          // rolling rotation checks
          if (C->rolling) {
            struct timespec now2; clock_gettime(CLOCK_REALTIME, &now2);
            if (C->dir0) {
              double dt = (now2.tv_sec - C->roll0_t0.tv_sec) + (now2.tv_nsec - C->roll0_t0.tv_nsec)/1e9;
              if (C->wrote0 >= C->roll_count || dt >= C->roll_seconds) {
                if (C->d0) { pcap_dump_close(C->d0); C->d0=NULL; }
                char tsbuf[32]; time_t t=now2.tv_sec; struct tm tm; gmtime_r(&t,&tm); strftime(tsbuf,sizeof tsbuf, "%Y-%m-%dT%H-%M-%SZ", &tm);
                snprintf(C->cur0, sizeof C->cur0, "%s/port0_%s.pcap", C->dir0, tsbuf);
                C->d0 = pcap_dump_open(C->p_dead, C->cur0);
                C->wrote0 = 0; C->roll0_t0 = now2;
                prune_dir_budget(C->dir0, "port0_", C->roll_max_bytes);
              }
            }
            if (C->dir1) {
              double dt1 = (now2.tv_sec - C->roll1_t0.tv_sec) + (now2.tv_nsec - C->roll1_t0.tv_nsec)/1e9;
              if (C->wrote1 >= C->roll_count || dt1 >= C->roll_seconds) {
                if (C->d1) { pcap_dump_close(C->d1); C->d1=NULL; }
                char tsbuf[32]; time_t t=now2.tv_sec; struct tm tm; gmtime_r(&t,&tm); strftime(tsbuf,sizeof tsbuf, "%Y-%m-%dT%H-%M-%SZ", &tm);
                snprintf(C->cur1, sizeof C->cur1, "%s/port1_%s.pcap", C->dir1, tsbuf);
                C->d1 = pcap_dump_open(C->p_dead, C->cur1);
                C->wrote1 = 0; C->roll1_t0 = now2;
                prune_dir_budget(C->dir1, "port1_", C->roll_max_bytes);
              }
            }
          }
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
    // Use RX packet decode Duplicate counter as requested
    uint64_t d1_pkts = (p1 && p1->valid.decode) ? p1->decode.pktsDuplicate : 0;

    double gbps0 = 0.0, gbps1 = 0.0;
    if (p0) { gbps0 = ((double)(p0->RMON1.octets - prev_octets[0]) * 8.0 / interval) / 1e9; prev_octets[0] = p0->RMON1.octets; }
    if (p1) { gbps1 = ((double)(p1->RMON1.octets - prev_octets[1]) * 8.0 / interval) / 1e9; prev_octets[1] = p1->RMON1.octets; }

    /* no summary window */

    if (!no_clear) { if (full_clear) clear_screen_full(); else clear_screen(); }
    char ts[64];
    printf("Traffic Impact Monitor            %s\n\n", now_str(ts, sizeof ts));
    printf("Adapter %d  Interval %.1fs\n\n", adapter, interval);

    // Stage-1 interface per tid-reqs-stage1.pdf
    // Stage-2 header: remove leading port indices in column labels
    printf("%-18s | %-22s | %-22s\n", "Metric", "Ingress Port 1 TAP", "Egress Port 2 TAP");
    printf("------------------+----------------------+----------------------\n");
    print_bw_row("RX Speed", gbps0, gbps1);
    print_side_row("Packets", v0_pkts, v1_pkts);

    // Derived rows per Stage-2: explicitly show both equal and not-equal counts
    // Port 1 = Port 2 shows the Duplicate counter on Port 1 (RX decode)
    print_single_row("Port 1 = Port 2", d1_pkts);
    // Port 1 != Port 2 is Port0 packets minus duplicate count; render single-value row (second column removed)
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
      printf("\nPCAP sample: p0=%u/%u p1=%u/%u (port0=%d seen=%" PRIu64 ", port1=%d seen=%" PRIu64 ") [SID=%d HBA=%d%s]\n",
             SC.wrote0, (SC.rolling?SC.roll_count:(SC.path0?SC.target:0)),
             SC.wrote1, (SC.rolling?SC.roll_count:(SC.path1?SC.target:0)),
             SC.port0, SC.port_seen[(unsigned)SC.port0], SC.port1, SC.port_seen[(unsigned)SC.port1], rx_stream_id, host_buffer_allow,
             (SC.auto_ports && !SC.auto_done)?" probing-ports":"");
      if (SC.rolling) {
        if (SC.dir0 && SC.cur0[0]) printf("pcap0=%s\n", SC.cur0);
        if (SC.dir1 && SC.cur1[0]) printf("pcap1=%s\n", SC.cur1);
      } else {
        if (SC.path0) printf("pcap0=%s\n", SC.path0);
        if (SC.path1) printf("pcap1=%s\n", SC.path1);
      }

      // Hint: If [SID=-1] and seen stays 0, run with --rx-stream-id=0 for your NTPL setup.
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
  if (alt_screen) { fputs("\033[?1049l", stdout); fflush(stdout); }
  return 0;
}
