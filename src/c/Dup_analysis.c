/**
 * Duplicate Analysis Monitor (Dup_analysis.c)
 *
 * Build:
 *   gcc -O2 -g -pthread src/c/Dup_analysis.c \
 *       -I/opt/napatech3/include \
 *       -L/opt/napatech3/lib \
 *       -lpcap -lntapi \
 *       -o bin/Dup_analysis
 *
 * The binary expects the Napatech capture libraries to be available in the
 * include/library paths above. Adjust paths if your SDK is installed elsewhere.
 *
 * Expected NTPL configuration (Stream ID 0 by default):
 *   Delete = All
 *   DeduplicationConfig[ColorBit=7; Retransmit=Duplicate] = GroupID == 0
 *   Define ckFull = CorrelationKey(Begin=Layer3Header[0], End=Layer3PayloadEnd[0], DeduplicationGroupID=0)
 *   Setup[State=Active] = StreamId == 0
 *   Assign[StreamId=0; Descriptor=DYN3; CorrelationKey=ckFull] = (Port == <tap-port>) AND (Layer3Protocol == IPv4 OR Layer3Protocol == IPv6)
 *
 * Use the --ntpl-* command-line options to have the monitor push a compatible
 * configuration automatically, or pre-load NTPL as shown above before running.
*/
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
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>

#define ARRAY_LEN(x) (sizeof(x)/sizeof((x)[0]))

// Delete oldest files with given prefix in dir until total size <= max_bytes
static void prune_dir_budget(const char* dir, const char* prefix, uint64_t max_bytes){
  if (!dir || max_bytes==0) return;
  DIR* d = opendir(dir); if (!d) return;
  typedef struct { char path[768]; time_t mt; off_t sz; } ent_t;
  ent_t* list = NULL; size_t n=0, cap=0; uint64_t total=0;
  struct dirent* e;
  size_t prefix_len = strlen(prefix);
  while ((e = readdir(d)) != NULL){
    if (e->d_name[0]=='.') continue;
    size_t len = strlen(e->d_name);
    if (len < 5 || strncmp(e->d_name, prefix, prefix_len)!=0 || strcmp(e->d_name+len-5, ".pcap")!=0)
      continue;
    if (n == cap){
      size_t new_cap = cap ? cap * 2 : 64;
      ent_t* tmp = realloc(list, new_cap * sizeof *list);
      if (!tmp) { free(list); closedir(d); return; }
      list = tmp; cap = new_cap;
    }
    ent_t* it = &list[n];
    snprintf(it->path, sizeof it->path, "%s/%s", dir, e->d_name);
    struct stat st; if (stat(it->path, &st)!=0) continue;
    it->mt = st.st_mtime; it->sz = st.st_size; total += (uint64_t)st.st_size;
    n++;
  }
  closedir(d);
  if (total <= max_bytes || n==0) { free(list); return; }
  // insertion sort by mtime asc
  for (size_t i=1;i<n;i++){
    ent_t key=list[i]; size_t j=i; while (j>0 && list[j-1].mt > key.mt){ list[j]=list[j-1]; j--; } list[j]=key;
  }
  for (size_t i=0; i<n && total > max_bytes; ++i){
    unlink(list[i].path);
    if (total >= (uint64_t)list[i].sz) total -= (uint64_t)list[i].sz; else total = 0;
  }
  free(list);
}

static uint16_t ethertype_from_l2(const uint8_t* buf, uint32_t len) {
  if (!buf || len < 14) return 0;
  uint32_t offset = 12;
  uint16_t type = (uint16_t)((buf[offset] << 8) | buf[offset + 1]);
  // Walk stacked VLAN/MPLS tags (common EtherType values)
  while ((type == 0x8100 || type == 0x88A8 || type == 0x9100 ||
          type == 0x9200 || type == 0x9800) &&
         offset + 4 < len) {
    offset += 4;
    type = (uint16_t)((buf[offset] << 8) | buf[offset + 1]);
  }
  return type;
}

static int packet_is_duplicate(NtNetBuf_t nb, unsigned descriptor_type, int dup_bit) {
  if (dup_bit < 0) return 0;
  uint64_t color_bits = 0;
  if (descriptor_type == 4) {
    const struct NtDyn4Descr_s* d4 = _NT_NET_GET_PKT_DESCR_PTR_DYN4(nb);
    color_bits = ((uint64_t)d4->color1 << 8) | (uint64_t)d4->color0;
  } else if (descriptor_type == NT_PACKET_DESCRIPTOR_TYPE_DYNAMIC || descriptor_type == 3) {
    const struct NtDyn3Descr_s* d3 = _NT_NET_GET_PKT_DESCR_PTR_DYN3(nb);
    color_bits = (((uint64_t)d3->color_hi) << 14) | (uint64_t)d3->color_lo;
  } else {
    return 0;
  }
  return (int)((color_bits >> dup_bit) & 0x1ULL);
}

typedef struct sample_ctx_s {
  volatile sig_atomic_t running;
  NtNetStreamRx_t rx;
  pcap_t* p_dead;
  int pcap_is_nano;
  pcap_dumper_t* d0;
  pcap_dumper_t* d1;
  const char* path0;
  const char* path1;
  const char* dir0;
  const char* dir1;
  uint32_t snaplen;
  uint32_t target;
  uint32_t wrote0;
  uint32_t wrote1;
  int port0;
  int port1;
  double max_sec;
  struct timespec t0;
  uint64_t port_seen[256];
  int rolling;
  uint32_t roll_count;
  double roll_seconds;
  struct timespec roll0_t0;
  struct timespec roll1_t0;
  char cur0[512];
  char cur1[512];
  uint64_t roll_max_bytes;
  int dup_port;
  uint64_t dup_ipv4;
  uint64_t dup_ipv6;
  uint64_t dup_other;
  int dup_bit;
  uint64_t roll_file_limit;
  uint64_t roll_file_bytes;
} sample_ctx_t;

static void warn_nt(const char* where, int status);
static void* capture_thread(void* arg);

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
  struct timespec ts;
  ts.tv_sec = (time_t)seconds;
  double frac = seconds - (double)ts.tv_sec;
  if (frac < 0.0) frac = 0.0;
  long nsec = (long)(frac * 1000000000.0 + 0.5);
  if (nsec >= 1000000000L) {
    ts.tv_sec += nsec / 1000000000L;
    nsec %= 1000000000L;
  }
  ts.tv_nsec = nsec;
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

static void print_single_row_pct(const char* label, uint64_t count, double pct){
  printf("%-18s | #%018" PRIu64 " (%6.2f %%) |\n", label, count, pct);
}

static void warn_nt(const char* where, int status){
  char buf[NT_ERRBUF_SIZE];
  NT_ExplainError(status, buf, sizeof buf);
  fprintf(stderr, "%s failed: %s (0x%08X)\n", where, buf, status);
}

static void* capture_thread(void* arg){
  sample_ctx_t* C = (sample_ctx_t*)arg;
  while (C->running) {
    NtNetBuf_t nb = NULL;
    int st = NT_NetRxGet(C->rx, &nb, 1000);
    if (st==NT_STATUS_TIMEOUT || st==NT_STATUS_TRYAGAIN) {
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
    unsigned int rxp = 255;
    if (dtp == 4)      rxp = _NT_NET_GET_PKT_DESCR_PTR_DYN4(nb)->rxPort;
    else if (dtp == 3 || dtp == NT_PACKET_DESCRIPTOR_TYPE_DYNAMIC)
                        rxp = _NT_NET_GET_PKT_DESCR_PTR_DYN3(nb)->rxPort;
    if (rxp < ARRAY_LEN(C->port_seen))
      C->port_seen[rxp]++;

    uint64_t ts_ns = 0;
    if (dtp == 4)      ts_ns = _NT_NET_GET_PKT_DESCR_PTR_DYN4(nb)->timestamp;
    else if (dtp == 3 || dtp == NT_PACKET_DESCRIPTOR_TYPE_DYNAMIC)
                        ts_ns = _NT_NET_GET_PKT_DESCR_PTR_DYN3(nb)->timestamp;
    else {
      struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
      ts_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }

    struct pcap_pkthdr h; memset(&h, 0, sizeof h);
    uint32_t data_len = cap;
    if (wire && data_len > wire)
      data_len = wire;
    if (C->snaplen && data_len > C->snaplen)
      data_len = C->snaplen;
    h.caplen = data_len;
    h.len = wire ? wire : data_len;
    h.ts.tv_sec = (time_t)(ts_ns / 1000000000ULL);
    if (C->pcap_is_nano) h.ts.tv_usec = (suseconds_t)(ts_ns % 1000000000ULL);
    else h.ts.tv_usec = (suseconds_t)((ts_ns / 1000ULL) % 1000000ULL);

    int on_dup_port = ((int)rxp == C->dup_port);
    uint16_t ethertype = ethertype_from_l2(l2, cap);
    int is_dup = on_dup_port && packet_is_duplicate(nb, dtp, C->dup_bit);

    if (is_dup) {
      if (ethertype == 0x0800) C->dup_ipv4++;
      else if (ethertype == 0x86DD) C->dup_ipv6++;
      else C->dup_other++;
    }

    if (C->d0 && is_dup) {
      int quota_reached = 0;
      if (!C->rolling && C->target && C->wrote0 >= C->target) quota_reached = 1;
      if (!C->rolling && C->roll_file_limit && C->roll_file_bytes >= C->roll_file_limit) quota_reached = 1;
      if (C->rolling && C->roll_count && C->wrote0 >= C->roll_count) quota_reached = 1;

      if (!quota_reached) {
        pcap_dump((u_char*)C->d0, &h, l2);
        C->wrote0++;
        FILE* f = (FILE*)pcap_dump_file(C->d0);
        if (f) {
          long long pos = ftello(f);
          if (pos >= 0) C->roll_file_bytes = (uint64_t)pos;
        }
      }
    }

    if (C->rolling) {
      struct timespec now2; clock_gettime(CLOCK_REALTIME, &now2);
      if (C->dir0 && C->d0) {
        double dt0 = (now2.tv_sec - C->roll0_t0.tv_sec) + (now2.tv_nsec - C->roll0_t0.tv_nsec)/1e9;
        int time_expired0 = (C->roll_seconds > 0.0) && (dt0 >= C->roll_seconds);
        int count_expired0 = (C->roll_seconds <= 0.0) && C->roll_count && (C->wrote0 >= C->roll_count);
        int size_expired0 = (C->roll_file_limit > 0) && (C->roll_file_bytes >= C->roll_file_limit);
        if (time_expired0 || count_expired0 || size_expired0) {
          pcap_dump_close(C->d0); C->d0=NULL;
          char tsb[32]; time_t tt=now2.tv_sec; struct tm tm2; gmtime_r(&tt,&tm2); strftime(tsb,sizeof tsb, "%Y-%m-%dT%H-%M-%SZ", &tm2);
          snprintf(C->cur0, sizeof C->cur0, "%s/duplicates_%s.pcap", C->dir0, tsb);
          C->d0 = pcap_dump_open(C->p_dead, C->cur0);
          if (C->d0){
            FILE* nf = (FILE*)pcap_dump_file(C->d0);
            if (nf){
              int fd = fileno(nf);
              if (fd>=0) fchmod(fd, 0644);
              long long pos = ftello(nf);
              if (pos >= 0) C->roll_file_bytes = (uint64_t)pos;
            }
          }
          C->wrote0=0; C->roll0_t0 = now2;
          if (C->roll_max_bytes) prune_dir_budget(C->dir0, "duplicates_", C->roll_max_bytes);
        }
      }
    } else if (C->d0 && C->roll_file_limit > 0 && C->roll_file_bytes >= C->roll_file_limit) {
      // Non-rolling mode: close once the size limit is hit.
      pcap_dump_close(C->d0);
      C->d0 = NULL;
    }

    NT_NetRxRelease(C->rx, nb);
    if (!C->rolling && C->max_sec <= 0.0) {
      int done0 = C->path0 ? (C->target ? (C->wrote0 >= C->target) : 0) : 1;
      if (done0) C->running = 0;
    }
  }
  return NULL;
}

int main(int argc, char** argv) {
  int adapter = 0;
  double interval = 0.5;
  /* summary window removed in this simplified tool */
  /* color bit removed from simplified UI */
  int once = 0;

  // Sampling options
  const char* pcap0_path = NULL;
  const char* pcap1_path = NULL;
  const char* pcap0_dir  = "/dev/shm";  // default rolling dirs
  const char* pcap1_dir  = "/dev/shm";
  uint32_t snaplen = 0;           // 0 = full captured packet
  uint32_t sample_count = 256;    // per port target (non-rolling)
  double sample_seconds = 0.0;    // 0 = disabled
  int rx_stream_id = 0;           // capture stream id (default 0 per working tag)
  int port0_index = 0;            // match rxPort for Port 0 (default 0)
  int port1_index = 1;            // match rxPort for Port 1 (default 1)
  int dup_bit = 7;                // default duplicate color bit
  // Rolling controls (defaults enabled)
  int rolling = 1;                // default: roll files to /dev/shm
  uint32_t roll_count = 0;        // 0 = unlimited per file
  double roll_seconds = 60.0;     // seconds per file
  uint64_t roll_max_bytes = 0;    // per-dir budget; 0=unlimited
  long long roll_file_mib = 20;   // per-file limit for duplicate dumps (0 = unlimited)
  // NTPL apply (inline). Modes: 0=none, 1=dedup duplicate+mark, 2=dedup drop
  int ntpl_mode = 0;              // default: do NOT apply NTPL automatically
  int ntpl_clear = 0;             // optionally clear rules first

  static struct option long_opts[] = {
    {"adapter",   required_argument, NULL, 'a'},
    {"interval",  required_argument, NULL, 'i'},
    {"once",      no_argument,       NULL, 'o'},
    {"pcap0",     required_argument, NULL, 1001},
    {"pcap1",     required_argument, NULL, 1002},
    {"pcap0-dir", required_argument, NULL, 1011},
    {"pcap1-dir", required_argument, NULL, 1012},
    {"snaplen",   required_argument, NULL, 1003},
    {"sample-count", required_argument, NULL, 1004},
    {"sample-seconds", required_argument, NULL, 1005},
    {"rx-stream-id", required_argument, NULL, 1006},
    {"port0",     required_argument, NULL, 1007},
    {"port1",     required_argument, NULL, 1008},
    {"ntpl-duplicate", no_argument, NULL, 1030},
    {"ntpl-drop",      no_argument, NULL, 1031},
    {"no-ntpl",        no_argument, NULL, 1032},
    {"ntpl-clear",     no_argument, NULL, 1033},
    {"roll",      no_argument,       NULL, 1020},
    {"no-roll",   no_argument,       NULL, 1021},
    {"roll-count", required_argument, NULL, 1022},
    {"roll-seconds", required_argument, NULL, 1023},
    {"roll-max-mib", required_argument, NULL, 1024},
    {"roll-file-mib", required_argument, NULL, 1025},
    {"dup-bit", required_argument, NULL, 1026},
    {NULL, 0, NULL, 0}
  };
  int opt;
  while ((opt = getopt_long(argc, argv, "a:i:o", long_opts, NULL)) != -1) {
    switch (opt) {
      case 'a': adapter = atoi(optarg); break;
      case 'i': interval = atof(optarg); if (interval <= 0.0) interval = 0.5; break;
      case 'o': once = 1; break;
      case 1001: pcap0_path = optarg; break;
      case 1002: pcap1_path = optarg; break;
      case 1011: pcap0_dir = optarg; break;
      case 1012: pcap1_dir = optarg; break;
      case 1003: snaplen = (uint32_t)atoi(optarg); if ((int)snaplen < 0) snaplen = 0; break;
      case 1004: sample_count = (uint32_t)atoi(optarg); if ((int)sample_count < 0) sample_count = 0; break;
      case 1005: sample_seconds = atof(optarg); if (sample_seconds < 0.0) sample_seconds = 0.0; break;
      case 1006: rx_stream_id = atoi(optarg); break;
      case 1007: port0_index = atoi(optarg); break;
      case 1008: port1_index = atoi(optarg); break;
      case 1030: ntpl_mode = 1; break; /* duplicate + mark */
      case 1031: ntpl_mode = 2; break; /* drop duplicates */
      case 1032: ntpl_mode = 0; break; /* skip NTPL apply */
      case 1033: ntpl_clear = 1; break;
      case 1020: rolling = 1; break;
      case 1021: rolling = 0; break;
      case 1022: roll_count = (uint32_t)atoi(optarg); break;
      case 1023: roll_seconds = atof(optarg); if (roll_seconds <= 0.0) roll_seconds = 1.0; break;
      case 1024: { long long mib = atoll(optarg); if (mib < 0) mib = 0; roll_max_bytes = (uint64_t)mib * 1024ULL * 1024ULL; } break;
      case 1025: { long long mib = atoll(optarg); if (mib < 0) mib = 0; roll_file_mib = mib; } break;
      case 1026: dup_bit = atoi(optarg); if (dup_bit < 0) dup_bit = 0; if (dup_bit > 63) dup_bit = 63; break;
      default:
        fprintf(stderr, "Usage: %s [--adapter=N] [--interval=SEC] [--once]\n"
                        "            [--pcap0=PATH] [--pcap1=PATH] [--pcap0-dir=DIR] [--pcap1-dir=DIR]\n"
                        "            [--snaplen=B(0=full)] [--sample-count=N] [--sample-seconds=S]\n"
                        "            [--rx-stream-id=N] [--port0=N] [--port1=N] (defaults: port0=0, port1=1)\n"
                        "            [--ntpl-duplicate|--ntpl-drop|--no-ntpl] [--ntpl-clear]\n"
                        "            [--roll-file-mib=N] [--dup-bit=N]\n", argv[0]);
        return EXIT_FAILURE;
    }
  }

  uint64_t roll_file_limit = (roll_file_mib <= 0) ? 0u : (uint64_t)roll_file_mib * 1024ULL * 1024ULL;

  int status = NT_Init(NTAPI_VERSION);
  if (status != NT_SUCCESS) die_nt("NT_Init", status);

  NtStatStream_t stat_stream = NULL;
  status = NT_StatOpen(&stat_stream, "tid");
  if (status != NT_SUCCESS) die_nt("NT_StatOpen", status);

  signal(SIGINT, on_sigint);
  setvbuf(stdout, NULL, _IONBF, 0);

  // Apply NTPL inline if requested
  if (ntpl_mode != 0) {
    NtConfigStream_t cfg = NULL; NtNtplInfo_t info; memset(&info, 0, sizeof info);
    int st_cfg = NT_ConfigOpen(&cfg, "tid_cfg"); if (st_cfg != NT_SUCCESS) die_nt("NT_ConfigOpen", st_cfg);
    char line[512]; int stn;
    // use chosen SID for NTPL setup/assign
    uint32_t sid_ntpl = (rx_stream_id >= 0) ? (uint32_t)rx_stream_id : 0u;
    if (ntpl_clear) {
      snprintf(line, sizeof line, "Delete = All");
      stn = NT_NTPL(cfg, line, &info, NT_NTPL_PARSER_VALIDATE_NORMAL); if (stn != NT_SUCCESS) warn_nt("NT_NTPL(Delete)", stn);
    }
    if (ntpl_mode == 1) {
      // Duplicate + mark via ColorBit 7
      snprintf(line, sizeof line, "DeduplicationConfig[ColorBit=7; Retransmit=Duplicate] = GroupID == 0");
      stn = NT_NTPL(cfg, line, &info, NT_NTPL_PARSER_VALIDATE_NORMAL); if (stn != NT_SUCCESS) warn_nt("NT_NTPL(DedupConfig)", stn);
    } else if (ntpl_mode == 2) {
      // Drop duplicates
      snprintf(line, sizeof line, "DeduplicationConfig[ColorBit=7; Retransmit=Drop] = GroupID == 0");
      stn = NT_NTPL(cfg, line, &info, NT_NTPL_PARSER_VALIDATE_NORMAL); if (stn != NT_SUCCESS) warn_nt("NT_NTPL(DedupConfig)", stn);
    }
    snprintf(line, sizeof line, "Define ckFull = CorrelationKey(Begin=StartOfFrame[0], End=EndOfFrame[0], DeduplicationGroupID=0)");
    stn = NT_NTPL(cfg, line, &info, NT_NTPL_PARSER_VALIDATE_NORMAL); if (stn != NT_SUCCESS) warn_nt("NT_NTPL(Define)", stn);
    snprintf(line, sizeof line, "Setup[State=Active] = StreamId == %u", sid_ntpl);
    stn = NT_NTPL(cfg, line, &info, NT_NTPL_PARSER_VALIDATE_NORMAL); if (stn != NT_SUCCESS) warn_nt("NT_NTPL(Setup)", stn);
    snprintf(line, sizeof line, "Assign[StreamId=%u; Descriptor=DYN3; CorrelationKey=ckFull] = Port == %d", sid_ntpl, port0_index);
    stn = NT_NTPL(cfg, line, &info, NT_NTPL_PARSER_VALIDATE_NORMAL); if (stn != NT_SUCCESS) warn_nt("NT_NTPL(Assign p0)", stn);
    snprintf(line, sizeof line, "Assign[StreamId=%u; Descriptor=DYN3; CorrelationKey=ckFull] = Port == %d", sid_ntpl, port1_index);
    stn = NT_NTPL(cfg, line, &info, NT_NTPL_PARSER_VALIDATE_NORMAL); if (stn != NT_SUCCESS) warn_nt("NT_NTPL(Assign p1)", stn);
    NT_ConfigClose(cfg);
  }

  sample_ctx_t SC = {0};
  pthread_t cap_thread;
  int capture_thread_started = 0;
  int open_dumpers = rolling || pcap0_path;

  {
    SC.running = 1; SC.snaplen = snaplen; SC.target = sample_count; SC.max_sec = sample_seconds;
    SC.path0 = pcap0_path; SC.path1 = pcap1_path; SC.dir0 = pcap0_dir; SC.dir1 = pcap1_dir; SC.port0 = port0_index; SC.port1 = port1_index;
    SC.rolling = rolling; SC.roll_count = roll_count; SC.roll_seconds = roll_seconds; SC.roll_max_bytes = roll_max_bytes;
    SC.dup_port = port0_index;
    SC.dup_bit = dup_bit;
    SC.roll_file_limit = roll_file_limit;
    SC.roll_file_bytes = 0;
    clock_gettime(CLOCK_REALTIME, &SC.t0);
    if (open_dumpers) {
      /* Prefer nanosecond precision PCAP if libpcap supports it */
#ifdef PCAP_TSTAMP_PRECISION_NANO
      {
        uint32_t hdr_snap = (SC.snaplen == 0) ? 65535u : SC.snaplen;
        SC.p_dead = pcap_open_dead_with_tstamp_precision(DLT_EN10MB, hdr_snap, PCAP_TSTAMP_PRECISION_NANO);
      }
      SC.pcap_is_nano = 1;
      if (!SC.p_dead)
#endif
      {
        uint32_t hdr_snap = (SC.snaplen == 0) ? 65535u : SC.snaplen;
        SC.p_dead = pcap_open_dead(DLT_EN10MB, hdr_snap);
        SC.pcap_is_nano = 0;
      }
      if (!SC.p_dead) { fprintf(stderr, "pcap_open_dead failed\n"); open_dumpers = 0; }
    }
    if (open_dumpers) {
      if (SC.rolling) {
        struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
        char tsbuf[32]; time_t t=now.tv_sec; struct tm tm; gmtime_r(&t,&tm); strftime(tsbuf,sizeof tsbuf, "%Y-%m-%dT%H-%M-%SZ", &tm);
        if (SC.dir0) {
          snprintf(SC.cur0, sizeof SC.cur0, "%s/duplicates_%s.pcap", SC.dir0, tsbuf);
          SC.d0 = pcap_dump_open(SC.p_dead, SC.cur0);
          if (SC.d0) {
            FILE* nf = (FILE*)pcap_dump_file(SC.d0);
            if (nf) {
              int fd = fileno(nf);
              if (fd >= 0) fchmod(fd, 0644);
              long long pos = ftello(nf);
              if (pos >= 0) SC.roll_file_bytes = (uint64_t)pos;
            }
          }
          SC.wrote0 = 0;
          SC.roll0_t0 = now;
          if (SC.roll_max_bytes) prune_dir_budget(SC.dir0, "duplicates_", SC.roll_max_bytes);
        }
        SC.d1 = NULL;
      } else {
        if (SC.path0) {
          SC.d0 = pcap_dump_open(SC.p_dead, SC.path0);
          if (!SC.d0) {
            fprintf(stderr, "pcap_dump_open %s: %s\n", SC.path0, pcap_geterr(SC.p_dead));
          } else {
            FILE* nf = (FILE*)pcap_dump_file(SC.d0);
            if (nf) {
              int fd = fileno(nf);
              if (fd >= 0) fchmod(fd, 0644);
              long long pos = ftello(nf);
              if (pos >= 0) SC.roll_file_bytes = (uint64_t)pos;
            }
          }
        }
        SC.d1 = NULL;
      }
    }
    // Open a capture RX stream (always open for 'seen' and stats, even if not writing PCAP)
    {
      uint32_t sid_to_open = (uint32_t)rx_stream_id; // open exactly the requested SID (default 0)
      int rc = NT_NetRxOpen(&SC.rx, "tid_cap", NT_NET_INTERFACE_PACKET, sid_to_open, -1);
      if (rc != NT_SUCCESS) { die_nt("NT_NetRxOpen", rc); }
    }
    // Thread to pull and write samples (always run; dumper pointers may be NULL when not writing)
    {
      if (pthread_create(&cap_thread, NULL, capture_thread, &SC) != 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
      }
      capture_thread_started = 1;
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
    // Duplicate counter must be read from the tap port (port0) where the duplicates are marked
    uint64_t dup_pkts = (p0 && p0->valid.decode) ? p0->decode.pktsDuplicate : 0;

    double gbps0 = 0.0, gbps1 = 0.0;
    if (p0) { gbps0 = ((double)(p0->RMON1.octets - prev_octets[0]) * 8.0 / interval) / 1e9; prev_octets[0] = p0->RMON1.octets; }
    if (p1) { gbps1 = ((double)(p1->RMON1.octets - prev_octets[1]) * 8.0 / interval) / 1e9; prev_octets[1] = p1->RMON1.octets; }

    /* no summary window */

    clear_screen();
    char ts[64];
    printf("Duplicate Analysis Monitor            %s\n\n", now_str(ts, sizeof ts));
    printf("Adapter %d  Interval %.1fs  RX SID %d\n\n", adapter, interval, (rx_stream_id>=0?rx_stream_id:1));

    // Stage-1 interface per tid-reqs-stage1.pdf
    // Stage-2 header: remove leading port indices in column labels
    printf("%-18s | %-22s | %-22s\n", "Metric", "Ingress Port 1 TAP", "Egress Port 2 TAP");
    printf("------------------+----------------------+----------------------\n");
    print_bw_row("RX Speed", gbps0, gbps1);
    print_side_row("Total Packets", v0_pkts, v1_pkts);

    // Derived rows per Stage-2: explicitly show both equal and not-equal counts
    // Duplicates measured on the tap port (port0)
    print_single_row("Duplicates", dup_pkts);
    double pct_duplicates = 0.0;
    if (v0_pkts > 0) pct_duplicates = ((double)dup_pkts / (double)v0_pkts) * 100.0;
    printf("%-18s | %8.3f %%        |\n", "Duplicates %", pct_duplicates);

    uint64_t dup_captured_total = SC.dup_ipv4 + SC.dup_ipv6 + SC.dup_other;
    double dup_ipv4_pct = dup_captured_total ? ((double)SC.dup_ipv4 * 100.0 / (double)dup_captured_total) : 0.0;
    double dup_ipv6_pct = dup_captured_total ? ((double)SC.dup_ipv6 * 100.0 / (double)dup_captured_total) : 0.0;
    double dup_other_pct = dup_captured_total ? ((double)SC.dup_other * 100.0 / (double)dup_captured_total) : 0.0;
    print_single_row_pct("IPv4 packets", SC.dup_ipv4, dup_ipv4_pct);
    print_single_row_pct("IPv6 packets", SC.dup_ipv6, dup_ipv6_pct);
    print_single_row_pct("Unknown packets", SC.dup_other, dup_other_pct);

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
      print_side_row("Giant undersize", 0, 0);
      print_side_row("Baby giant", 0, 0);
      print_side_row("No VLAN/MPLS", 0, 0);
      print_side_row("VLAN", 0, 0);
      print_side_row("VLAN/MPLS", 0, 0);
    }

    // Stage-2 removes Drop counters, Dedup summary table, and adapter color totals

    if (open_dumpers) {
      double cur_mib = (double)SC.roll_file_bytes / (1024.0 * 1024.0);
      double limit_mib = SC.roll_file_limit ? (double)SC.roll_file_limit / (1024.0 * 1024.0) : 0.0;
      if (SC.rolling && SC.d0) {
        printf("\nDuplicates PCAP (rolling): frames=%u port%d seen=%" PRIu64,
               SC.wrote0, SC.dup_port, SC.port_seen[(unsigned)SC.dup_port]);
        if (SC.roll_file_limit) {
          printf("  file %.1f/%.1f MiB\n", cur_mib, limit_mib);
        } else {
          printf("  file %.1f MiB\n", cur_mib);
        }
        if (SC.cur0[0]) printf("current=%s\n", SC.cur0);
      } else if (SC.rolling && !SC.d0 && SC.cur0[0]) {
        printf("\nDuplicates PCAP (rolling) writer closed after reaching limit: %s\n", SC.cur0);
      } else if (!SC.rolling && SC.path0) {
        printf("\nDuplicates PCAP: %s\n", SC.path0);
        if (SC.roll_file_limit) {
          printf("frames=%u size≈%.1f/%.1f MiB\n", SC.wrote0, cur_mib, limit_mib);
          if (!SC.d0 && cur_mib >= limit_mib && limit_mib > 0.0) {
            printf("(writer closed after hitting size limit)\n");
          }
        } else {
          printf("frames=%u size≈%.1f MiB\n", SC.wrote0, cur_mib);
        }
      }
    }

    printf("\nPress Ctrl+C to exit\n");
    if (once) break;
  }

  NT_StatClose(stat_stream);
  if (capture_thread_started) {
    SC.running = 0;
    pthread_join(cap_thread, NULL);
  }
  if (SC.rx) NT_NetRxClose(SC.rx);
  if (SC.d0) { pcap_dump_close(SC.d0); }
  if (SC.d1) { pcap_dump_close(SC.d1); }
  if (SC.p_dead) { pcap_close(SC.p_dead); }
  NT_Done();
  return 0;
}
