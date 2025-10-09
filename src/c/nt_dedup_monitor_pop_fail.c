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
#include <stdbool.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <nt.h>
#include <ntapi/stream_statistics.h>
// For optional capture of ingress packets (to PCAP when egress duplicate is missing)
#include <ntapi/pktdescr.h>
#include <ntapi/pktdescr_dyn3.h>
#include <ntapi/pktdescr_dyn4.h>
#include <pcap/pcap.h>

#define VLAN_MAP_SZ 8192

// ---------------- Capture support types ----------------
typedef struct {
  uint64_t ts_ns;
  uint16_t cap_len;
  uint16_t wire_len;
  uint16_t s_vlan;
  uint16_t c_vlan;
  uint8_t  ip_is_v6;
  uint8_t  l2[0]; // flexible tail for snapshot
} pend_rec_t;

typedef struct {
  pend_rec_t** slots;
  uint64_t mask;
  uint64_t head; // pop position
  uint64_t tail; // push position
  pthread_mutex_t mu;
} pend_q_t;

typedef struct {
  // config
  int ingress_port;
  int egress_port;
  uint32_t win_us;
  uint32_t snaplen;
  int pend_pow;
  const char* pcap_path;
  const char* csv_path;
  const char* vlan_out_path;

  // runtime
  pend_q_t q;
  pcap_t* p_dead;
  pcap_dumper_t* p_dump;
  FILE* f_drop_csv;
  int csv_header_done;
  NtNetStreamRx_t cap_rx;
  uint64_t pop_total;
  uint64_t expired_total;
  volatile sig_atomic_t running;

  // VLAN aggregator (S/C -> count)
  pthread_mutex_t vlan_mu;
  uint32_t vlan_key[VLAN_MAP_SZ];
  uint64_t vlan_cnt[VLAN_MAP_SZ];
  uint8_t  vlan_used[VLAN_MAP_SZ];
  // capture debug/counters
  uint64_t cap_seen_total;
  uint64_t cap_seen_ingress;
  int cap_debug;
  uint64_t cap_debug_emitted;
} capture_ctx_t;

// Forward declarations for VLAN aggregator helpers
static void vlan_accumulate(capture_ctx_t* C, uint16_t s, uint16_t c, uint64_t inc);
static void vlan_write_top(capture_ctx_t* C);

static void q_init(pend_q_t* q, int pow){
  size_t n = 1ull << pow;
  q->slots = (pend_rec_t**)calloc(n, sizeof(pend_rec_t*));
  if (!q->slots) { fprintf(stderr, "pending queue alloc failed\n"); exit(1); }
  q->mask = n - 1;
  q->head = q->tail = 0;
  pthread_mutex_init(&q->mu, NULL);
}
static inline size_t q_size_unsafe(const pend_q_t* q){ return (size_t)(q->tail - q->head); }
static int q_push(pend_q_t* q, const uint8_t* l2, uint32_t wire_len, uint32_t cap_len,
                  uint16_t s_vlan, uint16_t c_vlan, uint64_t ts_ns){
  pthread_mutex_lock(&q->mu);
  if (q_size_unsafe(q) >= q->mask){ pthread_mutex_unlock(&q->mu); return -1; }
  uint64_t idx = q->tail & q->mask;
  size_t rec_sz = sizeof(pend_rec_t) + cap_len;
  pend_rec_t* r = (pend_rec_t*)malloc(rec_sz);
  if (!r){ pthread_mutex_unlock(&q->mu); return -1; }
  r->ts_ns = ts_ns;
  r->cap_len = (uint16_t)cap_len;
  r->wire_len = (uint16_t)wire_len;
  r->s_vlan = s_vlan; r->c_vlan = c_vlan;
  r->ip_is_v6 = 0;
  if (cap_len)
    memcpy(r->l2, l2, cap_len);
  q->slots[idx] = r;
  q->tail++;
  pthread_mutex_unlock(&q->mu);
  return 0;
}
static pend_rec_t* q_pop_head_locked(pend_q_t* q){
  if (q->head == q->tail) return NULL;
  uint64_t idx = q->head & q->mask;
  pend_rec_t* r = q->slots[idx];
  q->slots[idx] = NULL;
  q->head++;
  return r;
}
static size_t q_pop_n(pend_q_t* q, size_t n){
  size_t popped = 0;
  pthread_mutex_lock(&q->mu);
  while (popped < n){
    pend_rec_t* r = q_pop_head_locked(q);
    if (!r) break;
    free(r);
    popped++;
  }
  pthread_mutex_unlock(&q->mu);
  return popped;
}
static size_t q_expire_and_dump(capture_ctx_t* C, uint64_t now_ns, uint64_t win_ns){
  size_t dropped = 0;
  pend_q_t* q = &C->q;
  pthread_mutex_lock(&q->mu);
  while (1){
    if (q->head == q->tail) break;
    uint64_t idx = q->head & q->mask;
    pend_rec_t* r = q->slots[idx];
    if (!r) { q->head++; continue; }
    if (now_ns <= r->ts_ns || now_ns - r->ts_ns <= win_ns)
      break; // head not expired yet
    // expired -> write PCAP + CSV, then pop
      if (C->p_dump){
        struct pcap_pkthdr h; memset(&h, 0, sizeof h);
        h.caplen = r->cap_len; h.len = r->wire_len ? r->wire_len : r->cap_len;
        // r->ts_ns is host realtime ns
        h.ts.tv_sec = (time_t)(r->ts_ns / 1000000000ULL);
        h.ts.tv_usec= (suseconds_t)((r->ts_ns % 1000000000ULL) / 1000ULL);
        pcap_dump((u_char*)C->p_dump, &h, r->l2);
        pcap_dump_flush(C->p_dump);
      }
      if (C->f_drop_csv){
        if (!C->csv_header_done){
          fprintf(C->f_drop_csv, "ts_ns,s_vlan,c_vlan,cap_len,wire_len\n");
          C->csv_header_done = 1;
        }
        fprintf(C->f_drop_csv, "%" PRIu64 ",%u,%u,%u,%u\n",
                r->ts_ns, r->s_vlan, r->c_vlan, r->cap_len, r->wire_len);
        fflush(C->f_drop_csv);
      }
      vlan_accumulate(C, r->s_vlan, r->c_vlan, 1);
      free(r);
      q->slots[idx] = NULL;
      q->head++;
      dropped++;
    }
  pthread_mutex_unlock(&q->mu);
  return dropped;
}

static inline void parse_vlan_tags(const uint8_t* l2, uint32_t len, uint16_t* s_vlan, uint16_t* c_vlan){
  *s_vlan = 0; *c_vlan = 0;
  if (len < 14) return;
  const uint8_t* p = l2; uint16_t eth = ((uint16_t)p[12]<<8) | p[13]; int off = 14;
  for (int i=0;i<2;i++){
    if (eth==0x88A8 || eth==0x8100 || eth==0x9100 || eth==0x9200){
      if (len < (uint32_t)(off+4)) break;
      uint16_t tci = ((uint16_t)p[off]<<8) | p[off+1];
      uint16_t vid = tci & 0x0FFF;
      if (*s_vlan == 0) *s_vlan = vid; else if (*c_vlan == 0) *c_vlan = vid;
      eth = ((uint16_t)p[off+2]<<8) | p[off+3];
      off += 4;
    } else break;
  }
}

static void* rx_thread_fn(void* arg){
  capture_ctx_t* C = (capture_ctx_t*)arg;
  while (C->running){
    NtNetBuf_t nb=NULL; int st2 = NT_NetRxGet(C->cap_rx, &nb, 1000);
    if (st2==NT_STATUS_TIMEOUT || st2==NT_STATUS_TRYAGAIN) continue;
    if (st2!=NT_SUCCESS) { continue; }
    unsigned dt = NT_NET_GET_PKT_DESCRIPTOR_TYPE(nb);
    uint8_t* l2 = (uint8_t*)NT_NET_GET_PKT_L2_PTR(nb);
    uint32_t cap = NT_NET_GET_PKT_CAP_LENGTH(nb);
    uint32_t wire= NT_NET_GET_PKT_WIRE_LENGTH(nb);
    uint64_t ts = 0; uint8_t rxp = 0;
    if (dt == 4){
      NtDyn4Descr_t* d = _NT_NET_GET_PKT_DESCR_PTR_DYN4(nb);
      rxp = d->rxPort;
    } else if (dt == 3 || dt == NT_PACKET_DESCRIPTOR_TYPE_DYNAMIC){
      NtDyn3Descr_t* d = _NT_NET_GET_PKT_DESCR_PTR_DYN3(nb);
      rxp = d->rxPort;
    } else {
      // Unsupported descriptor; skip
      NT_NetRxRelease(C->cap_rx, nb);
      continue;
    }
    // Use host realtime for queue timestamp to align with expirer clock domain
    {
      struct timespec tsnow; clock_gettime(CLOCK_REALTIME, &tsnow);
      ts = (uint64_t)tsnow.tv_sec*1000000000ULL + (uint64_t)tsnow.tv_nsec;
    }
    C->cap_seen_total++;
    if (C->cap_debug > 0 && C->cap_debug_emitted < (uint64_t)C->cap_debug){
      uint16_t sdbg=0, cdbg=0; parse_vlan_tags(l2, wire, &sdbg, &cdbg);
      fprintf(stderr, "[cap-debug] #%" PRIu64 " dt=%u rxPort=%u len=%u S=%u C=%u\n",
              C->cap_seen_total, dt, rxp, wire, sdbg, cdbg);
      C->cap_debug_emitted++;
    }
    if ((int)rxp == C->ingress_port){
      uint16_t s=0,c=0; parse_vlan_tags(l2, wire, &s, &c);
      uint32_t copy = cap < C->snaplen ? cap : C->snaplen;
      (void)q_push(&C->q, l2, wire, copy, s, c, ts);
      C->cap_seen_ingress++;
    }
    NT_NetRxRelease(C->cap_rx, nb);
  }
  return NULL;
}

static void* exp_thread_fn(void* arg){
  capture_ctx_t* C = (capture_ctx_t*)arg;
  const uint64_t win_ns = (uint64_t)C->win_us * 1000ULL;
  while (C->running){
    struct timespec tsnow; clock_gettime(CLOCK_REALTIME, &tsnow);
    uint64_t now = (uint64_t)tsnow.tv_sec*1000000000ULL + (uint64_t)tsnow.tv_nsec;
    size_t n = q_expire_and_dump(C, now, win_ns);
    C->expired_total += n;
    usleep(1000);
  }
  return NULL;
}

static inline uint32_t vlan_pair_key(uint16_t s, uint16_t c){ return ((uint32_t)s<<16) | c; }
static inline uint32_t vlan_hash32(uint32_t k){ k ^= k>>16; k *= 0x7feb352dU; k ^= k>>15; k *= 0x846ca68bU; k ^= k>>16; return k; }
static void vlan_accumulate(capture_ctx_t* C, uint16_t s, uint16_t c, uint64_t inc){
  uint32_t key = vlan_pair_key(s,c);
  pthread_mutex_lock(&C->vlan_mu);
  uint32_t idx = vlan_hash32(key) & (VLAN_MAP_SZ-1);
  for (uint32_t i=0;i<VLAN_MAP_SZ;i++){
    uint32_t j=(idx+i)&(VLAN_MAP_SZ-1);
    if (!C->vlan_used[j]){ C->vlan_used[j]=1; C->vlan_key[j]=key; C->vlan_cnt[j]=inc; break; }
    if (C->vlan_used[j] && C->vlan_key[j]==key){ C->vlan_cnt[j]+=inc; break; }
  }
  pthread_mutex_unlock(&C->vlan_mu);
}
static void vlan_write_top(capture_ctx_t* C){
  if (!C->vlan_out_path || !*C->vlan_out_path) return;
  typedef struct { uint32_t key; uint64_t cnt; } item_t;
  item_t top[32]; size_t used=0;
  pthread_mutex_lock(&C->vlan_mu);
  for (uint32_t i=0;i<VLAN_MAP_SZ;i++){
    if (!C->vlan_used[i] || C->vlan_cnt[i]==0) continue;
    item_t it = { C->vlan_key[i], C->vlan_cnt[i] };
    // insert into top (descending)
    size_t pos = used;
    while (pos>0 && top[pos-1].cnt < it.cnt) pos--;
    if (used < 32) used++;
    for (size_t k=used-1; k>pos; k--) top[k] = top[k-1];
    if (pos < used) top[pos] = it;
  }
  pthread_mutex_unlock(&C->vlan_mu);
  // Write to temp then rename
  char tmp[512];
  snprintf(tmp, sizeof tmp, "%s.tmp", C->vlan_out_path);
  FILE* f = fopen(tmp, "w");
  if (!f) return;
  size_t limit = used < 32 ? used : 32;
  for (size_t i=0;i<limit;i++){
    uint16_t s = (uint16_t)(top[i].key >> 16);
    uint16_t c = (uint16_t)(top[i].key & 0xFFFF);
    fprintf(f, "%u,%u,%" PRIu64 "\n", s, c, top[i].cnt);
  }
  fclose(f);
  rename(tmp, C->vlan_out_path);
}

/*
 * Traffic Impact Monitor
 * ----------------------
 * Console program that polls the Napatech statistics stream and renders the
 * most important receive (RMON) and extended-drop counters side-by-side for
 * two ports. It also shows deduplication drop totals/deltas and, if provided,
 * top VLAN drop counts produced by the drop monitor.
 */
static volatile sig_atomic_t g_running = 1;

static void on_sigint(int sig) {
  (void)sig;
  g_running = 0;
}

static void die_nt(const char* where, int status) {
  char buf[NT_ERRBUF_SIZE];
  NT_ExplainError(status, buf, sizeof buf);
  fprintf(stderr, "%s failed: %s (0x%08X)\n", where, buf, status);
  exit(EXIT_FAILURE);
}

static void sleep_interval(double seconds) {
  if (seconds <= 0.0)
    return;
  struct timespec ts;
  ts.tv_sec = (time_t)seconds;
  ts.tv_nsec = (long)((seconds - ts.tv_sec) * 1e9);
  if (ts.tv_nsec < 0)
    ts.tv_nsec = 0;
  nanosleep(&ts, NULL);
}

static void clear_screen(void) {
  fputs("\033[2J\033[H", stdout);
}

static const char* now_str(char* buf, size_t len) {
  time_t now = time(NULL);
  struct tm tm_now;
  localtime_r(&now, &tm_now);
  strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm_now);
  return buf;
}

static void print_side_row(const char* label, uint64_t v0, uint64_t v1) {
  printf("%-18s | #%018" PRIu64 " | #%018" PRIu64 "\n", label, v0, v1);
}

static void print_bw_row(const char* label, double bps0, double bps1) {
  printf("%-18s | %9.3f Gbps      | %9.3f Gbps     \n", label, bps0 / 1e9, bps1 / 1e9);
}

static void sort_desc(uint16_t (*pairs)[2], uint64_t* counts, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    size_t max_idx = i;
    for (size_t j = i + 1; j < n; ++j)
      if (counts[j] > counts[max_idx])
        max_idx = j;
    if (max_idx != i) {
      uint64_t tmpc = counts[i];
      counts[i] = counts[max_idx];
      counts[max_idx] = tmpc;
      uint16_t tmp0 = pairs[i][0];
      uint16_t tmp1 = pairs[i][1];
      pairs[i][0] = pairs[max_idx][0];
      pairs[max_idx][0] = tmp0;
      pairs[i][1] = pairs[max_idx][1];
      pairs[max_idx][1] = tmp1;
    }
  }
}

static size_t load_vlan_table(const char* path,
                              uint16_t (*pairs)[2],
                              uint64_t* counts,
                              size_t cap) {
  FILE* f = fopen(path, "r");
  if (!f)
    return 0;
  size_t used = 0;
  while (used < cap) {
    unsigned sv = 0;
    unsigned cv = 0;
    uint64_t cnt = 0;
    int rc = fscanf(f, "%u,%u,%" SCNu64, &sv, &cv, &cnt);
    if (rc != 3)
      break;
    pairs[used][0] = (uint16_t)sv;
    pairs[used][1] = (uint16_t)cv;
    counts[used] = cnt;
    ++used;
  }
  fclose(f);
  return used;
}

int main(int argc, char** argv) {
  int adapter = 0;
  double interval = 1.0;
  double summary_period = 10.0;
  int color_bit = 7;
  int clear_hw = 0;
  int once = 0;
  const char* vlan_path = "/dev/shm/nt_hw_dedup_vlan.csv";

  // --- Optional capture + PCAP/CSV of missing egress duplicates ---
  int enable_capture = 0;        // --capture: enable Rx of ingress to build pending queue
  int ingress_port = 0;          // --ingress-port: first copy expected on this RX port
  int egress_port  = 1;          // --egress-port: duplicates (dropped in HW) expected here
  uint32_t win_us = 2000000;     // --win-us: consider missing if not popped within this window (default 2s)
  uint32_t snaplen = 128;        // --snaplen: bytes to save in PCAP per drop
  int pend_pow = 20;             // --pend-pow: queue size = 2^pend_pow
  const char* pcap_path = "/dev/shm/nt_dedup_drops.pcap";       // --pcap
  const char* csv_path  = "/dev/shm/nt_dedup_drop_events.csv";  // --drop-csv
  int cap_debug = 0;             // --cap-debug=N: print first N packets from capture thread
  int pop_debug = 0;             // --pop-debug: print per-poll pop diagnostics (1=on)
  int rx_stream_id = -1;         // --rx-stream-id=N: stream id for NT_NetRxOpen (default -1 any)
  int pop_sid = -1;              // --pop-sid=N: stream-id whose drop counter is used for pops (disabled by default)
  int pop_from_color = 0;        // --pop-from-color: use adapter color bit delta as pop source (fallback)
  const char* pop_mode = "auto"; // --pop-mode=auto|port|stream|color

  static struct option long_opts[] = {
    {"adapter",   required_argument, NULL, 'a'},
    {"interval",  required_argument, NULL, 'i'},
    {"summary",   required_argument, NULL, 's'},
    {"color-bit", required_argument, NULL, 'b'},
    {"clear-hw",  no_argument,       NULL, 'C'},
    {"once",      no_argument,       NULL, 'o'},
    {"vlan-table",required_argument, NULL, 'v'},
    {"capture",   no_argument,       NULL, 'X'},
    {"ingress-port", required_argument, NULL, 1001},
    {"egress-port",  required_argument, NULL, 1002},
    {"win-us",    required_argument, NULL, 1003},
    {"snaplen",   required_argument, NULL, 1004},
    {"pend-pow",  required_argument, NULL, 1005},
    {"pcap",      required_argument, NULL, 1006},
    {"drop-csv",  required_argument, NULL, 1007},
    {"cap-debug", required_argument, NULL, 1008},
    {"rx-stream-id", required_argument, NULL, 1009},
    {"pop-sid", required_argument, NULL, 1010},
    {"pop-debug", no_argument, NULL, 1011},
    {"pop-from-color", no_argument, NULL, 1012},
    {"pop-mode", required_argument, NULL, 1013},
    {NULL, 0, NULL, 0}
  };

  int opt;
  while ((opt = getopt_long(argc, argv, "a:i:s:b:Cov:X", long_opts, NULL)) != -1) {
    switch (opt) {
      case 'a': adapter = atoi(optarg); break;
      case 'i': interval = atof(optarg); if (interval <= 0.0) interval = 1.0; break;
      case 's': summary_period = atof(optarg); if (summary_period <= 0.0) summary_period = 10.0; break;
      case 'b': color_bit = atoi(optarg); if (color_bit < 0) color_bit = 0; if (color_bit > 63) color_bit = 63; break;
      case 'C': clear_hw = 1; break;
      case 'o': once = 1; break;
      case 'v': vlan_path = optarg; break;
      case 'X': enable_capture = 1; break;
      case 1001: ingress_port = atoi(optarg); break;
      case 1002: egress_port  = atoi(optarg); break;
      case 1003: win_us = (uint32_t)atoi(optarg); break;
      case 1004: snaplen = (uint32_t)atoi(optarg); if (snaplen < 64) snaplen = 64; break;
      case 1005: pend_pow = atoi(optarg); if (pend_pow < 10) pend_pow = 10; if (pend_pow > 26) pend_pow = 26; break;
      case 1006: pcap_path = optarg; break;
      case 1007: csv_path  = optarg; break;
      case 1008: cap_debug = atoi(optarg); if (cap_debug < 0) cap_debug = 0; break;
      case 1009: rx_stream_id = atoi(optarg); break;
      case 1010: pop_sid = atoi(optarg); if (pop_sid < -1) pop_sid = -1; if (pop_sid > 255) pop_sid = 255; break;
      case 1011: pop_debug = 1; break;
      case 1012: pop_from_color = 1; break;
      case 1013: pop_mode = optarg ? optarg : "auto"; break;
      default:
        fprintf(stderr, "Usage: %s [--adapter=N] [--interval=SEC] [--summary=SEC] [--color-bit=N] [--clear-hw] [--once] [--vlan-table=PATH]\n"
                        "            [--capture] [--ingress-port=N] [--egress-port=N] [--win-us=US] [--snaplen=B] [--pend-pow=POW]\n"
                        "            [--pcap=PATH] [--drop-csv=PATH] [--cap-debug=N] [--rx-stream-id=N] [--pop-sid=N]\n"
                        "            [--pop-debug] [--pop-from-color] [--pop-mode=auto|port|stream|color]\n", argv[0]);
        return EXIT_FAILURE;
    }
  }

  int status = NT_Init(NTAPI_VERSION);
  if (status != NT_SUCCESS)
    die_nt("NT_Init", status);

  NtStatStream_t stat_stream = NULL;
  status = NT_StatOpen(&stat_stream, "traffic_impact");
  if (status != NT_SUCCESS)
    die_nt("NT_StatOpen", status);

  signal(SIGINT, on_sigint);
  setvbuf(stdout, NULL, _IONBF, 0);

  if (enable_capture) {
    // Heuristic safety: ensure expire window comfortably exceeds poll cadence
    uint64_t min_us = (uint64_t)(interval * 1000000.0) * 2ULL;
    if ((uint64_t)win_us < min_us) {
      fprintf(stderr,
              "[warn] capture window --win-us=%u is smaller than ~2x poll interval (%.0f us);\n"
              "       packets may expire before pops occur. Consider --win-us>=%" PRIu64 "\n",
              win_us, interval * 1e6, min_us);
    }
    if (summary_period * 1e6 > (double)win_us) {
      fprintf(stderr,
              "[warn] summary window (%.0f us) exceeds capture window (%u us);\n"
              "       moved egress pop to each poll, but consider increasing --win-us.\n",
              summary_period * 1e6, win_us);
    }
  }

  uint64_t dedup_tot_pkts[64] = {0};
  uint64_t dedup_tot_octets[64] = {0};
  uint64_t dedup_delta_pkts[64] = {0};
  uint64_t dedup_delta_octets[64] = {0};

  uint16_t vlan_pairs[16][2];
  uint64_t vlan_counts[16];
  size_t vlan_used = 0;

  double since_summary = summary_period;
  uint64_t prev_octets_0 = 0;
  uint64_t prev_octets_1 = 0;

  capture_ctx_t C = {0};
  if (enable_capture){
    C.ingress_port = ingress_port;
    C.egress_port  = egress_port;
    C.win_us = win_us;
    C.snaplen = snaplen;
    C.pend_pow = pend_pow;
    C.pcap_path = pcap_path;
    C.csv_path  = csv_path;
    C.vlan_out_path = vlan_path;
    C.running = 1;
    C.cap_debug = cap_debug;
    C.cap_debug_emitted = 0;
    C.cap_seen_total = 0;
    C.cap_seen_ingress = 0;

    // Initialize queue and outputs
    q_init(&C.q, C.pend_pow);
    pthread_mutex_init(&C.vlan_mu, NULL);
    C.p_dead = pcap_open_dead(DLT_EN10MB, C.snaplen);
    if (!C.p_dead){ fprintf(stderr, "pcap_open_dead failed\n"); return EXIT_FAILURE; }
    C.p_dump = pcap_dump_open(C.p_dead, C.pcap_path);
    if (!C.p_dump){ fprintf(stderr, "pcap_dump_open failed: %s\n", pcap_geterr(C.p_dead)); return EXIT_FAILURE; }
    C.f_drop_csv = fopen(C.csv_path, "a");
    if (!C.f_drop_csv){ perror("open drop-csv"); }

    // Open RX bound to adapter; NTPL is assumed pre-applied as per requirements
    int rc = NT_NetRxOpen(&C.cap_rx, "cap_rx", NT_NET_INTERFACE_PACKET, adapter, rx_stream_id);
    if (rc != NT_SUCCESS){ die_nt("NT_NetRxOpen", rc); }

    // RX + Expirer threads
    pthread_t rx_thread, exp_thread;
    pthread_create(&rx_thread, NULL, rx_thread_fn, &C);
    pthread_create(&exp_thread, NULL, exp_thread_fn, &C);
  }

  static uint64_t last_stream_drop_pkts[256] = {0};
  static uint64_t last_dedup_pkts_poll[64] = {0};
  static uint64_t last_color_pkts_poll = 0;
  while (g_running) {
    sleep_interval(interval);

    NtStatistics_t stat;
    memset(&stat, 0, sizeof stat);
    stat.cmd = NT_STATISTICS_READ_CMD_QUERY_V4;
    stat.u.query_v4.poll = 1;
    stat.u.query_v4.clear = clear_hw ? 1 : 0;
    status = NT_StatRead(stat_stream, &stat);
    if (status != NT_SUCCESS)
      die_nt("NT_StatRead", status);

    const struct NtStatisticsQueryPortResult_v4_s* port_res = &stat.u.query_v4.data.port;
    const struct NtStatisticsQueryAdapterResult_v4_s* adapter_res = &stat.u.query_v4.data.adapter;

    // Pop on every poll using the selected source (port/stream/color). Avoid double-pop.
    if (enable_capture) {
      size_t popn_stream = 0;
      if (pop_sid >= 0) {
        const struct NtStatGroupStream_s* stream_res = &stat.u.query_v4.data.stream;
        uint32_t sid = (uint32_t)(pop_sid & 0xFF);
        uint64_t cur = stream_res->streamid[sid].drop.pkts;
        uint64_t prev = last_stream_drop_pkts[sid];
        popn_stream = (size_t)((cur >= prev) ? (cur - prev) : cur);
        last_stream_drop_pkts[sid] = cur;
      }

      // Also pop on every poll using per-port dedup drop delta on the configured egress_port
      size_t popn_port = 0;
      if (C.egress_port >= 0 && C.egress_port < (int)port_res->numPorts) {
        const struct NtPortStatistics_v3_s* rx = &port_res->aPorts[C.egress_port].rx;
        if (rx->valid.extDrop) {
          uint64_t curp = rx->extDrop.pktsDedup;
          uint64_t prevp = last_dedup_pkts_poll[C.egress_port];
          popn_port = (size_t)((curp >= prevp) ? (curp - prevp) : curp);
          last_dedup_pkts_poll[C.egress_port] = curp;
        }
      }

      // Optional: adapter color bit as fallback pop source
      size_t popn_color = 0;
      if (pop_from_color && adapter < adapter_res->numAdapters && adapter_res->aAdapters[adapter].color.supported) {
        uint64_t col_cur = adapter_res->aAdapters[adapter].color.aColor[color_bit].pkts;
        uint64_t col_prev = last_color_pkts_poll;
        popn_color = (size_t)((col_cur >= col_prev) ? (col_cur - col_prev) : col_cur);
        last_color_pkts_poll = col_cur;
      }

      // Choose pop source according to pop_mode; never sum to avoid double-pop
      size_t pop_total_this_poll = 0; const char* src = "none";
      if (!strcmp(pop_mode, "port")) { pop_total_this_poll = popn_port; src = "port"; }
      else if (!strcmp(pop_mode, "stream")) { pop_total_this_poll = popn_stream; src = "stream"; }
      else if (!strcmp(pop_mode, "color")) { pop_total_this_poll = popn_color; src = "color"; }
      else { // auto: prefer port, then stream, then color
        if (popn_port) { pop_total_this_poll = popn_port; src = "port"; }
        else if (popn_stream) { pop_total_this_poll = popn_stream; src = "stream"; }
        else if (popn_color) { pop_total_this_poll = popn_color; src = "color"; }
      }

      if (pop_total_this_poll) {
        size_t did = q_pop_n(&C.q, pop_total_this_poll);
        C.pop_total += did;
        if (pop_debug) {
          size_t pend_sz; pthread_mutex_lock(&C.q.mu); pend_sz = (size_t)(C.q.tail - C.q.head); pthread_mutex_unlock(&C.q.mu);
          fprintf(stderr, "[pop-debug] src=%s stream=%zu port=%zu color=%zu -> popped=%zu pend=%zu\n",
                  src, popn_stream, popn_port, popn_color, did, pend_sz);
        }
      } else if (pop_debug) {
        size_t pend_sz; pthread_mutex_lock(&C.q.mu); pend_sz = (size_t)(C.q.tail - C.q.head); pthread_mutex_unlock(&C.q.mu);
        fprintf(stderr, "[pop-debug] src=none stream=%zu port=%zu color=%zu -> popped=0 pend=%zu\n",
                popn_stream, popn_port, popn_color, pend_sz);
      }
    }

    since_summary += interval;
    if (since_summary >= summary_period) {
      for (uint8_t p = 0; p < port_res->numPorts && p < 64; ++p) {
        const struct NtPortStatistics_v3_s* rx = &port_res->aPorts[p].rx;
        if (rx->valid.extDrop) {
          uint64_t pkts = rx->extDrop.pktsDedup;
          uint64_t octs = rx->extDrop.octetsDedup;
          dedup_delta_pkts[p] = pkts >= dedup_tot_pkts[p] ? pkts - dedup_tot_pkts[p] : pkts;
          dedup_delta_octets[p] = octs >= dedup_tot_octets[p] ? octs - dedup_tot_octets[p] : octs;
          dedup_tot_pkts[p] = pkts;
          dedup_tot_octets[p] = octs;
        }
      }
      if (enable_capture){
        vlan_write_top(&C);
      }
      vlan_used = load_vlan_table(vlan_path, vlan_pairs, vlan_counts, 16);
      sort_desc(vlan_pairs, vlan_counts, vlan_used);
      since_summary = 0.0;

      // Note: per-poll pop is performed above; do not pop again here to avoid double counting
    }

    const struct NtPortStatistics_v3_s* p0 = port_res->numPorts > 0 ? &port_res->aPorts[0].rx : NULL;
    const struct NtPortStatistics_v3_s* p1 = port_res->numPorts > 1 ? &port_res->aPorts[1].rx : NULL;

    uint64_t values0[16] = {0};
    uint64_t values1[16] = {0};

    if (p0) {
      const struct NtExtendedRMONCounters_v1_s* ext = p0->valid.extRMON ? &p0->extRMON : NULL;
      values0[0] = p0->RMON1.pkts;
      values0[1] = ext ? ext->unicastPkts : p0->RMON1.pkts;
      values0[2] = p0->RMON1.multicastPkts;
      values0[3] = p0->RMON1.broadcastPkts;
      values0[4] = p0->RMON1.pkts64Octets;
      values0[5] = p0->RMON1.pkts65to127Octets;
      values0[6] = p0->RMON1.pkts128to255Octets;
      values0[7] = p0->RMON1.pkts256to511Octets;
      values0[8] = p0->RMON1.pkts512to1023Octets;
      values0[9] = p0->RMON1.pkts1024to1518Octets;
      values0[10] = ext ? ext->pkts1519to2047Octets : 0;
      values0[11] = ext ? ext->pkts2048to4095Octets : 0;
      values0[12] = ext ? ext->pkts4096to8191Octets : 0;
      values0[13] = ext ? ext->pkts8192toMaxOctets : 0;
      values0[14] = p0->RMON1.octets;
      values0[15] = p0->RMON1.crcAlignErrors;
    }
    if (p1) {
      const struct NtExtendedRMONCounters_v1_s* ext = p1->valid.extRMON ? &p1->extRMON : NULL;
      values1[0] = p1->RMON1.pkts;
      values1[1] = ext ? ext->unicastPkts : p1->RMON1.pkts;
      values1[2] = p1->RMON1.multicastPkts;
      values1[3] = p1->RMON1.broadcastPkts;
      values1[4] = p1->RMON1.pkts64Octets;
      values1[5] = p1->RMON1.pkts65to127Octets;
      values1[6] = p1->RMON1.pkts128to255Octets;
      values1[7] = p1->RMON1.pkts256to511Octets;
      values1[8] = p1->RMON1.pkts512to1023Octets;
      values1[9] = p1->RMON1.pkts1024to1518Octets;
      values1[10] = ext ? ext->pkts1519to2047Octets : 0;
      values1[11] = ext ? ext->pkts2048to4095Octets : 0;
      values1[12] = ext ? ext->pkts4096to8191Octets : 0;
      values1[13] = ext ? ext->pkts8192toMaxOctets : 0;
      values1[14] = p1->RMON1.octets;
      values1[15] = p1->RMON1.crcAlignErrors;
    }

    double gbps0 = 0.0;
    double gbps1 = 0.0;
    if (p0) {
      gbps0 = (double)(p0->RMON1.octets - prev_octets_0) * 8.0 / interval;
      prev_octets_0 = p0->RMON1.octets;
    }
    if (p1) {
      gbps1 = (double)(p1->RMON1.octets - prev_octets_1) * 8.0 / interval;
      prev_octets_1 = p1->RMON1.octets;
    }

    clear_screen();
    char ts[64];
    printf("Traffic Impact Monitor            %s\n", now_str(ts, sizeof ts));
    printf("Adapter %d   Interval %.1fs   Summary %.1fs   Color bit %d\n\n",
           adapter, interval, summary_period, color_bit);

    printf("%-18s | %-20s | %-20s\n", "Metric", "Port 0", "Port 1");
    printf("------------------+----------------------+----------------------\n");
    print_bw_row("RX Speed", gbps0, gbps1);
    static const char* labels[] = {
      "Packets", "Unicast", "Multicast", "Broadcast",
      "64 octets", "65-127 octets", "128-255 octets", "256-511 octets",
      "512-1023 octets", "1024-1518 octets", "1519-2047 octets", "2048-4095 octets",
      "4096-8191 octets", "8192-Max octets", "Octets", "CRC"
    };
    for (size_t i = 0; i < sizeof(labels)/sizeof(labels[0]); ++i)
      print_side_row(labels[i], values0[i], values1[i]);

    printf("\nDrop counters\n");
    uint64_t drop0 = (p0 && p0->valid.extDrop) ? p0->extDrop.pktsDedup : 0;
    uint64_t drop1 = (p1 && p1->valid.extDrop) ? p1->extDrop.pktsDedup : 0;
    print_side_row("Dedup pkts", drop0, drop1);

    printf("\nDedup summary (last %.0fs window)\n", summary_period);
    printf("Port | total_pkts           delta_pkts           total_octets         delta_octets\n");
    for (uint8_t p = 0; p < port_res->numPorts && p < 64; ++p) {
      printf("%4u | #%018" PRIu64 "  #%018" PRIu64 "  #%018" PRIu64 "  #%018" PRIu64 "\n",
             p, dedup_tot_pkts[p], dedup_delta_pkts[p], dedup_tot_octets[p], dedup_delta_octets[p]);
    }

    if (vlan_used) {
      printf("\nTop VLAN drop counts (S/C)\n");
      size_t show = vlan_used < 5 ? vlan_used : 5;
      for (size_t i = 0; i < show; ++i)
        printf("%3u/%-3u : %" PRIu64 "\n", vlan_pairs[i][0], vlan_pairs[i][1], vlan_counts[i]);
    }

    if (adapter < adapter_res->numAdapters && adapter_res->aAdapters[adapter].color.supported) {
      const struct NtColorStatistics_s* col = &adapter_res->aAdapters[adapter].color.aColor[color_bit];
      printf("\nAdapter color bit %d totals: pkts=%" PRIu64 " octets=%" PRIu64 "\n",
             color_bit, col->pkts, col->octets);
    }

    if (enable_capture){
      size_t pend_sz; pthread_mutex_lock(&C.q.mu); pend_sz = (size_t)(C.q.tail - C.q.head); pthread_mutex_unlock(&C.q.mu);
      printf("\nCapture: pend=%zu  popped=%" PRIu64 "  expired(drops)=%" PRIu64 "  seen=%" PRIu64 " ingressSeen=%" PRIu64
             "  pcap=%s  csv=%s\n",
             pend_sz, C.pop_total, C.expired_total, C.cap_seen_total, C.cap_seen_ingress,
             C.pcap_path, C.csv_path);
    }

    printf("\nPress Ctrl+C to exit\n");

    if (once)
      break;
  }

  NT_StatClose(stat_stream);
  if (enable_capture){
    C.running = 0;
    if (C.cap_rx) NT_NetRxClose(C.cap_rx);
    if (C.p_dump) { pcap_dump_close(C.p_dump); C.p_dump=NULL; }
    if (C.p_dead) { pcap_close(C.p_dead); C.p_dead=NULL; }
    if (C.f_drop_csv) { fclose(C.f_drop_csv); C.f_drop_csv=NULL; }
  }
  NT_Done();
  return 0;
}
