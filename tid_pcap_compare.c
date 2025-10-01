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
#include <sys/stat.h>
#include <pcap/pcap.h>

static volatile sig_atomic_t g_running = 1;
static void on_sigint(int sig){ (void)sig; g_running = 0; }

static void sleep_interval(double seconds){
  if (seconds <= 0.0) return;
  struct timespec ts; ts.tv_sec = (time_t)seconds; ts.tv_nsec = (long)((seconds - ts.tv_sec) * 1e9);
  if (ts.tv_nsec < 0) ts.tv_nsec = 0;
  nanosleep(&ts, NULL);
}

static const char* now_str(char* buf, size_t len){
  struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
  struct tm tm; localtime_r(&ts.tv_sec, &tm);
  strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm);
  return buf;
}

static void clear_screen(void){ fputs("\033[2J\033[H", stdout); }

static uint64_t fnv1a64(const uint8_t* data, size_t len){
  uint64_t h = 1469598103934665603ULL;
  for (size_t i=0;i<len;i++){ h ^= data[i]; h *= 1099511628211ULL; }
  return h;
}

typedef struct {
  uint64_t* digests;
  uint32_t* lens;
  size_t cap;
  size_t used;
} digest_vec_t;

static void dv_init(digest_vec_t* v){ v->digests=NULL; v->lens=NULL; v->cap=0; v->used=0; }
static void dv_reserve(digest_vec_t* v, size_t need){
  if (need <= v->cap) return;
  size_t nc = v->cap ? v->cap*2 : 1024; while (nc < need) nc*=2;
  v->digests = (uint64_t*)realloc(v->digests, nc*sizeof(uint64_t));
  v->lens    = (uint32_t*)realloc(v->lens,    nc*sizeof(uint32_t));
  if (!v->digests || !v->lens){ fprintf(stderr, "alloc failed\n"); exit(1);} v->cap = nc;
}
static void dv_push(digest_vec_t* v, uint64_t d, uint32_t l){ dv_reserve(v, v->used+1); v->digests[v->used]=d; v->lens[v->used]=l; v->used++; }
static void dv_reset(digest_vec_t* v){ v->used=0; }
static void dv_free(digest_vec_t* v){ free(v->digests); free(v->lens); dv_init(v);} 

typedef struct {
  const char* path0;
  const char* path1;
  double interval;
  size_t max_pairs;   // 0 = all available
  size_t last_pairs;
  uint64_t total_diffs;
  uint64_t last_diffs;
  time_t mtime0, mtime1;
  off_t size0, size1;
  digest_vec_t v0, v1;
} compare_ctx_t;

static int file_stat(const char* p, time_t* mt, off_t* sz){
  struct stat st; if (!p || stat(p, &st)!=0) return -1; if (mt) *mt = st.st_mtime; if (sz) *sz = st.st_size; return 0;
}

static size_t load_pcaps(const char* path, digest_vec_t* out){
  dv_reset(out);
  if (!path) return 0;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* p = pcap_open_offline(path, errbuf);
  if (!p) return 0;
  const u_char* data; struct pcap_pkthdr* hdr; int rc;
  while ((rc = pcap_next_ex(p, &hdr, &data)) == 1){
    uint32_t l = hdr->caplen;
    uint64_t d = fnv1a64((const uint8_t*)data, l);
    dv_push(out, d, l);
  }
  pcap_close(p);
  return out->used;
}

static void print_two(const char* label, uint64_t a, uint64_t b){
  printf("%-18s | #%018" PRIu64 " | #%018" PRIu64 "\n", label, a, b);
}
static void print_one(const char* label, uint64_t v){ printf("%-18s | #%018" PRIu64 " |\n", label, v); }

int main(int argc, char** argv){
  const char* p0 = NULL, *p1 = NULL; 
  double interval = 0.5; int once = 0; size_t max_pairs = 0; int verbose_first = 0;
  static struct option opts[] = {
    {"pcap0", required_argument, NULL, 1001},
    {"pcap1", required_argument, NULL, 1002},
    {"interval", required_argument, NULL, 'i'},
    {"once", no_argument, NULL, 'o'},
    {"max-pairs", required_argument, NULL, 1003},
    {"print-first-diff", no_argument, NULL, 1004},
    {NULL,0,NULL,0}
  };
  int c; while ((c = getopt_long(argc, argv, "i:o", opts, NULL)) != -1){
    switch(c){
      case 1001: p0 = optarg; break;
      case 1002: p1 = optarg; break;
      case 'i': interval = atof(optarg); if (interval<=0.0) interval=0.5; break;
      case 'o': once = 1; break;
      case 1003: max_pairs = (size_t)atol(optarg); break;
      case 1004: verbose_first = 1; break;
      default:
        fprintf(stderr, "Usage: %s --pcap0=PATH --pcap1=PATH [--interval=SEC] [--once] [--max-pairs=N] [--print-first-diff]\n", argv[0]);
        return 1;
    }
  }
  if (!p0 || !p1){
    fprintf(stderr, "Both --pcap0 and --pcap1 are required.\n");
    return 1;
  }
  signal(SIGINT, on_sigint);

  compare_ctx_t C = {0}; C.path0 = p0; C.path1 = p1; C.interval = interval; C.max_pairs = max_pairs;
  dv_init(&C.v0); dv_init(&C.v1);

  while (g_running){
    sleep_interval(C.interval);

    time_t mt0=0, mt1=0; off_t sz0=0, sz1=0;
    file_stat(C.path0, &mt0, &sz0); file_stat(C.path1, &mt1, &sz1);

    size_t n0 = load_pcaps(C.path0, &C.v0);
    size_t n1 = load_pcaps(C.path1, &C.v1);
    size_t pairs = n0 < n1 ? n0 : n1;
    if (C.max_pairs && pairs > C.max_pairs) pairs = C.max_pairs;

    uint64_t diffs = 0; size_t first_i = (size_t)-1;
    for (size_t i=0;i<pairs;i++){
      if (C.v0.lens[i] != C.v1.lens[i] || C.v0.digests[i] != C.v1.digests[i]){ diffs++; if (first_i==(size_t)-1) first_i=i; }
    }
    uint64_t delta = (diffs >= C.last_diffs) ? (diffs - C.last_diffs) : diffs;
    C.total_diffs = diffs; C.last_diffs = diffs; C.last_pairs = pairs;
    C.mtime0 = mt0; C.mtime1 = mt1; C.size0 = sz0; C.size1 = sz1;

    clear_screen(); char ts[64];
    printf("Traffic PCAP Compare            %s\n\n", now_str(ts, sizeof ts));
    printf("Files\n");
    print_two("Packets", n0, n1);
    print_two("Size(bytes)", (uint64_t)sz0, (uint64_t)sz1);
    print_two("Compared", pairs, pairs);
    print_one("Differences", diffs);
    if (verbose_first && first_i != (size_t)-1){ printf("First diff at index: %zu\n", first_i); }

    printf("\nStatus: comparing every %.2fs. Ctrl+C to exit\n", C.interval);
    (void)delta;
    if (once) break;
  }

  dv_free(&C.v0); dv_free(&C.v1);
  return 0;
}
