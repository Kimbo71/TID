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
  // report options
  const char* report_path;
  size_t report_limit;   // number of mismatches to include
  size_t report_bytes;   // bytes of each side to hex-dump

  size_t last_pairs;
  uint64_t total_diffs;
  uint64_t last_diffs;
  time_t mtime0, mtime1;
  off_t size0, size1;
  digest_vec_t v0, v1;
} compare_ctx_t;

typedef struct {
  size_t* a; size_t used; size_t cap;
} index_vec_t;
static void iv_init(index_vec_t* v){ v->a=NULL; v->used=0; v->cap=0; }
static void iv_push(index_vec_t* v, size_t x){ if (v->used==v->cap){ size_t nc=v->cap?v->cap*2:32; v->a=(size_t*)realloc(v->a,nc*sizeof(size_t)); if(!v->a){perror("realloc"); exit(1);} v->cap=nc;} v->a[v->used++]=x; }
static void iv_reset(index_vec_t* v){ v->used=0; }
static void iv_free(index_vec_t* v){ free(v->a); iv_init(v);} 

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

static void hexdump_line(FILE* f, const uint8_t* p, size_t n){
  for (size_t i=0;i<n;i++){ fprintf(f, "%02x%s", p[i], ((i&15)==15||i==n-1)?"":" "); }
}

static int dump_nth(const char* path, size_t idx, size_t max_bytes, FILE* f){
  char errbuf[PCAP_ERRBUF_SIZE]; pcap_t* p = pcap_open_offline(path, errbuf); if(!p) return -1;
  const u_char* data; struct pcap_pkthdr* hdr; int rc; size_t i=0; int found=0;
  while ((rc = pcap_next_ex(p, &hdr, &data)) == 1){ if (i==idx){ found=1; break; } i++; }
  if (!found){ pcap_close(p); return -1; }
  size_t n = hdr->caplen < max_bytes ? hdr->caplen : max_bytes;
  fprintf(f, "len=%u cap=%u dump=%zu bytes\n", (unsigned)hdr->len, (unsigned)hdr->caplen, n);
  hexdump_line(f, (const uint8_t*)data, n); fputc('\n', f);
  pcap_close(p); return 0;
}

static void write_report(compare_ctx_t* C, const index_vec_t* mis){
  if (!C->report_path || mis->used==0) return;
  char tmp[512]; snprintf(tmp, sizeof tmp, "%s.tmp", C->report_path);
  FILE* f = fopen(tmp, "w"); if(!f) return;
  time_t now = time(NULL); char ts[64]; struct tm tm; localtime_r(&now,&tm); strftime(ts,sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
  fprintf(f, "Traffic PCAP Compare Report\nGenerated: %s\nFiles:\n  pcap0: %s\n  pcap1: %s\nPairs compared: %zu\nDifferences: %" PRIu64 "\nEntries: %zu (limit %zu)\n\n",
          ts, C->path0, C->path1, C->last_pairs, C->total_diffs, mis->used, C->report_limit);
  for (size_t k=0;k<mis->used;k++){
    size_t i = mis->a[k];
    fprintf(f, "#%zu\n", i);
    fprintf(f, "pcap0: "); (void)dump_nth(C->path0, i, C->report_bytes, f);
    fprintf(f, "pcap1: "); (void)dump_nth(C->path1, i, C->report_bytes, f);
    fputc('\n', f);
  }
  fclose(f); rename(tmp, C->report_path);
}

int main(int argc, char** argv){
  const char* p0 = NULL, *p1 = NULL; 
  double interval = 0.5; int once = 0; size_t max_pairs = 0; int verbose_first = 0;
  const char* report_path = NULL; size_t report_limit = 20; size_t report_bytes = 64;
  static struct option opts[] = {
    {"pcap0", required_argument, NULL, 1001},
    {"pcap1", required_argument, NULL, 1002},
    {"interval", required_argument, NULL, 'i'},
    {"once", no_argument, NULL, 'o'},
    {"max-pairs", required_argument, NULL, 1003},
    {"print-first-diff", no_argument, NULL, 1004},
    {"report", required_argument, NULL, 1005},
    {"report-limit", required_argument, NULL, 1006},
    {"report-bytes", required_argument, NULL, 1007},
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
      case 1005: report_path = optarg; break;
      case 1006: report_limit = (size_t)atol(optarg); break;
      case 1007: report_bytes = (size_t)atol(optarg); if (report_bytes==0) report_bytes=1; break;
      default:
        fprintf(stderr, "Usage: %s --pcap0=PATH --pcap1=PATH [--interval=SEC] [--once] [--max-pairs=N] [--print-first-diff]\n"
                        "            [--report=PATH] [--report-limit=N] [--report-bytes=B]\n", argv[0]);
        return 1;
    }
  }
  if (!p0 || !p1){
    fprintf(stderr, "Both --pcap0 and --pcap1 are required.\n");
    return 1;
  }
  signal(SIGINT, on_sigint);

  compare_ctx_t C = {0}; C.path0 = p0; C.path1 = p1; C.interval = interval; C.max_pairs = max_pairs;
  C.report_path = report_path; C.report_limit = report_limit; C.report_bytes = report_bytes;
  dv_init(&C.v0); dv_init(&C.v1);
  index_vec_t mis; iv_init(&mis);

  while (g_running){
    sleep_interval(C.interval);

    time_t mt0=0, mt1=0; off_t sz0=0, sz1=0;
    file_stat(C.path0, &mt0, &sz0); file_stat(C.path1, &mt1, &sz1);

    size_t n0 = load_pcaps(C.path0, &C.v0);
    size_t n1 = load_pcaps(C.path1, &C.v1);
    size_t pairs = n0 < n1 ? n0 : n1;
    if (C.max_pairs && pairs > C.max_pairs) pairs = C.max_pairs;

    uint64_t diffs = 0; size_t first_i = (size_t)-1; iv_reset(&mis);
    for (size_t i=0;i<pairs;i++){
      if (C.v0.lens[i] != C.v1.lens[i] || C.v0.digests[i] != C.v1.digests[i]){
        diffs++; if (first_i==(size_t)-1) first_i=i; if (mis.used < C.report_limit) iv_push(&mis, i);
      }
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

    if (C.report_path && diffs>0){
      printf("Report: writing first %zu diffs to %s (bytes=%zu)\n", mis.used, C.report_path, C.report_bytes);
      write_report(&C, &mis);
    }

    printf("\nStatus: comparing every %.2fs. Ctrl+C to exit\n", C.interval);
    (void)delta;
    if (once) break;
  }

  dv_free(&C.v0); dv_free(&C.v1); iv_free(&mis);
  return 0;
}
