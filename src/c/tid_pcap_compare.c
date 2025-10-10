/**
 * Traffic PCAP Compare (tid_pcap_compare.c)
 *
 * Build:
 *   gcc -O2 -g src/c/tid_pcap_compare.c \
 *       -I/opt/napatech3/include \
 *       -L/opt/napatech3/lib \
 *       -lpcap -lntapi \
 *       -o bin/tid_pcap_compare
 *
 * The tool compares two PCAP capture streams (or rolling directories) and can
 * tolerate re-ordered packets when used with the --window-us option.
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
#include <sys/stat.h>
#include <pcap/pcap.h>
#include <dirent.h>
#include <dirent.h>

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
  uint64_t* ts_us;   // packet header timestamp (microseconds)
  size_t cap;
  size_t used;
} digest_vec_t;

static void dv_init(digest_vec_t* v){ v->digests=NULL; v->lens=NULL; v->ts_us=NULL; v->cap=0; v->used=0; }
static void dv_reserve(digest_vec_t* v, size_t need){
  if (need <= v->cap) return;
  size_t nc = v->cap ? v->cap*2 : 1024; while (nc < need) nc*=2;
  v->digests = (uint64_t*)realloc(v->digests, nc*sizeof(uint64_t));
  v->lens    = (uint32_t*)realloc(v->lens,    nc*sizeof(uint32_t));
  v->ts_us   = (uint64_t*)realloc(v->ts_us,   nc*sizeof(uint64_t));
  if (!v->digests || !v->lens || !v->ts_us){ fprintf(stderr, "alloc failed\n"); exit(1);} v->cap = nc;
}
static void dv_push(digest_vec_t* v, uint64_t d, uint32_t l, uint64_t ts){ dv_reserve(v, v->used+1); v->digests[v->used]=d; v->lens[v->used]=l; v->ts_us[v->used]=ts; v->used++; }
static void dv_reset(digest_vec_t* v){ v->used=0; }
static void dv_free(digest_vec_t* v){ free(v->digests); free(v->lens); free(v->ts_us); dv_init(v);} 

typedef struct {
  const char* path0;
  const char* path1;
  const char* dir0;
  const char* dir1;
  double interval;
  size_t max_pairs;   // 0 = all available
  uint64_t window_us;
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
  int follow_latest;
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
    uint64_t ts = (uint64_t)hdr->ts.tv_sec * 1000000ULL + (uint64_t)hdr->ts.tv_usec;
    dv_push(out, d, l, ts);
  }
  pcap_close(p);
  return out->used;
}

static size_t dv_lower_bound_ts(const digest_vec_t* v, uint64_t target){
  size_t lo=0, hi=v->used; while (lo<hi){ size_t mid=(lo+hi)/2; if (v->ts_us[mid] < target) lo=mid+1; else hi=mid; } return lo;
}

static void auto_offsets_by_ts(const digest_vec_t* v0, const digest_vec_t* v1, size_t* off0, size_t* off1){
  size_t o0=0,o1=0; if (v0->used==0 || v1->used==0){ *off0=o0; *off1=o1; return; }
  uint64_t t0=v0->ts_us[0]; size_t j=dv_lower_bound_ts(v1,t0); size_t bj=j; if (j>0){ uint64_t d1 = (j<v1->used)? (v1->ts_us[j]>t0? v1->ts_us[j]-t0 : t0-v1->ts_us[j]) : UINT64_MAX; uint64_t d0 = (v1->ts_us[j-1]>t0? v1->ts_us[j-1]-t0 : t0-v1->ts_us[j-1]); if (j>=v1->used || d0<=d1) bj=j-1; }
  uint64_t t1=v1->ts_us[0]; size_t i=dv_lower_bound_ts(v0,t1); size_t bi=i; if (i>0){ uint64_t d1=(i<v0->used)? (v0->ts_us[i]>t1? v0->ts_us[i]-t1 : t1-v0->ts_us[i]) : UINT64_MAX; uint64_t d0=(v0->ts_us[i-1]>t1? v0->ts_us[i-1]-t1 : t1-v0->ts_us[i-1]); if (i>=v0->used || d0<=d1) bi=i-1; }
  size_t cand_o0[2]={0,bi}; size_t cand_o1[2]={bj,0}; int best=0; size_t best_mm=SIZE_MAX;
  for(int k=0;k<2;k++){
    size_t a=cand_o0[k], b=cand_o1[k]; size_t n0=v0->used>a?(v0->used-a):0; size_t n1=v1->used>b?(v1->used-b):0; size_t pairs = n0<n1?n0:n1; if (!pairs) continue; if (pairs>64) pairs=64; size_t mm=0; for(size_t x=0;x<pairs;x++){ size_t i0=a+x, i1=b+x; if (v0->lens[i0]!=v1->lens[i1] || v0->digests[i0]!=v1->digests[i1]) mm++; } if (mm<best_mm){ best_mm=mm; best=k; }
  }
  *off0=cand_o0[best]; *off1=cand_o1[best];
}

static const char* base_name(const char* p){ const char* s=strrchr(p?p:"", '/'); return s? s+1 : (p?p:""); }
static void extract_ts_from_base(const char* base, char* out, size_t n){
  if (!base||!n){ if(n) out[0]='\0'; return; }
  const char* us=strchr(base,'_'); const char* dot=strrchr(base,'.');
  if (!us||!dot||dot<=us+1){ out[0]='\0'; return; }
  size_t len=(size_t)(dot-(us+1)); if (len>=n) len=n-1; memcpy(out,us+1,len); out[len]='\0';
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

typedef struct {
  uint64_t diffs;
  size_t pairs;
  size_t matched;
  size_t first_mismatch;
} compare_result_t;

static compare_result_t compare_windowed(const digest_vec_t* v0,
                                         const digest_vec_t* v1,
                                         size_t off0,
                                         size_t off1,
                                         size_t max_pairs,
                                         uint64_t window_us,
                                         index_vec_t* mis,
                                         size_t mis_limit){
  compare_result_t res;
  res.diffs = 0;
  res.pairs = 0;
  res.matched = 0;
  res.first_mismatch = (size_t)-1;

  size_t avail0 = (v0->used > off0) ? (v0->used - off0) : 0;
  size_t avail1 = (v1->used > off1) ? (v1->used - off1) : 0;
  size_t pairs = (avail0 < avail1) ? avail0 : avail1;
  if (max_pairs && pairs > max_pairs) pairs = max_pairs;
  res.pairs = pairs;
  if (pairs == 0) return res;

  uint8_t* matched = (uint8_t*)calloc(pairs, sizeof(uint8_t));
  if (!matched){ perror("calloc"); exit(1); }

  for (size_t i = 0; i < pairs; ++i){
    size_t idx0 = off0 + i;
    uint64_t ts0 = v0->ts_us[idx0];
    size_t best = (size_t)-1;
    for (size_t j = 0; j < pairs; ++j){
      if (matched[j]) continue;
      size_t idx1 = off1 + j;
      uint64_t ts1 = v1->ts_us[idx1];
      uint64_t diff_ts = (ts0 > ts1) ? (ts0 - ts1) : (ts1 - ts0);
      if (diff_ts > window_us) continue;
      if (v0->lens[idx0] == v1->lens[idx1] && v0->digests[idx0] == v1->digests[idx1]){
        best = j;
        break;
      }
    }
    if (best != (size_t)-1){
      matched[best] = 1;
      res.matched++;
    } else {
      res.diffs++;
      if (res.first_mismatch == (size_t)-1) res.first_mismatch = i;
      if (mis && mis_limit && mis->used < mis_limit) iv_push(mis, i);
    }
  }

  free(matched);
  return res;
}

int main(int argc, char** argv){
  const char* p0 = NULL, *p1 = NULL; 
  double interval = 0.5; int once = 0; size_t max_pairs = 0; int verbose_first = 0;
  const char* report_path = NULL; size_t report_limit = 20; size_t report_bytes = 64;
  const char* dir0 = NULL; const char* dir1 = NULL; int follow_latest = 0; int scan_all = 0;
  const char* auto_report_dir = NULL; size_t auto_report_limit = 20; size_t auto_report_bytes = 64;
  int alt_screen = 0;
  size_t offset0 = 0, offset1 = 0; int auto_offset_ts = 0;
  uint64_t window_us = 0;
  static struct option opts[] = {
    {"pcap0", required_argument, NULL, 1001},
    {"pcap1", required_argument, NULL, 1002},
    {"pcap0-dir", required_argument, NULL, 1011},
    {"pcap1-dir", required_argument, NULL, 1012},
    {"follow-latest", no_argument, NULL, 1013},
    {"scan-all", no_argument, NULL, 1014},
    {"auto-report-dir", required_argument, NULL, 1015},
    {"auto-report-limit", required_argument, NULL, 1016},
    {"auto-report-bytes", required_argument, NULL, 1017},
    {"alt-screen", no_argument, NULL, 1018},
    {"window-us", required_argument, NULL, 1019},
    {"interval", required_argument, NULL, 'i'},
    {"once", no_argument, NULL, 'o'},
    {"max-pairs", required_argument, NULL, 1003},
    {"print-first-diff", no_argument, NULL, 1004},
    {"report", required_argument, NULL, 1005},
    {"report-limit", required_argument, NULL, 1006},
    {"report-bytes", required_argument, NULL, 1007},
    {"offset0", required_argument, NULL, 1008},
    {"offset1", required_argument, NULL, 1009},
    {"auto-offset-ts", no_argument, NULL, 1010},
    {NULL,0,NULL,0}
  };
  int c; while ((c = getopt_long(argc, argv, "i:o", opts, NULL)) != -1){
    switch(c){
      case 1001: p0 = optarg; break;
      case 1002: p1 = optarg; break;
      case 1011: dir0 = optarg; break;
      case 1012: dir1 = optarg; break;
      case 1013: follow_latest = 1; break;
      case 1014: scan_all = 1; break;
      case 1015: auto_report_dir = optarg; break;
      case 1016: { long long x = atoll(optarg); if (x<0) x=0; auto_report_limit=(size_t)x; } break;
      case 1017: { long long x = atoll(optarg); if (x<0) x=0; auto_report_bytes=(size_t)x; if (!auto_report_bytes) auto_report_bytes=1; } break;
      case 1018: alt_screen = 1; break;
      case 1019: { long long x = atoll(optarg); if (x < 0) x = 0; window_us = (uint64_t)x; } break;
      case 'i': interval = atof(optarg); if (interval<=0.0) interval=0.5; break;
      case 'o': once = 1; break;
      case 1003: max_pairs = (size_t)atol(optarg); break;
      case 1004: verbose_first = 1; break;
      case 1005: report_path = optarg; break;
      case 1006: report_limit = (size_t)atol(optarg); break;
      case 1007: report_bytes = (size_t)atol(optarg); if (report_bytes==0) report_bytes=1; break;
      case 1008: { long long x=atoll(optarg); if (x<0) x=0; offset0=(size_t)x; } break;
      case 1009: { long long x=atoll(optarg); if (x<0) x=0; offset1=(size_t)x; } break;
      case 1010: auto_offset_ts = 1; break;
      default:
        fprintf(stderr, "Usage: %s --pcap0=PATH --pcap1=PATH [--interval=SEC] [--once] [--max-pairs=N] [--print-first-diff]\n"
                        "            [--report=PATH] [--report-limit=N] [--report-bytes=B] [--alt-screen]\n"
                        "            [--offset0=N] [--offset1=N] [--auto-offset-ts] [--window-us=USEC]\n"
                        "   or:   %s --pcap0-dir=DIR --pcap1-dir=DIR [--follow-latest|--scan-all] [--interval=SEC] [--alt-screen]\n"
                        "            [--offset0=N] [--offset1=N] [--auto-report-dir=DIR] [--auto-report-limit=N] [--auto-report-bytes=B] [--window-us=USEC]\n", argv[0], argv[0]);
        return 1;
    }
  }
  if ((p0 && !p1) || (!p0 && p1)) { fprintf(stderr, "Specify both --pcap0 and --pcap1, or use --pcap0-dir and --pcap1-dir.\n"); return 1; }
  if (!p0 && !p1) {
    if (!dir0 || !dir1) { fprintf(stderr, "Provide --pcap0/--pcap1 or --pcap0-dir/--pcap1-dir.\n"); return 1; }
    if (!follow_latest && !scan_all) follow_latest = 1;
  }
  signal(SIGINT, on_sigint);
  if (alt_screen) { fputs("\033[?1049h", stdout); fflush(stdout); }

  compare_ctx_t C = {0}; C.path0 = p0; C.path1 = p1; C.dir0 = dir0; C.dir1 = dir1; C.follow_latest = follow_latest; C.interval = interval; C.max_pairs = max_pairs; C.window_us = window_us;
  C.report_path = report_path; C.report_limit = report_limit; C.report_bytes = report_bytes;
  dv_init(&C.v0); dv_init(&C.v1);
  index_vec_t mis; iv_init(&mis);

  while (g_running){
    sleep_interval(C.interval);

    time_t mt0=0, mt1=0; off_t sz0=0, sz1=0;
    // Directory mode
    if (C.dir0 && C.dir1 && (C.follow_latest || scan_all)){
      typedef struct { char ts[128]; char path[1024]; } ent_t; ent_t e0[1024]; size_t u0=0; ent_t e1[1024]; size_t u1=0;
      DIR* d; struct dirent* de;
      if ((d=opendir(C.dir0))){ while ((de=readdir(d))){ if (de->d_name[0]=='.') continue; size_t len=strlen(de->d_name); if (len<5||strcmp(de->d_name+len-5, ".pcap")!=0) continue; if (strncmp(de->d_name, "port0_", 6)!=0) continue; char tsb[128]; extract_ts_from_base(de->d_name, tsb, sizeof tsb); if(!tsb[0]) continue; if (u0<1024){ strncpy(e0[u0].ts, tsb, sizeof e0[u0].ts-1); e0[u0].ts[sizeof e0[u0].ts-1]='\0'; snprintf(e0[u0].path,sizeof e0[u0].path, "%s/%s", C.dir0, de->d_name); u0++; } } closedir(d);} 
      if ((d=opendir(C.dir1))){ while ((de=readdir(d))){ if (de->d_name[0]=='.') continue; size_t len=strlen(de->d_name); if (len<5||strcmp(de->d_name+len-5, ".pcap")!=0) continue; if (strncmp(de->d_name, "port1_", 6)!=0) continue; char tsb[128]; extract_ts_from_base(de->d_name, tsb, sizeof tsb); if(!tsb[0]) continue; if (u1<1024){ strncpy(e1[u1].ts, tsb, sizeof e1[u1].ts-1); e1[u1].ts[sizeof e1[u1].ts-1]='\0'; snprintf(e1[u1].path,sizeof e1[u1].path, "%s/%s", C.dir1, de->d_name); u1++; } } closedir(d);} 
      int cmp_ent(const void* a,const void* b){ const ent_t* A=a; const ent_t* B=b; return strcmp(A->ts,B->ts);} if(u0) qsort(e0,u0,sizeof(ent_t),cmp_ent); if(u1) qsort(e1,u1,sizeof(ent_t),cmp_ent);
      if (scan_all){
        // Sum across all matching pairs, optional auto-report
        size_t i0=0,i1=0, pairs_used=0, files_compared=0; uint64_t sum_diffs=0; size_t reports_written=0; char last0[1024]="", last1[1024]="";
        while (i0<u0 && i1<u1){ int c=strcmp(e0[i0].ts,e1[i1].ts); if (c<0) i0++; else if (c>0) i1++; else {
            pairs_used++;
            // load and compare this pair
            digest_vec_t dv0,dv1; dv_init(&dv0); dv_init(&dv1);
            load_pcaps(e0[i0].path,&dv0); load_pcaps(e1[i1].path,&dv1);
            size_t off0=offset0, off1=offset1; if (auto_offset_ts){ auto_offsets_by_ts(&dv0,&dv1,&off0,&off1);}
            index_vec_t mis_local; iv_init(&mis_local);
            compare_result_t cr = compare_windowed(&dv0, &dv1, off0, off1, max_pairs, window_us, &mis_local, auto_report_limit);
            uint64_t cdiffs = cr.diffs;
            size_t cpairs = cr.pairs;
            sum_diffs += cdiffs; files_compared++;
            if (auto_report_dir && cdiffs>0){ char outp[1024]; snprintf(outp,sizeof outp, "%s/pcap_diff_%s.txt", auto_report_dir, e0[i0].ts); struct stat strep; if (stat(outp,&strep)!=0){ compare_ctx_t CC={0}; CC.path0=e0[i0].path; CC.path1=e1[i1].path; CC.report_path=outp; CC.report_limit=auto_report_limit; CC.report_bytes=auto_report_bytes; CC.last_pairs=cpairs; CC.total_diffs=cdiffs;
                index_vec_t abs; iv_init(&abs); for (size_t t=0;t<mis_local.used;t++){ iv_push(&abs, mis_local.a[t] + off0); } write_report(&CC,&abs); iv_free(&abs); reports_written++; } }
            dv_free(&dv0); dv_free(&dv1); iv_free(&mis_local);
            strncpy(last0,e0[i0].path,sizeof last0-1); last0[sizeof last0-1]='\0'; strncpy(last1,e1[i1].path,sizeof last1-1); last1[sizeof last1-1]='\0';
            i0++; i1++; }
        }
        clear_screen(); char tsb[64]; printf("Traffic PCAP Compare            %s\n\n", now_str(tsb, sizeof tsb));
        printf("Dirs    %s    %s\n", C.dir0, C.dir1);
        printf("Pairs matched: %zu\n", pairs_used);
        printf("Total files compared: %zu\n", files_compared);
        printf("Total differences: %" PRIu64 "\n", sum_diffs);
        if (auto_report_dir) printf("Auto-report dir: %s (wrote %zu new)\n", auto_report_dir, reports_written);
        if (last0[0] && last1[0]){ printf("Latest match: %s   %s\n", base_name(last0), base_name(last1)); }
        printf("\nStatus: scanning every %.2fs. Ctrl+C to exit\n", C.interval);
        if (once) break; else continue;
      } else if (C.follow_latest){
        size_t i0=0,i1=0; const char* pick0=NULL; const char* pick1=NULL; while (i0<u0 && i1<u1){ int c=strcmp(e0[i0].ts,e1[i1].ts); if (c<0) i0++; else if (c>0) i1++; else { pick0=e0[i0].path; pick1=e1[i1].path; i0++; i1++; } }
        if (pick0 && pick1){ C.path0=pick0; C.path1=pick1; }
      }
    }
    file_stat(C.path0, &mt0, &sz0); file_stat(C.path1, &mt1, &sz1);

    size_t n0 = load_pcaps(C.path0, &C.v0);
    size_t n1 = load_pcaps(C.path1, &C.v1);
    size_t off0 = offset0, off1 = offset1;
    if (auto_offset_ts){ auto_offsets_by_ts(&C.v0, &C.v1, &off0, &off1); }
    iv_reset(&mis);
    compare_result_t res = compare_windowed(&C.v0, &C.v1, off0, off1, C.max_pairs, C.window_us, &mis, C.report_limit);
    size_t pairs = res.pairs;
    uint64_t diffs = res.diffs;
    size_t first_i = res.first_mismatch;
    uint64_t delta = (diffs >= C.last_diffs) ? (diffs - C.last_diffs) : diffs;
    C.total_diffs = diffs; C.last_diffs = diffs; C.last_pairs = pairs;
    C.mtime0 = mt0; C.mtime1 = mt1; C.size0 = sz0; C.size1 = sz1;

    clear_screen(); char ts[64];
    printf("Traffic PCAP Compare            %s\n\n", now_str(ts, sizeof ts));
    printf("Files\n");
    if (C.dir0 && C.dir1 && C.follow_latest){ printf("Dirs    %s    %s\n", C.dir0, C.dir1); }
    print_two("Packets", n0, n1);
    print_two("Size(bytes)", (uint64_t)sz0, (uint64_t)sz1);
    print_two("Compared", pairs, pairs);
    print_one("Differences", diffs);
    if (auto_offset_ts || offset0 || offset1) {
      printf("Offsets: pcap0=%zu pcap1=%zu%s\n", off0, off1, auto_offset_ts?" (auto-ts)":"");
    }
    if (verbose_first && first_i != (size_t)-1){ printf("First diff at pair=%zu (pcap0 idx=%zu, pcap1 idx=%zu)\n", first_i, off0+first_i, off1+first_i); }

    if (C.report_path && diffs>0){
      printf("Report: writing first %zu diffs to %s (bytes=%zu)\n", mis.used, C.report_path, C.report_bytes);
      // Convert relative indices to absolute by applying offsets
      index_vec_t abs; iv_init(&abs);
      for (size_t k=0;k<mis.used;k++){ iv_push(&abs, mis.a[k] + off0); }
      write_report(&C, &abs);
      iv_free(&abs);
    }

    printf("\nStatus: comparing every %.2fs. Ctrl+C to exit\n", C.interval);
    (void)delta;
    if (once) break;
  }

  dv_free(&C.v0); dv_free(&C.v1); iv_free(&mis);
  if (alt_screen) { fputs("\033[?1049l", stdout); fflush(stdout); }
  return 0;
}
