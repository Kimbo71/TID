// nt_drop_reader.c — HW-correlation drop detector (receive-all) with per-side watermarks
//
// Build (NATIVE_UNIX = 10ns ticks → ns):
//   gcc -O2 -Wall -Wextra -std=gnu11 \
//     -I/opt/napatech3/include -I/opt/napatech3/include/ntapi \
//     -L/opt/napatech3/lib -Wl,-rpath,/opt/napatech3/lib \
//     nt_drop_reader.c -lntapi -lpcap -pthread -o nt_drop_reader
// If your TimestampFormat is UNIX_NS (1 ns ticks): add -DTS_PKT_MULT=1
//
// NTPL (whole-frame key + color marks):
//   Delete = All
//   Setup [State=Active] = StreamId == 0
//   Define descAll = Descriptor(DYN4, ColorBits=8)
//   Define ckWhole = CorrelationKey(Begin=StartOfFrame[0], End=EndOfFrame[-4], DeduplicationGroupID=0)
//   Assign[ColorMask=0x01] = Port == 0
//   Assign[ColorMask=0x02] = Port == 1
//   Assign[StreamId=0; Descriptor=descAll; CorrelationKey=ckWhole] = (Port == 0 OR Port == 1)

#define _GNU_SOURCE
#include <nt.h>
#include <ntapi/pktdescr_dyn4.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

/* ---------- Config ---------- */
typedef struct {
  int adapter;                 // adapter index (default 0)
  uint8_t port_ing;            // ingress port (fallback if color0 missing)
  uint8_t port_egr;            // egress  port (fallback if color0 missing)
  uint32_t win_us;             // expiry window (µs) in packet timebase
  uint32_t snaplen;            // bytes saved for drops
  const char* pcap_path;       // drop PCAP path
  const char* state_path;      // CSV state path
  int pend_pow;                // pending table size = 2^pend_pow
  int quiet;                   // suppress stdout logs
} cfg_t;
static cfg_t g;

/* ---------- Metrics ---------- */
static atomic_uint_fast64_t g_seen_ing = 0, g_seen_egr = 0;
static atomic_uint_fast64_t g_expired  = 0, g_drops_written = 0;
static atomic_uint_fast64_t g_pend_live = 0;
static atomic_uint_fast64_t g_matched_oo = 0;   // out-of-order matches (egress-first)

/* Packet timebase watermarks (ns) — per side */
static atomic_uint_fast64_t g_now_ing_ns = 0;
static atomic_uint_fast64_t g_now_egr_ns = 0;

#ifndef TS_PKT_MULT
#define TS_PKT_MULT 10ULL   // NATIVE_UNIX: 10ns ticks -> ns
#endif

/* ---------- Pending table with tombstones + side ---------- */
typedef enum { SIDE_NONE=0, SIDE_ING=1, SIDE_EGR=2 } side_t;

typedef struct {
  atomic_uint_fast64_t key64;  // 0=FREE; TOMB=deleted; otherwise correlation key
  atomic_uint_fast64_t ts_ns;  // timestamp of first-seen side (ns)
  atomic_uint_fast8_t  side;   // SIDE_ING or SIDE_EGR
  uint32_t slab_idx;           // snapshot index (for ingress-first only)
  uint16_t caplen;             // bytes copied
} pend_t;

#define PEND_FREE 0ull
#define PEND_TOMB 0xFFFFFFFFFFFFFFFFull

static pend_t* PEND = NULL;
static uint64_t PEND_MASK = 0;

static inline uint32_t khash64(uint64_t k){
  k ^= k >> 33; k *= 0xff51afd7ed558ccdULL; k ^= k >> 33;
  k *= 0xc4ceb9fe1a85ec53ULL; k ^= k >> 33;
  return (uint32_t)k;
}

/* ---------- Slab snapshots ---------- */
typedef struct { uint8_t* base; uint32_t stride; uint32_t cap; atomic_uint_fast32_t head; } slab_t;
static slab_t SLAB;
static void* xaligned_alloc(size_t align, size_t bytes){ void* p=NULL; if (posix_memalign(&p,align,bytes)!=0) return NULL; return p; }
static void slab_init(uint32_t slots, uint32_t stride){
  SLAB.base=(uint8_t*)xaligned_alloc(64,(size_t)slots*stride);
  if(!SLAB.base){ fprintf(stderr,"slab alloc failed\n"); exit(1); }
  SLAB.stride=stride; SLAB.cap=slots; atomic_store(&SLAB.head,0);
}
static inline uint32_t slab_acquire(void){ return atomic_fetch_add(&SLAB.head,1)&(SLAB.cap-1); }
static inline uint8_t* slab_ptr(uint32_t idx){ return SLAB.base + (size_t)idx*SLAB.stride; }

/* ---------- PCAP (expirer writes) ---------- */
static pcap_t* p_dead = NULL; static pcap_dumper_t* p_dump = NULL;
static void pcap_open_writer(const char* path, uint32_t dltSnap){
  p_dead = pcap_open_dead(DLT_EN10MB, dltSnap);
  if (!p_dead){ fprintf(stderr,"pcap_open_dead failed\n"); exit(1); }
  p_dump = pcap_dump_open(p_dead, path);
  if (!p_dump){ fprintf(stderr,"pcap_dump_open failed: %s\n", pcap_geterr(p_dead)); exit(1); }
  if (!g.quiet) printf("pcap=%s\n", path);
}
static inline void pcap_write(const uint8_t* data, uint32_t caplen, uint64_t ts_ns){
  struct pcap_pkthdr h; memset(&h,0,sizeof h);
  h.caplen = caplen; h.len = caplen;
  h.ts.tv_sec  = (time_t)(ts_ns / 1000000000ULL);
  h.ts.tv_usec = (suseconds_t)((ts_ns % 1000000000ULL) / 1000ULL);
  pcap_dump((u_char*)p_dump, &h, data);
}

/* ---------- Minimal VLAN/IP/L4 parse for drop printf ---------- */
typedef struct {
  bool v6; uint8_t proto; uint16_t s, c;
  union { uint32_t v4; uint8_t v6b[16]; } src, dst;
  uint16_t sport, dport;
} drop_key_t;

static void parse_vlan_ip_l4(const uint8_t* p, uint32_t len, drop_key_t* dk){
  memset(dk,0,sizeof *dk);
  if (len < 14) return;
  int off = 14; uint16_t eth = (uint16_t)((p[12]<<8)|p[13]);
  uint16_t s=0,c=0;

  for (int i=0;i<2;i++){
    if (eth==0x88A8 || eth==0x8100){
      if (len < (uint32_t)(off+4)) break;
      uint16_t tci=(uint16_t)((p[off]<<8)|p[off+1]); uint16_t vid=(uint16_t)(tci&0x0FFF);
      if (eth==0x88A8 && s==0) s=vid; else if (c==0) c=vid;
      eth=(uint16_t)((p[off+2]<<8)|p[off+3]); off+=4;
    } else break;
  }
  dk->s=s; dk->c=c;

  if (eth==0x0800 && len >= (uint32_t)(off+20)){
    uint8_t ihl = (uint8_t)(p[off] & 0x0F);
    uint32_t ihl_bytes = (uint32_t)ihl * 4;
    if (ihl_bytes < 20 || len < (uint32_t)(off + ihl_bytes)) return;
    dk->v6=false; dk->proto=p[off+9];
    memcpy(&dk->src.v4, p+off+12, 4);
    memcpy(&dk->dst.v4, p+off+16, 4);
    uint32_t l4 = (uint32_t)off + ihl_bytes;
    if ((dk->proto==6 || dk->proto==17) && len >= l4+4){
      dk->sport=(uint16_t)((p[l4]<<8)|p[l4+1]);
      dk->dport=(uint16_t)((p[l4+2]<<8)|p[l4+3]);
    }
    return;
  }

  if (eth==0x86DD && len >= (uint32_t)(off+40)){
    dk->v6=true; dk->proto=p[off+6];
    memcpy(dk->src.v6b, p+off+8, 16);
    memcpy(dk->dst.v6b, p+off+24, 16);
    uint32_t l4 = (uint32_t)off + 40;
    if ((dk->proto==6 || dk->proto==17) && len >= l4+4){
      dk->sport=(uint16_t)((p[l4]<<8)|p[l4+1]);
      dk->dport=(uint16_t)((p[l4+2]<<8)|p[l4+3]);
    }
  }
}

/* ---------- Single receive-all RX ---------- */
static NtNetStreamRx_t g_rx = NULL;       // <-- defined here only (fixes duplicate)
static atomic_int g_banner_done = 0;

/* Helpers to insert/match */
typedef enum { INS_OK=0 } ins_res_t;

static inline void pend_insert_first(uint64_t key, uint64_t ts, side_t side,
                                     const uint8_t* l2, uint32_t caplen){
  uint32_t idx = khash64(key) & PEND_MASK;
  int32_t ins_slot = -1;
  for (uint32_t i=0;i<=PEND_MASK;i++){
    uint32_t j = (idx + i) & PEND_MASK;
    uint64_t cur = atomic_load(&PEND[j].key64);
    if (cur == PEND_FREE || cur == PEND_TOMB){
      if (ins_slot < 0) ins_slot = (int32_t)j;
      if (cur == PEND_FREE) break;
      continue;
    }
    if (cur == key) return; // someone else inserted
  }
  if (ins_slot >= 0){
    uint64_t expect = atomic_load(&PEND[ins_slot].key64);
    if (expect == PEND_FREE || expect == PEND_TOMB){
      if (atomic_compare_exchange_strong(&PEND[ins_slot].key64, &expect, key)){
        atomic_store(&PEND[ins_slot].ts_ns, ts);
        atomic_store(&PEND[ins_slot].side, (uint8_t)side);
        if (side == SIDE_ING){
          uint32_t si = slab_acquire();
          uint32_t copy = caplen < g.snaplen ? caplen : g.snaplen;
          memcpy(slab_ptr(si), l2, copy);
          PEND[ins_slot].slab_idx = si;
          PEND[ins_slot].caplen   = (uint16_t)copy;
        } else {
          PEND[ins_slot].slab_idx = 0;
          PEND[ins_slot].caplen   = 0;
        }
        atomic_fetch_add(&g_pend_live, 1);
      }
    }
  }
}

static inline void process_ingress(uint64_t key, uint64_t ts,
                                   const uint8_t* l2, uint32_t caplen){
  atomic_fetch_add(&g_seen_ing, 1);
  uint64_t curI = atomic_load_explicit(&g_now_ing_ns, memory_order_relaxed);
  if (ts > curI) atomic_store_explicit(&g_now_ing_ns, ts, memory_order_relaxed);

  uint32_t idx = khash64(key) & PEND_MASK;
  for (uint32_t i=0;i<=PEND_MASK;i++){
    uint32_t j = (idx + i) & PEND_MASK;
    uint64_t cur = atomic_load(&PEND[j].key64);
    if (cur == PEND_FREE) break;
    if (cur == key){
      side_t s = (side_t)atomic_load(&PEND[j].side);
      if (s == SIDE_EGR){
        atomic_exchange(&PEND[j].key64, PEND_TOMB);
        atomic_fetch_sub(&g_pend_live, 1);
        atomic_fetch_add(&g_matched_oo, 1);
        return;
      } else {
        atomic_store(&PEND[j].ts_ns, ts);
        uint32_t si = slab_acquire();
        uint32_t copy = caplen < g.snaplen ? caplen : g.snaplen;
        memcpy(slab_ptr(si), l2, copy);
        PEND[j].slab_idx = si; PEND[j].caplen = (uint16_t)copy;
        return;
      }
    }
  }
  pend_insert_first(key, ts, SIDE_ING, l2, caplen);
}

static inline void process_egress(uint64_t key, uint64_t ts){
  atomic_fetch_add(&g_seen_egr, 1);
  uint64_t curE = atomic_load_explicit(&g_now_egr_ns, memory_order_relaxed);
  if (ts > curE) atomic_store_explicit(&g_now_egr_ns, ts, memory_order_relaxed);

  uint32_t idx = khash64(key) & PEND_MASK;
  for (uint32_t i=0;i<=PEND_MASK;i++){
    uint32_t j = (idx + i) & PEND_MASK;
    uint64_t cur = atomic_load(&PEND[j].key64);
    if (cur == PEND_FREE) break;
    if (cur == key){
      side_t s = (side_t)atomic_load(&PEND[j].side);
      if (s == SIDE_ING){
        atomic_exchange(&PEND[j].key64, PEND_TOMB);
        atomic_fetch_sub(&g_pend_live, 1);
        return;
      } else {
        atomic_store(&PEND[j].ts_ns, ts);
        return;
      }
    }
  }
  pend_insert_first(key, ts, SIDE_EGR, NULL, 0);
}

static void* rx_loop(void* arg){
  (void)arg;
  while (1){
    NtNetBuf_t nb=NULL;
    if (NT_SUCCESS != NT_NetRxGet(g_rx, &nb, 1000)) continue;

    if (atomic_load(&g_banner_done) == 0){
      int dtype = NT_NET_GET_PKT_DESCRIPTOR_TYPE(nb);
      int dfmt  = _NT_NET_GET_PKT_DESCR_FORMAT_DYN(nb);  // 4 == DYN4
      NtDyn4Descr_t* dtmp = _NT_NET_GET_PKT_DESCR_PTR_DYN4(nb);
      uint64_t ts_raw = dtmp->timestamp;
      uint64_t ts_ns  = ts_raw * TS_PKT_MULT;
      if (!g.quiet){
        printf("[banner] first packet: descType=%d (2==Dynamic) dynFmt=%d (4==DYN4)\n", dtype, dfmt);
        printf("[banner] rxPort=%u color0=0x%02x color1=0x%016" PRIx64 "\n",
               dtmp->rxPort, dtmp->color0, dtmp->color1);
        printf("[banner] ts_raw=%" PRIu64 " ticks  TS_PKT_MULT=%llu  -> ts_ns=%" PRIu64 " ns\n",
               ts_raw, (unsigned long long)TS_PKT_MULT, ts_ns);
        printf("[banner] ports: ingress=%u egress=%u  (color marks: 0x01=ing, 0x02=egr)\n",
               g.port_ing, g.port_egr);
        fflush(stdout);
      }
      atomic_store(&g_banner_done, 1);
    }

    NtDyn4Descr_t* d = _NT_NET_GET_PKT_DESCR_PTR_DYN4(nb);
    uint8_t*  l2     = (uint8_t*)NT_NET_GET_PKT_L2_PTR(nb);
    uint32_t  caplen = NT_NET_GET_PKT_CAP_LENGTH(nb);
    uint64_t  ts     = d->timestamp * TS_PKT_MULT;
    uint64_t  key    = d->color1;
    uint8_t   c0     = d->color0;

    bool is_ing = (c0 & 0x01) != 0;
    bool is_egr = (c0 & 0x02) != 0;

    if (!is_ing && !is_egr){
      uint8_t rp = d->rxPort;
      if (rp == g.port_ing) is_ing = true;
      else if (rp == g.port_egr) is_egr = true;
    }

    if (is_ing && !is_egr)      process_ingress(key, ts, l2, caplen);
    else if (is_egr && !is_ing) process_egress(key, ts);

    NT_NetRxRelease(g_rx, nb);
  }
  return NULL;
}

/* ---------- Expirer (compare against the *other* side’s watermark) ---------- */
static void* expirer_thread(void* arg){
  (void)arg;
  const uint64_t win_ns = (uint64_t)g.win_us * 1000ULL;
  uint64_t cursor = 0;

  while (1){
    uint64_t now_ing = atomic_load_explicit(&g_now_ing_ns, memory_order_relaxed);
    uint64_t now_egr = atomic_load_explicit(&g_now_egr_ns, memory_order_relaxed);
    if (!now_ing && !now_egr) { usleep(1000); continue; }

    for (uint32_t k=0;k<65536; k++){
      uint64_t i = (cursor++) & PEND_MASK;

      uint64_t key = atomic_load(&PEND[i].key64);
      if (key==PEND_FREE || key==PEND_TOMB) continue;

      uint64_t ts = atomic_load(&PEND[i].ts_ns);
      uint8_t  sd = atomic_load(&PEND[i].side);

      if (sd == SIDE_ING){
        if (!now_egr || (now_egr - ts) <= win_ns) continue;  // egress hasn’t advanced enough
        uint8_t* snap = slab_ptr(PEND[i].slab_idx);
        uint16_t cap  = PEND[i].caplen;

        drop_key_t dk; parse_vlan_ip_l4(snap, cap, &dk);
        pcap_write(snap, cap, ts);
        if (!g.quiet){
          char sip[INET6_ADDRSTRLEN] = "-", dip[INET6_ADDRSTRLEN] = "-";
          const char* pstr = (dk.proto==6) ? "TCP" : (dk.proto==17) ? "UDP" : "-";
          if (dk.v6){
            inet_ntop(AF_INET6, dk.src.v6b, sip, sizeof sip);
            inet_ntop(AF_INET6, dk.dst.v6b, dip, sizeof dip);
          } else {
            if (dk.src.v4){ struct in_addr a; a.s_addr = dk.src.v4; inet_ntop(AF_INET,&a,sip,sizeof sip); }
            if (dk.dst.v4){ struct in_addr a; a.s_addr = dk.dst.v4; inet_ntop(AF_INET,&a,dip,sizeof dip); }
          }
          printf("[drop] ts=%" PRIu64 "ns s=%u c=%u %s %s:%u -> %s:%u cap=%u key=0x%016" PRIx64 "\n",
                 ts, dk.s, dk.c, pstr, sip, (unsigned)dk.sport, dip, (unsigned)dk.dport,
                 (unsigned)cap, key);
          fflush(stdout);
        }
        atomic_exchange(&PEND[i].key64, PEND_TOMB);
        atomic_fetch_sub(&g_pend_live, 1);
        atomic_fetch_add(&g_drops_written, 1);
        atomic_fetch_add(&g_expired, 1);
      } else if (sd == SIDE_EGR){
        if (!now_ing || (now_ing - ts) <= win_ns) continue;  // ingress hasn’t advanced enough
        atomic_exchange(&PEND[i].key64, PEND_TOMB);
        atomic_fetch_sub(&g_pend_live, 1);
        atomic_fetch_add(&g_expired, 1);
      }
    }
    usleep(1000);
  }
  return NULL;
}

/* ---------- 30s CSV reporter ---------- */
static void* reporter_thread(void* arg){
  (void)arg;
  while (1){
    sleep(30);
    const char* path = g.state_path ? g.state_path : "/dev/shm/nt_drop_state.csv";
    FILE* f = fopen(path, "w");
    if (f){
      struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
      fprintf(f, "ts,ingress_seen,egress_seen,pend_live,expired,drops_written\n");
      fprintf(f, "%lld.%09ld,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
              (long long)ts.tv_sec, ts.tv_nsec,
              atomic_load(&g_seen_ing), atomic_load(&g_seen_egr),
              atomic_load(&g_pend_live), atomic_load(&g_expired),
              atomic_load(&g_drops_written));
      fclose(f);
    }
    if (!g.quiet){
      printf("[state] ing=%" PRIu64 " egr=%" PRIu64 " pend=%" PRIu64 " exp=%" PRIu64 " drops=%" PRIu64 "\n",
             atomic_load(&g_seen_ing), atomic_load(&g_seen_egr),
             atomic_load(&g_pend_live), atomic_load(&g_expired),
             atomic_load(&g_drops_written));
      fflush(stdout);
    }
  }
  return NULL;
}

/* ---------- CLI & main ---------- */
static void parse_args(int argc, char** argv){
  g.adapter=0; g.port_ing=0; g.port_egr=1;
  g.win_us=200; g.snaplen=128;
  g.pcap_path="/dev/shm/drops.pcap"; g.state_path="/dev/shm/nt_drop_state.csv";
  g.pend_pow=20; g.quiet=0;
  for (int i=1;i<argc;i++){
    if      (!strncmp(argv[i],"--adapter=",10))      g.adapter = atoi(argv[i]+10);
    else if (!strncmp(argv[i],"--ingress_port=",15)) g.port_ing = (uint8_t)atoi(argv[i]+15);
    else if (!strncmp(argv[i],"--egress_port=",14))  g.port_egr = (uint8_t)atoi(argv[i]+14);
    else if (!strncmp(argv[i],"--win_us=",9))        g.win_us  = (uint32_t)atoi(argv[i]+9);
    else if (!strncmp(argv[i],"--snaplen=",10))      g.snaplen = (uint32_t)atoi(argv[i]+10);
    else if (!strncmp(argv[i],"--pcap=",7))          g.pcap_path = argv[i]+7;
    else if (!strncmp(argv[i],"--state=",8))         g.state_path = argv[i]+8;
    else if (!strncmp(argv[i],"--pend_pow=",11))     g.pend_pow = atoi(argv[i]+11);
    else if (!strcmp(argv[i],"--quiet"))             g.quiet = 1;
    else { fprintf(stderr,"unknown arg: %s\n", argv[i]); exit(1); }
  }
  if (g.pend_pow < 10){ fprintf(stderr,"pend_pow too small (min 10)\n"); exit(1); }
}

static void die_nt(const char* where, int st){
  char b[NT_ERRBUF_SIZE]; NT_ExplainError(st,b,sizeof b);
  fprintf(stderr,"%s failed: %s (0x%08X)\n", where, b, st); exit(1);
}

int main(int argc, char** argv){
  parse_args(argc, argv);

  int st = NT_Init(NTAPI_VERSION);
  if (st != NT_SUCCESS) die_nt("NT_Init", st);

  size_t pend_sz = 1ull << g.pend_pow;
  PEND = (pend_t*)calloc(pend_sz, sizeof(pend_t));
  if (!PEND){ fprintf(stderr,"PEND alloc failed\n"); exit(1); }
  PEND_MASK = pend_sz - 1;

  uint32_t stride = (g.snaplen + 63u) & ~63u;
  slab_init((uint32_t)pend_sz, stride);

  // ONE receive-all stream; demux in software using color0 (and fallback rxPort)
  st = NT_NetRxOpen(&g_rx, "rx-all", NT_NET_INTERFACE_PACKET, g.adapter, -1);
  if (st!=NT_SUCCESS) die_nt("NT_NetRxOpen", st);

  pcap_open_writer(g.pcap_path, g.snaplen);

  pthread_t t_rx, t_exp, t_rep;
  pthread_create(&t_rx,  NULL, rx_loop,        NULL);
  pthread_create(&t_exp, NULL, expirer_thread, NULL);
  pthread_create(&t_rep, NULL, reporter_thread, NULL);

  if (!g.quiet){
    printf("cfg: adapter=%d (receive-all) ports: ing=%u egr=%u win_us=%u snaplen=%u pend=2^%d\n",
           g.adapter, g.port_ing, g.port_egr, g.win_us, g.snaplen, g.pend_pow);
    printf("pcap=%s state=%s\n", g.pcap_path, g.state_path);
    fflush(stdout);
  }

  pthread_join(t_rx,  NULL);
  pthread_join(t_exp, NULL);
  pthread_join(t_rep, NULL);

  NT_NetRxClose(g_rx);
  if (p_dump) { pcap_dump_close(p_dump); p_dump=NULL; }
  if (p_dead) { pcap_close(p_dead); p_dead=NULL; }
  NT_Done();
  return 0;
}
