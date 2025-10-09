/*
 * nt_drop_reader.c — HW-marked dedup drop detector (single merged stream)
 * - NTPL merges ingress+egress taps into one host stream (DYN3 descriptor)
 * - Napatech hardware dedup marks the second copy via configurable colorbit
 * - First copy ⇒ stash (hash key, timestamp, snaplen-capped copy, ingress port)
 * - Duplicate copy (colorbit set) ⇒ remove pending entry; nothing logged
 * - Pending entries that age past win_us (default 5 µs) ⇒ log + dump to PCAP
 * - Parse VLAN/IP/L4 only on expiry for logging
 * - Periodic CSV state dump for Grafana (every 30s); --quiet to suppress stdout
 * - Write drops to tmpfs (/dev/shm/drops.pcap) by default; snaplen default 128
 *
 * HW requirements:
 *   - ntservice.ini: DeduplicationWindow >= 10 (µs) for the adapter
 *   - NTPL: DYN3 stream, DeduplicationConfig with Colorbit marking duplicates
 *
 * Build:
 *   gcc -O2 -Wall -I/opt/napatech3/include -I/opt/napatech3/include/ntapi \
 *       -L/opt/napatech3/lib -Wl,-rpath,/opt/napatech3/lib \
 *       nt_drop_reader.c -lntapi -lpcap -lpthread -o nt_drop_reader
 *
 * Example run:
 *   sudo ./nt_drop_reader --adapter=0 --sid=0 --dup_bit=7 \
 *        --win_us=5 --snaplen=128 --pcap=/dev/shm/drops.pcap \
 *        --state=/dev/shm/nt_drop_state.csv --pend_pow=20 --quiet
 *
 * Required NTPL (example ports 28/29):
 *   Setup[Descriptor=Dyn3] = StreamId == 0
 *   DeduplicationConfig[Colorbit=7] = GroupID == 100
 *   Define ckFull = CorrelationKey(Begin=StartOfFrame[0], End=EndOfFrame[0], DeduplicationGroupID=100)
 *   Assign[StreamId=0; CorrelationKey=ckFull] = (Port == 28) OR (Port == 29)
 */

#define _GNU_SOURCE
#include <nt.h>
#include <ntapi/pktdescr_dyn3.h>
#include <ntapi/pktdescr.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
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

// ---------- Config ----------
typedef struct {
  int adapter;
  int sid;
  uint32_t win_us;           // small expiry window (us)
  uint32_t snaplen;          // bytes saved for drops
  const char* pcap_path;     // drop PCAP (tmpfs default)
  const char* state_path;    // CSV for Grafana
  int pend_pow;              // pending table size = 2^pend_pow
  int quiet;                 // --quiet suppresses stdout
  int debug;                 // --debug=N for occasional prints
  int dup_bit;               // HW color bit marking duplicate packet
} cfg_t;

// Portable nanosecond clock helper (used by expirer thread)
static inline uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void die_nt(const char* where, int st){
  char b[NT_ERRBUF_SIZE]; NT_ExplainError(st,b,sizeof b);
  fprintf(stderr,"%s failed: %s (0x%08X)\n", where, b, st); exit(1);
}

// ---------- Globals / metrics ----------
static cfg_t g;
static atomic_uint_fast64_t g_seen_first = 0, g_seen_dup = 0;
static atomic_uint_fast64_t g_expired  = 0, g_drops_written = 0;
static atomic_uint_fast64_t g_pend_live = 0;

// ---------- Pending table (lock-free open addressing, no malloc) ----------
typedef struct {
  atomic_uint_fast64_t key64;   // 0 = free; fingerprint of first copy
  atomic_uint_fast64_t ts_ns;   // ingress timestamp (ns); 0 means entry not ready yet
  uint32_t slab_idx;            // index in slab ring holding snapshot
  uint32_t cap_len;             // snaplen used for copy (<= g.snaplen)
  uint32_t wire_len;            // original wire length for PCAP header
  uint16_t rx_port;             // port id of first copy
} pend_t;

static pend_t* PEND = NULL;
static uint64_t PEND_MASK = 0;

static inline uint32_t khash64(uint64_t k){
  // Good 64-bit mix (Murmur-like)
  k ^= k >> 33; k *= 0xff51afd7ed558ccdULL; k ^= k >> 33; k *= 0xc4ceb9fe1a85ec53ULL; k ^= k >> 33;
  return (uint32_t)k;
}

// ---------- Slab (preallocated fixed-size buffers; no malloc on hot path) ----------
typedef struct { uint8_t* base; uint32_t stride; uint32_t cap; atomic_uint_fast32_t head; } slab_t;
static slab_t SLAB;

static void slab_init(uint32_t slots, uint32_t stride){
  SLAB.base = (uint8_t*)aligned_alloc(64, (size_t)slots * stride);
  if (!SLAB.base){ fprintf(stderr,"slab alloc failed\n"); exit(1); }
  SLAB.stride = stride;
  SLAB.cap = slots;
  atomic_store(&SLAB.head, 0);
}
static inline uint32_t slab_acquire(void){
  // Very simple ring index; reuses buffers when ring wraps
  return atomic_fetch_add(&SLAB.head, 1) & (SLAB.cap - 1);
}
static inline uint8_t* slab_ptr(uint32_t idx){ return SLAB.base + (size_t)idx * SLAB.stride; }

// ---------- PCAP (done in expirer thread to keep RX hot) ----------
static pcap_t* p_dead = NULL; static pcap_dumper_t* p_dump = NULL;
static void pcap_open_writer(const char* path, uint32_t dltSnap){
  p_dead = pcap_open_dead(DLT_EN10MB, dltSnap);
  if (!p_dead){ fprintf(stderr,"pcap_open_dead failed\n"); exit(1); }
  p_dump = pcap_dump_open(p_dead, path);
  if (!p_dump){ fprintf(stderr,"pcap_dump_open failed: %s\n", pcap_geterr(p_dead)); exit(1); }
  if (!g.quiet) printf("Writing drops to PCAP: %s\n", path);
}
static inline void pcap_write(const uint8_t* data, uint32_t caplen, uint32_t wirelen, uint64_t ts_ns){
  struct pcap_pkthdr h; memset(&h,0,sizeof h);
  h.caplen = caplen;
  h.len = wirelen ? wirelen : caplen;
  h.ts.tv_sec  = (time_t)(ts_ns / 1000000000ULL);
  h.ts.tv_usec = (suseconds_t)((ts_ns % 1000000000ULL) / 1000ULL);
  pcap_dump((u_char*)p_dump, &h, data);
  pcap_dump_flush(p_dump);
}

// ---------- Minimal VLAN/IP parser (used only on expiry) ----------
typedef struct {
  bool v6;
  bool has_ports;
  uint8_t proto;
  uint16_t s_vlan;
  uint16_t c_vlan;
  uint16_t sport;
  uint16_t dport;
  union { uint32_t v4; uint8_t v6[16]; } src;
  union { uint32_t v4; uint8_t v6[16]; } dst;
} drop_meta_t;

static void log_drop(uint64_t ts_ns, uint64_t key, const drop_meta_t* dm);

static void parse_drop_meta(const uint8_t* l2, uint32_t len, drop_meta_t* dm){
  memset(dm, 0, sizeof *dm);
  if (len < 14) return;

  const uint8_t* p = l2;
  size_t offset = 14;
  uint16_t eth = ((uint16_t)p[12] << 8) | p[13];

  for (int i = 0; i < 2; ++i) {
    if (eth == 0x88A8 || eth == 0x8100) {
      if (len < offset + 4) break;
      uint16_t tci = ((uint16_t)p[offset] << 8) | p[offset + 1];
      uint16_t vid = tci & 0x0FFF;
      if (eth == 0x88A8 && dm->s_vlan == 0)
        dm->s_vlan = vid;
      else if (dm->c_vlan == 0)
        dm->c_vlan = vid;
      eth = ((uint16_t)p[offset + 2] << 8) | p[offset + 3];
      offset += 4;
    } else {
      break;
    }
  }

  if (eth == 0x0800) {  // IPv4
    if (len < offset + 20) return;
    uint8_t ihl = p[offset] & 0x0F;
    size_t ip_hdr = (size_t)ihl * 4;
    if (ip_hdr < 20 || len < offset + ip_hdr) return;
    dm->v6 = false;
    dm->proto = p[offset + 9];
    memcpy(&dm->src.v4, p + offset + 12, 4);
    memcpy(&dm->dst.v4, p + offset + 16, 4);
    size_t l4 = offset + ip_hdr;
    if ((dm->proto == IPPROTO_TCP || dm->proto == IPPROTO_UDP) && len >= l4 + 4) {
      dm->sport = ((uint16_t)p[l4] << 8) | p[l4 + 1];
      dm->dport = ((uint16_t)p[l4 + 2] << 8) | p[l4 + 3];
      dm->has_ports = true;
    }
  } else if (eth == 0x86DD) {  // IPv6
    if (len < offset + 40) return;
    dm->v6 = true;
    dm->proto = p[offset + 6];
    memcpy(dm->src.v6, p + offset + 8, 16);
    memcpy(dm->dst.v6, p + offset + 24, 16);
    size_t l4 = offset + 40;
    if ((dm->proto == IPPROTO_TCP || dm->proto == IPPROTO_UDP) && len >= l4 + 4) {
      dm->sport = ((uint16_t)p[l4] << 8) | p[l4 + 1];
      dm->dport = ((uint16_t)p[l4 + 2] << 8) | p[l4 + 3];
      dm->has_ports = true;
    }
  }
}

// ---------- RX threads ----------
typedef struct { NtNetStreamRx_t rx; int is_ingress; } rx_arg_t;

static void* rx_loop(void* arg){
  rx_arg_t* A = (rx_arg_t*)arg;
  while (1){
    NtNetBuf_t nb=NULL;
    if (NT_SUCCESS != NT_NetRxGet(A->rx, &nb, 1000)) continue;

    // DYN4 fast-path fields
    NtDyn4Descr_t* d = _NT_NET_GET_PKT_DESCR_PTR_DYN4(nb);
    uint8_t* l2 = (uint8_t*)NT_NET_GET_PKT_L2_PTR(nb);
    uint32_t cap = NT_NET_GET_PKT_CAP_LENGTH(nb);
    uint32_t wire = NT_NET_GET_PKT_WIRE_LENGTH(nb);
    uint64_t ts  = d->timestamp;
    uint64_t key = d->color1;                // HW correlation key

    if (A->is_ingress){
      atomic_fetch_add(&g_seen_ing, 1);

      // Insert into pending (CAS), copy to slab (no malloc)
      uint32_t idx = khash64(key) & PEND_MASK;
      for (uint32_t i=0;i<=PEND_MASK;i++){
        uint32_t j = (idx + i) & PEND_MASK;
        uint64_t expect = 0;
        if (atomic_compare_exchange_weak(&PEND[j].key64, &expect, key)){
          uint32_t si = slab_acquire();
          uint32_t copy = cap < g.snaplen ? cap : g.snaplen;
          if (wire < copy) wire = copy;
          atomic_store(&PEND[j].ts_ns, 0);              // mark not-ready while we fill
          if (copy)
            memcpy(slab_ptr(si), l2, copy);
          PEND[j].slab_idx = si;
          PEND[j].cap_len = copy;
          PEND[j].wire_len = wire;
          atomic_store(&PEND[j].ts_ns, ts);
          atomic_fetch_add(&g_pend_live, 1);
          break;
        } else if (expect == key){
          // Duplicate ingress before egress seen; update ts (keep most recent)
          uint32_t copy = cap < g.snaplen ? cap : g.snaplen;
          if (wire < copy) wire = copy;
          uint32_t si = PEND[j].slab_idx;
          if (copy && si < SLAB.cap)
            memcpy(slab_ptr(si), l2, copy);
          PEND[j].cap_len = copy;
          PEND[j].wire_len = wire;
          atomic_store(&PEND[j].ts_ns, ts);
          break;
        }
      }
    } else {
      atomic_fetch_add(&g_seen_egr, 1);
      // Remove from pending (CAS clear)
      uint32_t idx = khash64(key) & PEND_MASK;
      for (uint32_t i=0;i<=PEND_MASK;i++){
        uint32_t j = (idx + i) & PEND_MASK;
        uint64_t cur = atomic_load(&PEND[j].key64);
        if (cur == 0) break;         // empty chain end
        if (cur == key){
          atomic_store(&PEND[j].ts_ns, 0);
          PEND[j].cap_len = 0;
          PEND[j].wire_len = 0;
          PEND[j].slab_idx = 0;
          atomic_store(&PEND[j].key64, 0);
          atomic_fetch_sub(&g_pend_live, 1);
          break;
        }
      }
    }

    NT_NetRxRelease(A->rx, nb);
  }
  return NULL;
}

// ---------- Expirer + writer (separate from RX) ----------
static void* expirer_thread(void* arg){
  (void)arg;
  const uint64_t win_ns = (uint64_t)g.win_us * 1000ULL;
  while (1){
    // Scan a slice each tick
    static uint64_t cursor = 0;
    for (uint32_t k=0;k<65536; k++){ // small slice per loop
      uint64_t i = (cursor++) & PEND_MASK;
      uint64_t key = atomic_load(&PEND[i].key64);
      if (key==0) continue;
      uint64_t ts = atomic_load(&PEND[i].ts_ns);
      if (ts == 0) continue;                // still being populated
      uint64_t now = now_ns();
      if (now <= ts || now - ts <= win_ns) continue;

      // Expired → drop: parse from slab, write pcap, clear entry
      uint32_t cap_len = PEND[i].cap_len;
      if (cap_len == 0 || cap_len > g.snaplen) cap_len = g.snaplen;
      uint8_t* snap = slab_ptr(PEND[i].slab_idx);
      drop_meta_t meta; parse_drop_meta(snap, cap_len, &meta);
      pcap_write(snap, cap_len, PEND[i].wire_len, ts);
      log_drop(ts, key, &meta);
      atomic_fetch_add(&g_drops_written, 1);
      atomic_fetch_add(&g_expired, 1);
      atomic_store(&PEND[i].ts_ns, 0);
      PEND[i].cap_len = 0;
      PEND[i].wire_len = 0;
      PEND[i].slab_idx = 0;
      atomic_store(&PEND[i].key64, 0);
      atomic_fetch_sub(&g_pend_live, 1);
    }
    // Sleep a touch; RX threads stay hot
    usleep(1000);
  }
  return NULL;
}

// ---------- 30s CSV state writer (Grafana) ----------
static void* reporter_thread(void* arg){
  (void)arg;
  while (1){
    sleep(30);
    FILE* f = fopen(g.state_path ? g.state_path : "/dev/shm/nt_drop_state.csv", "w");
    if (f){
      // timestamp,ingress_seen,egress_seen,pend_live,expired,drops_written
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
    }
  }
  return NULL;
}

// ---------- Helpers ----------
static void parse_args(int argc, char** argv){
  // Defaults (as requested)
  g.adapter=0; g.sid_ing=0; g.sid_egr=1; g.win_us=5; g.snaplen=128;
  g.pcap_path="/dev/shm/drops.pcap"; g.state_path="/dev/shm/nt_drop_state.csv";
  g.pend_pow=20; g.quiet=0; g.debug=0;
  for (int i=1;i<argc;i++){
    if      (!strncmp(argv[i],"--adapter=",10))   g.adapter = atoi(argv[i]+10);
    else if (!strncmp(argv[i],"--ingress_sid=",14)) g.sid_ing = atoi(argv[i]+14);
    else if (!strncmp(argv[i],"--egress_sid=",13))  g.sid_egr = atoi(argv[i]+13);
    else if (!strncmp(argv[i],"--win_us=",9))    g.win_us = (uint32_t)atoi(argv[i]+9);
    else if (!strncmp(argv[i],"--snaplen=",10))  g.snaplen = (uint32_t)atoi(argv[i]+10);
    else if (!strncmp(argv[i],"--pcap=",7))      g.pcap_path = argv[i]+7;
    else if (!strncmp(argv[i],"--state=",8))     g.state_path = argv[i]+8;
    else if (!strncmp(argv[i],"--pend_pow=",11)) g.pend_pow = atoi(argv[i]+11);
    else if (!strcmp(argv[i],"--quiet"))         g.quiet = 1;
    else if (!strncmp(argv[i],"--debug=",8))     g.debug = atoi(argv[i]+8);
    else { fprintf(stderr,"unknown arg: %s\n", argv[i]); exit(1); }
  }
  if ((g.sid_ing==g.sid_egr)){ fprintf(stderr,"ingress_sid must differ from egress_sid\n"); exit(1); }
  if ((1u<<g.pend_pow) == 0 || g.pend_pow<10){ fprintf(stderr,"pend_pow too small\n"); exit(1); }
}

int main(int argc, char** argv){
  parse_args(argc, argv);

  // Init NTAPI
  int st = NT_Init(NTAPI_VERSION);
  if (st != NT_SUCCESS) die_nt("NT_Init", st);

  // Allocate pending table (power of two) & slab (no malloc on hot path)
  size_t pend_sz = 1ull << g.pend_pow;
  PEND = (pend_t*)calloc(pend_sz, sizeof(pend_t));
  if (!PEND){ fprintf(stderr,"PEND alloc failed\n"); exit(1); }
  PEND_MASK = pend_sz - 1;

  // Slab: same number of slots as pending; stride = snaplen (aligned)
  uint32_t stride = (g.snaplen + 63u) & ~63u;
  slab_init((uint32_t)pend_sz, stride);

  // Open two RX streams (one per SID) — no gating; start immediately
  NtNetStreamRx_t rx_ing=NULL, rx_egr=NULL;
  st = NT_NetRxOpen(&rx_ing, "ing", NT_NET_INTERFACE_PACKET, g.adapter, g.sid_ing);
  if (st!=NT_SUCCESS) die_nt("NT_NetRxOpen ingress", st);
  st = NT_NetRxOpen(&rx_egr, "egr", NT_NET_INTERFACE_PACKET, g.adapter, g.sid_egr);
  if (st!=NT_SUCCESS) die_nt("NT_NetRxOpen egress", st);

  // PCAP writer in tmpfs
  pcap_open_writer(g.pcap_path, g.snaplen);

  // Start threads
  pthread_t t_ing, t_egr, t_exp, t_rep;
  rx_arg_t A = { .rx = rx_ing, .is_ingress = 1 };
  rx_arg_t B = { .rx = rx_egr, .is_ingress = 0 };
  pthread_create(&t_ing, NULL, rx_loop, &A);
  pthread_create(&t_egr, NULL, rx_loop, &B);
  pthread_create(&t_exp, NULL, expirer_thread, NULL);
  pthread_create(&t_rep, NULL, reporter_thread, NULL);

  if (!g.quiet){
    printf("cfg: adapter=%d sid_ing=%d sid_egr=%d win_us=%u snaplen=%u pend=2^%d pcap=%s state=%s\n",
           g.adapter, g.sid_ing, g.sid_egr, g.win_us, g.snaplen, g.pend_pow, g.pcap_path, g.state_path);
  }

  // Stay alive
  pthread_join(t_ing, NULL);
  pthread_join(t_egr, NULL);
  pthread_join(t_exp, NULL);
  pthread_join(t_rep, NULL);

  // Cleanup (normally not reached)
  NT_NetRxClose(rx_ing); NT_NetRxClose(rx_egr);
  if (p_dump) { pcap_dump_close(p_dump); p_dump=NULL; }
  if (p_dead) { pcap_close(p_dead); p_dead=NULL; }
  NT_Done();
  return 0;
}
static const char* proto_to_str(uint8_t proto){
  switch (proto){
    case IPPROTO_TCP:   return "TCP";
    case IPPROTO_UDP:   return "UDP";
    case IPPROTO_ICMP:  return "ICMP";
#ifdef IPPROTO_ICMPV6
    case IPPROTO_ICMPV6:return "ICMPv6";
#endif
    default:            return NULL;
  }
}

static void log_drop(uint64_t ts_ns, uint64_t key, const drop_meta_t* dm){
  uint64_t sec = ts_ns / 1000000000ULL;
  uint64_t nsec = ts_ns % 1000000000ULL;

  char srcbuf[INET6_ADDRSTRLEN] = "?";
  char dstbuf[INET6_ADDRSTRLEN] = "?";

  if (dm->v6){
    inet_ntop(AF_INET6, dm->src.v6, srcbuf, sizeof srcbuf);
    inet_ntop(AF_INET6, dm->dst.v6, dstbuf, sizeof dstbuf);
  } else {
    struct in_addr a4;
    a4.s_addr = dm->src.v4;
    inet_ntop(AF_INET, &a4, srcbuf, sizeof srcbuf);
    a4.s_addr = dm->dst.v4;
    inet_ntop(AF_INET, &a4, dstbuf, sizeof dstbuf);
  }

  const char* pname = proto_to_str(dm->proto);
  if (!pname) pname = "proto";

  if (dm->has_ports)
    printf("drop ts=%" PRIu64 ".%09" PRIu64 " key=0x%016" PRIx64
           " svlan=%u cvlan=%u %s:%u -> %s:%u %s(%u)\n",
           sec, nsec, key, dm->s_vlan, dm->c_vlan,
           srcbuf, dm->sport, dstbuf, dm->dport, pname, dm->proto);
  else
    printf("drop ts=%" PRIu64 ".%09" PRIu64 " key=0x%016" PRIx64
           " svlan=%u cvlan=%u %s -> %s %s(%u)\n",
           sec, nsec, key, dm->s_vlan, dm->c_vlan,
           srcbuf, dstbuf, pname, dm->proto);

  fflush(stdout);
}
