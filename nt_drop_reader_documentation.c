/*
 * nt_drop_reader.c — High-speed HW-correlation drop detector for Napatech SmartNIC (Napatech SW 12.4)
 *
 * OVERVIEW
 * ========
 * Goal: Detect when packets seen on an "ingress" stream do not appear on an "egress" stream within a very
 * small time window (default 5 µs), and:
 *   - Write a snaplen-capped copy of the dropped packet into a PCAP (for post-mortem).
 *   - Emit a tiny, single-line log describing the drop (VLAN S/C, IPs, ports, proto, ts, correlation key).
 *   - Maintain lightweight counters, plus a 30s CSV state dump for dashboards.
 *
 * Throughput & Technique:
 *   - We open two RX streams (SIDs): one bound to Port 0 (ingress), one to Port 1 (egress).
 *   - Hardware computes a "correlation key" per packet via NTPL CorrelationKey(); we read it from DYN4.color1.
 *   - Ingress RX path inserts the key into a lock-free open-addressing hash table (the "pending" table)
 *     and copies a snaplen of the packet into a preallocated slab (no malloc/free on the hot path).
 *   - Egress RX path removes a matching key (if present), indicating the packet was forwarded.
 *   - A separate "expirer" thread scans the table. If an entry's timestamp ages beyond the window, we treat
 *     it as a "drop": emit a log line, write the snapshot to PCAP, and tombstone the slot.
 *
 * Concurrency & Safety:
 *   - Lock-free table using C11 atomics. Inserts use CAS on the key slot; deletions/tombstones avoid ABA by
 *     never reusing the pointer/slot identity (the key value is the identity).
 *   - Correctness under open addressing requires that we don't prematurely stop a probe chain when encountering
 *     a previously occupied slot that has since been cleared. We use "tombstone" markers for that.
 *   - Publish/consume ordering: Ingress publishes fields (slab_idx, caplen, ts_ns) before the expirer uses them.
 *     We store ts last and check `ts_ns != 0` in the expirer to avoid tearing/early reads.
 *   - Timers use CLOCK_MONOTONIC for stability (NTP jumps won't confuse expiry checks).
 *
 * NTPL (12.4) REQUIRED
 * ====================
 *   Delete = All
 *   Define ckL3 = CorrelationKey(Begin=Layer3Header[0], End=Layer3PayloadEnd[0], DeduplicationGroupID=0)
 *   Assign[StreamId=0; Descriptor=DYN4; CorrelationKey=ckL3] = Port == 0   # ingress
 *   Assign[StreamId=1; Descriptor=DYN4; CorrelationKey=ckL3] = Port == 1   # egress
 *
 * With this, Napatech hardware populates DYN4.color1 with a flow-stable correlation hash derived from the
 * L3 header/payload region you specified. The program uses that as the pending-table key.
 *
 * BUILD
 * =====
 *   gcc -O2 -Wall -Wextra -std=gnu11 \
 *       -I/opt/napatech3/include -I/opt/napatech3/include/ntapi \
 *       -L/opt/napatech3/lib -Wl,-rpath,/opt/napatech3/lib \
 *       nt_drop_reader.c -lntapi -lpcap -pthread -o nt_drop_reader
 *
 * RUN (example)
 * =============
 *   sudo ./nt_drop_reader --adapter=0 --ingress_sid=0 --egress_sid=1 \
 *        --win_us=5 --snaplen=128 \
 *        --pcap=/dev/shm/drops.pcap --state=/dev/shm/nt_drop_state.csv \
 *        --pend_pow=20 --quiet
 *
 * ARGUMENTS
 * =========
 *   --adapter=N         Informational only (the actual port->stream mapping is defined in NTPL)
 *   --ingress_sid=SID   Stream ID bound to Port 0 by NTPL
 *   --egress_sid=SID    Stream ID bound to Port 1 by NTPL
 *   --win_us=µs         Expiry window in microseconds (default 5)
 *   --snaplen=bytes     Bytes copied per drop to PCAP and slab (default 128)
 *   --pcap=PATH         Path to write PCAP for drops (default /dev/shm/drops.pcap)
 *   --state=PATH        Path to write 30s CSV snapshot (default /dev/shm/nt_drop_state.csv)
 *   --pend_pow=P        Pending table size is 2^P (default 20 → ~1M slots)
 *   --quiet             Suppress stdout logs (keeps PCAP & CSV writing)
 *   --debug=N           Reserved
 *
 * OUTPUT
 * ======
 *   - PCAP with snaplen-capped dropped packets (hardware timestamps).
 *   - Every 30s: CSV row with cumulative counters.
 *   - Per drop (unless --quiet): single line, e.g.:
 *     [drop] ts=175868999999999999ns s=123 c=45 UDP 10.0.0.1:53 -> 10.0.0.2:53000 cap=128 key=0x0123456789abcdef
 *
 * COMPATIBILITY NOTES
 * ===================
 *   - Verified against Napatech SW 12.4 semantics:
 *       NT_NetRxOpen(handle, name, NT_NET_INTERFACE_PACKET, streamId, hostBufferAllowance)
 *       Use hostBufferAllowance = -1 (disable HBA gating).
 *   - The adapter/port selection is **entirely** via NTPL Assign rules.
 */

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

/* Forward declarations for thread entry points */
static void* rx_loop(void* arg);
static void* expirer_thread(void* arg);
static void* reporter_thread(void* arg);

/*───────────────────────────────────────────────────────────────────────────*/
/* Configuration & global metrics                                            */
/*───────────────────────────────────────────────────────────────────────────*/

/*
 * cfg_t — Runtime configuration parsed from CLI.
 * Adapter index is informational; streams (SIDs) must match the NTPL Assign rules.
 */
typedef struct {
  int adapter;               /* informational only */
  int sid_ing;               /* ingress SID (Port 0; via NTPL) */
  int sid_egr;               /* egress  SID (Port 1; via NTPL) */
  uint32_t win_us;           /* expiry window in microseconds */
  uint32_t snaplen;          /* bytes captured/written per drop */
  const char* pcap_path;     /* PCAP path for drops */
  const char* state_path;    /* CSV path for 30s state dump */
  int pend_pow;              /* pending table size is 2^pend_pow */
  int quiet;                 /* suppress stdout if nonzero */
  int debug;                 /* reserved */
} cfg_t;

static cfg_t g;

/*
 * now_ns() — Monotonic nanosecond timer for expiry calculations.
 * Use CLOCK_MONOTONIC to avoid discontinuities when wall clock jumps (NTP).
 */
static inline uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * die_nt() — Abort with an NTAPI error explanation.
 */
static void die_nt(const char* where, int st){
  char b[NT_ERRBUF_SIZE]; NT_ExplainError(st,b,sizeof b);
  fprintf(stderr,"%s failed: %s (0x%08X)\n", where, b, st); exit(1);
}

/* Cumulative metrics, atomically updated from threads */
static atomic_uint_fast64_t g_seen_ing = 0, g_seen_egr = 0;
static atomic_uint_fast64_t g_expired  = 0, g_drops_written = 0;
static atomic_uint_fast64_t g_pend_live = 0;

/*───────────────────────────────────────────────────────────────────────────*/
/* Pending table & slab                                                      */
/*───────────────────────────────────────────────────────────────────────────*/

/*
 * We use lock-free open addressing with linear probing. Each slot stores:
 *   - key64: correlation key (DYN4.color1) (0 → empty)
 *   - ts_ns: ingress HW timestamp (0 → not yet published by writer)
 *   - slab_idx, caplen: where the snapshot bytes live
 *   - tag: EMPTY | OCC | TOMB. Tombstones are crucial to ensure that we do not
 *          prematurely stop probe chains when a previously occupied slot is cleared.
 */
enum { TAG_EMPTY=0, TAG_OCC=1, TAG_TOMB=2 };

typedef struct {
  atomic_uint_fast64_t key64;  /* 0 = empty; !=0 = occupied key */
  atomic_uint_fast64_t ts_ns;  /* 0 => not yet published */
  uint32_t slab_idx;
  uint16_t caplen;
  atomic_uchar tag;            /* TAG_EMPTY | TAG_OCC | TAG_TOMB */
} pend_t;

static pend_t* PEND = NULL;
static uint64_t PEND_MASK = 0;

/*
 * khash64() — A simple, good 64-bit mix for hashing the correlation key.
 */
static inline uint32_t khash64(uint64_t k){
  k ^= k >> 33; k *= 0xff51afd7ed558ccdULL; k ^= k >> 33; k *= 0xc4ceb9fe1a85ec53ULL; k ^= k >> 33;
  return (uint32_t)k;
}

/*
 * Slab allocator — fixed-size, aligned array of snaplen-sized buffers.
 * No malloc/free on hot path; RX just claims a slot and memcpy()s snaplen bytes.
 */
typedef struct { uint8_t* base; uint32_t stride; uint32_t cap; atomic_uint_fast32_t head; } slab_t;
static slab_t SLAB;

static void* xaligned_alloc(size_t align, size_t bytes){
  void* p=NULL;
  if (posix_memalign(&p, align, bytes)!=0) return NULL;
  return p;
}

/*
 * slab_init(slots, stride) — Allocate the slab memory.
 *  - slots: number of buffers (often equal to pending table size)
 *  - stride: per-buffer size in bytes, rounded up to cacheline alignment
 */
static void slab_init(uint32_t slots, uint32_t stride){
  SLAB.base = (uint8_t*)xaligned_alloc(64, (size_t)slots * stride);
  if (!SLAB.base){ fprintf(stderr,"slab alloc failed\n"); exit(1); }
  SLAB.stride = stride;
  SLAB.cap = slots;
  atomic_store(&SLAB.head, 0);
}

/*
 * slab_acquire() — Return the next buffer index (wraps using power-of-two mask).
 * Collision overwrite is OK: slab is only used for snapshots at drop time, and
 * any live pending entry holds its own slab_idx; overwriting another buffer will
 * not corrupt a different pending entry because we only read via that entry's slab_idx.
 */
static inline uint32_t slab_acquire(void){
  return atomic_fetch_add(&SLAB.head, 1) & (SLAB.cap - 1);
}

static inline uint8_t* slab_ptr(uint32_t idx){ return SLAB.base + (size_t)idx * SLAB.stride; }

/*───────────────────────────────────────────────────────────────────────────*/
/* PCAP output                                                               */
/*───────────────────────────────────────────────────────────────────────────*/

/*
 * We write drops from the expirer thread (off the RX hot path).
 * Timestamps written into PCAP are the Napatech hardware timestamps (ns), which
 * the Napatech service maps to epoch; ensure service time is synchronized if
 * you need wall-time alignment.
 */
static pcap_t* p_dead = NULL; static pcap_dumper_t* p_dump = NULL;

static void pcap_open_writer(const char* path, uint32_t dltSnap){
  p_dead = pcap_open_dead(DLT_EN10MB, dltSnap);
  if (!p_dead){ fprintf(stderr,"pcap_open_dead failed\n"); exit(1); }
  p_dump = pcap_dump_open(p_dead, path);
  if (!p_dump){ fprintf(stderr,"pcap_dump_open failed: %s\n", pcap_geterr(p_dead)); exit(1); }
}

static inline void pcap_write(const uint8_t* data, uint32_t caplen, uint64_t ts_ns){
  struct pcap_pkthdr h; memset(&h,0,sizeof h);
  h.caplen = caplen; h.len = caplen;
  h.ts.tv_sec  = (time_t)(ts_ns / 1000000000ULL);
  h.ts.tv_usec = (suseconds_t)((ts_ns % 1000000000ULL) / 1000ULL);
  pcap_dump((u_char*)p_dump, &h, data);
}

/*───────────────────────────────────────────────────────────────────────────*/
/* Minimal parsing (expiry-only): VLANs + IP + L4                            */
/*───────────────────────────────────────────────────────────────────────────*/

/*
 * drop_key_t — Structure holding a small subset of fields we print on drop:
 *   - VLAN S-TAG/C-TAG (if present, up to 2 VLANs, treating 0x88A8 as S-TAG)
 *   - IP version (v6 flag), L4 proto (6=TCP, 17=UDP)
 *   - Source/dest IPs and ports (if TCP/UDP and header present within snaplen)
 */
typedef struct {
  bool v6;
  uint8_t proto;            /* 6=TCP, 17=UDP, else 0 */
  uint16_t s, c;            /* S-TAG, C-TAG */
  union { uint32_t v4; uint8_t v6b[16]; } src;
  union { uint32_t v4; uint8_t v6b[16]; } dst;
  uint16_t sport, dport;    /* host byte order */
} drop_key_t;

/*
 * parse_vlan_ip_l4(l2, len, dk) — Parse a snaplen-capped L2 frame to extract:
 *   - VLANs (QinQ up to 2)
 *   - IPv4/IPv6 addresses
 *   - L4 ports for TCP/UDP (no IPv6 extension header walking; fast path only)
 *
 * Notes:
 *   - We only call this in the expirer thread (drop path) to keep RX hot.
 *   - All bounds checks use the snaplen to avoid overreads.
 */
static void parse_vlan_ip_l4(const uint8_t* l2, uint32_t len, drop_key_t* dk){
  memset(dk, 0, sizeof *dk);
  if (len < 14) return;

  const uint8_t* p = l2;
  int off = 14;
  uint16_t eth = (uint16_t)((p[12] << 8) | p[13]);

  /* VLANs (QinQ up to 2) */
  uint16_t s=0, c=0;
  for (int i=0; i<2; i++){
    if (eth==0x88A8 || eth==0x8100){
      if (len < (uint32_t)(off + 4)) break;
      uint16_t tci = (uint16_t)((p[off] << 8) | p[off+1]);
      uint16_t vid = (uint16_t)(tci & 0x0FFF);
      if (eth==0x88A8 && s==0) s=vid; else if (c==0) c=vid;
      eth = (uint16_t)((p[off+2] << 8) | p[off+3]);
      off += 4;
    } else break;
  }
  dk->s = s; dk->c = c;

  /* IPv4 */
  if (eth == 0x0800 && len >= (uint32_t)(off + 20)){
    uint8_t ihl = (uint8_t)(p[off] & 0x0F);
    uint32_t ihl_bytes = (uint32_t)ihl * 4;
    if (ihl_bytes < 20 || len < (uint32_t)(off + ihl_bytes)) return;

    dk->v6 = false;
    dk->proto = p[off + 9];
    memcpy(&dk->src.v4, p + off + 12, 4);
    memcpy(&dk->dst.v4, p + off + 16, 4);

    uint32_t l4 = (uint32_t)off + ihl_bytes;
    if ((dk->proto == 6 || dk->proto == 17) && len >= l4 + 4){
      dk->sport = (uint16_t)((p[l4] << 8) | p[l4+1]);
      dk->dport = (uint16_t)((p[l4+2] << 8) | p[l4+3]);
    }
    return;
  }

  /* IPv6 (no extension header walking) */
  if (eth == 0x86DD && len >= (uint32_t)(off + 40)){
    dk->v6 = true;
    dk->proto = p[off + 6];
    memcpy(dk->src.v6b, p + off + 8, 16);
    memcpy(dk->dst.v6b, p + off + 24, 16);

    uint32_t l4 = (uint32_t)off + 40;
    if ((dk->proto == 6 || dk->proto == 17) && len >= l4 + 4){
      dk->sport = (uint16_t)((p[l4] << 8) | p[l4+1]);
      dk->dport = (uint16_t)((p[l4+2] << 8) | p[l4+3]);
    }
    return;
  }
}

/*───────────────────────────────────────────────────────────────────────────*/
/* RX threads                                                                */
/*───────────────────────────────────────────────────────────────────────────*/

/*
 * rx_loop(arg) — RX thread body (one instance per stream).
 *
 * If is_ingress:
 *   - For each packet:
 *       key = DYN4.color1, ts = d->timestamp
 *       probe the pending table:
 *         - If empty slot found (key64==0), CAS it to our key, copy snaplen bytes to slab,
 *           populate slab_idx/caplen, then publish ts_ns last and mark TAG_OCC.
 *         - If same key found (in-order duplicate on ingress before egress), update ts_ns.
 *       bump g_seen_ing and g_pend_live (for new inserts).
 *
 * If egress:
 *   - For each packet:
 *       key = DYN4.color1
 *       probe the pending table:
 *         - If key found, mark TAG_TOMB, clear key64 (slot reusable later), decrement g_pend_live.
 *         - If we hit a truly empty slot (key64==0 AND tag!=TOMB), stop probing (end of chain).
 *         - If we encounter a tombstone (tag==TOMB), keep probing.
 *       bump g_seen_egr.
 *
 * Memory ordering:
 *   - Ingress publishes ts_ns last and sets TAG_OCC with a release fence before returning to ensure
 *     slab_idx/caplen/ts_ns are visible to expirer.
 *   - Expirer checks ts_ns != 0 before acting on a slot.
 */
typedef struct { NtNetStreamRx_t rx; int is_ingress; } rx_arg_t;

static void* rx_loop(void* arg){
  rx_arg_t* A = (rx_arg_t*)arg;
  while (1){
    NtNetBuf_t nb=NULL;
    if (NT_SUCCESS != NT_NetRxGet(A->rx, &nb, 1000)) continue;

    NtDyn4Descr_t* d = _NT_NET_GET_PKT_DESCR_PTR_DYN4(nb);
    uint8_t*  l2  = (uint8_t*)NT_NET_GET_PKT_L2_PTR(nb);
    uint32_t  cap = NT_NET_GET_PKT_CAP_LENGTH(nb);
    uint64_t  ts  = d->timestamp;
    uint64_t  key = d->color1; /* correlation key from NTPL */

    if (A->is_ingress){
      atomic_fetch_add(&g_seen_ing, 1);

      uint32_t idx = khash64(key) & PEND_MASK;
      for (uint32_t i=0;i<=PEND_MASK;i++){
        uint32_t j = (idx + i) & PEND_MASK;
        uint64_t expect = 0;
        if (atomic_compare_exchange_weak(&PEND[j].key64, &expect, key)){
          /* Found empty slot → insert */
          uint32_t si = slab_acquire();
          uint32_t copy = cap < g.snaplen ? cap : g.snaplen;
          memcpy(slab_ptr(si), l2, copy);
          PEND[j].slab_idx = si;
          PEND[j].caplen   = (uint16_t)copy;
          atomic_store(&PEND[j].ts_ns, ts);     /* publish last */
          atomic_store(&PEND[j].tag, TAG_OCC);
          atomic_thread_fence(memory_order_release);
          atomic_fetch_add(&g_pend_live, 1);
          break;
        } else if (expect == key){
          /* Duplicate ingress (e.g., recirc) before egress seen; refresh ts */
          atomic_store(&PEND[j].ts_ns, ts);
          break;
        }
      }
    } else {
      atomic_fetch_add(&g_seen_egr, 1);

      uint32_t idx = khash64(key) & PEND_MASK;
      for (uint32_t i=0;i<=PEND_MASK;i++){
        uint32_t j = (idx + i) & PEND_MASK;
        uint64_t cur = atomic_load(&PEND[j].key64);
        if (cur == key){
          atomic_store(&PEND[j].tag, TAG_TOMB);
          atomic_thread_fence(memory_order_release);
          atomic_store(&PEND[j].key64, 0);
          atomic_fetch_sub(&g_pend_live, 1);
          break;
        }
        if (cur == 0){
          atomic_thread_fence(memory_order_acquire);
          if (atomic_load(&PEND[j].tag) == TAG_TOMB) {
            continue; /* skip tombstone, continue probing */
          }
          break;      /* true empty → end of chain */
        }
      }
    }

    NT_NetRxRelease(A->rx, nb);
  }
  return NULL;
}

/*───────────────────────────────────────────────────────────────────────────*/
/* Expirer thread (drop detection, logging, PCAP write)                      */
/*───────────────────────────────────────────────────────────────────────────*/

/*
 * expirer_thread() — Scans the pending table in small slices continuously.
 *
 * For each non-empty slot with a published ts_ns:
 *   if now - ts_ns > window → treat as dropped:
 *     - Read the stored snapshot from the slab (caplen/idx).
 *     - Parse VLANs/IP/L4 (fast, bounds-checked within snaplen).
 *     - Write to PCAP, log a one-liner (unless --quiet).
 *     - Mark the slot as a tombstone and clear key + ts_ns; decrement g_pend_live.
 *
 * The scan is time-sliced (65536 entries per loop) with a small sleep to keep RX hot.
 */
static void* expirer_thread(void* arg){
  (void)arg;
  const uint64_t win_ns = (uint64_t)g.win_us * 1000ULL;
  uint64_t cursor = 0;
  while (1){
    uint64_t now = now_ns();

    /* Scan a slice each tick to amortize cost */
    for (uint32_t k=0;k<65536; k++){
      uint64_t i = (cursor++) & PEND_MASK;
      uint64_t key = atomic_load(&PEND[i].key64);
      if (key==0) continue;

      uint64_t ts = atomic_load(&PEND[i].ts_ns);
      if (ts == 0) continue;               /* writer has not fully published */
      if (now - ts <= win_ns) continue;    /* not expired yet */

      /* Drop: parse & write */
      atomic_thread_fence(memory_order_acquire); /* see slab fields */
      uint8_t* snap = slab_ptr(PEND[i].slab_idx);
      uint16_t cap  = PEND[i].caplen;

      drop_key_t dk; parse_vlan_ip_l4(snap, cap, &dk);
      pcap_write(snap, cap, ts);

      /* Tiny one-line log (skipped if --quiet) */
      if (!g.quiet){
        char sip[INET6_ADDRSTRLEN] = "-";
        char dip[INET6_ADDRSTRLEN] = "-";
        if (dk.v6) {
          (void)inet_ntop(AF_INET6, dk.src.v6b, sip, sizeof sip);
          (void)inet_ntop(AF_INET6, dk.dst.v6b, dip, sizeof dip);
        } else if (dk.src.v4 || dk.dst.v4) {
          struct in_addr a;
          a.s_addr = dk.src.v4; (void)inet_ntop(AF_INET, &a, sip, sizeof sip);
          a.s_addr = dk.dst.v4; (void)inet_ntop(AF_INET, &a, dip, sizeof dip);
        }
        const char* pstr = (dk.proto==6) ? "TCP" : (dk.proto==17) ? "UDP" : "-";
        printf("[drop] ts=%" PRIu64 "ns s=%u c=%u %s %s:%u -> %s:%u cap=%u key=0x%016" PRIx64 "\n",
               ts, dk.s, dk.c, pstr, sip, (unsigned)dk.sport, dip, (unsigned)dk.dport,
               (unsigned)cap, key);
        fflush(stdout);
      }

      atomic_fetch_add(&g_drops_written, 1);
      atomic_fetch_add(&g_expired, 1);

      /* Tombstone then clear; allow reuse later but keep probe chain continuity */
      atomic_store(&PEND[i].tag, TAG_TOMB);
      atomic_thread_fence(memory_order_release);
      atomic_store(&PEND[i].key64, 0);
      atomic_store(&PEND[i].ts_ns, 0);
      atomic_fetch_sub(&g_pend_live, 1);
    }

    /* Yield a bit; RX threads stay hot */
    usleep(1000);
  }
  return NULL;
}

/*───────────────────────────────────────────────────────────────────────────*/
/* Reporter thread (30s CSV dump)                                            */
/*───────────────────────────────────────────────────────────────────────────*/

/*
 * reporter_thread() — Every 30s, writes a CSV row with cumulative counters to
 * g.state_path (default /dev/shm/nt_drop_state.csv). Also prints a one-line state
 * snapshot unless --quiet is set.
 */
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

/*───────────────────────────────────────────────────────────────────────────*/
/* CLI parsing & main                                                        */
/*───────────────────────────────────────────────────────────────────────────*/

/*
 * parse_args(argc, argv) — Populates g with defaults, then overrides from CLI.
 * Sanity checks that ingress/egress SIDs differ and the pending table is not tiny.
 */
static void parse_args(int argc, char** argv){
  /* Defaults */
  g.adapter=0; g.sid_ing=0; g.sid_egr=1; g.win_us=5; g.snaplen=128;
  g.pcap_path="/dev/shm/drops.pcap"; g.state_path="/dev/shm/nt_drop_state.csv";
  g.pend_pow=20; g.quiet=0; g.debug=0;

  for (int i=1;i<argc;i++){
    if      (!strncmp(argv[i],"--adapter=",10))     g.adapter = atoi(argv[i]+10);
    else if (!strncmp(argv[i],"--ingress_sid=",14)) g.sid_ing = atoi(argv[i]+14);
    else if (!strncmp(argv[i],"--egress_sid=",13))  g.sid_egr = atoi(argv[i]+13);
    else if (!strncmp(argv[i],"--win_us=",9))       g.win_us  = (uint32_t)atoi(argv[i]+9);
    else if (!strncmp(argv[i],"--snaplen=",10))     g.snaplen = (uint32_t)atoi(argv[i]+10);
    else if (!strncmp(argv[i],"--pcap=",7))         g.pcap_path = argv[i]+7;
    else if (!strncmp(argv[i],"--state=",8))        g.state_path = argv[i]+8;
    else if (!strncmp(argv[i],"--pend_pow=",11))    g.pend_pow = atoi(argv[i]+11);
    else if (!strcmp(argv[i],"--quiet"))            g.quiet = 1;
    else if (!strncmp(argv[i],"--debug=",8))        g.debug = atoi(argv[i]+8);
    else { fprintf(stderr,"unknown arg: %s\n", argv[i]); exit(1); }
  }

  if (g.sid_ing==g.sid_egr){
    fprintf(stderr,"ingress_sid must differ from egress_sid\n"); exit(1);
  }
  if (g.pend_pow < 10){
    fprintf(stderr,"pend_pow too small (min 10)\n"); exit(1);
  }
}

/*
 * main() — Orchestrates initialization and thread startup:
 *   1) NTAPI init
 *   2) Allocate pending table (2^pend_pow slots) and preallocate slab
 *   3) Open two RX streams with NT_NetRxOpen(..., streamId, -1)  [HBA disabled]
 *   4) Open PCAP writer
 *   5) Spawn RX threads (ingress/egress), expirer, reporter
 *   6) Join threads (run forever until killed)
 *
 * Cleanup code exists but is rarely reached (daemon-style).
 */
int main(int argc, char** argv){
  parse_args(argc, argv);

  int st = NT_Init(NTAPI_VERSION);
  if (st != NT_SUCCESS) die_nt("NT_Init", st);

  /* Allocate pending table & slab */
  size_t pend_sz = 1ull << g.pend_pow;
  PEND = (pend_t*)calloc(pend_sz, sizeof(pend_t));
  if (!PEND){ fprintf(stderr,"PEND alloc failed\n"); exit(1); }
  PEND_MASK = pend_sz - 1;

  uint32_t stride = (g.snaplen + 63u) & ~63u; /* align to cacheline */
  slab_init((uint32_t)pend_sz, stride);

  /* Open two RX streams (one per SID) — HBA disabled (-1) */
  NtNetStreamRx_t rx_ing=NULL, rx_egr=NULL;
  st = NT_NetRxOpen(&rx_ing, "ing", NT_NET_INTERFACE_PACKET, g.sid_ing, -1);
  if (st!=NT_SUCCESS) die_nt("NT_NetRxOpen ingress", st);
  st = NT_NetRxOpen(&rx_egr, "egr", NT_NET_INTERFACE_PACKET, g.sid_egr, -1);
  if (st!=NT_SUCCESS) die_nt("NT_NetRxOpen egress", st);

  /* PCAP writer */
  pcap_open_writer(g.pcap_path, g.snaplen);

  /* Start threads */
  pthread_t t_ing, t_egr, t_exp, t_rep;
  rx_arg_t A = { .rx = rx_ing, .is_ingress = 1 };
  rx_arg_t B = { .rx = rx_egr, .is_ingress = 0 };
  pthread_create(&t_ing, NULL, rx_loop, &A);
  pthread_create(&t_egr, NULL, rx_loop, &B);
  pthread_create(&t_exp, NULL, expirer_thread, NULL);
  pthread_create(&t_rep, NULL, reporter_thread, NULL);

  if (!g.quiet){
    printf("cfg: adapter=%d sid_ing=%d sid_egr=%d win_us=%u snaplen=%u pend=2^%d\n",
           g.adapter, g.sid_ing, g.sid_egr, g.win_us, g.snaplen, g.pend_pow);
    printf("pcap=%s state=%s\n", g.pcap_path, g.state_path);
    fflush(stdout);
  }

  /* Join threads (until killed) */
  pthread_join(t_ing, NULL);
  pthread_join(t_egr, NULL);
  pthread_join(t_exp, NULL);
  pthread_join(t_rep, NULL);

  /* Cleanup (normally not reached) */
  NT_NetRxClose(rx_ing); NT_NetRxClose(rx_egr);
  if (p_dump) { pcap_dump_close(p_dump); p_dump=NULL; }
  if (p_dead) { pcap_close(p_dead); p_dead=NULL; }
  NT_Done();
  return 0;
}
