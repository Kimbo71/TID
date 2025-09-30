#define _GNU_SOURCE
#include <nt.h>
#include <ntapi/pktdescr_dyn3.h>
#include <ntapi/pktdescr.h>
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
#include <time.h>
#include <unistd.h>

/*
 * nt_hw_dedup_monitor.c
 *
 * Host-side monitor that leverages Napatech hardware deduplication. In NTPL the
 * ingress+egress taps are merged into one DYN3 stream and the Deduplication
 * engine marks the second packet in a correlated pair by setting a color bit.
 *
 * Software flow:
 *   - First copy (color bit cleared): fingerprint, cache, and keep a snaplen
 *     copy plus metadata in a lock-free open-addressing table.
 *   - Duplicate copy (color bit set): locate and release the cached entry.
 *   - Cached entries that overrun the software window (default 5 µs) are
 *     considered drops — they are logged and written to a PCAP for forensics.
 *
 * Build example:
 *   gcc -std=gnu11 -O2 -Wall -Wextra -I/opt/napatech3/include \
 *       -I/opt/napatech3/include/ntapi nt_hw_dedup_monitor.c \
 *       -L/opt/napatech3/lib -lntapi -lpcap -lpthread -o nt_hw_dedup_monitor
 */

typedef struct {
  int adapter;
  int sid;
  int dup_bit;                // color bit asserted by hardware on duplicate
  uint32_t win_us;            // software window (<= hardware dedup window)
  uint32_t snaplen;           // bytes preserved in PCAP/log
  const char* pcap_path;
  const char* state_path;
  int pend_pow;               // pending table size = 2^pend_pow
  int quiet;
  int debug;
  int egress_port;            // hardware port where duplicates drop
} cfg_t;

static cfg_t g;

static atomic_uint_fast64_t g_seen_first = 0;
static atomic_uint_fast64_t g_seen_dup = 0;
static atomic_uint_fast64_t g_expired = 0;
static atomic_uint_fast64_t g_drops_written = 0;
static atomic_uint_fast64_t g_pend_live = 0;

static inline uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void die_nt(const char* where, int status) {
  char buf[NT_ERRBUF_SIZE];
  NT_ExplainError(status, buf, sizeof buf);
  fprintf(stderr, "%s failed: %s (0x%08X)\n", where, buf, status);
  exit(EXIT_FAILURE);
}

static inline uint64_t fnv1a64_sample(const uint8_t* data, uint32_t caplen, uint32_t wirelen) {
  const uint32_t max_sample = 256;
  uint32_t n = caplen < max_sample ? caplen : max_sample;
  uint64_t h = 1469598103934665603ULL;
  for (uint32_t i = 0; i < n; ++i) {
    h ^= data[i];
    h *= 1099511628211ULL;
  }
  h ^= caplen;
  h *= 1099511628211ULL;
  h ^= wirelen;
  h *= 1099511628211ULL;
  return h;
}

static inline uint32_t mix64(uint64_t x) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33;
  return (uint32_t)x;
}

typedef struct {
  uint64_t key;               // fingerprint (0 == free)
  uint64_t ts_ns;             // timestamp of first copy (ns)
  uint32_t slab_idx;          // index of stored snaplen copy
  uint32_t cap_len;           // bytes preserved in slab
  uint32_t wire_len;          // original wire length
  uint16_t rx_port;           // port of first arrival
} pend_t;

static pend_t* PEND = NULL;
static uint64_t PEND_MASK = 0;

typedef struct {
  uint8_t* base;
  uint32_t stride;
  uint32_t cap;
  uint32_t head;
} slab_t;

static slab_t SLAB;

static uint32_t* PEND_QUEUE = NULL;
static uint32_t QUEUE_CAP = 0;
static uint32_t QUEUE_HEAD = 0;
static uint32_t QUEUE_TAIL = 0;
static uint32_t QUEUE_COUNT = 0;

static NtStatStream_t g_stat_stream = NULL;
static uint64_t g_hw_dedup_prev = 0;

static void slab_init(uint32_t slots, uint32_t stride) {
  size_t bytes = (size_t)slots * stride;
  SLAB.base = aligned_alloc(64, bytes);
  if (!SLAB.base) {
    fprintf(stderr, "slab allocation failed (%zu bytes)\n", bytes);
    exit(EXIT_FAILURE);
  }
  SLAB.stride = stride;
  SLAB.cap = slots;
  SLAB.head = 0;
}

static void queue_init(uint32_t cap) {
  PEND_QUEUE = calloc(cap, sizeof(uint32_t));
  if (!PEND_QUEUE) {
    fprintf(stderr, "queue allocation failed (%u entries)\n", cap);
    exit(EXIT_FAILURE);
  }
  for (uint32_t i = 0; i < cap; ++i)
    PEND_QUEUE[i] = UINT32_MAX;
  QUEUE_CAP = cap;
  QUEUE_HEAD = 0;
  QUEUE_TAIL = 0;
  QUEUE_COUNT = 0;
}

static inline void queue_push(uint32_t slot) {
  if (QUEUE_COUNT == QUEUE_CAP) {
    fprintf(stderr, "pending queue overflow\n");
    return;
  }
  PEND_QUEUE[QUEUE_TAIL] = slot;
  QUEUE_TAIL = (QUEUE_TAIL + 1) % QUEUE_CAP;
  ++QUEUE_COUNT;
}

static inline uint32_t queue_peek(void) {
  if (QUEUE_COUNT == 0)
    return UINT32_MAX;
  return PEND_QUEUE[QUEUE_HEAD];
}

static inline uint32_t queue_pop(void) {
  if (QUEUE_COUNT == 0)
    return UINT32_MAX;
  uint32_t slot = PEND_QUEUE[QUEUE_HEAD];
  PEND_QUEUE[QUEUE_HEAD] = UINT32_MAX;
  QUEUE_HEAD = (QUEUE_HEAD + 1) % QUEUE_CAP;
  --QUEUE_COUNT;
  return slot;
}

static inline uint32_t slab_acquire(void) {
  uint32_t idx = SLAB.head++;
  return idx & (SLAB.cap - 1);
}

static inline uint8_t* slab_ptr(uint32_t idx) {
  return SLAB.base + (size_t)idx * SLAB.stride;
}

static inline void clear_entry(pend_t* e) {
  e->key = 0;
  e->ts_ns = 0;
  e->cap_len = 0;
  e->wire_len = 0;
  e->rx_port = 0;
}

static void ack_duplicate_entry(uint32_t slot) {
  if (slot == UINT32_MAX)
    return;
  pend_t* e = &PEND[slot];
  if (e->key == 0)
    return;
  clear_entry(e);
  atomic_fetch_sub(&g_pend_live, 1);
  atomic_fetch_add(&g_seen_dup, 1);
}

static void ack_duplicates_hw(uint64_t count) {
  while (count-- > 0 && QUEUE_COUNT > 0) {
    uint32_t slot = queue_pop();
    ack_duplicate_entry(slot);
  }
}

static pcap_t* g_pcap_dead = NULL;
static pcap_dumper_t* g_pcap_dump = NULL;

static void pcap_open_writer(const char* path, uint32_t snaplen) {
  g_pcap_dead = pcap_open_dead(DLT_EN10MB, snaplen);
  if (!g_pcap_dead) {
    fprintf(stderr, "pcap_open_dead failed\n");
    exit(EXIT_FAILURE);
  }
  g_pcap_dump = pcap_dump_open(g_pcap_dead, path);
  if (!g_pcap_dump) {
    fprintf(stderr, "pcap_dump_open failed: %s\n", pcap_geterr(g_pcap_dead));
    exit(EXIT_FAILURE);
  }
  if (!g.quiet) {
    printf("writing drops to %s\n", path);
    fflush(stdout);
  }
}

static inline void pcap_write(const uint8_t* data, uint32_t caplen, uint32_t wirelen, uint64_t ts_ns) {
  struct pcap_pkthdr hdr;
  memset(&hdr, 0, sizeof hdr);
  hdr.caplen = caplen;
  hdr.len = wirelen ? wirelen : caplen;
  hdr.ts.tv_sec = (time_t)(ts_ns / 1000000000ULL);
  hdr.ts.tv_usec = (suseconds_t)((ts_ns % 1000000000ULL) / 1000ULL);
  pcap_dump((u_char*)g_pcap_dump, &hdr, data);
  pcap_dump_flush(g_pcap_dump);
}

typedef struct {
  bool is_v6;
  bool has_ports;
  uint8_t proto;
  uint16_t svlan;
  uint16_t cvlan;
  uint16_t sport;
  uint16_t dport;
  union { uint32_t v4; uint8_t v6[16]; } src;
  union { uint32_t v4; uint8_t v6[16]; } dst;
} drop_meta_t;

static void parse_drop_meta(const uint8_t* l2, uint32_t len, drop_meta_t* dm) {
  memset(dm, 0, sizeof *dm);
  if (len < 14)
    return;

  const uint8_t* p = l2;
  size_t offset = 14;
  uint16_t eth = ((uint16_t)p[12] << 8) | p[13];

  for (int i = 0; i < 2; ++i) {
    if (eth == 0x88A8 || eth == 0x8100) {
      if (len < offset + 4)
        return;
      uint16_t tci = ((uint16_t)p[offset] << 8) | p[offset + 1];
      uint16_t vid = tci & 0x0FFF;
      if (eth == 0x88A8 && dm->svlan == 0)
        dm->svlan = vid;
      else if (dm->cvlan == 0)
        dm->cvlan = vid;
      eth = ((uint16_t)p[offset + 2] << 8) | p[offset + 3];
      offset += 4;
    } else {
      break;
    }
  }

  if (eth == 0x0800) {
    if (len < offset + 20)
      return;
    uint8_t ihl = p[offset] & 0x0F;
    size_t ip_hdr = (size_t)ihl * 4;
    if (ip_hdr < 20 || len < offset + ip_hdr)
      return;
    dm->is_v6 = false;
    dm->proto = p[offset + 9];
    memcpy(&dm->src.v4, p + offset + 12, 4);
    memcpy(&dm->dst.v4, p + offset + 16, 4);
    size_t l4 = offset + ip_hdr;
    if ((dm->proto == IPPROTO_TCP || dm->proto == IPPROTO_UDP) && len >= l4 + 4) {
      dm->sport = ((uint16_t)p[l4] << 8) | p[l4 + 1];
      dm->dport = ((uint16_t)p[l4 + 2] << 8) | p[l4 + 3];
      dm->has_ports = true;
    }
  } else if (eth == 0x86DD) {
    if (len < offset + 40)
      return;
    dm->is_v6 = true;
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

static const char* proto_to_str(uint8_t proto) {
  switch (proto) {
    case IPPROTO_TCP: return "TCP";
    case IPPROTO_UDP: return "UDP";
    case IPPROTO_ICMP: return "ICMP";
#ifdef IPPROTO_ICMPV6
    case IPPROTO_ICMPV6: return "ICMPv6";
#endif
    default: return "proto";
  }
}

static void log_drop(uint64_t ts_ns, uint16_t port, uint64_t key, const drop_meta_t* dm) {
  uint64_t sec = ts_ns / 1000000000ULL;
  uint64_t nsec = ts_ns % 1000000000ULL;

  char srcbuf[INET6_ADDRSTRLEN] = "?";
  char dstbuf[INET6_ADDRSTRLEN] = "?";

  if (dm->is_v6) {
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

  if (dm->has_ports) {
    printf("drop ts=%" PRIu64 ".%09" PRIu64 " port=%u svlan=%u cvlan=%u %s:%u -> %s:%u %s(%u) key=0x%016" PRIx64 "\n",
           sec, nsec, port, dm->svlan, dm->cvlan,
           srcbuf, dm->sport, dstbuf, dm->dport, pname, dm->proto, key);
  } else {
    printf("drop ts=%" PRIu64 ".%09" PRIu64 " port=%u svlan=%u cvlan=%u %s -> %s %s(%u) key=0x%016" PRIx64 "\n",
           sec, nsec, port, dm->svlan, dm->cvlan,
           srcbuf, dstbuf, pname, dm->proto, key);
  }
  fflush(stdout);
}

static uint64_t g_win_ns = 0;

static void expire_pending(uint64_t now) {
  const uint32_t slice = 4096;
  for (uint32_t n = 0; n < slice && QUEUE_COUNT > 0; ++n) {
    uint32_t slot = queue_peek();
    if (slot == UINT32_MAX) {
      queue_pop();
      continue;
    }
    pend_t* e = &PEND[slot];
    if (e->key == 0) {
      queue_pop();
      continue;
    }
    uint64_t ts = e->ts_ns;
    if (ts == 0) {
      queue_pop();
      continue;
    }
    if (now <= ts || now - ts <= g_win_ns)
      break;

    uint32_t cap = e->cap_len;
    if (cap == 0 || cap > g.snaplen)
      cap = g.snaplen;
    uint8_t* snap = slab_ptr(e->slab_idx);

    drop_meta_t meta;
    parse_drop_meta(snap, cap, &meta);
    pcap_write(snap, cap, e->wire_len, ts);
    log_drop(ts, e->rx_port, e->key, &meta);

    atomic_fetch_add(&g_drops_written, 1);
    atomic_fetch_add(&g_expired, 1);
    atomic_fetch_sub(&g_pend_live, 1);

    clear_entry(e);
    queue_pop();
  }
}

static void poll_hw_stats(void) {
  if (!g_stat_stream)
    return;

  NtStatistics_t st;
  memset(&st, 0, sizeof st);
  st.cmd = NT_STATISTICS_READ_CMD_QUERY_V4;
  st.u.query_v4.poll = 1;
  st.u.query_v4.clear = 0;
  int status = NT_StatRead(g_stat_stream, &st);
  if (status != NT_SUCCESS)
    return;

  const struct NtStatisticsQueryPortResult_v4_s* port_res = &st.u.query_v4.data.port;
  if (g.egress_port < 0 || g.egress_port >= port_res->numPorts)
    return;
  const struct NtPortStatistics_v3_s* rx = &port_res->aPorts[g.egress_port].rx;
  if (!rx->valid.extDrop)
    return;

  uint64_t hw = rx->extDrop.pktsDedup;
  uint64_t delta = hw >= g_hw_dedup_prev ? (hw - g_hw_dedup_prev) : hw;
  g_hw_dedup_prev = hw;
  if (delta)
    ack_duplicates_hw(delta);
}

static bool table_insert(uint64_t key, const uint8_t* data, uint32_t caplen, uint32_t wirelen, uint16_t rx_port, uint64_t ts) {
  uint32_t idx = mix64(key) & (uint32_t)PEND_MASK;
  for (uint32_t i = 0; i <= PEND_MASK; ++i) {
    uint32_t slot = (idx + i) & (uint32_t)PEND_MASK;
    pend_t* e = &PEND[slot];
    if (e->key == 0) {
      uint32_t copy = caplen < g.snaplen ? caplen : g.snaplen;
      uint32_t si = slab_acquire();
      if (copy)
        memcpy(slab_ptr(si), data, copy);
      e->key = key;
      e->ts_ns = ts;
      e->slab_idx = si;
      e->cap_len = copy;
      e->wire_len = wirelen;
      e->rx_port = rx_port;
      atomic_fetch_add(&g_pend_live, 1);
      queue_push(slot);
      return true;
    }
    if (e->key == key) {
      // Refresh in-place (rare but possible if first packet retriggered)
      e->ts_ns = ts;
      e->wire_len = wirelen;
      uint32_t copy = caplen < g.snaplen ? caplen : g.snaplen;
      if (copy) {
        memcpy(slab_ptr(e->slab_idx), data, copy);
        e->cap_len = copy;
      }
      e->rx_port = rx_port;
      return true;
    }
  }
  return false;
}

static bool table_remove(uint64_t key) {
  uint32_t idx = mix64(key) & (uint32_t)PEND_MASK;
  for (uint32_t i = 0; i <= PEND_MASK; ++i) {
    uint32_t slot = (idx + i) & (uint32_t)PEND_MASK;
    pend_t* e = &PEND[slot];
    if (e->key == 0)
      return false;
    if (e->key == key) {
      ack_duplicate_entry(slot);
      return true;
    }
  }
  return false;
}

static void* reporter_thread(void* arg) {
  (void)arg;
  while (1) {
    sleep(30);
    const char* path = g.state_path ? g.state_path : "/dev/shm/nt_hw_dedup_state.csv";
    FILE* f = fopen(path, "w");
    if (f) {
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      fprintf(f, "ts,first_seen,duplicates,pend_live,expired,drops_written\n");
      fprintf(f, "%lld.%09ld,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
              (long long)ts.tv_sec, ts.tv_nsec,
              atomic_load(&g_seen_first),
              atomic_load(&g_seen_dup),
              atomic_load(&g_pend_live),
              atomic_load(&g_expired),
              atomic_load(&g_drops_written));
      fclose(f);
    }
    if (!g.quiet) {
      printf("[state] first=%" PRIu64 " dup=%" PRIu64 " pend=%" PRIu64 " exp=%" PRIu64 " drops=%" PRIu64 "\n",
             atomic_load(&g_seen_first),
             atomic_load(&g_seen_dup),
             atomic_load(&g_pend_live),
             atomic_load(&g_expired),
             atomic_load(&g_drops_written));
      fflush(stdout);
    }
  }
  return NULL;
}

static void handle_packet(NtNetStreamRx_t rx) {
  NtNetBuf_t nb = NULL;
  int status = NT_NetRxGet(rx, &nb, 1000);
  uint64_t now = now_ns();
  expire_pending(now);
  if (status != NT_SUCCESS) {
    poll_hw_stats();
    return;
  }

  NtDyn3Descr_t* d = _NT_NET_GET_PKT_DESCR_PTR_DYN3(nb);
  const uint8_t* l2 = (const uint8_t*)NT_NET_GET_PKT_L2_PTR(nb);
  uint32_t caplen = NT_NET_GET_PKT_CAP_LENGTH(nb);
  uint32_t wirelen = NT_NET_GET_PKT_WIRE_LENGTH(nb);
  uint64_t ts = d->timestamp;
  uint16_t rx_port = (uint16_t)d->rxPort;
  uint64_t color = ((uint64_t)d->color_hi << 14) | (uint64_t)d->color_lo;
  bool is_dup = ((color >> g.dup_bit) & 0x1ULL) != 0ULL;

  uint64_t key = fnv1a64_sample(l2, caplen, wirelen);

  if (!is_dup) {
    if (!table_insert(key, l2, caplen, wirelen, rx_port, ts)) {
      fprintf(stderr, "pending table full — drop ts=%" PRIu64 " port=%u\n", ts, rx_port);
    } else {
      atomic_fetch_add(&g_seen_first, 1);
      if (g.debug > 0 && (atomic_load(&g_seen_first) % g.debug) == 0 && !g.quiet) {
        printf("[debug] cached first copy key=0x%016" PRIx64 " port=%u\n", key, rx_port);
        fflush(stdout);
      }
    }
  } else {
    bool removed = table_remove(key);
    if (!removed && g.debug >= 0) {
      fprintf(stderr, "warning: duplicate without pending entry key=0x%016" PRIx64 " port=%u\n", key, rx_port);
    } else if (removed && g.debug > 0 && (atomic_load(&g_seen_dup) % g.debug) == 0 && !g.quiet) {
      printf("[debug] matched duplicate key=0x%016" PRIx64 " port=%u\n", key, rx_port);
      fflush(stdout);
    }
  }

  NT_NetRxRelease(rx, nb);
  poll_hw_stats();
}

static void parse_args(int argc, char** argv) {
  g.adapter = 0;
  g.sid = 0;
  g.dup_bit = 7;
  g.win_us = 5;
  g.snaplen = 128;
  g.pcap_path = "/dev/shm/nt_hw_dedup_drops.pcap";
  g.state_path = "/dev/shm/nt_hw_dedup_state.csv";
  g.pend_pow = 20;
  g.quiet = 0;
  g.debug = 0;
  g.egress_port = 1;

  for (int i = 1; i < argc; ++i) {
    if (!strncmp(argv[i], "--adapter=", 10))
      g.adapter = atoi(argv[i] + 10);
    else if (!strncmp(argv[i], "--sid=", 6))
      g.sid = atoi(argv[i] + 6);
    else if (!strncmp(argv[i], "--dup_bit=", 10))
      g.dup_bit = atoi(argv[i] + 10);
    else if (!strncmp(argv[i], "--win_us=", 9))
      g.win_us = (uint32_t)atoi(argv[i] + 9);
    else if (!strncmp(argv[i], "--snaplen=", 10))
      g.snaplen = (uint32_t)atoi(argv[i] + 10);
    else if (!strncmp(argv[i], "--pcap=", 7))
      g.pcap_path = argv[i] + 7;
    else if (!strncmp(argv[i], "--state=", 8))
      g.state_path = argv[i] + 8;
    else if (!strncmp(argv[i], "--pend_pow=", 11))
      g.pend_pow = atoi(argv[i] + 11);
    else if (!strncmp(argv[i], "--egress_port=", 14))
      g.egress_port = atoi(argv[i] + 14);
    else if (!strcmp(argv[i], "--quiet"))
      g.quiet = 1;
    else if (!strncmp(argv[i], "--debug=", 8))
      g.debug = atoi(argv[i] + 8);
    else {
      fprintf(stderr, "unknown arg: %s\n", argv[i]);
      exit(EXIT_FAILURE);
    }
  }

  if (g.dup_bit < 0 || g.dup_bit > 41) {
    fprintf(stderr, "dup_bit must be between 0 and 41\n");
    exit(EXIT_FAILURE);
  }
  if (g.pend_pow < 10 || g.pend_pow > 26) {
    fprintf(stderr, "pend_pow must be between 10 and 26\n");
    exit(EXIT_FAILURE);
  }
  if (g.egress_port < 0)
    g.egress_port = 0;
  if (g.snaplen == 0)
    g.snaplen = 64;
  g_win_ns = (uint64_t)g.win_us * 1000ULL;

  if (!g.quiet) {
    printf("cfg: adapter=%d sid=%d dup_bit=%d win_us=%u snaplen=%u pend=2^%d egress_port=%d pcap=%s state=%s\n",
           g.adapter, g.sid, g.dup_bit, g.win_us, g.snaplen, g.pend_pow, g.egress_port,
           g.pcap_path, g.state_path);
    fflush(stdout);
  }
}

int main(int argc, char** argv) {
  parse_args(argc, argv);

  int status = NT_Init(NTAPI_VERSION);
  if (status != NT_SUCCESS)
    die_nt("NT_Init", status);

  size_t pend_sz = 1ULL << g.pend_pow;
  PEND = calloc(pend_sz, sizeof *PEND);
  if (!PEND) {
    fprintf(stderr, "pending table allocation failed (size=%zu)\n", pend_sz);
    exit(EXIT_FAILURE);
  }
  PEND_MASK = pend_sz - 1;

  uint32_t stride = (g.snaplen + 63u) & ~63u;
  slab_init((uint32_t)pend_sz, stride);
  queue_init((uint32_t)pend_sz);

  NtNetStreamRx_t rx = NULL;
  status = NT_NetRxOpen(&rx, "hw_dedup", NT_NET_INTERFACE_PACKET, g.sid, -1);
  if (status != NT_SUCCESS)
    die_nt("NT_NetRxOpen", status);

  status = NT_StatOpen(&g_stat_stream, "hw_dedup_stats");
  if (status == NT_SUCCESS) {
    NtStatistics_t init;
    memset(&init, 0, sizeof init);
    init.cmd = NT_STATISTICS_READ_CMD_QUERY_V4;
    init.u.query_v4.poll = 1;
    init.u.query_v4.clear = 0;
    if (NT_StatRead(g_stat_stream, &init) == NT_SUCCESS) {
      const struct NtStatisticsQueryPortResult_v4_s* port_res = &init.u.query_v4.data.port;
      if (g.egress_port >= 0 && g.egress_port < port_res->numPorts) {
        const struct NtPortStatistics_v3_s* rx_stats = &port_res->aPorts[g.egress_port].rx;
        if (rx_stats->valid.extDrop)
          g_hw_dedup_prev = rx_stats->extDrop.pktsDedup;
      }
    }
  } else {
    g_stat_stream = NULL;
  }

  pcap_open_writer(g.pcap_path, g.snaplen);

  pthread_t reporter;
  pthread_create(&reporter, NULL, reporter_thread, NULL);

  while (1) {
    handle_packet(rx);
  }

  // not reached, but keep tidy
  pthread_join(reporter, NULL);
  NT_NetRxClose(rx);
  if (g_pcap_dump) {
    pcap_dump_close(g_pcap_dump);
    g_pcap_dump = NULL;
  }
  if (g_pcap_dead) {
    pcap_close(g_pcap_dead);
    g_pcap_dead = NULL;
  }
  if (g_stat_stream) {
    NT_StatClose(g_stat_stream);
    g_stat_stream = NULL;
  }
  NT_Done();
  return 0;
}
