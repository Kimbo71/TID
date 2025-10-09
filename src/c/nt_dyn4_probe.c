// nt_dyn4_probe.c — Probe up to two SIDs and dump key descriptor fields.
// Optional: apply minimal NTPL (Descriptor selectable, Port0->SID0, Port1->SID1).
//
/* Build:
 *   gcc -O2 -Wall -Wextra 
 *     -I/opt/napatech3/include -I/opt/napatech3/include/ntapi 
 *     -L/opt/napatech3/lib -Wl,-rpath,/opt/napatech3/lib 
 *     nt_dyn4_probe.c -lntapi -o nt_dyn4_probe
 */
//
// Run examples:
//   sudo ./nt_dyn4_probe --adapter=0 --sid0=0 --sid1=1 --each=20 --timeout_ms=100
//   sudo ./nt_dyn4_probe --adapter=0 --sid0=0 --sid1=1 --descriptor=Dyn3 --apply_simple

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>

#include <nt.h>
#include <ntapi/stream_net.h>      // NtNetBuf_s (for portOffset)
#include <ntapi/pktdescr_dyn4.h>   // NtDyn4Descr_t
#include <ntapi/pktdescr_dyn3.h>   // NtDyn3Descr_t

typedef enum {
  DESC_DYN4,
  DESC_DYN3
} descriptor_t;

// --- helpers ----------------------------------------------------------------
static void die_err(const char* where, int st) {
  char b[NT_ERRBUF_SIZE]; NT_ExplainError(st, b, sizeof b);
  fprintf(stderr, "%s failed: %s (0x%08X)\n", where, b, st);
  exit(1);
}

static void parse_vlan_ip(const uint8_t* l2, uint32_t len,
                          uint16_t* eth, uint16_t* s, uint16_t* c,
                          char* ip, size_t iplen) {
  *eth = 0; *s = 0; *c = 0; if (ip) ip[0] = '\0';
  if (len < 14) return;
  const uint8_t* p = l2;
  uint16_t e = ((uint16_t)p[12] << 8) | p[13];
  int off = 14;
  for (int i = 0; i < 2; i++) {
    if (e == 0x88A8 || e == 0x8100) {
      if (len < (uint32_t)(off + 4)) break;
      uint16_t tci = ((uint16_t)p[off] << 8) | p[off + 1];
      uint16_t vid = tci & 0x0FFF;
      if (e == 0x88A8 && *s == 0) *s = vid;
      else if (*c == 0) *c = vid;
      e = ((uint16_t)p[off + 2] << 8) | p[off + 3];
      off += 4;
    } else break;
  }
  *eth = e;
  if (!ip) return;
  if (e == 0x0800 && len >= (uint32_t)(off + 20)) {
    struct in_addr a; memcpy(&a.s_addr, p + off + 12, 4);
    inet_ntop(AF_INET, &a, ip, iplen);
  } else if (e == 0x86DD && len >= (uint32_t)(off + 40)) {
    inet_ntop(AF_INET6, p + off + 8, ip, iplen);
  }
}

static void clear_stream_stats_once(NtStatStream_t hStat) {
  NtStatistics_t s; memset(&s, 0, sizeof s);
  s.cmd = NT_STATISTICS_READ_CMD_QUERY_V4;
  s.u.query_v4.poll  = 1;
  s.u.query_v4.clear = 1;  // clear on this read
  (void)NT_StatRead(hStat, &s);
}

static void print_sid_stats(NtStatStream_t hStat, int sid) {
  NtStatistics_t s; memset(&s, 0, sizeof s);
  s.cmd = NT_STATISTICS_READ_CMD_QUERY_V4;
  s.u.query_v4.poll  = 1;
  s.u.query_v4.clear = 0;
  if (NT_StatRead(hStat, &s) != NT_SUCCESS) return;
  const typeof(s.u.query_v4.data.stream.streamid[0]) *st =
      &s.u.query_v4.data.stream.streamid[sid];
  printf("[sid=%d] hw_drop_pkts=%" PRIu64 " hw_drop_bytes=%" PRIu64
         " hw_flush_pkts=%" PRIu64 " hw_flush_bytes=%" PRIu64 "\n",
         sid, st->drop.pkts, st->drop.octets, st->flush.pkts, st->flush.octets);
}

// --- main -------------------------------------------------------------------
int main(int argc, char** argv) {
  int adapter = 0, sid0 = 0, sid1 = 1, each = 20, timeout_ms = 100, apply_simple = 0;
  int dup_bit = 7;
  descriptor_t desc = DESC_DYN4;

  for (int i = 1; i < argc; i++) {
    if      (!strncmp(argv[i], "--adapter=",     10)) adapter     = atoi(argv[i] + 10);
    else if (!strncmp(argv[i], "--sid0=",         7)) sid0        = atoi(argv[i] + 7);
    else if (!strncmp(argv[i], "--sid1=",         7)) sid1        = atoi(argv[i] + 7);
    else if (!strncmp(argv[i], "--each=",         7)) each        = atoi(argv[i] + 7);
    else if (!strncmp(argv[i], "--timeout_ms=",  13)) timeout_ms  = atoi(argv[i] + 13);
    else if (!strcmp (argv[i], "--apply_simple"))      apply_simple = 1;
    else if (!strncmp(argv[i], "--descriptor=", 13)) {
      const char* v = argv[i] + 13;
      if (!strcasecmp(v, "dyn4"))      desc = DESC_DYN4;
      else if (!strcasecmp(v, "dyn3")) desc = DESC_DYN3;
      else {
        fprintf(stderr, "unknown descriptor: %s\n", v);
        return 1;
      }
    }
    else if (!strncmp(argv[i], "--dup_bit=", 10)) {
      dup_bit = atoi(argv[i] + 10);
      if (dup_bit < 0 || dup_bit > 63) {
        fprintf(stderr, "dup_bit must be between 0 and 63\n");
        return 1;
      }
    }
    else {
      fprintf(stderr,
        "Usage: %s --adapter=N --sid0=S [--sid1=S] [--each=N] [--timeout_ms=MS] "
        "[--descriptor=Dyn4|Dyn3] [--dup_bit=N] [--apply_simple]\n",
        argv[0]);
      return 1;
    }
  }

  int st = NT_Init(NTAPI_VERSION);
  if (st != NT_SUCCESS) die_err("NT_Init", st);

  // Optional: apply a minimal NTPL split (Port 0 -> SID 0, Port 1 -> SID 1), DYN4.
  NtConfigStream_t cfg = NULL;
  NtNtplInfo_t info; memset(&info, 0, sizeof info);
  if (apply_simple) {
    if ((st = NT_ConfigOpen(&cfg, "ntpl")) != NT_SUCCESS) die_err("NT_ConfigOpen", st);
    const char* ntpl =
      desc == DESC_DYN4 ?
        "Delete = All\n"
        "Setup [State=Active] = StreamId == 0\n"
        "Setup [State=Active] = StreamId == 1\n"
        "Assign[StreamId=0; Descriptor=DYN4] = Port == 0\n"
        "Assign[StreamId=1; Descriptor=DYN4] = Port == 1\n"
      : "Delete = All\n"
        "Setup [State=Active] = StreamId == 0\n"
        "Setup [State=Active] = StreamId == 1\n"
        "Assign[StreamId=0; Descriptor=DYN3] = Port == 0\n"
        "Assign[StreamId=1; Descriptor=DYN3] = Port == 1\n";
    st = NT_NTPL(cfg, ntpl, &info, NT_NTPL_PARSER_VALIDATE_NORMAL);
    if (st != NT_SUCCESS) {
      char eb0[256]={0}, eb1[256]={0}, eb2[256]={0};
      if (info.u.errorData.errBuffer[0]) snprintf(eb0, sizeof eb0, "%.255s", info.u.errorData.errBuffer[0]);
      if (info.u.errorData.errBuffer[1]) snprintf(eb1, sizeof eb1, "%.255s", info.u.errorData.errBuffer[1]);
      if (info.u.errorData.errBuffer[2]) snprintf(eb2, sizeof eb2, "%.255s", info.u.errorData.errBuffer[2]);
      fprintf(stderr, "NT_NTPL failed: code=0x%08X\n>>> %s\n>>> %s\n>>> %s\n",
              info.u.errorData.errCode, eb0, eb1, eb2);
      die_err("NT_NTPL", st);
    }
    printf("[apply_simple] NTPL applied.\n");
  }

  NtNetStreamRx_t r0 = NULL, r1 = NULL;
  st = NT_NetRxOpen(&r0, "sid0", NT_NET_INTERFACE_PACKET, sid0, -1);
  if (st) die_err("NT_NetRxOpen(sid0)", st);

  if (sid1 >= 0) {
    st = NT_NetRxOpen(&r1, "sid1", NT_NET_INTERFACE_PACKET, sid1, -1);
    if (st) die_err("NT_NetRxOpen(sid1)", st);
  }

  NtStatStream_t hStat = NULL;
  if ((st = NT_StatOpen(&hStat, "hStat")) != NT_SUCCESS) die_err("NT_StatOpen", st);
  clear_stream_stats_once(hStat);

  printf("[open] success adapter=%d sid0=%d sid1=%d (each=%d, timeout=%dms)\n",
         adapter, sid0, sid1, each, timeout_ms);

  int seen0 = 0, seen1 = 0;
  int warned_desc0 = 0, warned_desc1 = 0;
  uint64_t first0 = 0, dup0 = 0, first1 = 0, dup1 = 0;
  time_t last_hb = 0;

  while (seen0 < each || (sid1 >= 0 && seen1 < each)) {
    int did = 0;

    if (seen0 < each) {
      NtNetBuf_t nb = NULL;
      st = NT_NetRxGet(r0, &nb, timeout_ms);
      if (st == NT_SUCCESS) {
        did = 1;
        int dtype = NT_NET_GET_PKT_DESCRIPTOR_TYPE(nb);
        if (dtype != NT_PACKET_DESCRIPTOR_TYPE_DYNAMIC && !warned_desc0) {
          fprintf(stderr, "[WARN sid0] descriptor=%d (expected DYN)\n", dtype);
          warned_desc0 = 1;
        }
        uint8_t* l2 = (uint8_t*)NT_NET_GET_PKT_L2_PTR(nb);
        uint32_t wire = NT_NET_GET_PKT_WIRE_LENGTH(nb);
        uint64_t ts;
        uint8_t  rxp_raw;
        uint64_t color_lo = 0;
        uint64_t color_hi = 0;
        uint64_t color_val = 0;
        if (desc == DESC_DYN4) {
          NtDyn4Descr_t* d4 = _NT_NET_GET_PKT_DESCR_PTR_DYN4(nb);
          ts = d4->timestamp;
          rxp_raw = d4->rxPort;
          color_lo = d4->color0;
          color_hi = d4->color1;
          color_val = (color_hi << 8) | color_lo;
        } else {
          NtDyn3Descr_t* d3 = _NT_NET_GET_PKT_DESCR_PTR_DYN3(nb);
          ts = d3->timestamp;
          rxp_raw = d3->rxPort;
          color_hi = ((uint64_t)d3->color_hi << 14) | (uint64_t)d3->color_lo;
          color_val = color_hi;
        }
        // Absolute RX port = raw + portOffset
        struct NtNetBuf_s* nbh = (struct NtNetBuf_s*)nb;
        uint8_t  rxp_abs = (uint8_t)(nbh->portOffset + rxp_raw);

        uint16_t eth=0, s=0, c=0; char ip[64] = {0};
        parse_vlan_ip(l2, wire, &eth, &s, &c, ip, sizeof ip);

        int dup_flag = (dup_bit >= 0) ? (int)((color_val >> dup_bit) & 0x1ULL) : 0;
        if (dup_flag)
          ++dup0;
        else
          ++first0;

        if (desc == DESC_DYN4) {
          printf("[sid=%d] #%d ts=%" PRIu64 "ns rxPort_raw=%u rxPort_abs=%u "
                 "color0=0x%02" PRIx64 " color1=0x%016" PRIx64 " dedup_bit=%d len=%u eth=0x%04x S=%u C=%u src=%s\n",
                 sid0, ++seen0, ts, rxp_raw, rxp_abs,
                 color_lo, color_hi, dup_flag, wire, eth, s, c, ip[0] ? ip : "-");
        } else {
          printf("[sid=%d] #%d ts=%" PRIu64 "ns rxPort_raw=%u rxPort_abs=%u "
                 "color_bits=0x%016" PRIx64 " dedup_bit=%d len=%u eth=0x%04x S=%u C=%u src=%s\n",
                 sid0, ++seen0, ts, rxp_raw, rxp_abs,
                 color_hi, dup_flag, wire, eth, s, c, ip[0] ? ip : "-");
        }

        NT_NetRxRelease(r0, nb);
      }
    }

    if (sid1 >= 0 && seen1 < each) {
      NtNetBuf_t nb = NULL;
      st = NT_NetRxGet(r1, &nb, timeout_ms);
      if (st == NT_SUCCESS) {
        did = 1;
        int dtype = NT_NET_GET_PKT_DESCRIPTOR_TYPE(nb);
        if (dtype != NT_PACKET_DESCRIPTOR_TYPE_DYNAMIC && !warned_desc1) {
          fprintf(stderr, "[WARN sid1] descriptor=%d (expected DYN)\n", dtype);
          warned_desc1 = 1;
        }
        uint8_t* l2 = (uint8_t*)NT_NET_GET_PKT_L2_PTR(nb);
        uint32_t wire = NT_NET_GET_PKT_WIRE_LENGTH(nb);
        uint64_t ts;
        uint8_t  rxp_raw;
        uint64_t color_lo = 0;
        uint64_t color_hi = 0;
        uint64_t color_val = 0;
        if (desc == DESC_DYN4) {
          NtDyn4Descr_t* d4 = _NT_NET_GET_PKT_DESCR_PTR_DYN4(nb);
          ts = d4->timestamp;
          rxp_raw = d4->rxPort;
          color_lo = d4->color0;
          color_hi = d4->color1;
          color_val = (color_hi << 8) | color_lo;
        } else {
          NtDyn3Descr_t* d3 = _NT_NET_GET_PKT_DESCR_PTR_DYN3(nb);
          ts = d3->timestamp;
          rxp_raw = d3->rxPort;
          color_hi = ((uint64_t)d3->color_hi << 14) | (uint64_t)d3->color_lo;
          color_val = color_hi;
        }
        struct NtNetBuf_s* nbh = (struct NtNetBuf_s*)nb;
        uint8_t  rxp_abs = (uint8_t)(nbh->portOffset + rxp_raw);

        uint16_t eth=0, s=0, c=0; char ip[64] = {0};
        parse_vlan_ip(l2, wire, &eth, &s, &c, ip, sizeof ip);

        int dup_flag = (dup_bit >= 0) ? (int)((color_val >> dup_bit) & 0x1ULL) : 0;
        if (dup_flag)
          ++dup1;
        else
          ++first1;

        if (desc == DESC_DYN4) {
          printf("[sid=%d] #%d ts=%" PRIu64 "ns rxPort_raw=%u rxPort_abs=%u "
                 "color0=0x%02" PRIx64 " color1=0x%016" PRIx64 " dedup_bit=%d len=%u eth=0x%04x S=%u C=%u src=%s\n",
                 sid1, ++seen1, ts, rxp_raw, rxp_abs,
                 color_lo, color_hi, dup_flag, wire, eth, s, c, ip[0] ? ip : "-");
        } else {
          printf("[sid=%d] #%d ts=%" PRIu64 "ns rxPort_raw=%u rxPort_abs=%u "
                 "color_bits=0x%016" PRIx64 " dedup_bit=%d len=%u eth=0x%04x S=%u C=%u src=%s\n",
                 sid1, ++seen1, ts, rxp_raw, rxp_abs,
                 color_hi, dup_flag, wire, eth, s, c, ip[0] ? ip : "-");
        }

        NT_NetRxRelease(r1, nb);
      }
    }

    time_t now = time(NULL);
    if (!did && now - last_hb >= 1) {
      last_hb = now;
      printf("[timeout] adapter=%d sid0=%d sid1=%d\n", adapter, sid0, sid1);
      print_sid_stats(hStat, sid0);
      if (sid1 >= 0)
        print_sid_stats(hStat, sid1);
      fflush(stdout);
    }
  }

  if (first0 + dup0) {
    printf("[summary sid=%d] first_bit0=%" PRIu64 " dup_bit1=%" PRIu64 "\n", sid0, first0, dup0);
  }
  if (sid1 >= 0 && (first1 + dup1)) {
    printf("[summary sid=%d] first_bit0=%" PRIu64 " dup_bit1=%" PRIu64 "\n", sid1, first1, dup1);
  }

  if (hStat) NT_StatClose(hStat);
  NT_NetRxClose(r0);
  if (r1) NT_NetRxClose(r1);
  if (cfg) NT_ConfigClose(cfg);
  NT_Done();
  return 0;
}
