// nt_drop_reader.c — single-stream (SID 0) ingress/egress compare at line rate
// Diagnostics added: --ext_ntpl, --nogate, --debug=N, per-second heartbeat.
// Fast path only: hardware correlation key (DYN4 color1). No software hashing.
//
// Build:
//   gcc -O2 -Wall -I/opt/napatech3/include -I/opt/napatech3/include/ntapi \
//       -L/opt/napatech3/lib -Wl,-rpath,/opt/napatech3/lib \
//       nt_drop_reader.c -lntapi -lpcap -o nt_drop_reader
//
// Examples:
//   # Prove stream 0 is delivering packets (external NTPL):
//   /opt/napatech3/bin/ntpl -e "Delete = All"
//   /opt/napatech3/bin/ntpl -e "Assign[StreamId=0; Descriptor=DYN4, ColorBits=8] = All"
//   sudo ./nt_drop_reader --adapter=0 --sid=0 --ext_ntpl --nogate --debug=20
//
//   # Correlation key recipe (external NTPL):
//   /opt/napatech3/bin/ntpl -e "Delete = All"
//   /opt/napatech3/bin/ntpl -e "DeduplicationConfig[ColorBit=1] = GroupID == 0"
//   /opt/napatech3/bin/ntpl -e "Define ckL3 = CorrelationKey(Begin=Layer3Header[0], End=Layer3PayloadEnd[0], DeduplicationGroupID=0)"
//   /opt/napatech3/bin/ntpl -e "Assign[StreamId=0; Descriptor=DYN4, ColorBits=8; CorrelationKey=ckL3] = (Port == 0 OR Port == 1)"
//   sudo ./nt_drop_reader --adapter=0 --sid=0 --ext_ntpl --nogate --debug=20
//
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#include <nt.h>
#include <ntapi/pktdescr_dyn4.h>

/* ---------- CLI ---------- */
typedef struct {
  int adapter_no;
  int sid;            // single stream id (we assign both ports 0,1 to this)
  uint32_t win_us;    // expire unmatched ingress after this many usec
  uint32_t snaplen;   // bytes to dump for unmatched
  const char* pcap_path;

  int debug_print;    // print first N packets
  int ext_ntpl;       // 1 = do not push NTPL, use external
  int no_gate;        // 1 = skip NTPL timestamp gating
} cfg_t;

static void parse_args(int argc, char** argv, cfg_t* c){
  c->adapter_no = 0;
  c->sid = 0;
  c->win_us = 5000;
  c->snaplen = 1600;
  c->pcap_path = "/var/log/drops.pcap";
  c->debug_print = 0;
  c->ext_ntpl = 0;
  c->no_gate = 0;

  for (int i=1;i<argc;i++){
    if      (!strncmp(argv[i],"--adapter=",10)) c->adapter_no = atoi(argv[i]+10);
    else if (!strncmp(argv[i],"--sid=",6))      c->sid        = atoi(argv[i]+6);
    else if (!strncmp(argv[i],"--win_us=",9))   c->win_us     = (uint32_t)atoi(argv[i]+9);
    else if (!strncmp(argv[i],"--snaplen=",10)) c->snaplen    = (uint32_t)atoi(argv[i]+10);
    else if (!strncmp(argv[i],"--pcap=",7))     c->pcap_path  = argv[i]+7;
    else if (!strncmp(argv[i],"--debug=",8))    c->debug_print= atoi(argv[i]+8);
    else if (!strcmp(argv[i],"--ext_ntpl"))     c->ext_ntpl   = 1;
    else if (!strcmp(argv[i],"--nogate"))       c->no_gate    = 1;
    else {
      fprintf(stderr,"Usage: %s --adapter=N --sid=SID [--win_us=US] [--snaplen=B] [--pcap=PATH] [--ext_ntpl] [--nogate] [--debug=N]\n", argv[0]);
      exit(1);
    }
  }
  printf("cfg: adapter=%d sid=%d win_us=%u snaplen=%u pcap=%s ext_ntpl=%d nogate=%d debug=%d\n",
         c->adapter_no, c->sid, c->win_us, c->snaplen, c->pcap_path, c->ext_ntpl, c->no_gate, c->debug_print);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

/* ---------- Error helper ---------- */
static void die_err(const char* where, int status){
  char buf[NT_ERRBUF_SIZE];
  NT_ExplainError(status, buf, sizeof(buf));
  fprintf(stderr, "%s failed: 0x%08X (%s)\n", where, (unsigned)status, buf);
  exit(1);
}

/* ---------- Descriptor helpers ---------- */
#if defined(NT_PACKET_DESCRIPTOR_TYPE_DYNAMIC)
  #define DESC_DYN NT_PACKET_DESCRIPTOR_TYPE_DYNAMIC
#elif defined(NT_PACKET_DESCRIPTOR_TYPE_NT_DYNAMIC)
  #define DESC_DYN NT_PACKET_DESCRIPTOR_TYPE_NT_DYNAMIC
#else
  #define DESC_DYN 4u
#endif

/* ---------- (IP,S,C) drop counters ---------- */
typedef struct {
  bool is_v6;
  union { uint32_t v4; uint8_t v6[16]; } ip; // src IP
  uint16_t s_tag;
  uint16_t c_tag;
} drop_key_t;

typedef struct { drop_key_t key; uint64_t count; bool used; } kv_t;
#define MAP_SZ 131072
static kv_t gmap[MAP_SZ];

static uint32_t key_hash(const drop_key_t* k){
  uint32_t h=2166136261u;
  if (k->is_v6){ for(int i=0;i<16;i++){ h^=k->ip.v6[i]; h*=16777619u; } }
  else { const uint8_t* p=(const uint8_t*)&k->ip.v4; for(int i=0;i<4;i++){ h^=p[i]; h*=16777619u; } }
  h^=(k->s_tag&0xFF); h*=16777619u; h^=(k->s_tag>>8); h*=16777619u;
  h^=(k->c_tag&0xFF); h*=16777619u; h^=(k->c_tag>>8); h*=16777619u;
  return h;
}
static kv_t* map_get_or_add(const drop_key_t* k){
  uint32_t idx = key_hash(k) & (MAP_SZ-1);
  for (uint32_t i=0;i<MAP_SZ;i++){
    uint32_t j=(idx+i)&(MAP_SZ-1);
    if (!gmap[j].used){ gmap[j].used=true; gmap[j].key=*k; gmap[j].count=0; return &gmap[j]; }
    if (gmap[j].used &&
        gmap[j].key.is_v6==k->is_v6 &&
        gmap[j].key.s_tag==k->s_tag &&
        gmap[j].key.c_tag==k->c_tag &&
        (!k->is_v6 ? (gmap[j].key.ip.v4==k->ip.v4)
                   : (0==memcmp(gmap[j].key.ip.v6,k->ip.v6,16))))
      return &gmap[j];
  }
  return NULL;
}
static void print_table_periodic(time_t* last){
  time_t now=time(NULL);
  if (now-*last<1) return;
  *last=now;
  printf("\n(IP, S-TAG, C-TAG) -> drops (total)\n");
  int shown=0;
  for (int i=0;i<MAP_SZ;i++) if (gmap[i].used && gmap[i].count>0){
    char ipbuf[INET6_ADDRSTRLEN]={0};
    if (gmap[i].key.is_v6) inet_ntop(AF_INET6, gmap[i].key.ip.v6, ipbuf, sizeof ipbuf);
    else { struct in_addr a; a.s_addr=gmap[i].key.ip.v4; inet_ntop(AF_INET,&a,ipbuf,sizeof ipbuf); }
    printf("%-39s  S=%-5u  C=%-5u  ->  %" PRIu64 "\n",
      ipbuf, gmap[i].key.s_tag, gmap[i].key.c_tag, gmap[i].count);
    if (++shown>=20){ printf("... (showing first 20)\n"); break; }
  }
  fflush(stdout);
}

/* ---------- VLAN/IP parse ---------- */
typedef struct { drop_key_t dk; int l3_off; uint16_t eth; } parse_out_t;
static void parse_vlan_ip_l3off(const uint8_t* l2, uint32_t len, parse_out_t* out){
  memset(out,0,sizeof *out);
  if (len<14){ out->l3_off=-1; return; }
  const uint8_t* p=l2; uint16_t eth=((uint16_t)p[12]<<8)|p[13]; uint16_t s=0,c=0; int off=14;
  for (int i=0;i<2;i++){
    if (eth==0x88A8 || eth==0x8100){
      if (len<off+4){ out->l3_off=-1; return; }
      uint16_t tci=((uint16_t)p[off]<<8)|p[off+1]; uint16_t vid=tci&0x0FFF;
      if (eth==0x88A8 && s==0) s=vid; else if (c==0) c=vid;
      eth=((uint16_t)p[off+2]<<8)|p[off+3]; off+=4;
    } else break;
  }
  out->dk.s_tag=s; out->dk.c_tag=c; out->eth=eth; out->l3_off=off;
  if (eth==0x0800 && len>=off+20){ out->dk.is_v6=false; memcpy(&out->dk.ip.v4, p+off+12,4); }
  else if (eth==0x86DD && len>=off+40){ out->dk.is_v6=true; memcpy(out->dk.ip.v6, p+off+8,16); }
}

/* ---------- Pending by HW correlation key ---------- */
typedef struct {
  bool used;
  uint64_t key64;
  uint64_t ts_ns;
  uint8_t rxp;       // rxPort where first seen
  drop_key_t parsed;
  uint16_t caplen;
  uint8_t* snap;
} pend_t;

#define PEND_SZ 262144
static pend_t pend[PEND_SZ];

static uint32_t khash64(uint64_t k){
  k^=k>>33; k*=0xff51afd7ed558ccdULL; k^=k>>33; k*=0xc4ceb9fe1a85ec53ULL; k^=k>>33;
  return (uint32_t)k;
}
static bool pend_remove_if_opposite(uint64_t key64, uint8_t rxp){
  uint32_t idx = khash64(key64) & (PEND_SZ-1);
  for (uint32_t i=0;i<PEND_SZ;i++){
    uint32_t j=(idx+i)&(PEND_SZ-1);
    if (!pend[j].used) return false;
    if (pend[j].used && pend[j].key64==key64){
      if (pend[j].rxp == rxp) return false; // same side sighting -> not a match
      if (pend[j].snap) free(pend[j].snap);
      pend[j].snap=NULL; pend[j].used=false; return true;
    }
  }
  return false;
}
static void pend_insert(uint64_t key64, uint64_t ts_ns, uint8_t rxp,
                        const drop_key_t* dk,
                        const uint8_t* l2, uint32_t len, uint32_t snaplen){
  uint32_t idx = khash64(key64) & (PEND_SZ-1);
  for (uint32_t i=0;i<PEND_SZ;i++){
    uint32_t j=(idx+i)&(PEND_SZ-1);
    if (!pend[j].used){
      pend[j].used=true; pend[j].key64=key64; pend[j].ts_ns=ts_ns; pend[j].rxp=rxp;
      pend[j].parsed=*dk;
      pend[j].caplen=(uint16_t)((len<snaplen)?len:snaplen);
      pend[j].snap=(uint8_t*)malloc(pend[j].caplen);
      if (pend[j].snap) memcpy(pend[j].snap, l2, pend[j].caplen);
      return;
    }
  }
}
static bool pend_expire_one(uint64_t now_ns, uint64_t win_ns,
                            drop_key_t* out_key, uint8_t** out_snap,
                            uint16_t* out_caplen, uint64_t* out_ts){
  static uint32_t sweep=0;
  for (uint32_t i=0;i<1024;i++){
    sweep=(sweep+1)&(PEND_SZ-1);
    if (!pend[sweep].used) continue;
    if (now_ns - pend[sweep].ts_ns > win_ns){
      *out_key = pend[sweep].parsed;
      *out_snap= pend[sweep].snap;
      *out_caplen= pend[sweep].caplen;
      *out_ts  = pend[sweep].ts_ns;
      pend[sweep].snap=NULL; pend[sweep].used=false; return true;
    }
  }
  return false;
}
static uint32_t pend_count(void){
  uint32_t n=0; for (uint32_t i=0;i<PEND_SZ;i++) if (pend[i].used) n++; return n;
}

/* ---------- PCAP ---------- */
static pcap_t* pcap_dead=NULL; static pcap_dumper_t* pcap_dumpf=NULL;
static void pcap_open_writer(const char* path){
  pcap_dead = pcap_open_dead(DLT_EN10MB, 65535);
  if (!pcap_dead){ fprintf(stderr,"pcap_open_dead failed\n"); exit(1); }
  pcap_dumpf = pcap_dump_open(pcap_dead, path);
  if (!pcap_dumpf){ fprintf(stderr,"pcap_dump_open failed: %s\n", pcap_geterr(pcap_dead)); exit(1); }
  printf("Writing drops to PCAP: %s\n", path);
}
static void pcap_append(const uint8_t* data, uint32_t len, uint64_t ts_ns){
  if (!pcap_dumpf) return;
  struct pcap_pkthdr h; memset(&h,0,sizeof h);
  h.caplen=h.len=len; h.ts.tv_sec = ts_ns/1000000000ULL; h.ts.tv_usec=(ts_ns%1000000000ULL)/1000ULL;
  pcap_dump((u_char*)pcap_dumpf, &h, data);
}

/* ---------- Globals for cleanup ---------- */
static volatile int g_stop=0;
static NtConfigStream_t g_cfg=NULL;
static int g_assign_id=-1;
static NtNetStreamRx_t g_rx=NULL;
static NtStatStream_t g_stat=NULL;
static uint64_t g_seen_pkts = 0;
static uint64_t g_drops_written = 0;
static unsigned g_first_desc = 0;

static void on_signal(int sig){ (void)sig; g_stop=1; }
static void cleanup(void){
  if (g_rx){ NT_NetRxClose(g_rx); g_rx=NULL; }
  if (pcap_dumpf){ pcap_dump_close(pcap_dumpf); pcap_dumpf=NULL; }
  if (pcap_dead){ pcap_close(pcap_dead); pcap_dead=NULL; }
  if (g_stat){ NT_StatClose(g_stat); g_stat=NULL; }
  if (g_cfg){
    NtNtplInfo_t info; char del[32];
    if (g_assign_id>0){
      snprintf(del,sizeof del,"delete=%d", g_assign_id);
      (void)NT_NTPL(g_cfg, del, &info, NT_NTPL_PARSER_VALIDATE_NORMAL);
    }
    NT_ConfigClose(g_cfg); g_cfg=NULL;
  }
  NT_Done();
}

/* ---------- Periodic stats ---------- */
static void stream_stats_periodic(int adapter, int sid, time_t* last){
  time_t now=time(NULL);
  if (now-*last<1) return;
  *last=now;

  if (!g_stat){
    int s=NT_StatOpen(&g_stat, "hStat");
    if (s!=NT_SUCCESS){
      fprintf(stderr,"[stat] NT_StatOpen failed: 0x%08X\n", s);
      return;
    }
  }

  static NtStatistics_t st;
  memset(&st,0,sizeof st);
  st.cmd = NT_STATISTICS_READ_CMD_QUERY_V4;
  st.u.query_v4.poll  = 1;
  st.u.query_v4.clear = 0;

  int rc = NT_StatRead(g_stat, &st);
  if (rc!=NT_SUCCESS){
    fprintf(stderr,"[stat] StatRead rc=0x%08X\n", rc);
    return;
  }

  uint64_t drops = st.u.query_v4.data.stream.streamid[sid].drop.pkts;
  uint64_t flush = st.u.query_v4.data.stream.streamid[sid].flush.pkts;
  fprintf(stderr,"[HB a%d sid%d] seen=%" PRIu64 " pend=%u dropsWritten=%" PRIu64 " hwDrops=%" PRIu64 " hwFlush=%" PRIu64 " desc=%u\n",
          adapter, sid, g_seen_pkts, pend_count(), g_drops_written, drops, flush, g_first_desc);
}

/* ---------- Debug helpers ---------- */
static void dbg_vlan_ip(const uint8_t* l2, uint32_t wire, uint16_t* eth, uint16_t* s, uint16_t* c, char* ip, size_t iplen){
  *eth=0; *s=0; *c=0; ip[0]='\0';
  if (wire<14) return;
  const uint8_t* p=l2; uint16_t e=((uint16_t)p[12]<<8)|p[13]; int off=14;
  for (int i=0;i<2;i++){
    if (e==0x88A8 || e==0x8100){
      if (wire<off+4) break;
      uint16_t tci=((uint16_t)p[off]<<8)|p[off+1]; uint16_t vid=tci&0x0FFF;
      if (e==0x88A8 && *s==0) *s=vid; else if (*c==0) *c=vid;
      e=((uint16_t)p[off+2]<<8)|p[off+3]; off+=4;
    } else break;
  }
  *eth=e;
  if (e==0x0800 && wire>=off+20){
    struct in_addr a; memcpy(&a.s_addr, p+off+12, 4); inet_ntop(AF_INET,&a,ip,iplen);
  } else if (e==0x86DD && wire>=off+40){
    inet_ntop(AF_INET6, p+off+8, ip, iplen);
  }
}

/* ---------- Main ---------- */
int main(int argc, char** argv){
  atexit(cleanup);
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);

  cfg_t cfg; parse_args(argc, argv, &cfg);

  int st = NT_Init(NTAPI_VERSION);
  if (st != NT_SUCCESS) die_err("NT_Init", st);

  uint64_t ntpl_ts = 0;

  /* NTPL (optional in-app) */
  if (!cfg.ext_ntpl){
    NtNtplInfo_t info;
    st = NT_ConfigOpen(&g_cfg, "nt_drop_reader_cfg");
    if (st!=NT_SUCCESS) die_err("NT_ConfigOpen", st);

    st = NT_NTPL(g_cfg, "Delete = All", &info, NT_NTPL_PARSER_VALIDATE_NORMAL);
    if (st!=NT_SUCCESS) die_err("NT_NTPL(Delete=All)", st);
    fprintf(stderr,"NTPL ok: id=%d ts=%" PRIu64 " (Delete)\n", info.ntplId, info.ts);

    st = NT_NTPL(g_cfg, "DeduplicationConfig[ColorBit=1] = GroupID == 0",
                 &info, NT_NTPL_PARSER_VALIDATE_NORMAL);
    if (st!=NT_SUCCESS) die_err("NT_NTPL(DeduplicationConfig)", st);
    fprintf(stderr,"NTPL ok: id=%d ts=%" PRIu64 " (Dedup)\n", info.ntplId, info.ts);

    st = NT_NTPL(g_cfg,
      "Define ckL3 = CorrelationKey(Begin=Layer3Header[0], End=Layer3PayloadEnd[0], DeduplicationGroupID=0)",
      &info, NT_NTPL_PARSER_VALIDATE_NORMAL);
    if (st!=NT_SUCCESS) die_err("NT_NTPL(Define ckL3)", st);
    fprintf(stderr,"NTPL ok: id=%d ts=%" PRIu64 " (Define)\n", info.ntplId, info.ts);

    st = NT_NTPL(g_cfg,
      "Assign[StreamId=0; Descriptor=DYN4, ColorBits=8; CorrelationKey=ckL3] = (Port == 0 OR Port == 1)",
      &info, NT_NTPL_PARSER_VALIDATE_NORMAL);
    if (st!=NT_SUCCESS){
      char eb0[256]={0}, eb1[256]={0}, eb2[256]={0};
      const char *s0 = info.u.errorData.errBuffer[0] ? info.u.errorData.errBuffer[0] : "";
      const char *s1 = info.u.errorData.errBuffer[1] ? info.u.errorData.errBuffer[1] : "";
      const char *s2 = info.u.errorData.errBuffer[2] ? info.u.errorData.errBuffer[2] : "";
      snprintf(eb0, sizeof eb0, "%.*s", (int)sizeof(eb0)-1, s0);
      snprintf(eb1, sizeof eb1, "%.*s", (int)sizeof(eb1)-1, s1);
      snprintf(eb2, sizeof eb2, "%.*s", (int)sizeof(eb2)-1, s2);
      fprintf(stderr,"NTPL Assign failed: err=0x%X\n%s\n%s\n%s\n",
              info.u.errorData.errCode, eb0, eb1, eb2);
      die_err("NT_NTPL(Assign)", st);
    }
    g_assign_id = info.ntplId;
    ntpl_ts = info.ts;
    fprintf(stderr,"NTPL ok: id=%d ts=%" PRIu64 " (Assign)\n", info.ntplId, info.ts);
  } else {
    fprintf(stderr,"[ext_ntpl] Using external NTPL. (No Delete/Assign from app)\n");
  }

  /* Open RX stream bound to adapter + sid */
  st = NT_NetRxOpen(&g_rx, "rx0", NT_NET_INTERFACE_PACKET, cfg.adapter_no, -1);
  if (st!=NT_SUCCESS) die_err("NT_NetRxOpen", st);

  /* Gating */
  if (cfg.no_gate) {
    fprintf(stderr,"[nogate] Starting immediately.\n");
  } else {
    fprintf(stderr,"Gating until packets newer than NTPL ts=%" PRIu64 " ...\n", ntpl_ts);
    if (ntpl_ts==0){
      fprintf(stderr,"NTPL returned ts=0; starting immediately (tolerant gate).\n");
    } else {
      while (!g_stop){
        NtNetBuf_t nb=NULL;
        int rc=NT_NetRxGet(g_rx,&nb,1000);
        if (rc==NT_STATUS_TIMEOUT || rc==NT_STATUS_TRYAGAIN) continue;
        if (rc!=NT_SUCCESS) die_err("NT_NetRxGet(gate)", rc);
        unsigned dt = NT_NET_GET_PKT_DESCRIPTOR_TYPE(nb);
        if (!g_first_desc) g_first_desc = dt;
        if (dt==DESC_DYN){
          NtDyn4Descr_t* d=_NT_NET_GET_PKT_DESCR_PTR_DYN4(nb);
          uint64_t ts = d->timestamp;
          NT_NetRxRelease(g_rx, nb);
          if (ts > ntpl_ts) break;
        } else {
          NT_NetRxRelease(g_rx, nb);
        }
      }
    }
  }
  fprintf(stderr,"Gate passed. Starting capture loop.\n");

  pcap_open_writer(cfg.pcap_path);

  const uint64_t win_ns = (uint64_t)cfg.win_us * 1000ULL;
  uint64_t last_ts_ns = 0;
  time_t last_print=0, last_stat=0;

  while (!g_stop){
    NtNetBuf_t nb=NULL;
    int rc = NT_NetRxGet(g_rx, &nb, 500);
    if (rc==NT_STATUS_TIMEOUT || rc==NT_STATUS_TRYAGAIN){
      // idle: expire a few, print heartbeat
      if (last_ts_ns){
        drop_key_t dk; uint8_t* snap=NULL; uint16_t cap=0; uint64_t ts=0;
        for (int i=0;i<8;i++){
          if (pend_expire_one(last_ts_ns, win_ns, &dk, &snap, &cap, &ts)){
            kv_t* e = map_get_or_add(&dk); if (e) e->count++;
            if (snap){ pcap_append(snap, cap, ts); free(snap); g_drops_written++; }
          } else break;
        }
      }
      print_table_periodic(&last_print);
      stream_stats_periodic(cfg.adapter_no, cfg.sid, &last_stat);
      continue;
    }
    if (rc!=NT_SUCCESS) die_err("NT_NetRxGet", rc);

    unsigned dt = NT_NET_GET_PKT_DESCRIPTOR_TYPE(nb);
    if (!g_first_desc) g_first_desc = dt;
    if (dt!=DESC_DYN){
      fprintf(stderr,"WARN: descriptor=%u; expected DYN. Check Assign Descriptor=DYN4.\n", dt);
      NT_NetRxRelease(g_rx, nb);
      continue;
    }

    NtDyn4Descr_t* d=_NT_NET_GET_PKT_DESCR_PTR_DYN4(nb);
    uint8_t* l2      = (uint8_t*)NT_NET_GET_PKT_L2_PTR(nb);
    uint32_t len     = NT_NET_GET_PKT_WIRE_LENGTH(nb);
    uint64_t ts_ns   = d->timestamp;
    uint64_t key64   = d->color1;   // HW correlation key
    uint8_t  rxp     = d->rxPort;   // typically 1 and 2 on your board

    g_seen_pkts++;
    last_ts_ns = ts_ns;

    if (cfg.debug_print>0 && (int)g_seen_pkts<=cfg.debug_print){
      uint16_t eth=0,s=0,c=0; char ip[64]={0};
      dbg_vlan_ip(l2, len, &eth, &s, &c, ip, sizeof ip);
      fprintf(stderr,"#%-6" PRIu64 " ts=%" PRIu64 " rxPort=%u color0=0x%02x color1=0x%016" PRIx64 " len=%u eth=0x%04x S=%u C=%u src=%s\n",
              g_seen_pkts, ts_ns, rxp, (unsigned)d->color0, key64, len, eth, s, c, ip[0]?ip:"-");
    }

    // Parse once (only needed if this later becomes a drop)
    parse_out_t po; parse_vlan_ip_l3off(l2, len, &po);

    // Match/pend logic: require opposite port to clear
    if (!pend_remove_if_opposite(key64, rxp)){
      pend_insert(key64, ts_ns, rxp, &po.dk, l2, len, cfg.snaplen);
    }

    NT_NetRxRelease(g_rx, nb);

    // opportunistic expiries
    drop_key_t dk; uint8_t* snap=NULL; uint16_t cap=0; uint64_t ts=0;
    for (int i=0;i<4;i++){
      if (pend_expire_one(last_ts_ns, win_ns, &dk, &snap, &cap, &ts)){
        kv_t* e = map_get_or_add(&dk); if (e) e->count++;
        if (snap){ pcap_append(snap, cap, ts); free(snap); g_drops_written++; }
      } else break;
    }

    print_table_periodic(&last_print);
    stream_stats_periodic(cfg.adapter_no, cfg.sid, &last_stat);
  }

  return 0; // cleanup via atexit()
}
