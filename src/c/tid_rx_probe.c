/*
 * tid_rx_probe — tiny RX stream verifier
 * --------------------------------------
 * Opens an RX stream (NT_NET_INTERFACE_PACKET) on a given StreamId
 * and prints a few packets (descriptor type, rxPort, lengths).
 *
 * Build:
 *  gcc -std=gnu11 -O2 -Wall -Wextra \
 *      -I/opt/napatech3/include -I/opt/napatech3/include/ntapi \
 *      tid_rx_probe.c -L/opt/napatech3/lib -lntapi -o tid_rx_probe
 *
 * Usage:
 *  ./tid_rx_probe --sid=0 --max=20 --timeout=1000
 *  Options: --sid=N (default 0), --max=N (default 20), --timeout=ms (default 1000)
 *
 * Notes:
 *  - The StreamId (SID) must match your NTPL Assign rules.
 *  - Descriptor type DYN4 or DYN3 is expected; rxPort is read accordingly.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <getopt.h>

#include <nt.h>
#include <ntapi/pktdescr.h>
#include <ntapi/pktdescr_dyn3.h>
#include <ntapi/pktdescr_dyn4.h>

static volatile sig_atomic_t g_run = 1;
static void on_sigint(int sig){ (void)sig; g_run = 0; }

static void die_nt(const char* where, int status){
  char buf[NT_ERRBUF_SIZE];
  NT_ExplainError(status, buf, sizeof buf);
  fprintf(stderr, "%s failed: %s (0x%08X)\n", where, buf, status);
  exit(EXIT_FAILURE);
}

int main(int argc, char** argv){
  int sid = 0; int max = 20; int timeout_ms = 1000;
  static struct option opts[] = {
    {"sid", required_argument, NULL, 1001},
    {"max", required_argument, NULL, 1002},
    {"timeout", required_argument, NULL, 1003},
    {NULL,0,NULL,0}
  };
  int c; while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1){
    switch(c){
      case 1001: sid = atoi(optarg); break;
      case 1002: max = atoi(optarg); if (max < 0) max = 0; break;
      case 1003: timeout_ms = atoi(optarg); if (timeout_ms < 0) timeout_ms = 0; break;
      default:
        fprintf(stderr, "Usage: %s [--sid=N] [--max=N] [--timeout=ms]\n", argv[0]);
        return 1;
    }
  }

  signal(SIGINT, on_sigint);

  int st = NT_Init(NTAPI_VERSION);
  if (st != NT_SUCCESS) die_nt("NT_Init", st);

  NtNetStreamRx_t hNetRx = NULL;
  st = NT_NetRxOpen(&hNetRx, "tid_rx_probe", NT_NET_INTERFACE_PACKET, (uint32_t)sid, -1);
  if (st != NT_SUCCESS) die_nt("NT_NetRxOpen", st);

  printf("Probing adapter=0 sid=%d timeout=%dms max=%d\n", sid, timeout_ms, max);
  int printed = 0; int timeouts = 0;
  while (g_run && (max == 0 || printed < max)){
    NtNetBuf_t nb = NULL;
    st = NT_NetRxGet(hNetRx, &nb, timeout_ms);
    if (st == NT_STATUS_TIMEOUT || st == NT_STATUS_TRYAGAIN){
      puts("timeout");
      if (++timeouts > 100 && max == 0) break;
      continue;
    }
    if (st != NT_SUCCESS) continue;

    unsigned dtp = NT_NET_GET_PKT_DESCRIPTOR_TYPE(nb);
    uint8_t* l2   = (uint8_t*)NT_NET_GET_PKT_L2_PTR(nb);
    (void)l2;
    uint32_t cap  = NT_NET_GET_PKT_CAP_LENGTH(nb);
    uint32_t wire = NT_NET_GET_PKT_WIRE_LENGTH(nb);
    uint8_t rxp   = 255;
    if (dtp == 4){ rxp = _NT_NET_GET_PKT_DESCR_PTR_DYN4(nb)->rxPort; }
    else if (dtp == 3 || dtp == NT_PACKET_DESCRIPTOR_TYPE_DYNAMIC){ rxp = _NT_NET_GET_PKT_DESCR_PTR_DYN3(nb)->rxPort; }
    printf("pkt#%d dt=%u rxPort=%u len=%u\n", printed+1, dtp, rxp, wire ? wire : cap);
    printed++;
    NT_NetRxRelease(hNetRx, nb);
  }

  NT_NetRxClose(hNetRx);
  NT_Done();
  return 0;
}

