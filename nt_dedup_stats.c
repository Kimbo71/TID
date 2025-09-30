#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#include <nt.h>
#include <ntapi/stream_statistics.h>

static void die_nt(const char* where, int status) {
  char buf[NT_ERRBUF_SIZE];
  NT_ExplainError(status, buf, sizeof buf);
  fprintf(stderr, "%s failed: %s (0x%08X)\n", where, buf, status);
  exit(EXIT_FAILURE);
}

static void nanosleep_interval(double seconds) {
  if (seconds <= 0.0)
    return;
  struct timespec ts;
  ts.tv_sec = (time_t)seconds;
  ts.tv_nsec = (long)((seconds - ts.tv_sec) * 1e9);
  if (ts.tv_nsec < 0) ts.tv_nsec = 0;
  nanosleep(&ts, NULL);
}

int main(int argc, char** argv) {
  int adapter = 0;
  int clear_after = 0;
  double interval = 1.0;

  static struct option long_opts[] = {
    {"adapter",  required_argument, NULL, 'a'},
    {"interval", required_argument, NULL, 'i'},
    {"clear",    no_argument,       NULL, 'c'},
    {NULL, 0, NULL, 0}
  };

  int opt;
  while ((opt = getopt_long(argc, argv, "a:i:c", long_opts, NULL)) != -1) {
    switch (opt) {
      case 'a': adapter = atoi(optarg); break;
      case 'i': interval = atof(optarg); if (interval <= 0.0) interval = 1.0; break;
      case 'c': clear_after = 1; break;
      default:
        fprintf(stderr, "Usage: %s [--adapter=N] [--interval=SEC] [--clear]\n", argv[0]);
        return EXIT_FAILURE;
    }
  }

  int status = NT_Init(NTAPI_VERSION);
  if (status != NT_SUCCESS)
    die_nt("NT_Init", status);

  NtStatStream_t hStat = NULL;
  status = NT_StatOpen(&hStat, "dedup_stats");
  if (status != NT_SUCCESS)
    die_nt("NT_StatOpen", status);

  NtStatistics_t stat_before, stat_after;
  memset(&stat_before, 0, sizeof stat_before);
  stat_before.cmd = NT_STATISTICS_READ_CMD_QUERY_V4;
  stat_before.u.query_v4.poll = 1;
  stat_before.u.query_v4.clear = 0;

  status = NT_StatRead(hStat, &stat_before);
  if (status != NT_SUCCESS)
    die_nt("NT_StatRead", status);

  const struct NtStatisticsQueryPortResult_v4_s* port_before = &stat_before.u.query_v4.data.port;
  uint8_t numPorts = port_before->numPorts;

  uint64_t* rx_pkts0 = calloc(numPorts, sizeof(uint64_t));
  uint64_t* rx_octets0 = calloc(numPorts, sizeof(uint64_t));
  uint64_t* dedup_pkts0 = calloc(numPorts, sizeof(uint64_t));
  uint64_t* dedup_octets0 = calloc(numPorts, sizeof(uint64_t));
  if (!rx_pkts0 || !rx_octets0 || !dedup_pkts0 || !dedup_octets0) {
    fprintf(stderr, "memory allocation failure\n");
    return EXIT_FAILURE;
  }

  for (uint8_t p = 0; p < numPorts; ++p) {
    const struct NtPortStatistics_v3_s* rx = &port_before->aPorts[p].rx;
    rx_pkts0[p] = rx->RMON1.pkts;
    rx_octets0[p] = rx->RMON1.octets;
    if (rx->valid.extDrop) {
      dedup_pkts0[p] = rx->extDrop.pktsDedup;
      dedup_octets0[p] = rx->extDrop.octetsDedup;
    }
  }

  nanosleep_interval(interval);

  memset(&stat_after, 0, sizeof stat_after);
  stat_after.cmd = NT_STATISTICS_READ_CMD_QUERY_V4;
  stat_after.u.query_v4.poll = 1;
  stat_after.u.query_v4.clear = clear_after;
  status = NT_StatRead(hStat, &stat_after);
  if (status != NT_SUCCESS)
    die_nt("NT_StatRead", status);

  const struct NtStatisticsQueryPortResult_v4_s* port_after = &stat_after.u.query_v4.data.port;

  printf("Adapter %d port statistics over %.3f s\n", adapter, interval);
  printf("%-4s %20s %20s %12s\n", "Port", "rx_pkts", "rx_octets", "rx_Gbps");
  printf("%-4s %20s %20s\n", "", "pktsDedup", "octetsDedup");

  for (uint8_t p = 0; p < numPorts; ++p) {
    const struct NtPortStatistics_v3_s* rx = &port_after->aPorts[p].rx;
    uint64_t rx_pkts = rx->RMON1.pkts - rx_pkts0[p];
    uint64_t rx_octets = rx->RMON1.octets - rx_octets0[p];
    double rx_gbps = interval > 0.0 ? ((double)rx_octets * 8.0) / interval / 1e9 : 0.0;

    uint64_t dpkts = 0;
    uint64_t doctets = 0;
    if (rx->valid.extDrop) {
      dpkts = rx->extDrop.pktsDedup - dedup_pkts0[p];
      doctets = rx->extDrop.octetsDedup - dedup_octets0[p];
    }

    printf("%-4u %20" PRIu64 " %20" PRIu64 " %12.3f\n", p, rx_pkts, rx_octets, rx_gbps);
    printf("%-4s %20" PRIu64 " %20" PRIu64 "\n", "", dpkts, doctets);
  }

  free(rx_pkts0);
  free(rx_octets0);
  free(dedup_pkts0);
  free(dedup_octets0);

  NT_StatClose(hStat);
  NT_Done();
  return 0;
}
