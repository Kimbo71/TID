#define _GNU_SOURCE
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const uint8_t* safe_advance(const uint8_t* base, size_t len, size_t offset, size_t need) {
  if (offset + need > len) return NULL;
  return base + offset;
}

static void print_mac(const uint8_t* mac, char* buf, size_t buflen) {
  snprintf(buf, buflen, "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void usage(const char* argv0) {
  fprintf(stderr, "Usage: %s [-c limit] <pcap-file>\n", argv0);
}

int main(int argc, char** argv) {
  int opt;
  int64_t limit = -1;

  while ((opt = getopt(argc, argv, "c:")) != -1) {
    switch (opt) {
      case 'c':
        limit = atoll(optarg);
        if (limit < 0) {
          fprintf(stderr, "-c requires a non-negative integer\n");
          return EXIT_FAILURE;
        }
        break;
      default:
        usage(argv[0]);
        return EXIT_FAILURE;
    }
  }

  if (optind >= argc) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  const char* filename = argv[optind];

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_offline(filename, errbuf);
  if (!handle) {
    fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
    return EXIT_FAILURE;
  }

  int ts_precision = pcap_get_tstamp_precision(handle);
  printf("frame\ttimestamp(ns)\tframe.len\teth.src\teth.dst\tip.src\tip.dst\tSvlan\tCvlan\n");

  struct pcap_pkthdr header;
  const uint8_t* data;
  uint64_t frame_no = 0;

  while ((data = (const uint8_t*)pcap_next(handle, &header)) != NULL) {
    frame_no++;
    size_t caplen = header.caplen;
    if (caplen < 14) {
      continue;
    }

    char eth_src[18], eth_dst[18];
    print_mac(data + 6, eth_src, sizeof eth_src);
    print_mac(data + 0, eth_dst, sizeof eth_dst);

    size_t offset = 12;
    uint16_t ethertype = (uint16_t)((data[offset] << 8) | data[offset + 1]);
    offset += 2;

    int s_vlan = -1;
    int c_vlan = -1;

    while (ethertype == 0x8100 || ethertype == 0x88A8 || ethertype == 0x9100 || ethertype == 0x9200) {
      const uint8_t* tag_ptr = safe_advance(data, caplen, offset, 4);
      if (!tag_ptr) break;
      uint16_t tci = (uint16_t)((tag_ptr[0] << 8) | tag_ptr[1]);
      ethertype = (uint16_t)((tag_ptr[2] << 8) | tag_ptr[3]);
      offset += 4;
      int vlan_id = tci & 0x0FFF;
      if (s_vlan < 0)
        s_vlan = vlan_id;
      else if (c_vlan < 0)
        c_vlan = vlan_id;
    }

    const char* ip_src = "-";
    const char* ip_dst = "-";
    char ip_src_buf[INET_ADDRSTRLEN];
    char ip_dst_buf[INET_ADDRSTRLEN];

    if (ethertype == 0x0800) {  // IPv4
      const uint8_t* ip_hdr = safe_advance(data, caplen, offset, 20);
      if (ip_hdr) {
        inet_ntop(AF_INET, ip_hdr + 12, ip_src_buf, sizeof ip_src_buf);
        inet_ntop(AF_INET, ip_hdr + 16, ip_dst_buf, sizeof ip_dst_buf);
        ip_src = ip_src_buf;
        ip_dst = ip_dst_buf;
      }
    }

    long sec = (long)header.ts.tv_sec;
    long nsec;
    if (ts_precision == PCAP_TSTAMP_PRECISION_NANO) {
      nsec = (long)header.ts.tv_usec; // tv_usec holds nanoseconds in nano-precision captures
    } else {
      nsec = (long)header.ts.tv_usec * 1000L;
    }
    if (nsec >= 1000000000L) {
      sec += nsec / 1000000000L;
      nsec %= 1000000000L;
    }

    printf("%" PRIu64 "\t%ld.%09ld\t%u\t%s\t%s\t%s\t%s\t",
           frame_no,
           sec,
           nsec,
           header.len,
           eth_src,
           eth_dst,
           ip_src,
           ip_dst);

    if (s_vlan >= 0)
      printf("%d\t", s_vlan);
    else
      printf("-\t");

    if (c_vlan >= 0)
      printf("%d\n", c_vlan);
    else
      printf("-\n");
    if (limit >= 0 && (int64_t)frame_no >= limit) {
      break;
    }
  }

  pcap_close(handle);
  return EXIT_SUCCESS;
}
