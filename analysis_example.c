/*
 *
 * Copyright 2025 Napatech A/S. All Rights Reserved.
 *
 * 1. Copying, modification, and distribution of this file, or executable
 * versions of this file, is governed by the terms of the Napatech Software
 * license agreement under which this file was made available. If you do not
 * agree to the terms of the license do not install, copy, access or
 * otherwise use this file.
 *
 * 2. Under the Napatech Software license agreement you are granted a
 * limited, non-exclusive, non-assignable, copyright license to copy, modify
 * and distribute this file in conjunction with Napatech SmartNIC's and
 * similar hardware manufactured or supplied by Napatech A/S.
 *
 * 3. The full Napatech Software License Agreement is included in this
 * distribution, please see "NA-0009 Software License Agreement.pdf"
 *
 * 4. Redistributions of source code must retain this copyright notice,
 * list of conditions and the following disclaimer.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTIES, EXPRESS OR
 * IMPLIED, AND NAPATECH DISCLAIMS ALL IMPLIED WARRANTIES INCLUDING ANY
 * IMPLIED WARRANTY OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, OR OF
 * FITNESS FOR A PARTICULAR PURPOSE. TO THE EXTENT NOT PROHIBITED BY
 * APPLICABLE LAW, IN NO EVENT SHALL NAPATECH BE LIABLE FOR PERSONAL INJURY,
 * OR ANY INCIDENTAL, SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES WHATSOEVER,
 * INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF PROFITS, CORRUPTION OR
 * LOSS OF DATA, FAILURE TO TRANSMIT OR RECEIVE ANY DATA OR INFORMATION,
 * BUSINESS INTERRUPTION OR ANY OTHER COMMERCIAL DAMAGES OR LOSSES, ARISING
 * OUT OF OR RELATED TO YOUR USE OR INABILITY TO USE NAPATECH SOFTWARE OR
 * SERVICES OR ANY THIRD PARTY SOFTWARE OR APPLICATIONS IN CONJUNCTION WITH
 * THE NAPATECH SOFTWARE OR SERVICES, HOWEVER CAUSED, REGARDLESS OF THE THEORY
 * OF LIABILITY (CONTRACT, TORT OR OTHERWISE) AND EVEN IF NAPATECH HAS BEEN
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. SOME JURISDICTIONS DO NOT ALLOW
 * THE EXCLUSION OR LIMITATION OF LIABILITY FOR PERSONAL INJURY, OR OF
 * INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THIS LIMITATION MAY NOT APPLY TO YOU.
 *
 *
 */
/**
 * @example net/analysis/analysis_example.c
 * @section analysis_example_description Description
 *
 * This source file is an example of how to do realtime analysis of packets
 * using NTAPI.
 *
 * The following NTAPI functions are used:
 * - @ref NT_Init()
 * - @ref NT_ConfigOpen()
 * - @ref NT_NetRxOpen()
 * - @ref NT_NTPL()
 * - @ref NT_NetRxGet()
 *   - @ref NT_NET_GET_PKT_DESCRIPTOR_TYPE()
 *   - @ref NT_NET_GET_PKT_TIMESTAMP()
 *   - @ref NT_NET_GET_PKT_WIRE_LENGTH()
 *   - @ref NT_NET_GET_PKT_L2_PTR()
 * - @ref NT_NetRxRelease()
 * - @ref NT_NetRxClose()
 * - @ref NT_ConfigClose()
 * - @ref NT_ExplainError()
 *
 * @note
 * This example does not work with the NT4E-STD accelerator
 *
 * <hr>
 * @section analysis_example_prerequisites Prerequisites
 * A Napatech capture accelerator is needed to run this example. The ntservice.ini must
 * have at least one HostBuffersRx defined. Below is an example of a
 * minimum ini-file. It will create a 32MB RX hostbuffer from NUMA
 * node 0.
 * @code
 * [System]
 * TimestampFormat = NATIVE
 *
 * [Adapter0]
 * AdapterType     = NT20E
 * BusId           = 00:0a:00.00
 * HostBuffersRx   = [1,32,0]
 * @endcode
 *
 * @section analysis_example_flow Program flow
 * @{
 * The following is required to perform real-time analysis on packets:
 * - \#include/nt.h - Applications/Tools only need to include @ref
 *   nt.h to obtain prototypes, macros etc. from NTAPI.
 * - @ref NT_Init(@ref NTAPI_VERSION) - Initialize the NTAPI
 *   library. @ref NTAPI_VERSION is a define that describes the version
 *   of the API described in the header files included by @ref
 *   nt.h. NT_Init() will ask the NTAPI library to convert return data
 *   to the @ref NTAPI_VERSION if possible. This will ensure that
 *   applications can run on NTAPI libraries of newer versions.
 * - @ref NT_ConfigOpen() - Open a config stream in order to setup
 *   filter using the @ref NT_NTPL() command.
 * - @ref NT_NetRxOpen() - Open a stream. The stream ID must match the
 *   one used when creating the filter using the @ref NT_NTPL()
 *   command. A stream does not return data until traffic is assigned
 *   to it by creating a filter. Stream IDs might be shared between
 *   other streams and it is possible to make several filters to one
 *   stream ID. Each filter can have a unique color in the ASSIGN. The
 *   "color" of the ASSIGN can be used to mark packets making it
 *   possible for the stream to determine if the packets it receives
 *   via @ref NT_NetRxGet() as based on its assign or if the packet belongs
 *   to the other streams that also share the hostbuffer.
 * - @ref NT_NTPL() - Assign traffic to a stream by creating a filter
 *   using a manually chosen stream ID. The stream ID must match the
 *   one used @ref NT_NetRxOpen().
 * - Optional step. Wait until we start seeing packets that are hit by
 *   the NTPL assign command.  This is done to avoid getting packets
 *   that are not fully classified by the stream.  NT_NetRxGet() is
 *   called with a timeout of 1000ms and will return NT_STATUS_TIMEOUT
 *   in case nothing is received within 1000ms and will return
 *   NT_SUCCESS if something is returned. Return values different from
 *   that is an indication of an error. Packets that are prior to the
 *   expected time are released via NT_NetRxRelease().
 * - NT_NetRxGet() and NT_NetRxRelease() - Receive and release packets. Each received packet is printed with help of the @ref PacketMacros
 *   - @ref NT_NET_GET_PKT_DESCRIPTOR_TYPE() - Get the descriptor type (@ref NT_PACKET_DESCRIPTOR_TYPE_PCAP, @ref NT_PACKET_DESCRIPTOR_TYPE_NT, @ref NT_PACKET_DESCRIPTOR_TYPE_NT_EXTENDED).
 *   - @ref NT_NET_GET_PKT_TIMESTAMP() - Get the timestamp of the packet.
 *   - @ref NT_NET_GET_PKT_WIRE_LENGTH() - Get the wire length of the packet.
 *   - @ref NT_NET_GET_PKT_L2_PTR() - Get a pointer to the L2 part of the packet, which is where SW decoding would start.
 * - NT_NetRxClose() - Close the stream when terminating. This will
 *   close the stream and release the NTPL assignment made on the
 *   hostbuffer.
 *
 *<hr>
 * @section analysis_example_code Code
 * @}
 */
// Include this in order to access the Napatech API
#include <nt.h>
#if defined(WIN32) || defined (WIN64)
  #define snprintf(dst, ...)    _snprintf_s((dst), _countof(dst), __VA_ARGS__)
#endif
int main(void)
{
  int numPackets = 0;               // The number of packets received
  int numBytes = 0;                 // The number of bytes received (wire length)
  char tmpBuffer[20];             // Buffer to build filter string
  char errorBuffer[NT_ERRBUF_SIZE];           // Error buffer
  int status;                     // Status variable
  NtNetStreamRx_t hNetRx;           // Handle to the RX stream
  NtConfigStream_t hCfgStream;      // Handle to a config stream
  NtNtplInfo_t ntplInfo;            // Return data structure from the NT_NTPL() call.
  NtNetBuf_t hNetBuf;               // Net buffer container. Packet data is returned in this when calling NT_NetRxGet().
  // Initialize the NTAPI library and thereby check if NTAPI_VERSION can be used together with this library
  if ((status = NT_Init(NTAPI_VERSION)) != NT_SUCCESS) {
    // Get the status code as text
    NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
    fprintf(stderr, "NT_Init() failed: %s\n", errorBuffer);
    return -1;
  }
  // Open a config stream to assign a filter to a stream ID.
  if ((status = NT_ConfigOpen(&hCfgStream, "TestStream")) != NT_SUCCESS) {
    // Get the status code as text
    NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
    fprintf(stderr, "NT_ConfigOpen() failed: %s\n", errorBuffer);
    return -1;
  }
  // Assign traffic to stream ID 1 and mask all traffic matching the assign statement color=7.
  if ((status = NT_NTPL(hCfgStream, "Assign[streamid=1;color=7] = All", &ntplInfo, NT_NTPL_PARSER_VALIDATE_NORMAL)) != NT_SUCCESS) {
    // Get the status code as text
    NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
    fprintf(stderr, "NT_NTPL() failed: %s\n", errorBuffer);
    fprintf(stderr, ">>> NTPL errorcode: %X\n", ntplInfo.u.errorData.errCode);
    fprintf(stderr, ">>> %s\n", ntplInfo.u.errorData.errBuffer[0]);
    fprintf(stderr, ">>> %s\n", ntplInfo.u.errorData.errBuffer[1]);
    fprintf(stderr, ">>> %s\n", ntplInfo.u.errorData.errBuffer[2]);
    return -1;
  }
  // Open stat stream
  NtStatStream_t hStat = NULL;
  if ((status = NT_StatOpen(&hStat, "hStat")) != 0) {
    fprintf(stderr, "Failed to create statistics stream: 0x%08X\n", status);
    return -1;
  }
  // Reset stats
  static NtStatistics_t statSet;
  statSet.cmd = NT_STATISTICS_READ_CMD_QUERY_V4;
  statSet.u.query_v4.poll = 1;
  statSet.u.query_v4.clear = 1;
  if ((status = NT_StatRead(hStat, &statSet))) {
    fprintf(stderr, "Failed resetting statistics: 0x%08X\n", status);
    return -1;
  }
  // Get a stream handle with the hostBuffer mapped to it. NT_NET_INTERFACE_PACKET specify that we will receive data packet-by-packet
  if ((status = NT_NetRxOpen(&hNetRx, "TestStream", NT_NET_INTERFACE_PACKET, 1, -1)) != NT_SUCCESS) {
    // Get the status code as text
    NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
    fprintf(stderr, "NT_NetRxOpen() failed: %s\n", errorBuffer);
    return -1;
  }
  // Optional step. Wait for the first packet that hit the NTPL assign command
  printf("Waiting for the first packet\n");
  while (1) {
    if ((status = NT_NetRxGet(hNetRx, &hNetBuf, 1000)) != NT_SUCCESS) {
      if ((status == NT_STATUS_TIMEOUT) || (status == NT_STATUS_TRYAGAIN)) {
        // Timeouts are ok, we just need to wait a little longer for a packet
        continue;
      }
      // Get the status code as text
      NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
      fprintf(stderr, "NT_NetRxGet() failed: %s\n", errorBuffer);
      return -1;
    }
    // We got a packet. Check if the timestamp is newer than when the NTPL assign command was applied
    if (NT_NET_GET_PKT_TIMESTAMP(hNetBuf) > ntplInfo.ts) {
      break; // Break out, we have received a packet that is received after the NTPL assign command was applied
    }
    // Release the packet, it is too "old".
    if ((status = NT_NetRxRelease(hNetRx, hNetBuf)) != NT_SUCCESS) {
      // Get the status code as text
      NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
      fprintf(stderr, "NT_NetRxRelease() failed: %s\n", errorBuffer);
      return -1;
    }
  }
  // Dump packet info. Stop when 100 packets has been received
  while (1) {
    struct _mac {
      uint8_t dst[6];
      uint8_t src[6];
      uint16_t typelen;
    } *mac = (struct _mac*) NT_NET_GET_PKT_L2_PTR(hNetBuf);
    printf("#%03d: %6s %016llX - %04d - %02X:%02X:%02X:%02X:%02X:%02X  %02X:%02X:%02X:%02X:%02X:%02X  %04x\n",
           numPackets+1,
           (NT_NET_GET_PKT_DESCRIPTOR_TYPE(hNetBuf)==NT_PACKET_DESCRIPTOR_TYPE_PCAP?"PCAP":
            NT_NET_GET_PKT_DESCRIPTOR_TYPE(hNetBuf)==NT_PACKET_DESCRIPTOR_TYPE_NT?"NT":
            NT_NET_GET_PKT_DESCRIPTOR_TYPE(hNetBuf)==NT_PACKET_DESCRIPTOR_TYPE_NT_EXTENDED?"NT_EXT":"Unknown"),
           (unsigned long long)NT_NET_GET_PKT_TIMESTAMP(hNetBuf),
           NT_NET_GET_PKT_WIRE_LENGTH(hNetBuf),
           mac->dst[0], mac->dst[1], mac->dst[2], mac->dst[3], mac->dst[4], mac->dst[5],
           mac->src[0], mac->src[1], mac->src[2], mac->src[3], mac->src[4], mac->src[5],
           mac->typelen);
    // Increment the number of packets processed.
    numPackets++;
    // Increment the bytes received
    numBytes += NT_NET_GET_PKT_WIRE_LENGTH(hNetBuf);
    // Release the current packet
    if ((status = NT_NetRxRelease(hNetRx, hNetBuf)) != NT_SUCCESS) {
      // Get the status code as text
      NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
      fprintf(stderr, "NT_NetRxGet() failed: %s\n", errorBuffer);
      return -1;
    }
    if (numPackets == 100) {
      break;
    }
    // Get the next packet
    while (1) {
      if ((status = NT_NetRxGet(hNetRx, &hNetBuf, 1000)) != NT_SUCCESS) {
        if ((status == NT_STATUS_TIMEOUT)  || (status == NT_STATUS_TRYAGAIN)) {
          // Timeouts are ok, we just need to wait a little longer for a packet
          continue;
        }
        // Get the status code as text
        NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
        fprintf(stderr, "NT_NetRxGet() failed: %s\n", errorBuffer);
        return -1;
      }
      break; // We got a packet
    }
  }
  // Close the stream and release the hostbuffer
  NT_NetRxClose(hNetRx);
  // Request stats
  statSet.cmd = NT_STATISTICS_READ_CMD_QUERY_V4;
  statSet.u.query_v4.poll = 1;
  statSet.u.query_v4.clear = 0;
  if ((status = NT_StatRead(hStat, &statSet)) != NT_SUCCESS) {
    fprintf(stderr, "Failed reading statistics: 0x%08X\n", status);
    return -1;
  }
  // Read drop counters for streamid 1
  uint64_t totDropsPkts = statSet.u.query_v4.data.stream.streamid[1].drop.pkts;
  uint64_t totDropsBytes = statSet.u.query_v4.data.stream.streamid[1].drop.octets;
  // Close stat stream
  NT_StatClose(hStat);
  // Delete the filter
  snprintf(tmpBuffer, sizeof(tmpBuffer), "delete=%d", ntplInfo.ntplId);
  if ((status = NT_NTPL(hCfgStream, tmpBuffer, &ntplInfo, NT_NTPL_PARSER_VALIDATE_NORMAL)) != NT_SUCCESS) {
    // Get the status code as text
    NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
    fprintf(stderr, "NT_NTPL() failed: %s\n", errorBuffer);
    fprintf(stderr, ">>> NTPL errorcode: %X\n", ntplInfo.u.errorData.errCode);
    fprintf(stderr, ">>> %s\n", ntplInfo.u.errorData.errBuffer[0]);
    fprintf(stderr, ">>> %s\n", ntplInfo.u.errorData.errBuffer[1]);
    fprintf(stderr, ">>> %s\n", ntplInfo.u.errorData.errBuffer[2]);
    return -1;
  }
  // Close the config stream
  if ((status = NT_ConfigClose(hCfgStream)) != NT_SUCCESS) {
    // Get the status code as text
    NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
    fprintf(stderr, "NT_ConfigClose() failed: %s\n", errorBuffer);
    return -1;
  }
  // Output totals
  printf("Drop: %lu packets, %lu bytes\n", totDropsPkts, totDropsBytes);
  printf("Done: %d packets, %d bytes\n", numPackets, numBytes);
  // Close down the NTAPI library
  NT_Done();
  return 0;
}
//
// EOF
//
