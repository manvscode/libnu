/* Copyright (C) 2013 by Joseph A. Marrero, http://www.manvscode.com/
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifndef _NETUTILS_H_
#define _NETUTILS_H_
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/un.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(WIN32) || defined(WIN64)
#include <windows.h>
#else
#include <unistd.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif

#define NETUTILS_IP4_HDRLEN      20         /* IPv4 header length */
#define NETUTILS_ICMP_HDRLEN     ICMP_MINLEN         /* ICMP header length. This is 8. */

#define  netutils_tcp_socket()          socket( AF_INET, SOCK_STREAM, 0 )
#define  netutils_udp_socket()          socket( AF_INET, SOCK_DGRAM, 0 )
#define  netutils_raw_socket(proto)     socket( AF_INET, SOCK_RAW, proto )

bool        netutils_resolve_hostname       ( const char* hostname, struct in_addr* ip );
bool        netutils_address_from_ip_string ( const char* ip_str, struct in_addr* ip );
const char* netutils_address_to_string      ( struct in_addr ip );
void        netutils_address_to_string_r    ( struct in_addr ip, char* str, size_t str_size );
void        netutils_set_ipaddress          ( struct sockaddr_in* addr, struct in_addr ip, uint16_t port );
uint16_t    netutils_checksum               ( const void* data, size_t len );

#if defined(NDEBUG) || defined(DEBUG_NETUTILS)
void print_ip_header( struct ip *ip );
#define trace(...) fprintf( stderr, __VA_ARGS__ )
#else
#define trace(...) 
#endif

typedef struct packet {
	struct ip ip_header;
	uint8_t payload[];
} packet_t;

packet_t* netutils_packet_create          ( uint8_t protocol, struct in_addr ip_src, struct in_addr ip_dst, size_t payload_size );
void      netutils_packet_destroy         ( packet_t** p_packet );
void      netutils_packet_recalc_checksum ( packet_t* packet, size_t payload_size );
packet_t* netutils_icmp_packet_create     ( uint8_t icmp_type, struct in_addr ip_src, struct in_addr ip_dst, const void* payload, size_t payload_size );


bool netutils_icmp_echo( struct in_addr src, struct in_addr dst, uint8_t ttl /* max = MAXTTL */ );

/*
typedef struct icmp_packet {
	struct ip ip_header;
	struct icmp icmp_header;
	uint8_t payload[];
} icmp_packet_t;

typedef struct tcp_packet {
	struct ip ip_header;
	struct tcphdr tcp_header;
	uint8_t payload[];
} tcp_packet_t;

typedef struct udp_packet {
	struct ip ip_header;
	struct udphdr udp_header;
	uint8_t payload[];
} udp_packet_t;

typedef struct packet {
	union {
		icmp_packet_t* icmp;
		tcp_packet_t*  tcp;
		udp_packet_t*  udp;
	};
} packet_t;
*/





#ifdef __cplusplus
} /* C linkage */
#endif
#endif /* _NETUTILS_H_ */
