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
#ifndef __USE_BSD
#define __USE_BSD
#endif
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h> /* symlink missing headers for iOS */
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

#define NETUTILS_IP4_HDRLEN               20           /* IPv4 header length */
#define NETUTILS_ICMP_HDRLEN              ICMP_MINLEN  /* ICMP header length. This is 8. */
#define NETUTILS_UDP_HDRLEN               8            /* UDP header length. */
#define NETUTILS_MAX_RETRIES              2
//#define NETUTILS_ICMP_INCLUDE_IP4_HEADER  1

typedef enum nu_result {
	NETUTILS_TRYAGAIN = -1,
	NETUTILS_FAILED   =  0,
	NETUTILS_SUCCESS  =  1
} nu_result_t;

#define  nu_tcp_socket()          socket( AF_INET, SOCK_STREAM, 0 )
#define  nu_udp_socket()          socket( AF_INET, SOCK_DGRAM, 0 )
#define  nu_raw_socket(proto)     socket( AF_INET, SOCK_RAW, proto )

bool        nu_resolve_hostname       ( const char* hostname, struct in_addr* ip );
bool        nu_address_from_ip_string ( const char* ip_str, struct in_addr* ip );
const char* nu_address_to_string      ( struct in_addr ip );
void        nu_address_to_string_r    ( struct in_addr ip, char* str, size_t str_size );
void        nu_set_ipaddress          ( struct sockaddr_in* addr, struct in_addr ip, uint16_t port );
uint16_t    nu_checksum               ( const void* data, size_t len );
bool        nu_set_include_header     ( int socket, bool include_header );
bool        nu_set_timeout            ( int socket, uint32_t timeout );
bool        nu_set_ttl                ( int socket, uint8_t ttl /* max = MAXTTL */ );
uint8_t     nu_get_ttl                ( int socket );
bool        nu_send                   ( int socket, const uint8_t* data, size_t size );
nu_result_t nu_send_async             ( int socket, const void* data, size_t size );
bool        nu_recv                   ( int socket, void* data, size_t size );
nu_result_t nu_recv_async             ( int socket, void* data, size_t size );

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


packet_t* nu_packet_create          ( uint8_t protocol, struct in_addr ip_src, struct in_addr ip_dst, size_t payload_size );
packet_t* nu_packet_create_from_buf ( const void* buffer, size_t buffer_size );
void      nu_packet_destroy         ( packet_t** p_packet );
void      nu_packet_recalc_checksum ( packet_t* packet, size_t payload_size );


packet_t* nu_icmp_create           ( uint8_t icmp_type, struct in_addr ip_src, struct in_addr ip_dst, const void* payload, size_t payload_size );
void      nu_icmp_recalc_checksum  ( packet_t* packet, size_t icmp_payload_size );
packet_t* nu_icmp_create_echo      ( struct in_addr src, struct in_addr dst, uint8_t ttl /* max = MAXTTL */, uint32_t timeout, double* p_latency );

static inline struct icmp* nu_icmp_header( const packet_t* packet )
{
	return (struct icmp*) &packet->payload;
}

static inline uint8_t* nu_icmp_payload( const packet_t* packet )
{
	return (uint8_t*) &packet->payload[ NETUTILS_ICMP_HDRLEN ];
}

typedef struct ping_stats {
	double   min;
	double   max;
	double   sum;
	double   avg;
	uint32_t count;
	uint32_t lost;
} ping_stats_t;

bool nu_ping( struct in_addr src, struct in_addr dst, uint32_t timeout, uint32_t count, ping_stats_t* stats );


#ifdef __cplusplus
} /* C linkage */
#endif
#endif /* _NETUTILS_H_ */
