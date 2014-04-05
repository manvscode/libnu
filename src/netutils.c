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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "netutils.h"

/*
 *	Print an IP header with options.
 */
void print_ip_header( struct ip *ip )
{
	u_char *cp;
	int hlen;

	hlen = ip->ip_hl << 2;
	cp = (u_char *)ip + 20;		/* point to options */

	(void)printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst\n");
	(void)printf(" %1x  %1x  %02x %04x %04x",
	    ip->ip_v, ip->ip_hl, ip->ip_tos, ntohs(ip->ip_len),
	    ntohs(ip->ip_id));
	(void)printf("   %1lx %04lx",
	    (u_long) (ntohl(ip->ip_off) & 0xe000) >> 13,
	    (u_long) ntohl(ip->ip_off) & 0x1fff);
	(void)printf("  %02x  %02x %04x", ip->ip_ttl, ip->ip_p,
							    ntohs(ip->ip_sum));
	(void)printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->ip_src.s_addr));
	(void)printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->ip_dst.s_addr));
	/* dump any option bytes */
	while (hlen-- > 20) {
		(void)printf("%02x", *cp++);
	}
	(void)putchar('\n');
}

bool nu_resolve_hostname( const char* hostname, struct in_addr* ip )
{
	struct hostent* host = gethostbyname( hostname );

	if( host )
	{
		ip->s_addr = *((uint32_t*) host->h_addr_list[ 0 ]);
		return true;
	}

	return false;
}

//struct hostent	*gethostbyaddr(const void *, socklen_t, int);

bool nu_address_from_ip_string( const char* ipstr, struct in_addr* ip )
{
	assert( ipstr && *ipstr );
	assert( ip );
	#if 1
	return inet_aton( ipstr, ip );
	#else
	return inet_pton( AF_INET, ipstr, &ip ) == 1;
	#endif
}

const char* nu_address_to_string( struct in_addr ip )
{
	#if 0
	return inet_ntoa( ip );
	#else
	static char address[ 128 ];
	return inet_ntop( AF_INET, &ip, address, sizeof(address) );
	#endif
}

void nu_address_to_string_r( struct in_addr ip, char* str, size_t str_size )
{
	inet_ntop( AF_INET, &ip, str, str_size );
}

void nu_set_ipaddress( struct sockaddr_in* addr, struct in_addr ip, uint16_t port )
{
	memset( addr, 0, sizeof(struct sockaddr_in) );
	addr->sin_family = AF_INET;
	addr->sin_addr   = ip;
	addr->sin_port   = htons( port );
}

uint16_t nu_checksum( const void* data, size_t len )
{
	int nleft, sum;
	uint16_t *w;
	union {
		uint16_t	us;
		uint8_t	uc[2];
	} last;
	uint16_t answer;

	nleft = len;
	sum = 0;
	w = (uint16_t*) data;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		last.uc[0] = *(uint8_t *)w;
		last.uc[1] = 0;
		sum += last.us;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return answer;
}

bool nu_set_include_header( int socket, bool include_header )
{
	const int on = include_header;
	return setsockopt( socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on) ) == 0;
}

bool nu_set_timeout( int socket, uint32_t timeout )
{
	const struct timeval opt_timeout = { .tv_sec = (timeout / 1000), .tv_usec = (timeout % 1000) * 1000 };
	return setsockopt( socket, SOL_SOCKET, SO_RCVTIMEO, &opt_timeout, sizeof(opt_timeout) ) == 0;
}

#ifdef IP_TTL
bool nu_set_ttl( int socket, uint8_t ttl /* max = MAXTTL */ )
{
	const int option_ttl = ttl;
	return setsockopt( socket, IPPROTO_IP, IP_TTL /*IPV6_UNICAST_HOPS*/, &option_ttl, sizeof(option_ttl) ) == 0;
}
uint8_t nu_get_ttl( int socket )
{
	int option_ttl = 0;
	socklen_t option_size = 0;

	if( getsockopt( socket, IPPROTO_IP, IP_TTL, &option_ttl, &option_size ) < 0 )
	{
		perror( "ERROR" );
		option_ttl = 0;
	}

	return option_ttl;
}
#else
#error "Not socket option IP_TTL.  Need a way to set the TTL."
#endif

packet_t* nu_packet_create( uint8_t protocol, struct in_addr ip_src, struct in_addr ip_dst, size_t payload_size )
{
	size_t packet_size = sizeof(packet_t) + payload_size;
	packet_t* packet   = (packet_t*) malloc( packet_size );

	if( packet )
	{
		assert( sizeof(struct ip) == NETUTILS_IP4_HDRLEN );
		memset( packet, 0, packet_size );

		/* Initialize IP header */
		{
			assert( IPVERSION == 4 );
			packet->ip_header.ip_hl  = NETUTILS_IP4_HDRLEN / sizeof(uint32_t); /* IPv4 header length (4 bits): Number of 32-bit words in header = 5 */
			packet->ip_header.ip_v   = IPVERSION; /* IPv4 */
			packet->ip_header.ip_tos = 0; /* Type of service (8 bits) */
			#if __APPLE__
			packet->ip_header.ip_len = NETUTILS_IP4_HDRLEN + payload_size; /* Total length of datagram (16 bits): IP header + data */
			packet->ip_header.ip_id  = 0; /* ID sequence number (16 bits): unused, since single datagram */
			#else
			packet->ip_header.ip_len = htons( NETUTILS_IP4_HDRLEN + payload_size ); /* Total length of datagram (16 bits): IP header + data */
			packet->ip_header.ip_id  = htons( 0 ); /* ID sequence number (16 bits): unused, since single datagram */
			#endif

			/* Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram */
			{
				int8_t ip_flags[ 4 ] = {
					0, /* Zero (1 bit) */
					0, /* Do not fragment flag (1 bit) */
					0, /* More fragments following flag (1 bit) */
					0, /* Fragmentation offset (13 bits) */
				};
				#if __APPLE__
				packet->ip_header.ip_off = (ip_flags[0] << 15)
				                         + (ip_flags[1] << 14)
				                         + (ip_flags[2] << 13)
				                         +  ip_flags[3];
				#else
				packet->ip_header.ip_off = htons( (ip_flags[0] << 15)
				                                + (ip_flags[1] << 14)
				                                + (ip_flags[2] << 13)
				                                +  ip_flags[3] );
				#endif
			}

			packet->ip_header.ip_ttl = IPDEFTTL; /* Time-to-Live (8 bits): default to maximum value */
			packet->ip_header.ip_p   = protocol; /* Transport layer protocol (8 bits): 1 for ICMP */
			packet->ip_header.ip_src = ip_src;
			packet->ip_header.ip_dst = ip_dst;
			packet->ip_header.ip_sum = 0; /* IPv4 header checksum (16 bits): set to 0 when calculating checksum */
			//packet->ip_header.ip_sum = nu_checksum( &packet->ip_header, NETUTILS_IP4_HDRLEN + payload_size );
		}

		trace( "Packet created [proto = %u, ", protocol );
		trace( "src = %s, ", nu_address_to_string(ip_src) );
		trace( "dst = %s].\n", nu_address_to_string(ip_dst) );
	}
	else
	{
		#if defined(DEBUG_NETUTILS)
		perror( "ERROR" );
		#endif
	}

	return packet;
}

packet_t* nu_packet_create_from_buf( const void* buffer, size_t buffer_size )
{
	packet_t* packet = (packet_t*) malloc( buffer_size );

	if( packet )
	{
		memcpy( packet, buffer, buffer_size );

		trace( "Packet created [proto = %u, ", packet->ip_header.ip_p );
		trace( "src = %s, ", nu_address_to_string(packet->ip_header.ip_src) );
		trace( "dst = %s].\n", nu_address_to_string(packet->ip_header.ip_dst) );
	}

	return packet;
}

void nu_packet_destroy( packet_t** p_packet )
{
	if( p_packet )
	{
		packet_t* p = *p_packet;
		free( p );
		*p_packet = NULL;
		trace( "Packet destroyed.\n" );
	}
}


void nu_packet_recalc_checksum( packet_t* packet, size_t payload_size )
{
	packet->ip_header.ip_sum = 0;
	packet->ip_header.ip_sum = nu_checksum( &packet->ip_header, NETUTILS_IP4_HDRLEN + payload_size );
}

