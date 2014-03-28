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
#include <errno.h>
#include <assert.h>
#include "netutils.h"

packet_t* netutils_icmp_packet_create( uint8_t icmp_type, struct in_addr ip_src, struct in_addr ip_dst, const void* payload, size_t payload_size )
{
	size_t ip_payload_size = NETUTILS_ICMP_HDRLEN + payload_size;
	packet_t* packet       = netutils_packet_create( IPPROTO_ICMP, ip_src, ip_dst, ip_payload_size );

	if( packet )
	{
		/* ICMP header */
		{
			struct icmp icmp_header;
			icmp_header.icmp_type  = icmp_type; /* Message Type (8 bits): echo request */
			icmp_header.icmp_code  = 0; /* Message Code (8 bits): echo request */
			#if __APPLE__
			icmp_header.icmp_id    = 1000; /* Identifier (16 bits): usually pid of sending process - pick a number */
			icmp_header.icmp_seq   = 0; /* Sequence Number (16 bits): starts at 0 */
			#else
			icmp_header.icmp_id    = htons( 1000 ); /* Identifier (16 bits): usually pid of sending process - pick a number */
			icmp_header.icmp_seq   = htons( 0 ); /* Sequence Number (16 bits): starts at 0 */
			#endif
			icmp_header.icmp_cksum = 0; /* ICMP header checksum (16 bits): set to 0 when calculating checksum */

			/* Prepare packet. */
			/* Next part of packet is upper layer protocol header. */
			memcpy( packet->payload, &icmp_header, NETUTILS_ICMP_HDRLEN );

			/* Finally, add the ICMP payload. */
			memcpy( packet->payload + NETUTILS_ICMP_HDRLEN, payload, payload_size );

			// Calculate ICMP header checksum
			icmp_header.icmp_cksum = netutils_checksum( packet->payload, ip_payload_size );

			memcpy( packet->payload, &icmp_header, NETUTILS_ICMP_HDRLEN );

			netutils_packet_recalc_checksum( packet, ip_payload_size );
		}

		#ifdef DEBUG_NETUTILS
		trace( "ICMP packet created.\n" );
		print_ip_header( &packet->ip_header );
		#endif
	}

	return packet;
}

bool netutils_icmp_echo( struct in_addr src, struct in_addr dst, uint8_t ttl /* max = MAXTTL */ )
{
	bool result = false;
	uint8_t data[] = { 'T', 'e', 's', 't' };
	int sock = netutils_raw_socket( IPPROTO_ICMP );
	packet_t* packet = NULL;

	if( sock < 0 )
	{
		trace( "Unable to create socket.\n" );
		perror( "ERROR" );
		goto done;
	}

	packet = netutils_icmp_packet_create( ICMP_ECHO, src, dst, data, sizeof(data) );

	/*
	if( setsockopt( sock, IPPROTO_IP, IP_OPTIONS, NULL, 0 ) < 0 )
	{
		trace( "Unable to set socket option: IP_OPTIONS.\n" );
		perror( "ERROR" );
		goto done;
	}
	*/

	// Set flag so socket expects us to provide IPv4 header.
	const int on = 1;
	if( setsockopt( sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on) ) < 0 )
	{
		trace( "Unable to set socket option: IP_HDRINCL.\n" );
		perror( "ERROR" );
		goto done;
	}

	// Bind socket to interface index.
	//if( setsockopt( sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr) ) < 0 )
	//{
		//return false;
	//}

	/*
	const int opt_ttl = ttl;
	if( setsockopt( sock, IPPROTO_IP, IP_TTL, &opt_ttl, sizeof(opt_ttl) ) < 0 )
	{
		trace( "Unable to set socket option: IP_TTL.\n" );
		perror( "ERROR" );
		goto done;
	}
	*/

	struct sockaddr_in dst_addr;
	memset( &dst_addr, 0, sizeof(struct sockaddr_in) );
	dst_addr.sin_family      = AF_INET;
	dst_addr.sin_addr.s_addr = packet->ip_header.ip_dst.s_addr;

	/* Send packet. */
	if( sendto( sock, &packet, NETUTILS_IP4_HDRLEN + NETUTILS_ICMP_HDRLEN + sizeof(data), 0, (struct sockaddr *) &dst_addr, sizeof(struct sockaddr) ) < 0 )
	{
		trace( "Unable to send ICMP packet [errno = %d].\n", errno );
		perror( "ERROR" );
		goto done;
	}

	result = true;

done:
	if( sock >= 0 ) close( sock );
	netutils_packet_destroy( &packet );
	return result;
}
