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
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include "netutils.h"
#include "netutils-internal.h"

packet_t* nu_icmp_create( uint8_t icmp_type, struct in_addr ip_src, struct in_addr ip_dst, const void* icmp_payload, size_t icmp_payload_size )
{
	size_t ip_payload_size = NETUTILS_ICMP_HDRLEN + icmp_payload_size;
	packet_t* packet       = nu_packet_create( IPPROTO_ICMP, ip_src, ip_dst, ip_payload_size );

	if( packet )
	{
		/* ICMP header */
		{
			struct icmp* icmp_header = (struct icmp*) packet->payload;
			icmp_header->icmp_type  = icmp_type; /* Message Type (8 bits): echo request */
			icmp_header->icmp_code  = 0; /* Message Code (8 bits): echo request */
			#if __APPLE__
			icmp_header->icmp_id    = 1000; /* Identifier (16 bits): usually pid of sending process - pick a number */
			icmp_header->icmp_seq   = 0; /* Sequence Number (16 bits): starts at 0 */
			#else
			icmp_header->icmp_id    = htons( 1000 ); /* Identifier (16 bits): usually pid of sending process - pick a number */
			icmp_header->icmp_seq   = htons( 0 ); /* Sequence Number (16 bits): starts at 0 */
			#endif

			/* Finally, add the ICMP payload. */
			if( icmp_payload )
			{
				memcpy( packet->payload + NETUTILS_ICMP_HDRLEN, icmp_payload, icmp_payload_size );
			}

			nu_icmp_recalc_checksum( packet, icmp_payload_size );
		}

		#ifdef DEBUG_NETUTILS
		trace( "ICMP packet created.\n" );
		#endif
	}

	return packet;
}

void nu_icmp_recalc_checksum( packet_t* packet, size_t icmp_payload_size )
{
	struct icmp* icmp_header = (struct icmp*) packet->payload;
	size_t ip_payload_size   = NETUTILS_ICMP_HDRLEN + icmp_payload_size;

	/* Calculate ICMP header checksum */
	icmp_header->icmp_cksum = 0; /* ICMP header checksum (16 bits): set to 0 when calculating checksum */
	icmp_header->icmp_cksum = nu_checksum( packet->payload, ip_payload_size );

	nu_packet_recalc_checksum( packet, ip_payload_size );
}

struct icmp* nu_icmp_header( const packet_t* packet )
{
	return (struct icmp*) &packet->payload;
}

uint8_t* nu_icmp_payload( const packet_t* packet )
{
	return (uint8_t*) &packet->payload[ NETUTILS_ICMP_HDRLEN ];
}

packet_t* nu_icmp_create_echo( struct in_addr src, struct in_addr dst, uint8_t ttl /* max = MAXTTL */, uint32_t timeout, double* p_latency )
{
	packet_t* reply_packet    = NULL;
	struct timeval* time_sent = NULL;
	struct protoent* proto    = getprotobyname( "ICMP" );
	#if __APPLE__
	int sock                  = socket( AF_INET, SOCK_DGRAM, proto->p_proto );
	#else
	int sock                  = nu_raw_socket( proto->p_proto /* IPPROTO_ICMP */ );
	#endif
	size_t icmp_payload_size  = sizeof(*time_sent);
	size_t ip_payload_size    = NETUTILS_ICMP_HDRLEN + icmp_payload_size;
	packet_t* echo_packet     = NULL;

	if( sock < 0 )
	{
		trace( "Unable to create socket.\n" );
		#if defined(DEBUG_NETUTILS)
		perror( "ERROR" );
		#endif
		goto done;
	}

	echo_packet = nu_icmp_create( ICMP_ECHO, src, dst, NULL, icmp_payload_size );

	#ifdef NETUTILS_ICMP_INCLUDE_IP4_HEADER
	if( !nu_set_include_header( sock, true ) )
	{
		trace( "Unable to set socket option: IP_HDRINCL.\n" );
		#if defined(DEBUG_NETUTILS)
		perror( "ERROR" );
		#endif
		goto done;
	}
	echo_packet->ip_ttl = ttl;
	nu_packet_recalc_checksum( packet, ip_payload_size );
	#else
	if( !nu_set_ttl( sock, ttl ) )
	{
		trace( "Unable to set TTL.\n" );
		#if defined(DEBUG_NETUTILS)
		perror( "ERROR" );
		#endif
		goto done;
	}
	#endif

	if( !nu_set_timeout( sock, timeout ) )
	{
		trace( "Unable to set timeout: %u.\n", timeout );
		#if defined(DEBUG_NETUTILS)
		perror( "ERROR" );
		#endif
		goto done;
	}

	struct sockaddr_in dst_addr;
	memset( &dst_addr, 0, sizeof(struct sockaddr_in) );
	dst_addr.sin_family      = AF_INET;
	dst_addr.sin_addr.s_addr = echo_packet->ip_header.ip_dst.s_addr;

	uint8_t recv_packet_buffer[ IP_MAXPACKET ];
	struct sockaddr_in from_addr;
	socklen_t from_addr_size;

	time_sent = (struct timeval*) &echo_packet->payload[ NETUTILS_ICMP_HDRLEN ];

	if( gettimeofday( time_sent, NULL ) < 0 )
	{
		#if defined(DEBUG_NETUTILS)
		perror( "ERROR" );
		#endif
		goto done;
	}


	nu_icmp_recalc_checksum( echo_packet, icmp_payload_size );

	/* Send ICMP_ECHO packet. */
	#ifdef NETUTILS_ICMP_INCLUDE_IP4_HEADER
	if( sendto( sock, &packet, NETUTILS_IP4_HDRLEN + ip_payload_size, 0, (struct sockaddr *) &dst_addr, sizeof(struct sockaddr) ) < 0 )
	#else
	if( sendto( sock, &echo_packet->payload, ip_payload_size, 0, (struct sockaddr *) &dst_addr, sizeof(struct sockaddr) ) < 0 )
	#endif
	{
		trace( "Unable to send ICMP packet [errno = %d].\n", errno );
		#if defined(DEBUG_NETUTILS)
		perror( "ERROR" );
		#endif
		goto done;
	}
	else
	{
		#if defined(DEBUG_NETUTILS)
		struct icmp* icmp_header = (struct icmp*) echo_packet->payload;
		trace( "Sent packet [icmp_type = %u].\n", icmp_header->icmp_type );
		//print_ip_header( &echo_packet->ip_header );
		#endif
	}

	/* Receive ICMP_ECHOREPLY or ICMP_TIME_EXCEEDED packet. */
	ssize_t bytes_read = recvfrom( sock, recv_packet_buffer, sizeof(recv_packet_buffer), 0, (struct sockaddr*)  &from_addr, &from_addr_size );

	if( bytes_read <= 0 )
	{
		trace( "Unable to receive ICMP packet [errno = %d].\n", errno );
		#if defined(DEBUG_NETUTILS)
		perror( "ERROR" );
		#endif
	}
	else
	{
		reply_packet                  = nu_packet_create_from_buf( recv_packet_buffer, bytes_read );
		struct icmp* recv_icmp_header = (struct icmp*) reply_packet->payload;

		if( recv_icmp_header->icmp_type == ICMP_ECHOREPLY )
		{
			time_sent = (struct timeval*) &reply_packet->payload[ NETUTILS_ICMP_HDRLEN ];

			struct timeval now = { .tv_sec = 0, .tv_usec = 0 };
			if( gettimeofday( &now, NULL ) < 0 )
			{
				#if defined(DEBUG_NETUTILS)
				perror( "ERROR" );
				#endif
				goto done;
			}

			*p_latency = 1000 * (now.tv_sec - time_sent->tv_sec) + (now.tv_usec - time_sent->tv_usec) / 1000.0;


			#if defined(DEBUG_NETUTILS)
			struct icmp* icmp_header = (struct icmp*) reply_packet->payload;
			trace( "Received packet [icmp_type = %u, icmp_code = %u, latency = %lf].\n", icmp_header->icmp_type, icmp_header->icmp_code, *p_latency );
			//print_ip_header( &reply_packet->ip_header );
			#endif
		}
		else
		{
			*p_latency = 0.0;
		}
	}

done:
	if( sock >= 0 ) close( sock );
	if( echo_packet) nu_packet_destroy( &echo_packet );
	return reply_packet;
}
