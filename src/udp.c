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

packet_t* nu_udp_create( struct in_addr ip_src, uint16_t sport, struct in_addr ip_dst, uint16_t dport, const void* udp_payload, size_t udp_payload_size )
{
	size_t ip_payload_size = NETUTILS_UDP_HDRLEN + udp_payload_size;
	packet_t* packet       = nu_packet_create( IPPROTO_UDP, ip_src, ip_dst, ip_payload_size );

	if( packet )
	{
		/* UDP header */
		{
			struct udphdr* udp_header = (struct udphdr*) packet->payload;
			udp_header->uh_sport  = htons(sport);
			udp_header->uh_dport  = htons(dport);

			/* Finally, add the UDP payload. */
			if( udp_payload )
			{
				memcpy( packet->payload + NETUTILS_UDP_HDRLEN, udp_payload, udp_payload_size );
			}

			nu_udp_recalc_checksum( packet, udp_payload_size );
		}

		#ifdef DEBUG_NETUTILS
		trace( "UDP packet created.\n" );
		#endif
	}

	return packet;
}

void nu_udp_recalc_checksum( packet_t* packet, size_t udp_payload_size )
{
	struct icmp* udp_header = (struct icmp*) packet->payload;
	size_t ip_payload_size   = NETUTILS_UDP_HDRLEN + udp_payload_size;

	/* Calculate UDP header checksum */
	udp_header->icmp_cksum = 0; /* UDP header checksum (16 bits): set to 0 when calculating checksum */
	udp_header->icmp_cksum = nu_checksum( packet->payload, ip_payload_size );

	nu_packet_recalc_checksum( packet, ip_payload_size );
}

