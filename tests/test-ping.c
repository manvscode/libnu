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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "../src/netutils.h"

bool ping( const char* host );

int main( int argc, char* argv[] )
{
	const char* host  = argv[ 1 ];

	ping( host );
	return 0;
}


bool ping( const char* host )
{
	struct in_addr src_ip = { .s_addr = INADDR_ANY };
	struct in_addr dst_ip;

	if( !nu_address_from_ip_string( "127.0.0.1", &src_ip ) )
	{
		fprintf( stderr, "Failed to initialize loopback address.\n" );
		goto failed;
	}

	if( !nu_resolve_hostname( host, &dst_ip ) )
	{
		fprintf( stderr, "Failed to resolve %s.\n", host );
		goto failed;
	}
	else
	{
		fprintf( stdout, "Pinging %s\n", nu_address_to_string(dst_ip) );
	}


	ping_stats_t stats;
	const uint32_t timeout = 200;
	const uint32_t count   = 20;

	if( !nu_ping( src_ip, dst_ip, timeout, count, &stats ) )
	{
		fprintf( stdout, "Ping failed!\n" );
	}
	else
	{
		char src_ip_str[ 16 ] = { '\0' };
		char dst_ip_str[ 16 ] = { '\0' };

		nu_address_to_string_r( src_ip, src_ip_str, sizeof(src_ip_str) );
		nu_address_to_string_r( dst_ip, dst_ip_str, sizeof(dst_ip_str) );

		fprintf( stdout, "-----------------------------------------------------------------------------------------\n" );
		fprintf( stdout, "|  Source: %-15s  |  Destination: %-15s                             |\n", src_ip_str, dst_ip_str );
		fprintf( stdout, "-----------------------------------------------------------------------------------------\n" );
		fprintf( stdout, "| Timeout: %05u ms             | Min: %08.1lf ms | Max: %08.1lf ms | Avg: %08.1lf ms |\n", timeout, stats.min, stats.max, stats.avg );
		fprintf( stdout, "-----------------------------------------------------------------------------------------\n" );
		fprintf( stdout, "| Packets Sent: %-14u | Packets Lost: %-14u | Percent Lost: %-6.2lf%%   |\n", stats.count, stats.lost, (stats.lost * 100.0) / stats.count );
		fprintf( stdout, "-----------------------------------------------------------------------------------------\n" );
	}

	return true;

failed:
	return false;
}

