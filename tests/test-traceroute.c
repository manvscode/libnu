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
#include <math.h>
#include <errno.h>
#include "../src/netutils.h"

#define COLOR_BEGIN(bg,fg)                    "\e[" #bg ";" #fg "m"
#define COLOR_END                             "\e[m"
#define COLOR_TOKEN(color_bg, color_fg, tok)  COLOR_BEGIN(color_bg, color_fg) #tok COLOR_END
#define COLOR_STRING(color_bg, color_fg, str) COLOR_BEGIN(color_bg, color_fg) str COLOR_END
#define COLOR_GREEN                           COLOR_BEGIN(0,32)
#define COLOR_RED                             COLOR_BEGIN(0,31)
#define COLOR_YELLOW                          COLOR_BEGIN(0,33)
#define COLOR_BLUE                            COLOR_BEGIN(0,34)
#define COLOR_MAGENTA                         COLOR_BEGIN(0,35)
#define COLOR_CYAN                            COLOR_BEGIN(0,36)
#define COLOR_WHITE                           COLOR_BEGIN(0,37)

#define COLOR_GREEN_STR(s)                    COLOR_STRING(0,32,s)
#define COLOR_YELLOW_STR(s)                   COLOR_STRING(0,33,s)
#define COLOR_RED_STR(s)                      COLOR_STRING(0,31,s)
#define COLOR_CYAN_STR(s)                     COLOR_STRING(0,36,s)

struct {
	char* host;
	uint32_t timeout;
	uint32_t hops;
	uint32_t count;
} app = {
	.host    = NULL,
	.timeout = 200,
	.hops    = IPDEFTTL,
	.count   = 10
};


void about      ( const char *prog_name );
bool traceroute ( const char* host, uint32_t timeout, uint32_t ttl, uint32_t count );

int main( int argc, char* argv[] )
{
	int result = 1;

	if( argc >= 2 )
	{
		/* Command line arguments. */
		for( int arg = 1; arg < argc; arg++ )
		{
			if( !strcmp( argv[ arg ], "--host" ) || !strcmp( argv[ arg ], "-h" ) )
			{
				app.host = argv[ ++arg ];
			}
			else if( !strcmp( argv[ arg ], "--timeout" ) || !strcmp( argv[ arg ], "-t" ) )
			{
				app.timeout = atoi( argv[ ++arg ] );
			}
			else if( !strcmp( argv[ arg ], "--max-hops" ) || !strcmp( argv[ arg ], "-n" ) )
			{
				app.hops = atoi( argv[ ++arg ] );
			}
			else if( !strcmp( argv[ arg ], "--count" ) || !strcmp( argv[ arg ], "-c" ) )
			{
				app.count = atoi( argv[ ++arg ] );
			}
			else
			{
				if( !strcmp( argv[ arg ], "--help" ) || !strcmp( argv[ arg ], "-h" ) )
				{
					about( argv[ 0 ] );
					return EXIT_SUCCESS;
				}
				else
				{
					about( argv[ 0 ] );
					return EXIT_FAILURE;
				}
			}
		}

		if( app.host == NULL )
		{
			fprintf( stdout, "Need to have the host address.\n" );
			about( argv[ 0 ] );
		}
		else
		{
			result = traceroute( app.host, app.timeout, app.hops, app.count ) ?
				   EXIT_SUCCESS :
				   EXIT_FAILURE;
		}
	}
	else
	{
		about( argv[ 0 ] );
	}

	return result;
}

void about( const char *prog_name )
{
    printf( "%s -- ICMP Traceroute\n", prog_name );
    printf( "Copyright (c) 2014, Joseph Marrero. All rights reserved.\n" );
    printf( "More information at http://www.manvscode.com/\n\n" );

    printf( "The syntax is: \n" );
    printf( "%s [OPTIONS]\n\n", prog_name );

    printf( "Options:\n" );
    printf( "   %-30s  %s\n", "-h, --host <hostname>", "Set the hostname." );
    printf( "   %-30s  %s\n", "-t, --timeout <timeout>", "Set the timeout (in milliseconds)." );
    printf( "   %-30s  %s\n", "-n, --max-hops <hops>", "Set the max number of hops." );
    printf( "   %-30s  %s\n", "-c, --count <count>", "Set the number of ICMP packets to send." );
    printf( "   %-30s  %s\n", "-h, --help", "Display help and copyright information." );

    printf( "Please report any bugs to manvscode@gmail.com\n" );
}

static inline const char* color_latency( double p )
{
	if( p > 150.0 )
	{
		return COLOR_RED;
	}
	else if( p > 75.0 )
	{
		return COLOR_YELLOW;
	}
	else
	{
		return COLOR_GREEN;
	}
}

static inline const char* color_percentage( double p )
{
	if( p > 0.3 )
	{
		return COLOR_RED;
	}
	else if( p > 0.1 )
	{
		return COLOR_YELLOW;
	}
	else
	{
		return COLOR_GREEN;
	}
}

bool traceroute( const char* host, uint32_t timeout, uint32_t max_hops, uint32_t count )
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

	bool is_done = false;

	for( uint8_t ttl = 1; !is_done && ttl < max_hops; ttl++ )
	{
		bool first_packet = false;
		ping_stats_t stats = {
			.min = 0,
			.max = 0,
			.sum = 0,
			.avg = 0,
			.count = count,
			.lost = 0
		};

		for( uint32_t i = 1; i <= count; i++ )
		{
			double latency = 0.0;
			packet_t* p    = nu_icmp_create_echo( src_ip, dst_ip, ttl, timeout, &latency );
			int s  = socket( AF_INET, SOCK_DGRAM, 0 );

			if( p )
			{
				struct icmp* icmp_header = nu_icmp_header( p );

				if( icmp_header->icmp_type == ICMP_ECHOREPLY )
				{
					if( !first_packet )
					{
						stats.min   = latency;
						stats.max   = latency;
						stats.avg   = latency;
						stats.sum   = latency;
						first_packet = true;
					}
					else
					{
						stats.min  = fmin( stats.min, latency );
						stats.max  = fmax( stats.max, latency );
						stats.sum += latency;
					}

					//fprintf( stdout, "Packet %s%06u%s -- Sent %s%02u%s bytes in %s%.2lf%s ms\n", COLOR_CYAN, i, COLOR_END, COLOR_CYAN, ntohs(p->ip_header.ip_len), COLOR_END, color_latency(latency), latency, COLOR_END );
				}
				else if( icmp_header->icmp_type == ICMP_UNREACH /* ICMP_DEST_UNREACH */ )
				{
					//fprintf( stdout, "Packet %s%06u%s -- %sDestination unreacheable%s\n", COLOR_CYAN, i, COLOR_END, COLOR_RED, COLOR_END );

				}
				else if( icmp_header->icmp_type == ICMP_TIMXCEED /* ICMP_TIME_EXCEEDED */ )
				{
					//fprintf( stdout, "Packet %s%06u%s -- Time exceeded\n", COLOR_CYAN, i, COLOR_END );
					//fprintf( stdout, "%u --
				}

				nu_packet_destroy( &p );
			}
			else
			{
				fprintf( stdout, "Packet %s%06u%s -- %sLost%s\n", COLOR_CYAN, i, COLOR_END, COLOR_RED, COLOR_END );
				stats.lost += 1;
			}
		} /* for */
	} /* for */

	fprintf( stdout, "\n" );

	char src_ip_str[ 16 ]  = { '\0' };
	char dst_ip_str[ 16 ]  = { '\0' };
	nu_address_to_string_r( src_ip, src_ip_str, sizeof(src_ip_str) );
	nu_address_to_string_r( dst_ip, dst_ip_str, sizeof(dst_ip_str) );
	//float percent_lost = (stats.lost * 100.0) / stats.count;
	fprintf( stdout, "-----------------------------------------------------------------------------------------\n" );
	//fprintf( stdout, "|  Source: %s%-15s%s  |  Destination: %s%-15s%s                             |\n", COLOR_CYAN, src_ip_str, COLOR_END, COLOR_CYAN, dst_ip_str, COLOR_END );
	fprintf( stdout, "-----------------------------------------------------------------------------------------\n" );
	//fprintf( stdout, "| Timeout: %s%5u%s ms | Max Hops: %s%03u%s | Min: %s%8.1lf%s ms | Max: %s%8.1lf%s ms | Avg: %s%8.1lf%s ms |\n", COLOR_CYAN, timeout, COLOR_END, COLOR_CYAN, max_hops, COLOR_END, COLOR_CYAN, stats.min, COLOR_END, COLOR_CYAN, stats.max, COLOR_END, COLOR_CYAN, stats.avg, COLOR_END );
	fprintf( stdout, "-----------------------------------------------------------------------------------------\n" );
	//fprintf( stdout, "| Packets Sent: %s%-14u%s | Packets Lost: %s%-14u%s | Percent Lost: %s%-6.2lf%%%s   |\n", COLOR_CYAN, stats.count, COLOR_END, stats.lost > 0 ? COLOR_RED : COLOR_GREEN, stats.lost, COLOR_END, color_percentage(percent_lost), percent_lost, COLOR_END );
	fprintf( stdout, "-----------------------------------------------------------------------------------------\n" );

	return true;

failed:
	return false;
}
