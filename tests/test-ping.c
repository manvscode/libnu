#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "../src/netutils.h"

bool ping( const char* host );
bool test( struct in_addr src, struct in_addr dst, int ttl /* max = MAXTTL */ );

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

	if( !netutils_resolve_hostname( host, &dst_ip ) )
	{
		fprintf( stderr, "Failed to resolve %s.\n", host );
		goto failed;
	}
	else
	{
		fprintf( stdout, "Pinging %s\n", netutils_address_to_string(dst_ip) );
	}


	#if 0
	test( src_ip, dst_ip, MAXTTL );
	#else
	if( !netutils_icmp_echo( src_ip, dst_ip, MAXTTL ) )
	{
		fprintf( stdout, "Ping failed!\n" );
	}
	#endif

	return true;

failed:
	return false;
}


bool test( struct in_addr src, struct in_addr dst, int ttl /* max = MAXTTL */ )
{
	bool result = false;
	const char data[] = "This is a test. This is a test. This is a test. This is a test. This is a test. This is a test. ";
	int sock = netutils_raw_socket( IPPROTO_IP );
	packet_t* packet = NULL;

	if( sock < 0 )
	{
		trace( "Unable to create socket.\n" );
		perror( "ERROR" );
		goto done;
	}

	packet = netutils_packet_create( IPPROTO_IP, src, dst, sizeof(data) );

	memcpy( packet->payload, data, sizeof(data) );
	netutils_packet_recalc_checksum( packet, sizeof(data) );

	print_ip_header( &packet->ip_header );


	/* Set flag so socket expects us to provide IPv4 header. */
	const int on = 1;
	if( setsockopt( sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on) ) < 0 )
	{
		trace( "Unable to set socket option: IP_HDRINCL.\n" );
		perror( "ERROR" );
		goto done;
	}

	struct sockaddr_in dst_addr;
	memset( &dst_addr, 0, sizeof(struct sockaddr_in) );
	dst_addr.sin_family      = AF_INET;
	dst_addr.sin_addr.s_addr = packet->ip_header.ip_dst.s_addr;

	/* Send packet. */
	if( sendto( sock, &packet, NETUTILS_IP4_HDRLEN, 0, (struct sockaddr *) &dst_addr, sizeof(struct sockaddr) ) < 0 )
	{
		trace( "Unable to send IP packet [errno = %d].\n", errno );
		perror( "ERROR" );
		goto done;
	}

	result = true;

done:
	if( sock >= 0 ) close( sock );
	netutils_packet_destroy( &packet );
	return result;
}
