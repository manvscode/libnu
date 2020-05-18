#ifndef _NETUTILS_INTERNAL_H_
#define _NETUTILS_INTERNAL_H_

//#include <netinet/icmp6.h>


struct packet {
	struct ip ip_header;
	uint8_t payload[];
};

#endif /* _NETUTILS_INTERNAL_H_ */
