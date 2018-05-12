#ifndef __PING_H__INCLUDED__
#define __PING_H__INCLUDED__

#include <stdlib.h>
#include <netinet/ip_icmp.h>

#define PACKETSIZE    64


struct icmp_packet {
    struct icmphdr hdr;
    char           msg[PACKETSIZE - sizeof(struct icmphdr)];
};



int make_socket_icmp();
size_t make_icmp_packet(char *buf, size_t buf_size, int cnt);

#endif
