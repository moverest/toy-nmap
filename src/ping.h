#ifndef __PING_H__INCLUDED__
#define __PING_H__INCLUDED__

#include <stdlib.h>
#include <netinet/ip_icmp.h>

#define PING_PACKET_SIZE    64


struct icmp_packet {
    struct icmphdr hdr;
    char           msg[PING_PACKET_SIZE - sizeof(struct icmphdr)];
};

void ping_main();

int make_socket_icmp();
void make_icmp_packet(char *buf, int seq_num);

#endif
