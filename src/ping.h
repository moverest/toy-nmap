#ifndef __PING_H__INCLUDED__
#define __PING_H__INCLUDED__

#include <stdlib.h>
#include <netinet/ip_icmp.h>

#define PING_PACKET_SIZE    256


struct icmp_packet {
    struct icmphdr hdr;
    char           msg[PING_PACKET_SIZE - sizeof(struct icmphdr)];
};

void ping_main(int argc, char **argv);

int make_socket_icmp();
void make_ping_packet(char *buf, int seq_num);

#endif
