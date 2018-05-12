#ifndef __TCPUTILS_H__
#define __TCPUTILS_H__

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#define TCP_ACK_FLAG    TH_ACK
#define TCP_SYN_FLAG    TH_SYN
#define PACKETSIZE	64


struct icmp_packet
{
	struct icmphdr hdr;
	char msg[PACKETSIZE-sizeof(struct icmphdr)];
};


// make_tcp_packet creates an empty TCP packet incapsulated into a IP
// packet with the given flags.
// Returns the length of the packet
size_t make_tcp_packet(char *buf, size_t buf_size, int flags,
                       in_addr_t ip_src, in_addr_t ip_dst,
                       uint16_t port_src, uint16_t port_dst);

// make_icmp_packet creates an ICMP packet with sequence nbr = $cnt
size_t make_icmp_packet(char *buf, size_t buf_size, int cnt);

int read_tcp_packet(char *buf);

int make_socket();
int make_socket_icmp();

void send_tcp_packet(int                socket,
                     in_addr_t          src_addr,
                     struct sockaddr_in dst_addr,
                     uint16_t           src_port,
                     int                flags);

#endif
