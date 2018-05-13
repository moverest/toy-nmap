#ifndef __TCPUTILS_H__
#define __TCPUTILS_H__

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define TCP_ACK_FLAG    TH_ACK
#define TCP_SYN_FLAG    TH_SYN

// make_tcp_packet creates an empty TCP packet incapsulated into a IP
// packet with the given flags.
// Returns the length of the packet
size_t make_tcp_packet(char *buf, size_t buf_size, int flags,
                       in_addr_t ip_src, in_addr_t ip_dst,
                       uint16_t port_src, uint16_t port_dst);

int make_socket();

void send_tcp_packet(int                socket,
                     in_addr_t          src_addr,
                     struct sockaddr_in dst_addr,
                     uint16_t           src_port,
                     int                flags);

int receive_tcp_packet(int socket,
                       in_addr_t src_addr,
                       in_addr_t dst_addr,
                       uint16_t dst_port,
                       uint16_t src_port);

void tcp_scan_main(int argc, char **argv);

#endif
