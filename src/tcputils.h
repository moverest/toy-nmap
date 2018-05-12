#ifndef __TCPUTILS_H__
#define __TCPUTILS_H__

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define TCP_ACK_FLAG    TH_ACK
#define TCP_SYN_FLAG    TH_SYN

void make_tcp_packet(char *buf, size_t buf_size, int flags,
                     struct in_addr ip_src, struct in_addr ip_dst,
                     uint16_t port_src, uint16_t port_dst);

int read_tcp_packet(char *buf);

#endif
