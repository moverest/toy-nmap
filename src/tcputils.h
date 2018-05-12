#ifndef __TCPUTILS_H__
#define __TCPUTILS_H__

#include <stdlib.h>

#define TCP_ACK_FLAG    1 << 0
#define TCP_SYN_FLAG    1 << 1

void make_tcp_packet(char *buf, size_t buf_size, int flags);
int read_tcp_packet(char *buf);

#endif
