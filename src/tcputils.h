#ifndef __TCPUTILS_H__
#define __TCPUTILS_H__

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdbool.h>

#define TCP_ACK_FLAG     TH_ACK
#define TCP_SYN_FLAG     TH_SYN
#define TCP_RST_FLAG     TH_RST
#define TCP_FIN_FLAG     TH_FIN
#define TCP_URG_FLAG     TH_URG
#define TCP_PUSH_FLAG    TH_PUSH

int make_tcp_socket();

bool tcp_scan_port_synack(int       socket,
                          in_addr_t src_addr,
                          in_addr_t dst_addr,
                          uint16_t  port,
                          in_addr_t zombie_addr);

bool tcp_scan_port_syn(int       socket,
                       in_addr_t src_addr,
                       in_addr_t dst_addr,
                       uint16_t  port,
                       in_addr_t zombie_addr);

bool tcp_scan_port_idle(int       socket,
                        in_addr_t src_addr,
                        in_addr_t dst_addr,
                        uint16_t  port,
                        in_addr_t zombie_addr);

#endif
