#ifndef __UDPUTILS_H__
#define __UDPUTILS_H__

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <stdbool.h>

// make_udp_packet creates an empty UDP packet incapsulated into a IP
// packet with the given flags.
// Returns the length of the packet
size_t make_udp_packet(char *buf, size_t buf_size,
                       in_addr_t ip_src, in_addr_t ip_dst,
                       uint16_t port_src, uint16_t port_dst);

int make_udp_socket();

void send_udp_packet(int                socket,
                     in_addr_t          src_addr,
                     struct sockaddr_in dst_addr,
                     uint16_t           src_port);

bool receive_udp_packet(int socket,
                       in_addr_t src_addr,
                       in_addr_t dst_addr,
                       uint16_t dst_port,
                       uint16_t src_port
                     );

void udp_scan_main(int argc, char **argv);

#endif
