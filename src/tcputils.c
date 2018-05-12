#include "tcputils.h"

#define PACKET_BUF_SIZE    2048

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// From the Minirighi project.
// See: http://minirighi.sourceforge.net/html/tcp_8h-source.html
static uint16_t tcp_checksum(const void *buff, size_t len,
                             in_addr_t src_addr, in_addr_t dest_addr) {
    const uint16_t *buf = buff;
    uint16_t       *ip_src = (void *)&src_addr, *ip_dst = (void *)&dest_addr;
    uint32_t       sum;
    size_t         length = len;

    // Calculate the sum
    sum = 0;
    while (len > 1) {
        sum += *buf++;
        if (sum & 0x80000000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        len -= 2;
    }

    if (len & 1) {
        // Add the padding if the packet lenght is odd
        sum += *((uint8_t *)buf);
    }

    // Add the pseudo-header
    sum += *(ip_src++);
    sum += *ip_src;
    sum += *(ip_dst++);
    sum += *ip_dst;
    sum += htons(IPPROTO_TCP);
    sum += htons(length);

    // Add the carries
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return the one's complement of sum
    return((uint16_t)(~sum));
}


size_t make_tcp_packet(char *buf, size_t buf_size, int flags,
                       in_addr_t ip_src, in_addr_t ip_dst,
                       uint16_t port_src, uint16_t port_dst) {
    memset(buf, 0, buf_size);
    size_t packet_len = sizeof(struct ip) + sizeof(struct tcphdr);

    struct ip *ip_header = (struct ip *)buf;
    ip_header->ip_hl  = 5;
    ip_header->ip_v   = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(packet_len);
    ip_header->ip_id  = htonl(13100);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 255;
    ip_header->ip_p   = IPPROTO_TCP;
    ip_header->ip_sum = 0; // Computed by the kernel with IP_HDRINCL.
    ip_header->ip_src = (struct in_addr){
        ip_src
    };
    ip_header->ip_dst = (struct in_addr){
        ip_dst
    };

    struct tcphdr *tcp_header = (struct tcphdr *)(buf + sizeof(struct ip));
    tcp_header->th_sport = htons(port_src);
    tcp_header->th_dport = htons(port_dst);
    tcp_header->th_seq   = 0;
    tcp_header->th_ack   = 0;
    tcp_header->th_off   = 5;
    tcp_header->th_flags = flags;
    tcp_header->th_win   = htons(5840);
    tcp_header->th_sum   = 0;
    tcp_header->th_urp   = 0;

    tcp_header->th_sum = tcp_checksum(tcp_header, sizeof(struct tcphdr),
                                      ip_src, ip_dst);

    return packet_len;
}


int read_tcp_packet(char *buf) {
    return 0;
}


int make_socket() {
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

    if (s < 0) {
        perror("Could not create socket");
        exit(1);
    }

    int value = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value)) < 0) {
        perror("Could not set socket options");
        exit(1);
    }

    return s;
}


void send_tcp_packet(int                socket,
                     in_addr_t          src_addr,
                     struct sockaddr_in dst_addr,
                     uint16_t           src_port,
                     int                flags) {
    char   packet_buf[PACKET_BUF_SIZE];
    size_t packet_len = make_tcp_packet(packet_buf, PACKET_BUF_SIZE,
                                        flags,
                                        src_addr, dst_addr.sin_addr.s_addr,
                                        ntohs(dst_addr.sin_port), src_port);

    if (sendto(socket, packet_buf, packet_len, 0,
               (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0) {
        perror("Could not send packet");
    }
}
