#include "tcputils.h"

#define PACKET_BUF_SIZE     2048
#define RECEIVE_BUF_SIZE    4096
#define SCAN_DST_PORT       13300

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

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
                                        src_port, ntohs(dst_addr.sin_port));

    if (sendto(socket, packet_buf, packet_len, 0,
               (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0) {
        perror("Could not send packet");
    }
}


static bool is_valid_packet(char *packet,
                            in_addr_t src_addr, in_addr_t dst_addr,
                            uint16_t dst_port,
                            uint16_t src_port,
                            uint8_t *flags) {
    struct ip     *ip_header  = (struct ip *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ip));

    if ((ntohs(ip_header->ip_len) < sizeof(struct ip) + sizeof(struct tcphdr)) ||
        (ip_header->ip_p != IPPROTO_TCP) ||
        (ip_header->ip_dst.s_addr != dst_addr) ||
        (ip_header->ip_src.s_addr != src_addr) ||
        (ntohs(tcp_header->th_dport) != dst_port) ||
        (ntohs(tcp_header->th_sport) != src_port)) {
        return false;
    }

    if (flags != NULL) {
        *flags = tcp_header->th_flags;
    }

    return true;
}


int receive_tcp_packet(int socket,
                       in_addr_t src_addr, in_addr_t dst_addr,
                       uint16_t dst_port,
                       uint16_t src_port) {
    char buf[RECEIVE_BUF_SIZE];

    while (1) {
        ssize_t len = recvfrom(socket, buf, RECEIVE_BUF_SIZE,
                               0, NULL, NULL);
        if (len < 0) {
            perror("Could not receive packet");
            exit(1);
        }

        uint8_t recv_flags;
        if (is_valid_packet(buf, src_addr, dst_addr, dst_port,
                            src_port, &recv_flags)) {
            return recv_flags;
        }
    }
}


static bool tcp_scan_port_syn(int       socket,
                              in_addr_t src_addr,
                              in_addr_t dst_addr,
                              uint16_t  port) {
    struct sockaddr_in addr;

    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = dst_addr;

    send_tcp_packet(socket, src_addr, addr, SCAN_DST_PORT, TCP_SYN_FLAG);

    int flags = receive_tcp_packet(socket,
                                   addr.sin_addr.s_addr,
                                   src_addr,
                                   SCAN_DST_PORT,
                                   port);

    return flags & TCP_ACK_FLAG && flags & TCP_SYN_FLAG;
}


static bool tcp_scan_port_synack(int       socket,
                                 in_addr_t src_addr,
                                 in_addr_t dst_addr,
                                 uint16_t  port) {
    puts("Not implemented.");
    exit(1);
    return 0;
}


void tcp_scan_main(int argc, char **argv) {
    if (argc <= 5) {
        goto usage;
    }

    bool (*tcp_scan_port)(int, in_addr_t,
                          in_addr_t, uint16_t);
    if (strcmp(argv[2], "syn") == 0) {
        tcp_scan_port = tcp_scan_port_syn;
    } else if (strcmp(argv[2], "synack") == 0) {
        tcp_scan_port = tcp_scan_port_synack;
    } else {
        goto usage;
    }

    uint16_t port_min = 0x0000;
    uint16_t port_max = 0xffff;

    if (argc >= 6) {
        port_min = atoi(argv[5]);
        port_max = port_min;
    }

    if (argc >= 7) {
        port_max = atoi(argv[6]);
    }

    in_addr_t src_addr = inet_addr(argv[3]);
    in_addr_t dst_addr = inet_addr(argv[4]);


    int s = make_socket();

    for (uint16_t port = port_min; port <= port_max; port++) {
        printf("%d", port);
        fflush(stdout);
        bool port_is_open = tcp_scan_port(s, src_addr, dst_addr, port);
        printf("%s", port_is_open ? "\t\x1b[32mopen\x1b[0m\n" : "\x1b[1K\r");
    }

    shutdown(s, 2);

    return;

usage:
    puts("Usage:");
    exit(1);
}
