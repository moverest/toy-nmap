#include "tcputils.h"

#define PACKET_BUF_SIZE      2048
#define RECEIVE_BUF_SIZE     4096
#define SCAN_DST_PORT        13300
#define SCAN_PORT_TIMEOUT    2

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

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


// make_tcp_packet creates an empty TCP packet incapsulated into a IP
// packet with the given flags.
// Returns the length of the packet
static size_t make_tcp_packet(char *buf, size_t buf_size, int flags,
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


int make_tcp_socket() {
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

    struct timeval tv;
    tv.tv_sec  = SCAN_PORT_TIMEOUT;
    tv.tv_usec = 0;
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Could not set timeout");
        exit(1);
    }

    return s;
}


static void send_tcp_packet(int                socket,
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
                            uint8_t *flags,
                            uint32_t *tcp_seq) {
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

    if (tcp_seq != NULL) {
        *tcp_seq = tcp_header->th_seq;
    }

    return true;
}


static int receive_tcp_packet(int socket,
                              in_addr_t src_addr, in_addr_t dst_addr,
                              uint16_t dst_port,
                              uint16_t src_port,
                              bool *did_timeout,
                              uint32_t *tcp_seq) {
    char   buf[RECEIVE_BUF_SIZE];
    time_t start_time = time(NULL);

    do {
        ssize_t len = recvfrom(socket, buf, RECEIVE_BUF_SIZE,
                               0, NULL, NULL);
        if (len < 0) {
            continue;
        }

        uint8_t recv_flags;
        if (is_valid_packet(buf, src_addr, dst_addr, dst_port,
                            src_port, &recv_flags, tcp_seq)) {
            if (did_timeout != NULL) {
                *did_timeout = false;
            }
            return recv_flags;
        }
    } while (start_time + SCAN_PORT_TIMEOUT > time(NULL));

    if (did_timeout != NULL) {
        *did_timeout = true;
    }

    return 0;
}


bool tcp_scan_port_syn(int       socket,
                       in_addr_t src_addr,
                       in_addr_t dst_addr,
                       uint16_t  port,
                       in_addr_t zombie_addr) {
    struct sockaddr_in addr;

    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = dst_addr;

    send_tcp_packet(socket, src_addr, addr, SCAN_DST_PORT, TCP_SYN_FLAG);

    int flags = receive_tcp_packet(socket,
                                   addr.sin_addr.s_addr,
                                   src_addr,
                                   SCAN_DST_PORT,
                                   port,
                                   NULL,
                                   NULL);

    return flags & TCP_ACK_FLAG && flags & TCP_SYN_FLAG;
}


bool tcp_scan_port_synack(int       socket,
                          in_addr_t src_addr,
                          in_addr_t dst_addr,
                          uint16_t  port,
                          in_addr_t zombie_addr) {
    struct sockaddr_in addr;

    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = dst_addr;

    send_tcp_packet(socket, src_addr, addr, SCAN_DST_PORT, TCP_PUSH_FLAG);

    bool did_timeout;
    int  flags = receive_tcp_packet(socket,
                                    addr.sin_addr.s_addr,
                                    src_addr,
                                    SCAN_DST_PORT,
                                    port,
                                    &did_timeout,
                                    NULL);

    return !(flags & TCP_RST_FLAG) && did_timeout;
}


bool tcp_scan_port_idle(int       socket,
                        in_addr_t src_addr,
                        in_addr_t dst_addr,
                        uint16_t  port,
                        in_addr_t zombie_addr) {
    struct sockaddr_in z_addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = zombie_addr
    };

    send_tcp_packet(socket, src_addr, z_addr, SCAN_DST_PORT,
                    TCP_SYN_FLAG | TCP_ACK_FLAG);

    bool     did_timeout;
    uint32_t initial_seq_num;
    int      flags = receive_tcp_packet(socket,
                                        zombie_addr,
                                        src_addr,
                                        SCAN_DST_PORT,
                                        port,
                                        &did_timeout,
                                        &initial_seq_num);

    if (did_timeout) {
        fprintf(stderr, "Zombie timeout 1.\n");
        exit(1);
    }

    if (!(flags & TCP_RST_FLAG)) {
        fprintf(stderr, "Zombie did not reply with RST flag.\n");
        exit(1);
    }



    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = dst_addr
    };
    send_tcp_packet(socket, zombie_addr, addr, SCAN_DST_PORT, TCP_SYN_FLAG);
    usleep(100000);
    send_tcp_packet(socket, src_addr, z_addr, SCAN_DST_PORT,
                    TCP_SYN_FLAG | TCP_ACK_FLAG);


    uint32_t seq_num;
    flags = receive_tcp_packet(socket,
                               zombie_addr,
                               src_addr,
                               SCAN_DST_PORT,
                               port,
                               &did_timeout,
                               &seq_num);

    return !did_timeout && seq_num - 2 == initial_seq_num && flags & TCP_RST_FLAG;
}
