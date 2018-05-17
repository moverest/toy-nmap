#include "udputils.h"

#define PACKET_BUF_SIZE     2048
#define RECEIVE_BUF_SIZE    4096
#define SCAN_DST_PORT       13300
#define UDP_WAIT_TIMEOUT    1

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

// From the Minirighi project.
// See: http://minirighi.sourceforge.net/html/udp_8h-source.html
static uint16_t udp_checksum(const void *buff, size_t len,
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
    sum += htons(IPPROTO_UDP);
    sum += htons(length);

    // Add the carries
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return the one's complement of sum
    return((uint16_t)(~sum));
}


size_t make_udp_packet(char *buf, size_t buf_size,
                       in_addr_t ip_src, in_addr_t ip_dst,
                       uint16_t port_src, uint16_t port_dst) {
    memset(buf, 0, buf_size);
    size_t packet_len = sizeof(struct ip) + sizeof(struct udphdr);

    struct ip *ip_header = (struct ip *)buf;
    ip_header->ip_hl  = 5;
    ip_header->ip_v   = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(packet_len);
    ip_header->ip_id  = htonl(13100);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 255;
    ip_header->ip_p   = IPPROTO_UDP;
    ip_header->ip_sum = 0; // Computed by the kernel with IP_HDRINCL.
    ip_header->ip_src = (struct in_addr){
        ip_src
    };
    ip_header->ip_dst = (struct in_addr){
        ip_dst
    };

    struct udphdr *udp_header = (struct udphdr *)(buf + sizeof(struct ip));
    udp_header->uh_sport = htons(port_src);
    udp_header->uh_dport = htons(port_dst);
    udp_header->uh_ulen  = htons(sizeof(struct udphdr));
    udp_header->uh_sum   = 0;

    udp_header->uh_sum = udp_checksum(udp_header, sizeof(struct udphdr),
                                      ip_src, ip_dst);

    return packet_len;
}


int make_udp_socket() {
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);

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
    tv.tv_sec  = UDP_WAIT_TIMEOUT;
    tv.tv_usec = 0;
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Could not set timeout");
        exit(1);
    }

    return s;
}


void send_udp_packet(int                socket,
                     in_addr_t          src_addr,
                     struct sockaddr_in dst_addr,
                     uint16_t           src_port) {
    char   packet_buf[PACKET_BUF_SIZE];
    size_t packet_len = make_udp_packet(packet_buf, PACKET_BUF_SIZE,
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
                            uint16_t src_port) {
    struct ip     *ip_header  = (struct ip *)packet;
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ip));

    if ((ntohs(ip_header->ip_len) < sizeof(struct ip) + sizeof(struct udphdr)) ||
        (ip_header->ip_p != IPPROTO_UDP) ||
        (ip_header->ip_dst.s_addr != dst_addr) ||
        (ip_header->ip_src.s_addr != src_addr) ||
        (ntohs(udp_header->uh_dport) != dst_port) ||
        (ntohs(udp_header->uh_sport) != src_port)) {
        return false;
    }

    return true;
}


static bool is_icmp_packet(char *packet,
                           in_addr_t src_addr, in_addr_t dst_addr,
                           uint16_t dst_port,
                           uint16_t src_port) {
    struct ip *ip_header = (struct ip *)packet;

    if ((ntohs(ip_header->ip_len) < sizeof(struct ip)) ||
        (ip_header->ip_p != IPPROTO_ICMP) ||
        (ip_header->ip_dst.s_addr != dst_addr) ||
        (ip_header->ip_src.s_addr != src_addr)) {
        return false;
    }

    return true;
}


bool receive_udp_packet(int socket,
                        in_addr_t src_addr, in_addr_t dst_addr,
                        uint16_t dst_port,
                        uint16_t src_port) {
    char buf[RECEIVE_BUF_SIZE];

    time_t start_time = time(NULL);

    do {
        ssize_t len = recvfrom(socket, buf, RECEIVE_BUF_SIZE, 0, NULL, NULL);
        if (len < 0) {
            continue;
        }
        //TODO Fix this shit, we need to receive icmp & udp packet
        if (is_valid_packet(buf, src_addr, dst_addr, dst_port, src_port)) {
            return true;
        } else if (is_icmp_packet(buf, src_addr, dst_addr, dst_port, src_port)) {
            return false;
        }
    } while (start_time + UDP_WAIT_TIMEOUT > time(NULL));
    //return false;
    return true;
}


bool udp_scan_port(int       socket,
                          in_addr_t src_addr,
                          in_addr_t dst_addr,
                          uint16_t  port) {
    struct sockaddr_in addr;

    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = dst_addr;

    send_udp_packet(socket, src_addr, addr, port);

    return receive_udp_packet(socket,
                              addr.sin_addr.s_addr,
                              src_addr,
                              SCAN_DST_PORT,
                              port);
}
