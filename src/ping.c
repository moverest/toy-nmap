#include "ping.h"

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

static unsigned short icmp_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int   sum  = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }

    if (len == 1) {
        sum += *(unsigned char *)buf;
    }

    sum    = (sum >> 16) + (sum & 0xFFFF);
    sum   += (sum >> 16);
    result = ~sum;
    return result;
}


int make_socket_icmp() {
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (s < 0) {
        perror("Could not create ICMP socket");
        exit(1);
    }

    int value = 255;
    if (setsockopt(s, SOL_IP, IP_TTL, &value, sizeof(value)) < 0) {
        perror("Could not set TTL option");
        exit(1);
    }

    return s;
}


size_t make_icmp_packet(char *buf, size_t buf_size, int cnt) {
    int i;

    memset(buf, 0, buf_size);
    struct icmp_packet *packet = (struct icmp_packet *)buf;
    packet->hdr.type       = ICMP_ECHO;
    packet->hdr.un.echo.id = 4; // A random number chosen by a fair dice roll
    for (i = 0; i < sizeof(packet->msg) - 1; i++) {
        packet->msg[i] = i + '0';
    }
    packet->msg[i] = 0;
    packet->hdr.un.echo.sequence = cnt;
    packet->hdr.checksum         = icmp_checksum(packet, sizeof(struct icmp_packet));

    return sizeof(struct icmp_packet);
}
