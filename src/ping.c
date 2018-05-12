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


void make_ping_packet(char *buf, int seq_num) {
    memset(buf, 0, PING_PACKET_SIZE);
    struct icmp_packet *packet = (struct icmp_packet *)buf;
    packet->hdr.type       = ICMP_ECHO;
    packet->hdr.un.echo.id = 4; // A random number chosen by a fair dice roll

    // From the Lego Movie.
    char *text = "Everything is awesome! Everything is cool when you're part of a team. Everything is awesome, when you are living your dream!\n";
    for (int i = 0; i < sizeof(packet->msg) - 1; i++) {
        packet->msg[i] = text[i % 125];
    }
    // The last byte is \0 (because of memset).

    packet->hdr.un.echo.sequence = seq_num;
    packet->hdr.checksum         = icmp_checksum(packet, PING_PACKET_SIZE);
}


void send_ping(int socket, in_addr_t dst) {
    char buf[PING_PACKET_SIZE];

    make_ping_packet(buf, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = dst;
    if (sendto(socket, buf, PING_PACKET_SIZE, 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Could not send ping packet");
        exit(1);
    }
}


void ping_main() {
    int socket = make_socket_icmp();

    send_ping(socket, inet_addr("127.0.0.1"));

    shutdown(socket, 2);
}
