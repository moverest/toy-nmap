#include "ping.h"

#define PING_WAIT_TIMEOUT     1
#define PING_RECV_BUF_SIZE    1024

// A random number chosen by a fair dice roll
#define PING_ECHO_ID          4

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
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

    struct timeval tv;
    tv.tv_sec  = 2;
    tv.tv_usec = 0;
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Could not set timeout");
        exit(1);
    }

    return s;
}


void make_ping_packet(char *buf, int seq_num) {
    memset(buf, 0, PING_PACKET_SIZE);
    struct icmp_packet *packet = (struct icmp_packet *)buf;
    packet->hdr.type       = ICMP_ECHO;
    packet->hdr.un.echo.id = PING_ECHO_ID;

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


bool receive_ping(int socket, in_addr_t src) {
    char   buf[PING_RECV_BUF_SIZE];
    time_t start_time = time(NULL);

    do {
        struct sockaddr_in addr;
        socklen_t          addr_len = sizeof(addr);

        ssize_t len = recvfrom(socket, buf, PING_RECV_BUF_SIZE,
                               0, (struct sockaddr *)&addr, &addr_len);
        if (len < 0) {
            continue;
        }

        struct icmphdr *header = (struct icmphdr *)(buf + sizeof(struct iphdr));
        if ((addr.sin_addr.s_addr == src) &&
            (len >= sizeof(struct icmphdr)) &&
            (header->type == ICMP_ECHOREPLY) &&
            (header->un.echo.id == PING_ECHO_ID)) {
            return true;
        }
    } while (start_time + PING_WAIT_TIMEOUT > time(NULL));

    return false;
}


void ping_main(int argc, char **argv) {
    if (argc != 4) {
        printf("Usage: %s %s <local network IP address> <mask>", argv[0], argv[1]);
        exit(1);
    }

    in_addr_t network_addr = inet_addr(argv[2]);
    in_addr_t mask         = inet_addr(argv[3]);



    in_addr_t network_addr_inverted = htonl(network_addr);
    in_addr_t current_addr_inverted = htonl(network_addr);
    in_addr_t mask_inverted         = htonl(mask);
    current_addr_inverted &= mask_inverted;

    int socket = make_socket_icmp();

    while (current_addr_inverted <
           network_addr_inverted + ~mask_inverted - 1) {
        current_addr_inverted++;
        in_addr_t     current_addr = htonl(current_addr_inverted);
        unsigned char *n           = (unsigned char *)&current_addr;
        printf("%d.%d.%d.%d", n[0], n[1], n[2], n[3]);
        fflush(stdout);

        send_ping(socket, current_addr);
        bool is_up = receive_ping(socket, current_addr);
        printf("\t%s\n", is_up ? "\x1b[32mup\x1b[0m" : "\x1b[31mdown\x1b[0m");
    }

    shutdown(socket, 2);
}
