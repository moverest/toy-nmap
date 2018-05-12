#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "tcputils.h"


int main(int argc, char **argv) {
    struct sockaddr_in addr;

    in_port_t port = 54500;

    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    in_addr_t src_addr = inet_addr("127.0.0.1");


    int s = make_socket();
    send_tcp_packet(s, src_addr, addr, 8081, TCP_SYN_FLAG);

    shutdown(s, 2);

    return 0;
}
