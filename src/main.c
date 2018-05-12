#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#include "tcputils.h"
#include "ping.h"


int main(int argc, char **argv) {
    if (argc >= 2) {
        if (strcmp(argv[1], "ip-scan") == 0) {
            ping_main(argc, argv);
            return 0;
        }
    }

    struct sockaddr_in addr;

    in_port_t dst_port = 54500;
    in_port_t src_port = 8081;

    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(dst_port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    in_addr_t src_addr = inet_addr("127.0.0.1");


    int s = make_socket();
    send_tcp_packet(s, src_addr, addr, src_port, TCP_SYN_FLAG + TCP_ACK_FLAG);

    int flags = receive_tcp_packet(s,
                                   addr.sin_addr.s_addr,
                                   src_addr,
                                   src_port,
                                   &dst_port);

    printf("port: %d, flags: %d, %d", dst_port, flags, flags & TCP_SYN_FLAG);


    shutdown(s, 2);

    return 0;
}
