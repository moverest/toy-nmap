#include "scan.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "tcputils.h"

void scan_main(int argc, char **argv) {
    struct {
        char *name;
        int  (*make_socket)();
        bool (*scan_port)(int, in_addr_t, in_addr_t, uint16_t);
    }
    scanners[] = {
        {
            "tcp-syn",
            make_tcp_socket,
            tcp_scan_port_syn
        },
        {
            "tcp-synack",
            make_tcp_socket,
            tcp_scan_port_synack
        }
    };



    if (argc < 5) {
        goto usage;
    }

    size_t scanner_i;
    for (scanner_i = 0;
         scanner_i < sizeof(scanners) / sizeof(scanners[0]) &&
         strcmp(scanners[scanner_i].name, argv[2]) != 0;
         scanner_i++) {
    }

    if (scanner_i == sizeof(scanners) / sizeof(scanners[0])) {
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


    int s = scanners[scanner_i].make_socket();

    for (uint32_t port = port_min; port <= port_max; port++) {
        printf("%d", port);
        fflush(stdout);
        bool port_is_open = scanners[scanner_i].scan_port(s, src_addr, dst_addr, port);
        printf("%s", port_is_open ? "\t\x1b[32mopen\x1b[0m\n" : "\x1b[1K\r");
    }

    shutdown(s, 2);

    return;

usage:
    puts("Usage:");
    exit(1);
}
