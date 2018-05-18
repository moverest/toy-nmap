#include "scan.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "tcputils.h"
#include "udputils.h"

bool scan_main(int argc, char **argv) {
    struct {
        char *name;
        int  (*make_socket)();
        bool (*scan_port)(int, in_addr_t, in_addr_t, uint16_t, in_addr_t);
        bool uses_zombie;
    }
    scanners[] = {
        {
            "tcp-syn",
            make_tcp_socket,
            tcp_scan_port_syn,
            false
        },
        {
            "tcp-synack",
            make_tcp_socket,
            tcp_scan_port_synack,
            false
        },
        {
            "tcp-idle",
            make_tcp_socket,
            tcp_scan_port_idle,
            true
        },
        {
            "udp",
            make_udp_socket,
            udp_scan_port,
            false
        }
    };



    if (argc < 5) {
        return false;
    }

    size_t scanner_i;
    for (scanner_i = 0;
         scanner_i < sizeof(scanners) / sizeof(scanners[0]) &&
         strcmp(scanners[scanner_i].name, argv[2]) != 0;
         scanner_i++) {
    }

    if (scanner_i == sizeof(scanners) / sizeof(scanners[0])) {
        return false;
    }


    in_addr_t src_addr    = inet_addr(argv[3]);
    in_addr_t dst_addr    = inet_addr(argv[4]);
    in_addr_t zombie_addr = 0;
    int       offset      = 0;

    if (scanners[scanner_i].uses_zombie) {
        zombie_addr = inet_addr(argv[5]);
        offset      = 1;
    }

    uint16_t port_min = 0x0000;
    uint16_t port_max = 0xffff;

    if (argc >= 6 + offset) {
        port_min = atoi(argv[5 + offset]);
        port_max = port_min;
    }

    if (argc >= 7 + offset) {
        port_max = atoi(argv[6 + offset]);
    }


    int s = scanners[scanner_i].make_socket();

    for (uint32_t port = port_min; port <= port_max; port++) {
        printf("%d", port);
        fflush(stdout);
        bool port_is_open = scanners[scanner_i].scan_port(s, src_addr, dst_addr,
                                                          port, zombie_addr);
        printf("%s", port_is_open ? "\t\x1b[32mopen\x1b[0m\n" : "\x1b[1K\r");
    }

    shutdown(s, 2);

    return true;
}
