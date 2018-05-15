#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#include "tcputils.h"
#include "ping.h"
#include "udputils.h"


int main(int argc, char **argv) {
    struct {
        char *name;
        void (*fc)(int, char **);
        char *usage;
    }
    mains[] = {
        { "ip-scan",
          ping_main,
          "<network ip> <mask>" },

        { "tcp-port-scan",
          tcp_scan_main,
          "syn|synack <scanner host ip> <scanned host ip> [<min port> [<max port>]]" },
        { "udp-port-scan",
          udp_scan_main,
          "never ever ever!" }
    };

    if (argc <= 1) {
        goto usage;
    }

    for (int i = 0; i < (int)(sizeof(mains) / sizeof(mains[0])); i++) {
        if (strcmp(argv[1], mains[i].name) == 0) {
            mains[i].fc(argc, argv);
            return 0;
        }
    }

usage:
    puts("Usages:");
    for (int i = 0; i < (int)(sizeof(mains) / sizeof(mains[0])); i++) {
        printf("   %s %s %s\n", argv[0], mains[i].name, mains[i].usage);
    }
    return 1;
}
