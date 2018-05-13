#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#include "ping.h"
#include "scan.h"


int main(int argc, char **argv) {
    struct {
        char *name;
        bool (*fc)(int, char **);
        char *usage;
    }
    mains[] = {
        { "ip-scan",
          ping_main,
          "<network ip> <mask>" },
        { "scan",
          scan_main,
          "tcp-syn|tcp-synack|udp <scanner host ip> <scanned host ip> [<min port> [<max port>]]" },
        { "scan",
          scan_main,
          "tcp-idle <scanner host ip> <scanned host ip> <zombie ip> [<min port> [<max port>]]" }
    };

    if (argc <= 1) {
        goto usage;
    }

    for (int i = 0; i < (int)(sizeof(mains) / sizeof(mains[0])); i++) {
        if (strcmp(argv[1], mains[i].name) == 0) {
            if (!mains[i].fc(argc, argv)) {
                goto usage;
            }
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


int test_get_service_port_name() {
    for (size_t i = 0; i < 100; i++) {
        /* code */
        printf("Port %ld : %s\n", i, get_service_port_name(i, 0));
    }
    return 0;
}
