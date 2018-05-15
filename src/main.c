#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#include "ping.h"
#include "scan.h"


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

        { "scan",
          scan_main,
          "tcp-syn|tcp-synack|udp-scan <scanner host ip> <scanned host ip> [<min port> [<max port>]]" }
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
