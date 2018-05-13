#ifndef __SCAN_H__INCLUDED__
#define __SCAN_H__INCLUDED__

#include <stdbool.h>
#include <stdint.h>

// scan_main return true if everything went alright. False if
// usage needs to be displayed.
// If something went wrong, scan_main calls `exit()` himself.
bool scan_main(int argc, char **argv);

// get_service_port_name return the name of the usual service running with
// port and protocol passed, and 0 if no correspondance were found
char *get_service_port_name(uint16_t port, int protocol);

#endif
