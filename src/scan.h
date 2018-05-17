#ifndef __SCAN_H__INCLUDED__
#define __SCAN_H__INCLUDED__

#include <stdbool.h>

// scan_main return true if everything went alright. False if
// usage needs to be displayed.
// If something went wrong, scan_main calls `exit()` himself.
bool scan_main(int argc, char **argv);

#endif
