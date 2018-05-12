#ifndef __IP_H__INCLUDED__
#define __IP_H__INCLUDED__

#include <stdint.h>

typedef struct {
    uint8_t  ihl             : 4,
             version         : 4;
    uint8_t  type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t fragment_offset : 13,
             flags           : 3;
    uint8_t  time_to_live;
    uint8_t  protocol;
    uint16_t header_checksum;
    uint32_t source_addr;
    uint32_t destination_addr;
} ip_header_t;

#define IP_TOS_HIGH_RELIBILITY 1<<2
#define IP_TOS_HIGH_THROUGHPUT 1<<3
#define IP_TOS_LOW_DELAY 1<<4

#define IP_PRECEDENCE_NETWORK_CONTROL 7<<5
#define IP_PRECEDENCE_INTERNETWORK_CONTROL 6<<5
#define IP_PRECEDENCE_CRITIC 5<<5
#define IP_PRECEDENCE_FLASH_OVERRIDE 4<<5
#define IP_PRECEDENCE_FLASH 3<<5
#define IP_PRECEDENCE_IMMEDIATE 2<<5
#define IP_PRECEDENCE_PRIORITY 1<<5
#define IP_PRECEDENCE_ROUTINE 0<<5





#endif
