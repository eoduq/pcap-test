#ifndef __HEADER_STRUCTURES_H__
#include <stdint.h>
#pragma once
typedef struct _ethernet_header{
    uint8_t dstAddr[6]; //MAC Destination Address
    uint8_t srcAddr[6]; //MAC Source Address
    uint16_t etherType; //Ehernet Type
    
}ETHERNET_HEADER;

typedef struct _ipv4_header{
    //unsigned char version;//(4)
    //unsigned char IHL;//Internet Header Length(5)
    uint8_t version_IHL;
    uint8_t TOS;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flag_fragmentOffset;
    uint8_t TTL;
    uint8_t protocol; //TCP라면 6
    uint16_t headerChecksum;
    uint32_t srcAddr; //source IP address
    uint32_t dstAddr; //destination IP address
    
    
}IPv4_HEADER;

typedef struct _tcp_header{
    uint16_t srcPort;//source port
    uint16_t dstPort;//destination port
    uint32_t seqNumber;//sequence number
    uint32_t ackNumber;//Acknowledgement number
    uint16_t dataOffset_reserved_flags;//Data Offset
    
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;
}TCP_HEADER;







#endif
