#ifndef __SET_HEADERS_H__
#pragma once
#include "header_structures.h"
#include <stdint.h>
#include "nums.h"
#include <sys/types.h>
void setEthr_Struct(ETHERNET_HEADER * h, const u_char * p);
void setIP_Struct(IPv4_HEADER *h, const u_char *p);
void setTCP_Struct(TCP_HEADER *h, const u_char *p, uint32_t tcp_start_index);

    
//    memcpy(h,p,sizeof(u_char)*ETHERNET_LENGTH);
//    printf("p[0]: 0x%hhx\n",p[0]);
//    printf("ETHERNET[0]: 0x%hhx\n",h->dstAddr[0]);






#endif
