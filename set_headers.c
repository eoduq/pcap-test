#ifndef __SET_HEADERS_C__
#include "header_structures.h"
#include <string.h>
#include <stdint.h>
#include "nums.h"
#include <sys/types.h>
void setEthr_Struct(ETHERNET_HEADER * h, const u_char * p){

    memcpy(h,p,sizeof(u_char)*ETHERNET_LENGTH);
//    printf("p[0]: 0x%hhx\n",p[0]);
//    printf("ETHERNET[0]: 0x%hhx\n",h->dstAddr[0]);
}

void setIP_Struct(IPv4_HEADER *h, const u_char *p){
    memcpy(h, &p[ETHERNET_LENGTH], sizeof(u_char)*IP_DEFAULT_SIZE);

}

void setTCP_Struct(TCP_HEADER *h, const u_char *p, uint32_t tcp_start_index){
    //printf("p[index]: %hhx\n",p[index]);

    //printf("set tcp header size: %x",size);
    memcpy(h,&p[tcp_start_index],sizeof(TCP_HEADER));
}
#endif
