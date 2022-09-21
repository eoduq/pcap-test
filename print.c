#pragma once
#include "header_structures.h"
#include <sys/types.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

void printEthrAddr(ETHERNET_HEADER *h){
    printf("----------------------------------\n");
    printf("----------------------------------\n");
    printf("Ethernet Header\n");
    printf("src mac: ");
    printf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",h->srcAddr[0],h->srcAddr[1],h->srcAddr[2],h->srcAddr[3],h->srcAddr[4],h->srcAddr[5]);
    printf("dst mac: ");
    printf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",h->dstAddr[0],h->dstAddr[1],h->dstAddr[2],h->dstAddr[3],h->dstAddr[4],h->dstAddr[5]);
    return;
}


void printIP_Struct(IPv4_HEADER *h){
    printf("----------------------------------\n");
    printf("IP Header\n");
    struct sockaddr_in addr;
    printf("src ip: ");
    addr.sin_addr.s_addr=h->srcAddr;
    printf("%s\n",inet_ntoa(addr.sin_addr));

    printf("dst ip: ");
    addr.sin_addr.s_addr=h->dstAddr;
    printf("%s\n",inet_ntoa(addr.sin_addr));
    
    return;

}


void printTCP_Struct(TCP_HEADER *h){
    printf("----------------------------------\n");
    printf("TCP Header\n");

    printf("src port: ");
    printf("%hu\n",ntohs(h->srcPort));
    printf("dst port: ");
    printf("%hu\n",ntohs(h->dstPort));

    return;

}


void printData(const u_char *p, uint32_t datasize, uint32_t data_start_index){
    printf("----------------------------------\n");
    printf("Payload(Data)\n");
    if(datasize>10){
        datasize=10;
    }
    for(int i=0;i<datasize;i++){
        printf("0x%02hhx ",p[data_start_index+i]);
    }
    printf("\n");
//    printf("----------------------------------\n");
//    printf("----------------------------------\n");
//    printf("\n\n");
    return;
}

