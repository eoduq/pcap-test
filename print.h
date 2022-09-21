#pragma once
#include "header_structures.h"
#include <sys/types.h>
void printEthrAddr(ETHERNET_HEADER *h);

void printIP_Struct(IPv4_HEADER *h)
void printTCP_Struct(TCP_HEADER *h)
void printData(const u_char *p, uint32_t datasize, uint32_t data_start_index)

