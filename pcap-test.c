#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "header_structures.h"
#include "set_headers.h"
#include "nums.h"
//#define IP_ETHERTYPE 0x0800
//#define ETHERNET_LENG 14
//#define IP_DEFAULT_SIZE 20
//#define TCP_PROTOCOL 6
//#define WEIGHT 4

void usage(void) {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

/*
bool isIP(ETHERNET_HEADER*h){
    return (ntohs(h->etherType)==IP_ETHERTYPE);
}

bool isTCP(IPv4_HEADER *h){
    return (h->protocol==TCP_PROTOCOL);
}
*/



int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
       	 
        	ETHERNET_HEADER ethrH;
        	setEthr_Struct(&ethrH, packet);
        	
		
		if(!ntohs(ethrH.etherType)==IP_ETHERTYPE)continue;
        	IPv4_HEADER ipH;
        	setIP_Struct(&ipH, packet);
        	
		if(!ipH.protocol==TCP_PROTOCOL)continue;
       		TCP_HEADER tcpH;

		uint32_t ip_header_size=WEIGHT*(ipH.version_IHL&0x0F);

        	uint32_t tcp_header_size=WEIGHT*(packet[ETHERNET_LENGTH+ip_header_size+12]>>4);
        	
		uint32_t tcp_start_index=ETHERNET_LENGTH+ip_header_size;

        	setTCP_Struct(&tcpH, packet, tcp_start_index);
		uint32_t total_packet_len=ntohs(ipH.totalLength);
		
		//length of payload
		uint32_t data_len=total_packet_len-ip_header_size-tcp_header_size;
      		
		uint32_t data_start_index=ETHERNET_LENGTH+ip_header_size+tcp_header_size;

        	printEthrAddr(&ethrH);
        	printIP_Struct(&ipH);
        	printTCP_Struct(&tcpH);
		if(data_len>0) printData(packet, data_len, data_start_index);

  		printf("----------------------------------\n");
    		printf("----------------------------------\n");
    		printf("\n\n");      

        
        	//printf("%u bytes captured\n", header->caplen);
	}
       
    
    

	pcap_close(pcap);
}
