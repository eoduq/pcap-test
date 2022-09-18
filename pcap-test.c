#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define IP_ETHERTYPE 8
#define ETHERNET_LENGTH 14
#define IP_DEFAULT_SIZE 20
#define TCP_PROTOCOL 6
#define WEIGHT 4

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

typedef struct _ethernet_header{
    uint8_t dstAddr[6]; //MAC Destination Address
    uint8_t srcAddr[6]; //MAC Source Address
    uint16_t etherType; //Ehernet Type
    
}ETHERNET_HEADER;

typedef struct _ipv4_header{
    unsigned char version;//(4)
    unsigned char IHL;//Internet Header Length(5)
    uint8_t TOS;
    uint16_t totalLength;
    uint16_t identification;
    unsigned char flag;
    unsigned char fragmentOffset[3];
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
    unsigned char dataOffset;//Data Offset
    unsigned char flags[3];
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;
}TCP_HEADER;

typedef struct _headers{
    ETHERNET_HEADER ethernetHeader;
    IPv4_HEADER ipv4Header;
    TCP_HEADER tcpHeader;
     
}HEADERS;

void setEthr_Struct(ETHERNET_HEADER * h, const u_char * p){
    memcpy(h,p,sizeof(ETHERNET_HEADER));
    
}

void printEthrAddr(ETHERNET_HEADER *h){
    printf("----------------------------------\n");
    printf("Ethernet Header\n");
    printf("src mac: ");
    printf("%hhd:%hhd:%hhd:%hhd:%hhd:%hhd",h->srcAddr[0],h->srcAddr[1],h->srcAddr[2],h->srcAddr[3],h->srcAddr[4],h->srcAddr[5]);
    printf("\n");
    printf("dst mac: ");
    printf("%hhd:%hhd:%hhd:%hhd:%hhd:%hhd",h->dstAddr[0],h->dstAddr[1],h->dstAddr[2],h->dstAddr[3],h->dstAddr[4],h->dstAddr[5]);
}

bool isIP(ETHERNET_HEADER*h){
    return (ntohs(h->etherType)==IP_ETHERTYPE);
}

void setIP_Struct(IPv4_HEADER *h, const u_char *p){
    memcpy(h, &p[ETHERNET_LENGTH], sizeof(char)*IP_DEFAULT_SIZE);
    
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
    
    
}

bool isTCP(IPv4_HEADER *h){
    return (h->protocol==TCP_PROTOCOL);
}

int calc_index(IPv4_HEADER *h){
    return ETHERNET_LENGTH+h->IHL*WEIGHT;
}
void setTCP_Struct(TCP_HEADER *h, const u_char *p, int index){
    memcpy(h,&p[index],h->dataOffset*WEIGHT);
}

void printTCP_Struct(TCP_HEADER *h){
    printf("----------------------------------\n");
    printf("TCP Header\n");
    
    printf("src port: ");
    printf("%hd\n",ntohs(h->srcPort));
    printf("dst port: ");
    printf("%hd\n",ntohs(h->srcPort));
    

    
}

int calc_data_size(IPv4_HEADER *h1, TCP_HEADER *h2){
    return ntohs(h1->totalLength)-ETHERNET_LENGTH-WEIGHT*h1->IHL-WEIGHT*h2->dataOffset;
}

int calc_data_offset(IPv4_HEADER *h1, TCP_HEADER *h2){
    return ETHERNET_LENGTH+WEIGHT*h1->IHL+WEIGHT*h2->dataOffset;
}

void printData(const u_char *p, int datasize, int dataoffset){
    printf("----------------------------------\n");
    printf("Payload(Data)\n");
    if(datasize>10){
        datasize=10;
    }
    for(int i=dataoffset;i<datasize;i++){
        printf("0x%02hhx ",p[i]);
    }
    
    
}




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
        //printf("%hhx\n",packet[0]);
        ETHERNET_HEADER ethrH;
        setEthr_Struct(&ethrH, packet);
        
        if(!isIP(&ethrH))continue;
        IPv4_HEADER ipH;
        setIP_Struct(&ipH, packet);
        
        if(!isTCP(&ipH))continue;
        TCP_HEADER tcpH;
        int index=calc_index(&ipH);
        setTCP_Struct(&tcpH, packet, index);
        
        int dataSize=calc_data_size(&ipH, &tcpH);
        int dataOffset=calc_data_offset(&ipH, &tcpH);
        printData(packet, dataSize, dataOffset);

        
        //printf("%u bytes captured\n", header->caplen);
	}
    
    
    
    
    
    
    
    

	pcap_close(pcap);
}
