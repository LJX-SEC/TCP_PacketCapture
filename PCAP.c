//gcc -o PCAP PCAP.c -lpcap
#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

typedef struct {
    char* Interface_;
} Param;

Param param = {
    .Interface_ = NULL
};

//Ethernet Header
#define ETHER_ADDR_LEN 6

struct ether_header{ //14-bytes
    u_char DMac[ETHER_ADDR_LEN];
    u_char SMac[ETHER_ADDR_LEN];
    u_short ether_type;
};
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_REVARP 0x8035
#define PROTOCOL_TCP 0x06

//IP Header
struct ip_header{ //20-bytes
    u_char version:4;
    u_char header_len:4;
    u_char tos;
    u_short total_length;
    u_short identification;
    u_char flagRb:1;
    u_char flagD:1;
    u_char flagM:1;
    u_int fragment_offset:13;
    u_char ttl;
    u_char protocol_identifier;
    u_short header_checksum;
    u_char Saddr[4];
    u_char Daddr[4];
};

//TCP Header
struct tcp_header{
    u_short Sport;
    u_short Dport;
    u_int sequenceNum;
    u_int acknowledgementNum;
    u_char offset:4;
    u_char reserved:4;
    u_char flagC:1;
    u_char flagE:1;
    u_char flagU:1;
    u_char flagA:1;
    u_char flagP:1;
    u_char flagR:1;
    u_char flagS:1;
    u_char flagF:1;
    u_short window;
    u_short checksum;
    u_short urgent_pointer;
};

void usage(){
    printf("syntax:  PCAP <interface>\n");
    printf("example: PCAP eth0\n");
}

bool parse(Param* param, int argc, char* argv[]){
    if(argc != 2){
        usage();
        return false;
    }
    param->Interface_ = argv[1];
    return true;
}

void printMac(const u_char* packet){
    int i = 0;
    struct ether_header* eh = (struct ether_header*)packet;
    
    printf("SMac[");
    for(i = 0; i < 6; i++){
        printf("%02X", eh->SMac[i]);

        if(i != 5){
            printf(":");
        }
    }
    printf("] <-> DMac[");
    for(i = 0; i < 6; i++){
        printf("%02X", eh->DMac[i]);

        if(i != 5){
            printf(":");
        }
    }
    printf("]\n");
}

u_int printIPPORT(const u_char* packet){
    int i = 0;
    u_int length = 0;

    packet += sizeof(struct ether_header);
    struct ip_header* ih = (struct ip_header*)packet;

    length = htons(ih->total_length) - (sizeof(struct ip_header) + sizeof(struct tcp_header));
    packet += sizeof(struct ip_header);
    struct tcp_header* th = (struct tcp_header*)packet;
    packet += sizeof(struct tcp_header);

    printf("Src[");
    for(i = 0; i < 4; i++){
        printf("%d", ih->Saddr[i]);

        if(i != 3){
            printf(".");
        }        
    }
    
    printf("][%d] <-> Dst[", ntohs(th->Sport));
    for(i = 0; i < 4; i++){
        printf("%d", ih->Daddr[i]);

        if(i != 3){
            printf(".");
        }        
    }
    printf("][%d]\n", ntohs(th->Dport));
    
    return length;
}

void printData(const u_char* ptr, u_int length){
    int count = 0;

    for(int i = 0; i < length; i++){
        if(count >= 15){
            count = 0;
            printf("\n");
        }
        printf("%02X ", ptr[i]);
        count++;
    }
}

int main(int argc, char* argv[]){
    if(!parse(&param, argc, argv))
        return -1;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.Interface_, BUFSIZ, 1, 1000, errbuf);

    if(pcap == NULL){
        fprintf(stderr, "[-] {%s} return null - %s\n", param.Interface_, errbuf);
        return -1;
    }

    while(1){
        struct pcap_pkthdr* header = {0,};
        const u_char* packet = NULL;
        u_int ip_data_length = 0;

        int res = pcap_next_ex(pcap, &header, &packet);

        if(res == 0)
            continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            printf("[-] pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        if(ntohs(((struct ether_header*)packet)->ether_type) != ETHERTYPE_IP){
            continue;
        }

        if(((struct ip_header*)(packet + sizeof(struct ether_header)))->protocol_identifier != PROTOCOL_TCP){ 
            continue;
        }
        printMac(packet);

        ip_data_length = printIPPORT(packet);

        packet += sizeof(struct ether_header);
        packet += sizeof(struct ip_header);
        packet += sizeof(struct tcp_header);
        if(ip_data_length > 0){
            printData(packet, ip_data_length);
        }
        printf("\n\n");
    }
    
    pcap_close(pcap);
}
