#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>

void print_eheader(const u_char *data);

typedef struct {
    char* Interface_;
} Param;

Param param = {
    .Interface_ = NULL
};


//Ethernet Header
#define ETHER_ADDR_LEN 6

struct ether_header{
    u_char DMac[ETHER_ADDR_LEN];
    u_char SMac[ETHER_ADDR_LEN];
    u_short ether_type;
};
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_REVARP 0x8035

//IP Header
struct ip_header{ //20 Bytes
    u_char header_len:4;
    u_char version:4;
    u_char tos;
    u_short total_length;
    u_short fragment_identifier;
    u_char fragmentation_flags:5;
    u_char ip_more_fragment:1;
    u_char ip_dont_fragment:1;
    u_char ip_reserved_zero:1;
    u_char ip_frag_offset1;
    u_char ttl;
    u_char protocal_identifier;
    u_short checksum;
    u_char Saddr[4];
    u_char Daddr[4];
};

//TCP Header
struct tcp_header{
    u_short Sport;
    u_short Dport;
    u_int sequence;
    u_int acknowledge;
    u_char header_len:4;
    u_char fin:1;
    u_char syn:1;
    u_char rst:1;
    u_char psh:1;
    u_char ack:1;
    u_char urg:1;
    u_short window_size;
    u_short checksum;
    u_short urgent_pointer;
};


void usage(){
    printf("syntax:  PCAP_HW <interface>\n");
    printf("example: PCAP_HW eth0\n");
}

bool parse(Param* param, int argc, char* argv[]){
    if(argc != 2){
        usage();
        return false;
    }
    param->Interface_ = argv[1];
    return true;
}

int main(int argc, char* argv[]){
    if(!parse(&param, argc, argv))
        return -1;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.Interface_, BUFSIZ, 1, 1000, errbuf);
    if(pcap == NULL){
        fprintf(stderr, "{%s} return null - %s\n", param.Interface_, errbuf);
        return -1;
    }

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if(res == 0)
            continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        struct ether_header *eheader = (struct ether_header*)packet;
        if(ntohs(eheader->ether_type) != ETHERTYPE_IP)
            continue;
        printf("Src Mac [%02X:%02X:%02X:%02X:%02X:%02X] <-> Dst Mac [%02X:%02X:%02X:%02X:%02X:%02X]\n", eheader->SMac[0], eheader->SMac[1], eheader->SMac[2], eheader->SMac[3], eheader->SMac[4], eheader->SMac[5], eheader->DMac[0], eheader->DMac[1], eheader->DMac[2], eheader->DMac[3], eheader->DMac[4], eheader->DMac[5]);

        packet = packet+14;
        struct ip_header *ih = (struct ip_header*)packet;

        packet = packet+ih->header_len*4;
        struct tcp_header *th = (struct tcp_header*)packet;

        if(ih->protocal_identifier == 0x06){ // type
            printf("Src IP  [%d.%d.%d.%d][%d] <-> Dst IP  [%d.%d.%d.%d][%d]\n", ih->Saddr[0], ih->Saddr[1], ih->Saddr[2], ih->Saddr[3], htons(th->Sport), ih->Daddr[0], ih->Daddr[1], ih->Daddr[2], ih->Daddr[3], htons(th->Dport));
            packet = packet + th->header_len*4;
            
            for(int i = 0; i < 8; i++)
                printf("%02X ", packet[i]);
        }
        printf("\n");
    }
    
    pcap_close(pcap);
}