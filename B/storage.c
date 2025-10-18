// ############## LLM Generated Code Begins ##############
#include "cshark.h"

stored_packet_t packet_storage[MAX_PACKETS];
int stored_packet_count = 0;

void clear_packet_storage() {
    for (int i = 0; i < stored_packet_count; i++) {
        if (packet_storage[i].packet_data != NULL) {
            free(packet_storage[i].packet_data);
            packet_storage[i].packet_data = NULL;
        }
    }
    stored_packet_count = 0;
    printf("[C-Shark] Previous session cleared from memory.\n");
}

void store_packet(const struct pcap_pkthdr *header, const u_char *packet, int packet_id) {
    if (stored_packet_count >= MAX_PACKETS) {
        return; // Storage full
    }
    
    packet_storage[stored_packet_count].header = *header;
    packet_storage[stored_packet_count].packet_data = (u_char*)malloc(header->caplen);
    if (packet_storage[stored_packet_count].packet_data == NULL) {
        fprintf(stderr, "Memory allocation failed for packet storage\n");
        return;
    }
    
    memcpy(packet_storage[stored_packet_count].packet_data, packet, header->caplen);
    packet_storage[stored_packet_count].packet_id = packet_id;
    stored_packet_count++;
}

void list_stored_packets() {
    if (stored_packet_count == 0) {
        printf("\n[C-Shark] No packets in storage. Run a capture session first.\n");
        return;
    }
    
    printf("\n========================================\n");
    printf("Stored Packets from Last Session: %d packets\n", stored_packet_count);
    printf("========================================\n\n");
    
    for (int i = 0; i < stored_packet_count; i++) {
        stored_packet_t *sp = &packet_storage[i];
        struct ether_header *eth_hdr = (struct ether_header *)sp->packet_data;
        uint16_t eth_type = ntohs(eth_hdr->ether_type);
        
        printf("Packet #%d | Time: %ld.%06ld | Length: %d bytes | Type: ",
               sp->packet_id, sp->header.ts.tv_sec, sp->header.ts.tv_usec, 
               sp->header.caplen);
        
        if (eth_type == ETHERTYPE_IP) {
            struct iphdr *ip = (struct iphdr *)(sp->packet_data + sizeof(struct ether_header));
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip->saddr), src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &(ip->daddr), dst_ip, sizeof(dst_ip));
            printf("IPv4 | %s -> %s | Proto: %d", src_ip, dst_ip, ip->protocol);
        } else if (eth_type == ETHERTYPE_IPV6) {
            printf("IPv6");
        } else if (eth_type == ETHERTYPE_ARP) {
            printf("ARP");
        } else {
            printf("Unknown");
        }
        printf("\n");
    }
    printf("\n");
}
// ############## LLM Generated Code Ends ################