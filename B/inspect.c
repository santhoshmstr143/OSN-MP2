// ############## LLM Generated Code Begins ##############
#include "cshark.h"

void inspect_packet_detailed(int packet_id) {
    stored_packet_t *sp = NULL;
    
    // Find packet by ID
    for (int i = 0; i < stored_packet_count; i++) {
        if (packet_storage[i].packet_id == packet_id) {
            sp = &packet_storage[i];
            break;
        }
    }
    
    if (sp == NULL) {
        printf("\n[C-Shark] Packet #%d not found in storage.\n", packet_id);
        return;
    }
    
    printf("\n========================================\n");
    printf("DETAILED INSPECTION: Packet #%d\n", sp->packet_id);
    printf("========================================\n\n");
    
    printf("=== PACKET METADATA ===\n");
    printf("Capture Timestamp: %ld.%06ld seconds\n", sp->header.ts.tv_sec, sp->header.ts.tv_usec);
    printf("Captured Length: %d bytes\n", sp->header.caplen);
    printf("Original Length: %d bytes\n\n", sp->header.len);
    
    const u_char *packet = sp->packet_data;
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    
    printf("=== LAYER 2: ETHERNET ===\n");
    printf("Destination MAC: ");
    print_mac_address(eth_hdr->ether_dhost);
    printf("\nSource MAC: ");
    print_mac_address(eth_hdr->ether_shost);
    printf("\nEtherType: 0x%04X (", ntohs(eth_hdr->ether_type));
    
    uint16_t eth_type = ntohs(eth_hdr->ether_type);
    
    switch (eth_type) {
        case ETHERTYPE_IP: printf("IPv4"); break;
        case ETHERTYPE_IPV6: printf("IPv6"); break;
        case ETHERTYPE_ARP: printf("ARP"); break;
        default: printf("Unknown");
    }
    printf(")\n\n");
    
    printf("Raw Ethernet Header (14 bytes):\n");
    print_hex_dump(packet, 14);
    printf("\n");
    
    // Layer 3 processing
    if (eth_type == ETHERTYPE_IP) {
        struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
        
        printf("=== LAYER 3: IPv4 ===\n");
        printf("Version: %d\n", ip->version);
        printf("Header Length: %d bytes (%d words)\n", ip->ihl * 4, ip->ihl);
        printf("Type of Service: 0x%02X\n", ip->tos);
        printf("Total Length: %d bytes\n", ntohs(ip->tot_len));
        printf("Identification: 0x%04X (%d)\n", ntohs(ip->id), ntohs(ip->id));
        
        uint16_t frag_off = ntohs(ip->frag_off);
        printf("Flags: ");
        if (frag_off & IP_RF) printf("RF ");
        if (frag_off & IP_DF) printf("DF ");
        if (frag_off & IP_MF) printf("MF ");
        printf("\nFragment Offset: %d\n", frag_off & IP_OFFMASK);
        
        printf("Time to Live: %d\n", ip->ttl);
        printf("Protocol: %d (", ip->protocol);
        switch (ip->protocol) {
            case IPPROTO_TCP: printf("TCP"); break;
            case IPPROTO_UDP: printf("UDP"); break;
            case IPPROTO_ICMP: printf("ICMP"); break;
            default: printf("Unknown");
        }
        printf(")\n");
        printf("Header Checksum: 0x%04X\n", ntohs(ip->check));
        
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->saddr), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &(ip->daddr), dst_ip, sizeof(dst_ip));
        printf("Source IP: %s\n", src_ip);
        printf("Destination IP: %s\n\n", dst_ip);
        
        printf("Raw IPv4 Header (%d bytes):\n", ip->ihl * 4);
        print_hex_dump((u_char*)ip, ip->ihl * 4);
        printf("\n");
        
        // Layer 4
        int ip_header_len = ip->ihl * 4;
        u_char *l4_packet = (u_char*)packet + sizeof(struct ether_header) + ip_header_len;
        int l4_length = ntohs(ip->tot_len) - ip_header_len;
        
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)l4_packet;
            
            printf("=== LAYER 4: TCP ===\n");
            printf("Source Port: %d %s\n", ntohs(tcp->th_sport), port_name(ntohs(tcp->th_sport)));
            printf("Destination Port: %d %s\n", ntohs(tcp->th_dport), port_name(ntohs(tcp->th_dport)));
            printf("Sequence Number: %u (0x%08X)\n", ntohl(tcp->th_seq), ntohl(tcp->th_seq));
            printf("Acknowledgment Number: %u (0x%08X)\n", ntohl(tcp->th_ack), ntohl(tcp->th_ack));
            printf("Data Offset: %d bytes (%d words)\n", tcp->th_off * 4, tcp->th_off);
            printf("Flags: 0x%02X [", tcp->th_flags);
            if (tcp->th_flags & TH_FIN) printf("FIN ");
            if (tcp->th_flags & TH_SYN) printf("SYN ");
            if (tcp->th_flags & TH_RST) printf("RST ");
            if (tcp->th_flags & TH_PUSH) printf("PSH ");
            if (tcp->th_flags & TH_ACK) printf("ACK ");
            if (tcp->th_flags & TH_URG) printf("URG ");
            printf("]\n");
            printf("Window Size: %d\n", ntohs(tcp->th_win));
            printf("Checksum: 0x%04X\n", ntohs(tcp->th_sum));
            printf("Urgent Pointer: %d\n\n", ntohs(tcp->th_urp));
            
            printf("Raw TCP Header (%d bytes):\n", tcp->th_off * 4);
            print_hex_dump((u_char*)tcp, tcp->th_off * 4);
            printf("\n");
            
            int payload_len = l4_length - (tcp->th_off * 4);
            if (payload_len > 0) {
                u_char *payload = l4_packet + (tcp->th_off * 4);
                printf("=== LAYER 7: PAYLOAD ===\n");
                printf("Payload Length: %d bytes\n", payload_len);
                printf("Application: ");
                uint16_t sport = ntohs(tcp->th_sport);
                uint16_t dport = ntohs(tcp->th_dport);
                if (sport == 80 || dport == 80) printf("HTTP\n");
                else if (sport == 443 || dport == 443) printf("HTTPS/TLS\n");
                else if (sport == 53 || dport == 53) printf("DNS\n");
                else printf("Unknown\n");
                printf("\nPayload Data:\n");
                print_hex_dump(payload, payload_len);
            }
        }
        else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)l4_packet;
            
            printf("=== LAYER 4: UDP ===\n");
            printf("Source Port: %d %s\n", ntohs(udp->uh_sport), port_name(ntohs(udp->uh_sport)));
            printf("Destination Port: %d %s\n", ntohs(udp->uh_dport), port_name(ntohs(udp->uh_dport)));
            printf("Length: %d bytes\n", ntohs(udp->uh_ulen));
            printf("Checksum: 0x%04X\n\n", ntohs(udp->uh_sum));
            
            printf("Raw UDP Header (8 bytes):\n");
            print_hex_dump((u_char*)udp, 8);
            printf("\n");
            
            int payload_len = l4_length - 8;
            if (payload_len > 0) {
                u_char *payload = l4_packet + 8;
                printf("=== LAYER 7: PAYLOAD ===\n");
                printf("Payload Length: %d bytes\n", payload_len);
                printf("Application: ");
                uint16_t sport = ntohs(udp->uh_sport);
                uint16_t dport = ntohs(udp->uh_dport);
                if (sport == 53 || dport == 53) printf("DNS\n");
                else printf("Unknown\n");
                printf("\nPayload Data:\n");
                print_hex_dump(payload, payload_len);
            }
        }
    }
    else if (eth_type == ETHERTYPE_IPV6) {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        
        printf("=== LAYER 3: IPv6 ===\n");
        printf("Version: 6\n");
        
        uint32_t vtc_flow = ntohl(*(uint32_t *)ip6);
        uint8_t traffic_class = (vtc_flow & 0x0FF00000) >> 20;
        uint32_t flow_label = vtc_flow & 0x000FFFFF;
        
        printf("Traffic Class: 0x%02X\n", traffic_class);
        printf("Flow Label: 0x%05X\n", flow_label);
        printf("Payload Length: %d bytes\n", ntohs(ip6->ip6_plen));
        printf("Next Header: %d (", ip6->ip6_nxt);
        switch (ip6->ip6_nxt) {
            case IPPROTO_TCP: printf("TCP"); break;
            case IPPROTO_UDP: printf("UDP"); break;
            case IPPROTO_ICMPV6: printf("ICMPv6"); break;
            default: printf("Unknown");
        }
        printf(")\n");
        printf("Hop Limit: %d\n", ip6->ip6_hlim);
        
        char src_ip6[INET6_ADDRSTRLEN], dst_ip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6->ip6_src), src_ip6, sizeof(src_ip6));
        inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_ip6, sizeof(dst_ip6));
        printf("Source IP: %s\n", src_ip6);
        printf("Destination IP: %s\n\n", dst_ip6);
        
        printf("Raw IPv6 Header (40 bytes):\n");
        print_hex_dump((u_char*)ip6, 40);
        printf("\n");
        
        // Layer 4 for IPv6
        u_char *l4_packet = (u_char*)packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr);
        int l4_length = ntohs(ip6->ip6_plen);
        
        if (ip6->ip6_nxt == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)l4_packet;
            
            printf("=== LAYER 4: TCP ===\n");
            printf("Source Port: %d %s\n", ntohs(tcp->th_sport), port_name(ntohs(tcp->th_sport)));
            printf("Destination Port: %d %s\n", ntohs(tcp->th_dport), port_name(ntohs(tcp->th_dport)));
            printf("Sequence Number: %u\n", ntohl(tcp->th_seq));
            printf("Acknowledgment Number: %u\n", ntohl(tcp->th_ack));
            printf("Data Offset: %d bytes\n", tcp->th_off * 4);
            printf("Flags: [");
            if (tcp->th_flags & TH_FIN) printf("FIN ");
            if (tcp->th_flags & TH_SYN) printf("SYN ");
            if (tcp->th_flags & TH_RST) printf("RST ");
            if (tcp->th_flags & TH_PUSH) printf("PSH ");
            if (tcp->th_flags & TH_ACK) printf("ACK ");
            if (tcp->th_flags & TH_URG) printf("URG ");
            printf("]\n");
            printf("Window Size: %d\n", ntohs(tcp->th_win));
            printf("Checksum: 0x%04X\n\n", ntohs(tcp->th_sum));
            
            printf("Raw TCP Header (%d bytes):\n", tcp->th_off * 4);
            print_hex_dump((u_char*)tcp, tcp->th_off * 4);
            printf("\n");
            
            int payload_len = l4_length - (tcp->th_off * 4);
            if (payload_len > 0) {
                u_char *payload = l4_packet + (tcp->th_off * 4);
                printf("=== LAYER 7: PAYLOAD ===\n");
                printf("Payload Length: %d bytes\n", payload_len);
                printf("\nPayload Data:\n");
                print_hex_dump(payload, payload_len);
            }
        }
        else if (ip6->ip6_nxt == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)l4_packet;
            
            printf("=== LAYER 4: UDP ===\n");
            printf("Source Port: %d %s\n", ntohs(udp->uh_sport), port_name(ntohs(udp->uh_sport)));
            printf("Destination Port: %d %s\n", ntohs(udp->uh_dport), port_name(ntohs(udp->uh_dport)));
            printf("Length: %d bytes\n", ntohs(udp->uh_ulen));
            printf("Checksum: 0x%04X\n\n", ntohs(udp->uh_sum));
            
            printf("Raw UDP Header (8 bytes):\n");
            print_hex_dump((u_char*)udp, 8);
            printf("\n");
            
            int payload_len = l4_length - 8;
            if (payload_len > 0) {
                u_char *payload = l4_packet + 8;
                printf("=== LAYER 7: PAYLOAD ===\n");
                printf("Payload Length: %d bytes\n", payload_len);
                printf("\nPayload Data:\n");
                print_hex_dump(payload, payload_len);
            }
        }
    }
    else if (eth_type == ETHERTYPE_ARP) {
        struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
        
        printf("=== LAYER 3: ARP ===\n");
        printf("Hardware Type: %d\n", ntohs(arp->arp_hrd));
        printf("Protocol Type: 0x%04X\n", ntohs(arp->arp_pro));
        printf("Hardware Length: %d\n", arp->arp_hln);
        printf("Protocol Length: %d\n", arp->arp_pln);
        printf("Operation: %d (", ntohs(arp->arp_op));
        switch (ntohs(arp->arp_op)) {
            case ARPOP_REQUEST: printf("Request"); break;
            case ARPOP_REPLY: printf("Reply"); break;
            default: printf("Unknown");
        }
        printf(")\n");
        
        printf("Sender MAC: ");
        print_mac_address(arp->arp_sha);
        printf("\n");
        
        char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->arp_spa, sender_ip, sizeof(sender_ip));
        inet_ntop(AF_INET, arp->arp_tpa, target_ip, sizeof(target_ip));
        printf("Sender IP: %s\n", sender_ip);
        
        printf("Target MAC: ");
        print_mac_address(arp->arp_tha);
        printf("\n");
        printf("Target IP: %s\n\n", target_ip);
        
        printf("Raw ARP Packet (28 bytes):\n");
        print_hex_dump((u_char*)arp, 28);
        printf("\n");
    }
    
    printf("=== COMPLETE PACKET DUMP ===\n");
    printf("Total %d bytes:\n", sp->header.caplen);
    print_hex_dump(packet, sp->header.caplen);
    printf("\n");
}

void inspect_last_session() {
    if (stored_packet_count == 0) {
        printf("\n[C-Shark] No packets in storage. Run a capture session first.\n");
        return;
    }
    
    list_stored_packets();
    
    printf("Enter Packet ID to inspect (or 0 to cancel): ");
    int packet_id;
    if (scanf("%d", &packet_id) != 1) {
        printf("Invalid input.\n");
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        return;
    }
    
    // Clear input buffer
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    if (packet_id == 0) {
        return;
    }
    
    inspect_packet_detailed(packet_id);
    
    printf("\nPress Enter to continue...");
    getchar();
}
// ############## LLM Generated Code Ends ################