#include "cshark.h"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int packet_id = 0;

    if (stop_sniffing) {
        pcap_breakloop((pcap_t *)args);
        return;
    }
    packet_id++;

    // Store packet
    store_packet(header, packet, packet_id);

    printf("-----------------------------------------\n");
    printf("Packet #%d | Timestamp: %ld.%06ld | Length: %d bytes\n",
           packet_id, header->ts.tv_sec, header->ts.tv_usec, header->caplen);

    struct ether_header *eth_hdr = (struct ether_header *)packet;

    printf("L2 (Ethernet): Dst MAC: ");
    print_mac_address(eth_hdr->ether_dhost);
    printf(" | Src MAC: ");
    print_mac_address(eth_hdr->ether_shost);
    printf(" |\n");  // Note the pipe and newline
    printf("EtherType: ");

    uint16_t eth_type = ntohs(eth_hdr->ether_type);
    int l4_protocol = 0;
    u_char *l4_packet = NULL;
    int l4_length = 0;

    switch (eth_type) {
        case ETHERTYPE_IP: {
            printf("IPv4 (0x%04X)\n", eth_type);
            struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));

            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip->saddr), src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &(ip->daddr), dst_ip, sizeof(dst_ip));

            printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: ", src_ip, dst_ip);
            switch (ip->protocol) {
                case IPPROTO_TCP: printf("TCP (%d)", ip->protocol); break;
                case IPPROTO_UDP: printf("UDP (%d)", ip->protocol); break;
                default: printf("Unknown (%d)", ip->protocol);
            }
            printf(" | TTL: %d\n", ip->ttl);

            printf("ID: 0x%X | Total Length: %d | Header Length: %d bytes\n",
                   ntohs(ip->id), ntohs(ip->tot_len), ip->ihl * 4);

            print_ip_flags(ip->frag_off);
            printf("\n");

            l4_protocol = ip->protocol;
            int ip_header_len = ip->ihl * 4;
            l4_packet = (u_char *)packet + sizeof(struct ether_header) + ip_header_len;
            l4_length = ntohs(ip->tot_len) - ip_header_len;
            break;
        }
        case ETHERTYPE_IPV6: {
            printf("IPv6 (0x%04X)\n", eth_type);
            struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + sizeof(struct ether_header));

            char src_ip6[INET6_ADDRSTRLEN], dst_ip6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ip6->ip6_src), src_ip6, sizeof(src_ip6));
            inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_ip6, sizeof(dst_ip6));

            uint32_t vtc_flow = ntohl(*(uint32_t *)ip6);
            uint8_t traffic_class = (vtc_flow & 0x0FF00000) >> 20;
            uint32_t flow_label = vtc_flow & 0x000FFFFF;

            printf("L3 (IPv6): Src IP: %s | Dst IP: %s\n", src_ip6, dst_ip6);
            printf("Next Header: ");
            switch (ip6->ip6_nxt) {
                case IPPROTO_TCP: printf("TCP (%d)", ip6->ip6_nxt); break;
                case IPPROTO_UDP: printf("UDP (%d)", ip6->ip6_nxt); break;
                default: printf("Unknown (%d)", ip6->ip6_nxt);
            }
            printf(" | Hop Limit: %d\n", ip6->ip6_hlim);
            printf("Traffic Class: %d | Flow Label: 0x%05X | Payload Length: %d\n",
                   traffic_class, flow_label, ntohs(ip6->ip6_plen));

            l4_protocol = ip6->ip6_nxt;
            l4_packet = (u_char *)packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr);
            l4_length = ntohs(ip6->ip6_plen);
            break;
        }
        case ETHERTYPE_ARP: {
            printf("ARP (0x%04X)\n", eth_type);
            struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));

            char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp->arp_spa, sender_ip, sizeof(sender_ip));
            inet_ntop(AF_INET, arp->arp_tpa, target_ip, sizeof(target_ip));

            printf("L3 (ARP): Operation: ");
            switch (ntohs(arp->arp_op)) {
                case ARPOP_REQUEST: printf("Request (1)"); break;
                case ARPOP_REPLY: printf("Reply (2)"); break;
                default: printf("Unknown (%d)", ntohs(arp->arp_op));
            }
            printf(" | Sender IP: %s | Target IP: %s\n", sender_ip, target_ip);

            printf("Sender MAC: ");
            print_mac_address(arp->arp_sha);
            printf(" | Target MAC: ");
            print_mac_address(arp->arp_tha);
            printf("\n");

            printf("HW Type: %d | Proto Type: 0x%X | HW Len: %d | Proto Len: %d\n",
                   ntohs(arp->arp_hrd), ntohs(arp->arp_pro), arp->arp_hln, arp->arp_pln);
            break;
        }
        default:
            printf("Unknown (0x%04X)\n", eth_type);
            break;
    }

    // Layer 4 processing
    if (l4_protocol == IPPROTO_TCP && l4_packet != NULL) {
        struct tcphdr *tcp = (struct tcphdr *)l4_packet;
        uint16_t src_port = ntohs(tcp->th_sport);
        uint16_t dst_port = ntohs(tcp->th_dport);

        printf("L4 (TCP): Src Port: %d %s | Dst Port: %d %s | Seq: %u | Ack: %u\n",
               src_port, port_name(src_port), dst_port, port_name(dst_port),
               ntohl(tcp->th_seq), ntohl(tcp->th_ack));
        printf(" | ");
        print_tcp_flags(tcp->th_flags);
        printf("\n");
        printf("Window: %d | Checksum: 0x%X | Header Length: %d bytes\n",
               ntohs(tcp->th_win), ntohs(tcp->th_sum), tcp->th_off * 4);

        int tcp_header_len = tcp->th_off * 4;
        int payload_len = l4_length - tcp_header_len;
        u_char *payload = l4_packet + tcp_header_len;

        if (payload_len > 0) {
            printf("L7 (Payload): Identified as %s on port %d - %d bytes\n",
                   (src_port == 80 || dst_port == 80) ? "HTTP" :
                   (src_port == 443 || dst_port == 443) ? "HTTPS/TLS" :
                   (src_port == 53 || dst_port == 53) ? "DNS" : "Unknown",
                   (dst_port == 443 || dst_port == 80 || dst_port == 53) ? dst_port : src_port, payload_len);

            int dump_len = payload_len < 64 ? payload_len : 64;
            printf("Data (first %d bytes):\n", dump_len);
            print_hex_dump(payload, dump_len);
        }
    }
    else if (l4_protocol == IPPROTO_UDP && l4_packet != NULL) {
        struct udphdr *udp = (struct udphdr *)l4_packet;
        uint16_t src_port = ntohs(udp->uh_sport);
        uint16_t dst_port = ntohs(udp->uh_dport);

        printf("L4 (UDP): Src Port: %d %s | Dst Port: %d %s | Length: %d | Checksum: 0x%X\n",
               src_port, port_name(src_port), dst_port, port_name(dst_port),
               ntohs(udp->uh_ulen), ntohs(udp->uh_sum));

        int udp_header_len = 8;
        int payload_len = l4_length - udp_header_len;
        u_char *payload = l4_packet + udp_header_len;

        if (payload_len > 0) {
            printf("L7 (Payload): Identified as %s on port %d - %d bytes\n",
                   (src_port == 53 || dst_port == 53) ? "DNS" : "Unknown",
                   (dst_port == 53) ? dst_port : src_port, payload_len);

            int dump_len = payload_len < 64 ? payload_len : 64;
            printf("Data (first %d bytes):\n", dump_len);
            print_hex_dump(payload, dump_len);
        }
    }
    printf("\n");
}