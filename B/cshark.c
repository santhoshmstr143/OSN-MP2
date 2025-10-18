// ############## LLM Generated Code Begins ##############
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <net/ethernet.h>     // Ethernet header
#include <netinet/if_ether.h> // ARP struct ether_arp
#include <arpa/inet.h>        // inet_ntop()
#include <netinet/ip.h>       // IPv4 header
#include <netinet/ip6.h>      // IPv6 header
#include <netinet/tcp.h>      // TCP header
#include <netinet/udp.h>      // UDP header

volatile sig_atomic_t stop_sniffing = 0;
volatile sig_atomic_t exit_program = 0;
int g_datalink_type = 0;

void sigint_handler(int signo)
{
    stop_sniffing = 1;
}

void print_hex_bytes(const u_char *data, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02X ", data[i]);
    }
}

void print_mac_address(const u_char *mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip_flags(uint16_t frag_off)
{
    printf("Flags:");
    if (frag_off & htons(IP_RF))
        printf(" RF");
    if (frag_off & htons(IP_DF))
        printf(" DF");
    if (frag_off & htons(IP_MF))
        printf(" MF");
    printf(" | Fragment offset: %d", ntohs(frag_off) & IP_OFFMASK);
}

const char *port_name(uint16_t port)
{
    switch (port)
    {
    case 53:
        return "DNS";
    case 80:
        return "HTTP";
    case 443:
        return "HTTPS";
    default:
        return "";
    }
}

void print_tcp_flags(uint8_t flags)
{
    printf("Flags: [");
    int printed = 0;
    if (flags & TH_FIN)
    {
        printf("FIN");
        printed = 1;
    }
    if (flags & TH_SYN)
    {
        if (printed)
            printf(", ");
        printf("SYN");
        printed = 1;
    }
    if (flags & TH_RST)
    {
        if (printed)
            printf(", ");
        printf("RST");
        printed = 1;
    }
    if (flags & TH_PUSH)
    {
        if (printed)
            printf(", ");
        printf("PSH");
        printed = 1;
    }
    if (flags & TH_ACK)
    {
        if (printed)
            printf(", ");
        printf("ACK");
        printed = 1;
    }
    if (flags & TH_URG)
    {
        if (printed)
            printf(", ");
        printf("URG");
        printed = 1;
    }
    printf("]");
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int packet_id = 0;

    if (stop_sniffing)
    {
        pcap_breakloop((pcap_t *)args);
        return;
    }
    packet_id++;

    printf("Packet #%d | Timestamp: %ld.%06ld | Length: %d bytes\n",
           packet_id, header->ts.tv_sec, header->ts.tv_usec, header->caplen);

    struct ether_header *eth_hdr = (struct ether_header *)packet;

    printf("L2 (Ethernet): Dst MAC: ");
    print_mac_address(eth_hdr->ether_dhost);
    printf(" | Src MAC: ");
    print_mac_address(eth_hdr->ether_shost);
    printf(" | EtherType: ");

    uint16_t eth_type = ntohs(eth_hdr->ether_type);

    switch (eth_type)
    {
    case ETHERTYPE_IP:
    {
        printf("IPv4 (0x%04X)\n", eth_type);
        struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->saddr), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &(ip->daddr), dst_ip, sizeof(dst_ip));

        printf("L3 (IPv4): Src IP: %s | Dst IP: %s | ", src_ip, dst_ip);

        printf("Protocol: ");
        switch (ip->protocol)
        {
        case IPPROTO_TCP:
            printf("TCP (%d)", ip->protocol);
            break;
        case IPPROTO_UDP:
            printf("UDP (%d)", ip->protocol);
            break;
        default:
            printf("Unknown (%d)", ip->protocol);
        }
        printf(" | TTL: %d\n", ip->ttl);

        printf("ID: 0x%X | Total Length: %d | Header Length: %d bytes\n",
               ntohs(ip->id), ntohs(ip->tot_len), ip->ihl * 4);

        print_ip_flags(ip->frag_off);
        printf("\n");

        // Layer 4 parsing for IPv4
        int ip_header_len = ip->ihl * 4;
        u_char *l4_packet = (u_char *)packet + sizeof(struct ether_header) + ip_header_len;

        if (ip->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr *)l4_packet;
            uint16_t src_port = ntohs(tcp->th_sport);
            uint16_t dst_port = ntohs(tcp->th_dport);

            printf("L4 (TCP): Src Port: %d %s | Dst Port: %d %s | Seq: %u | Ack: %u\n",
                   src_port, port_name(src_port), dst_port, port_name(dst_port),
                   ntohl(tcp->th_seq), ntohl(tcp->th_ack));
            print_tcp_flags(tcp->th_flags);
            printf(" | Window: %d | Checksum: 0x%X | Header Length: %d bytes\n",
                   ntohs(tcp->th_win), ntohs(tcp->th_sum), tcp->th_off * 4);
        }
        else if (ip->protocol == IPPROTO_UDP)
        {
            struct udphdr *udp = (struct udphdr *)l4_packet;
            uint16_t src_port = ntohs(udp->uh_sport);
            uint16_t dst_port = ntohs(udp->uh_dport);

            printf("L4 (UDP): Src Port: %d %s | Dst Port: %d %s | Length: %d | Checksum: 0x%X\n",
                   src_port, port_name(src_port), dst_port, port_name(dst_port),
                   ntohs(udp->uh_ulen), ntohs(udp->uh_sum));
        }
        break;
    }
    case ETHERTYPE_IPV6:
    {
        printf("IPv6 (0x%04X)\n", eth_type);
        struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + sizeof(struct ether_header));

        char src_ip6[INET6_ADDRSTRLEN], dst_ip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6->ip6_src), src_ip6, sizeof(src_ip6));
        inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_ip6, sizeof(dst_ip6));

        uint32_t vtc_flow = ntohl(*(uint32_t *)ip6);
        uint8_t traffic_class = (vtc_flow & 0x0FF00000) >> 20;
        uint32_t flow_label = vtc_flow & 0x000FFFFF;

        printf("L3 (IPv6): Src IP: %s | Dst IP: %s\nNext Header: ", src_ip6, dst_ip6);
        switch (ip6->ip6_nxt)
        {
        case IPPROTO_TCP:
            printf("TCP (%d)", ip6->ip6_nxt);
            break;
        case IPPROTO_UDP:
            printf("UDP (%d)", ip6->ip6_nxt);
            break;
        default:
            printf("Unknown (%d)", ip6->ip6_nxt);
        }
        printf(" | Hop Limit: %d | Traffic Class: %d | Flow Label: 0x%05X | Payload Length: %d\n",
               ip6->ip6_hlim, traffic_class, flow_label, ntohs(ip6->ip6_plen));

        // Layer 4 parsing for IPv6
        u_char *l4_packet6 = (u_char *)packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr);

        if (ip6->ip6_nxt == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr *)l4_packet6;
            uint16_t src_port = ntohs(tcp->th_sport);
            uint16_t dst_port = ntohs(tcp->th_dport);

            printf("L4 (TCP): Src Port: %d %s | Dst Port: %d %s | Seq: %u | Ack: %u\n",
                   src_port, port_name(src_port), dst_port, port_name(dst_port),
                   ntohl(tcp->th_seq), ntohl(tcp->th_ack));
            print_tcp_flags(tcp->th_flags);
            printf(" | Window: %d | Checksum: 0x%X | Header Length: %d bytes\n",
                   ntohs(tcp->th_win), ntohs(tcp->th_sum), tcp->th_off * 4);
        }
        else if (ip6->ip6_nxt == IPPROTO_UDP)
        {
            struct udphdr *udp = (struct udphdr *)l4_packet6;
            uint16_t src_port = ntohs(udp->uh_sport);
            uint16_t dst_port = ntohs(udp->uh_dport);

            printf("L4 (UDP): Src Port: %d %s | Dst Port: %d %s | Length: %d | Checksum: 0x%X\n",
                   src_port, port_name(src_port), dst_port, port_name(dst_port),
                   ntohs(udp->uh_ulen), ntohs(udp->uh_sum));
        }
        break;
    }
    case ETHERTYPE_ARP:
    {
        printf("ARP (0x%04X)\n", eth_type);

        struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));

        char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->arp_spa, sender_ip, sizeof(sender_ip));
        inet_ntop(AF_INET, arp->arp_tpa, target_ip, sizeof(target_ip));

        printf("L3 (ARP): Operation: ");
        switch (ntohs(arp->arp_op))
        {
        case ARPOP_REQUEST:
            printf("Request (1)");
            break;
        case ARPOP_REPLY:
            printf("Reply (2)");
            break;
        default:
            printf("Unknown (%d)", ntohs(arp->arp_op));
        }
        printf(" | Sender IP: %s | Target IP: %s\n", sender_ip, target_ip);

        printf("Sender MAC: ");
        print_mac_address(arp->arp_sha);
        printf(" | Target MAC: ");
        print_mac_address(arp->arp_tha);
        printf("\n");

        printf("HW Type: %d | Proto Type: 0x%X | HW Len: %d | Proto Len: %d\n",
               ntohs(arp->arp_hrd),
               ntohs(arp->arp_pro),
               arp->arp_hln,
               arp->arp_pln);
        break;
    }
    default:
        printf("Unknown (0x%04X)\n", eth_type);
    }

    printf("Hex dump (first 16 bytes): ");
    int to_print = header->caplen < 16 ? header->caplen : 16;
    print_hex_bytes(packet, to_print);
    printf("\n\n");
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    int i = 0;

    signal(SIGINT, sigint_handler);

    while (!exit_program)
    {
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            fprintf(stderr, "Error finding devices: %s\n", errbuf);
            return 1;
        }

        printf("[C-Shark] The Command-Line Packet Predator\n");
        printf("==============================================\n");
        printf("[C-Shark] Searching for available interfaces... Found!\n\n");

        for (d = alldevs; d != NULL; d = d->next)
        {
            printf("%d. %s", ++i, d->name);
            if (d->description)
                printf(" (%s)", d->description);
            printf("\n");
        }

        printf("\nSelect an interface to sniff (1-%d): ", i);
        int choice;
        if (scanf("%d", &choice) != 1)
        {
            printf("\nExiting C-Shark...\n");
            pcap_freealldevs(alldevs);
            break;
        }

        if (choice < 1 || choice > i)
        {
            printf("Invalid selection. Try again.\n\n");
            pcap_freealldevs(alldevs);
            i = 0;
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
                ;
            continue;
        }

        d = alldevs;
        for (int idx = 1; idx < choice; idx++)
            d = d->next;

        char selected_dev[256];
        strncpy(selected_dev, d->name, sizeof(selected_dev));
        selected_dev[sizeof(selected_dev) - 1] = '\0';

        pcap_freealldevs(alldevs);

        int menu_choice = 0;

        while (!exit_program)
        {
            printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", selected_dev);
            printf("1. Start Sniffing (All Packets)\n");
            printf("2. Start Sniffing (With Filters) <-- To be implemented later\n");
            printf("3. Inspect Last Session <-- To be implemented later\n");
            printf("4. Exit C-Shark\n\n");
            printf("Enter choice: ");

            if (scanf("%d", &menu_choice) != 1)
            {
                printf("\nExiting C-Shark...\n");
                exit_program = 1;
                break;
            }

            if (menu_choice == 1)
            {
                stop_sniffing = 0;
                pcap_t *handle = pcap_open_live(selected_dev, BUFSIZ, 1, 1000, errbuf);
                if (handle == NULL)
                {
                    fprintf(stderr, "Couldn't open device %s: %s\n", selected_dev, errbuf);
                    break;
                }

                // Get and store datalink type globally for handler
                g_datalink_type = pcap_datalink(handle);

                printf("[C-Shark] Starting packet capture... Press Ctrl+C to stop, Ctrl+D to exit.\n\n");

                signal(SIGINT, sigint_handler);

                pcap_loop(handle, -1, packet_handler, (u_char *)handle);

                pcap_close(handle);
                printf("\n[C-Shark] Capture stopped. Returning to menu.\n");
            }
            else if (menu_choice == 4)
            {
                printf("Exiting C-Shark...\n");
                exit_program = 1;
                break;
            }
            else
            {
                printf("Option not implemented yet.\n");
            }

            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF)
                ; // Clear stdin buffer
        }
        i = 0;
    }

    return 0;
}
// ############## LLM Generated Code Ends ################