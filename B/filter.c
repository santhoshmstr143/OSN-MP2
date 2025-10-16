#include "cshark.h"

void filtered_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Call the regular handler - filtering is done via BPF
    packet_handler(args, header, packet);
}

void start_sniffing_filtered(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[256] = "";
    bpf_u_int32 net, mask;
    
    printf("\n[C-Shark] Filter Options:\n");
    printf("1. HTTP (port 80)\n");
    printf("2. HTTPS (port 443)\n");
    printf("3. DNS (port 53)\n");
    printf("4. ARP\n");
    printf("5. TCP\n");
    printf("6. UDP\n");
    printf("\nEnter filter choice (1-6): ");
    
    int choice;
    if (scanf("%d", &choice) != 1) {
        printf("Invalid input.\n");
        return;
    }
    
    // Clear input buffer
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    switch (choice) {
        case 1:
            strcpy(filter_exp, "tcp port 80");
            break;
        case 2:
            strcpy(filter_exp, "tcp port 443");
            break;
        case 3:
            strcpy(filter_exp, "port 53");
            break;
        case 4:
            strcpy(filter_exp, "arp");
            break;
        case 5:
            strcpy(filter_exp, "tcp");
            break;
        case 6:
            strcpy(filter_exp, "udp");
            break;
        default:
            printf("Invalid choice.\n");
            return;
    }
    
    printf("[C-Shark] Applying filter: %s\n", filter_exp);
    
    // Clear previous session
    clear_packet_storage();
    
    stop_sniffing = 0;
    handle = pcap_open_live(device, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return;
    }
    
    // Get network address and mask
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", device);
        net = 0;
        mask = 0;
    }
    
    // Compile the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return;
    }
    
    // Apply the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return;
    }
    
    g_datalink_type = pcap_datalink(handle);
    
    printf("[C-Shark] Starting filtered capture... Press Ctrl+C to stop.\n\n");
    
    signal(SIGINT, sigint_handler);
    
    pcap_loop(handle, -1, filtered_packet_handler, (u_char *)handle);
    
    pcap_freecode(&fp);
    pcap_close(handle);
    printf("\n[C-Shark] Filtered capture stopped. Captured %d packets. Returning to menu.\n", stored_packet_count);
}