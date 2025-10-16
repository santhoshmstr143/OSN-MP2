#include "cshark.h"

int select_interface(char *selected_dev, size_t dev_size) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    int i = 0;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }
    
    printf("\n[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");
    printf("[C-Shark] Searching for available interfaces... Found!\n\n");
    
    for (d = alldevs; d != NULL; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)", d->description);
        printf("\n");
    }
    
    if (i == 0) {
        printf("\n[C-Shark] No interfaces found! Make sure pcap is installed correctly.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nSelect an interface to sniff (1-%d): ", i);
    int choice;
    if (scanf("%d", &choice) != 1) {
        printf("\nExiting C-Shark...\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    if (choice < 1 || choice > i) {
        printf("Invalid selection.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    d = alldevs;
    for (int idx = 1; idx < choice; idx++)
        d = d->next;
    
    strncpy(selected_dev, d->name, dev_size - 1);
    selected_dev[dev_size - 1] = '\0';
    
    pcap_freealldevs(alldevs);
    
    // Clear input buffer
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    return 0;
}

void start_sniffing_all(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Clear previous session
    clear_packet_storage();
    
    stop_sniffing = 0;
    pcap_t *handle = pcap_open_live(device, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return;
    }
    
    g_datalink_type = pcap_datalink(handle);
    
    printf("[C-Shark] Starting packet capture... Press Ctrl+C to stop.\n\n");
    
    signal(SIGINT, sigint_handler);
    
    pcap_loop(handle, -1, packet_handler, (u_char *)handle);
    
    pcap_close(handle);
    printf("\n[C-Shark] Capture stopped. Captured %d packets. Returning to menu.\n", stored_packet_count);
}