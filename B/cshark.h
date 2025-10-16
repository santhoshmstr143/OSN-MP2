#ifndef CSHARK_H
#define CSHARK_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAX_PACKETS 10000
#define SNAP_LEN 65535

// Packet storage structure
typedef struct {
    struct pcap_pkthdr header;
    u_char *packet_data;
    int packet_id;
} stored_packet_t;

// Global variables
extern volatile sig_atomic_t stop_sniffing;
extern volatile sig_atomic_t exit_program;
extern stored_packet_t packet_storage[MAX_PACKETS];
extern int stored_packet_count;
extern int g_datalink_type;

// Function prototypes
void sigint_handler(int signo);
void print_hex_bytes(const u_char *data, int len);
void print_ascii_bytes(const u_char *data, int len);
void print_mac_address(const u_char *mac);
void print_ip_flags(uint16_t frag_off);
const char* port_name(uint16_t port);
void print_tcp_flags(uint8_t flags);
void print_hex_dump(const u_char *data, int len);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void filtered_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void inspect_packet_detailed(int packet_id);
void clear_packet_storage();
void store_packet(const struct pcap_pkthdr *header, const u_char *packet, int packet_id);
void list_stored_packets();
int select_interface(char *selected_dev, size_t dev_size);
void start_sniffing_all(const char *device);
void start_sniffing_filtered(const char *device);
void inspect_last_session();

#endif