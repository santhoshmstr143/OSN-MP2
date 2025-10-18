// ############## LLM Generated Code Begins ##############
#include "cshark.h"

void print_hex_bytes(const u_char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
}

void print_ascii_bytes(const u_char *data, int len) {
    for (int i = 0; i < len; i++) {
        if (data[i] >= 32 && data[i] <= 126)
            printf("%c", data[i]);
        else
            printf(".");
    }
}

void print_mac_address(const u_char *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip_flags(uint16_t frag_off) {
    printf("Flags:");
    if (frag_off & htons(IP_RF)) printf(" RF");
    if (frag_off & htons(IP_DF)) printf(" DF");
    if (frag_off & htons(IP_MF)) printf(" MF");
    printf(" | Fragment offset: %d", ntohs(frag_off) & IP_OFFMASK);
}

const char* port_name(uint16_t port) {
    switch (port) {
        case 53: return "(DNS)";
        case 80: return "(HTTP)";
        case 443: return "(HTTPS)";
        default: return "";
    }
}

void print_tcp_flags(uint8_t flags) {
    printf("Flags: [");
    int printed = 0;
    if (flags & TH_FIN) { printf("FIN"); printed = 1; }
    if (flags & TH_SYN) { if (printed) printf(","); printf("SYN"); printed = 1; }
    if (flags & TH_RST) { if (printed) printf(","); printf("RST"); printed = 1; }
    if (flags & TH_PUSH) { if (printed) printf(","); printf("PSH"); printed = 1; }
    if (flags & TH_ACK) { if (printed) printf(","); printf("ACK"); printed = 1; }
    if (flags & TH_URG) { if (printed) printf(","); printf("URG"); printed = 1; }
    printf("]");
}

void print_hex_dump(const u_char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) {
            printf("  ");
            for (int j = i - 15; j <= i; j++) {
                printf("%c", (data[j] >= 32 && data[j] <= 126) ? data[j] : '.');
            }
            printf("\n");
        }
    }
    if (len % 16 != 0) {
        int pad = 16 - (len % 16);
        for (int i = 0; i < pad; i++) printf("   ");
        printf("  ");
        for (int j = len - (len % 16); j < len; j++) {
            printf("%c", (data[j] >= 32 && data[j] <= 126) ? data[j] : '.');
        }
        printf("\n");
    }
}

void sigint_handler(int signo) {
    (void)signo;
    stop_sniffing = 1;
}
// ############## LLM Generated Code Ends ################