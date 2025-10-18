# C-Shark: Network Packet Sniffer

A command-line packet analyzer built in C using libpcap library for capturing and analyzing network traffic.

## What It Does

C-Shark captures network packets and displays their contents layer by layer:
- **Layer 2**: MAC addresses and frame type
- **Layer 3**: IP addresses and protocol info (IPv4/IPv6/ARP)
- **Layer 4**: Port numbers and connection details (TCP/UDP)
- **Layer 7**: Application data with hex dump

## Requirements

- Linux system
- libpcap library
- GCC compiler
- Root privileges

Install dependencies:
```bash
sudo apt-get install libpcap-dev gcc make
```

## Building and Running

```bash
make
sudo ./cshark
```

## How It Works

### 1. Interface Selection
Program scans and lists all network interfaces. You select which one to monitor.

### 2. Main Menu
- **Start Sniffing (All Packets)**: Captures everything on the interface
- **Start Sniffing (With Filters)**: Captures only specific traffic (HTTP/HTTPS/DNS/ARP/TCP/UDP)
- **Inspect Last Session**: Review previously captured packets in detail
- **Exit**: Cleanup and quit

### 3. Live Capture
While capturing, each packet shows:
- Packet ID and timestamp
- Source and destination MAC/IP addresses
- Protocol information at each layer
- Port numbers and TCP flags
- First 64 bytes of payload in hex format

Press **Ctrl+C** to stop capture and return to menu.

### 4. Packet Storage
- Stores up to 10,000 packets from last session
- Can inspect any stored packet for full details
- Memory cleared when starting new capture

### 5. Detailed Inspection
Select a packet ID to see:
- Complete header breakdown for all layers
- All protocol fields with values
- Full packet hex dump
- Raw payload data

## Key Features

**Protocol Support**: IPv4, IPv6, ARP, TCP, UDP

**Filtering**: BPF filters for HTTP (port 80), HTTPS (port 443), DNS (port 53), and protocol types

**Port Recognition**: Automatically identifies DNS, HTTP, HTTPS services

**Hex Dump Format**: Shows both hex values and ASCII representation

## Project Structure

```
├── main.c              # Entry point and menu loop
├── cshark.h            # Definitions and prototypes
├── interface.c         # Interface selection
├── packet_handler.c    # Packet parsing and display
├── filter.c            # BPF filtering
├── storage.c           # Packet storage
├── inspect.c           # Detailed inspection
├── utils.c             # Helper functions
└── Makefile            # Build config
```

## Implementation Details

**Packet Parsing**: Uses standard C networking headers (ether_header, iphdr, ip6_hdr, tcphdr, udphdr, ether_arp)

**Memory Management**: Dynamic allocation for packets with proper cleanup between sessions

**Signal Handling**: Catches Ctrl+C to stop capture gracefully without exiting program

**BPF Compilation**: Converts user filter choice to Berkeley Packet Filter syntax and applies to capture

## Testing Tips

Use personal mobile hotspot for cleaner, predictable traffic or use localhost (lo interface) for basic testing.

Run Wireshark alongside to verify captured data accuracy.

## Common Issues

**"Operation not permitted"**: Need sudo to run

**No packets showing**: Check interface is active and has traffic

**Compilation errors**: Make sure libpcap-dev is installed

## What I Implemented

1. **Phase 1**: Interface discovery and basic packet capture with graceful Ctrl+C handling
2. **Phase 2**: Layer-by-layer protocol decoding (Ethernet, IPv4/IPv6/ARP, TCP/UDP, payload)
3. **Phase 3**: BPF filtering for specific protocols
4. **Phase 4**: Packet storage system with memory management
5. **Phase 5**: Detailed packet inspection feature with full hex dumps

All code is modular with separate files for each functionality.