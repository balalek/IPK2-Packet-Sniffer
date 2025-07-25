# Packet Sniffer

**Author:** Martin Baláž  
**Course:** Computer Communications and Networks (IPK)  
**Language:** C

## Project Description

A network analyzer written in C that can capture and filter packets on a specified network interface. The program uses the libpcap library for network traffic capture and supports filtering by protocols and ports.

## Installation and Usage

### Compilation
```bash
make
```

### Execution
```bash
sudo ./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp]} {-n num}
```

**Note:** The program requires administrator privileges (sudo) because it accesses network interfaces at a low level.

## Parameters

- **`-i interface`** / **`--interface interface`** – Network interface for packet capture
- **`-p port`** – Filter by port number
- **`--tcp`** / **`-t`** – Capture TCP packets
- **`--udp`** / **`-u`** – Capture UDP packets
- **`--arp`** – Capture ARP packets
- **`--icmp`** – Capture ICMP packets
- **`-n num`** – Number of packets to capture

## Usage Examples

### List available interfaces
```bash
./ipk-sniffer -i
```

### Capture specific protocols
```bash
# TCP packets on port 443, max 5 packets
sudo ./ipk-sniffer -i eth0 -p 443 --tcp -n 5

# ARP and ICMP packets
sudo ./ipk-sniffer -i eth0 --arp --icmp

# All packets on any interface, max 10
sudo ./ipk-sniffer -i any -n 10
```

## Output Format

The program displays captured packets including:
- Timestamp
- Source and destination IP addresses
- Source and destination ports (for TCP/UDP)
- Hexadecimal dump of packet data

## Terminating the Program

The program can be terminated using **Ctrl + C**.

## Submitted Files

1. `ipk-sniffer.c` – Source code
2. `Makefile` – Compilation file
3. `README.md` – Documentation
4. `manual.pdf` – Detailed manual
