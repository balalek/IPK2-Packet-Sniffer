/*******************************************************************************************
 * @file:       ipk-sniffer.c
 * @author:     Martin Balaz <xbalaz15@stud.fit.vutbr.cz>
 * @course:     IPK
 * @date:       03.04.2022
 * @brief:      Network analyzer for capturing and filtering packets
 * 
 ******************************************************************************************/

#include <time.h>               // Provides real time functions
#include <stdio.h>              // Provides the most basic C functions
#include <ctype.h>              // Provides isprint()
#include <string.h>             // Provides function for work with strings
#include <stdlib.h>             // Provides strtol()
#include <getopt.h>             // Provides functions for work with options and arguments
#include <stdbool.h>            // Provides boolean type
#include <pcap/pcap.h>          // Provides Lipcap library for work with packets
#include <arpa/inet.h>          // Provides inet_ntop()
#include <net/ethernet.h>       // Provides ethernet fundamental constants
#include <netinet/if_ether.h>   // Provides declarations for ethernet header
#include <netinet/udp.h>        // Provides declarations for udp header
#include <netinet/tcp.h>        // Provides declarations for tcp header
#include <netinet/ip.h>         // Provides declarations for ip header
#include <netinet/ip6.h>        // Provides declarations for ip6 header

// Functions declaration
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_tcp_packet(const u_char * Buffer, int Size, bool Ipv6);
void print_udp_packet(const u_char * Buffer, int Size, bool Ipv6);
void print_icmp_packet(const u_char * Buffer, bool Ipv6);
void print_arp_frame(const u_char * Buffer, bool Ipv6);
void print_ethernet_header(const u_char * Buffer);
void print_data(const u_char * Buffer, int Size);
void print_ip(char * source, char * dest);
void print_timestamp();

// Global variables
int frame_length = 0;

char src_ipv4[INET_ADDRSTRLEN];   // IPv4 source address
char dest_ipv4[INET_ADDRSTRLEN];  // IPv4 destination address

char src_ipv6[INET_ADDRSTRLEN];   // IPv6 source address
char dest_ipv6[INET_ADDRSTRLEN];  // IPv6 destination address

int main(int argc, char **argv)
{
    bool inf_flag = false;
    bool port_flag = false;
    bool udp_flag = false;
    bool tcp_flag = false;
    bool icmp_flag = false;
    bool arp_flag = false;
    bool num_flag = false;
    int option;

    struct option long_options[] =
        {
            {"interface", optional_argument, NULL, 'i'},
            {"tcp", no_argument, NULL, 't'},
            {"udp", no_argument, NULL, 'u'},
            {"arp", no_argument, NULL, 'a'},
            {"icmp", no_argument, NULL, 'c'},
            {0, 0, 0, 0} // Terminating element
        };

    char *short_options = "i::p::tun::";
    long conv_int;
    char port[15] = " port ";
    int num = 1;
    char *inf = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    while ((option = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
    {
        switch (option)
        {
        case 'i':
            if (inf_flag)
            {
                fprintf(stderr, "More than one interface option entered\n");
                return 1;
            }
            inf_flag = true;
            // source: https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
            // author: Lars Erik Wik
            // date: 13th August, 2021
            if (optarg == NULL && optind < argc && argv[optind][0] != '-') optarg = argv[optind++];
            if (optarg != NULL) inf = optarg;
            break;
        case 'p':
            if (port_flag)
            {
                fprintf(stderr, "More than one port option entered\n");
                return 1;
            }
            port_flag = true;
            if (optarg == NULL && optind < argc && argv[optind][0] != '-') optarg = argv[optind++];
            if (optarg != NULL) strcat(port, optarg);
            break;
        case 't':
            if (tcp_flag)
            {
                fprintf(stderr, "More than one tcp option entered\n");
                return 1;
            }
            tcp_flag = true;
            break;
        case 'u':
            if (udp_flag)
            {
                fprintf(stderr, "More than one udp option entered\n");
                return 1;
            }
            udp_flag = true;
            break;
        case 'a':
            if (arp_flag)
            {
                fprintf(stderr, "More than one arp option entered\n");
                return 1;
            }
            arp_flag = true;
            break;
        case 'c':
            if (icmp_flag)
            {
                fprintf(stderr, "More than one icmp option entered\n");
                return 1;
            }
            icmp_flag = true;
            break;
        case 'n':
            if (num_flag)
            {
                fprintf(stderr, "More than one num option entered\n");
                return 1;
            }
            num_flag = true;
            if (optarg == NULL && optind < argc && argv[optind][0] != '-') optarg = argv[optind++];
            if (optarg != NULL)
            {
                conv_int = strtol(optarg, NULL, 10);
                num = (int)conv_int;
            }
            break;
        default:
            puts("HELP:");
			puts("All options are purely optional and they can be written in any order.");
            puts("");
			puts("-i | --interface <interface>  interface, on which packet sniffer works (without argument, only list of active devices will be printed)");
			puts("-p <port_number>              packet filtering on given interface by port (default are all ports)");
			puts("-t | --tcp                    shows only tcp packets");
			puts("-u | --udp                    shows only udp packets");
            puts("--icmp                        shows only ICMPv4 and ICMPv6 pakets");
			puts("--arp                         shows only ARP frames");
			puts("-n <packets_count>            number of packets to be shown (default is 1)");
            puts("");
            return 1;
        }
    }

    // Catch an argument, that shouldn't be in argv
    // source: https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
    if (optind < argc)
    {
        printf("Please, delete these arguments: ");
        while (optind < argc) printf("%s ", argv[optind++]);
        putchar('\n');
        return 1;
    }

    // Print list to the user or open device for sniffing (depends on interface argument)
	// MODIFICATED from
	// source: https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
	// author: Silver Moon
	// date: 31st July, 2020
    if (inf == NULL)
	{
        pcap_if_t *alldevsp , *device;
        char errbuf[100];
        int count = 1;
        
        // First get the list of available interfaces
        if (pcap_findalldevs(&alldevsp, errbuf))
        {
            printf("Error finding interfaces : %s" , errbuf);
            return 1;
        }
        
        // Print the available interfaces
        printf("\nAvailable Interfaces are :\n");
        for (device = alldevsp ; device != NULL ; device = device->next)
        {
            printf("%d. %s - " , count, device->name);
            if (device->description) printf("(%s)\n", device->description);
			else printf("(No description)\n");
            count++;
        }
        printf("\n");
	}
    else
    {     
        pcap_t *handle;             // Handle of the device that shall be sniffed
        struct bpf_program fp;      // Hold compiled program 
        bpf_u_int32 pMask;          // Subnet mask 
        bpf_u_int32 pNet;           // Ip address

        // Fetch the network address and network mask
        if (pcap_lookupnet(inf, &pNet, &pMask, errbuf) == -1)
        {
            fprintf(stderr, "%s\n", errbuf);
            return 1;
        }

        // Open the device for sniffing
        //handle = pcap_open_live(inf, 65536, 0, 1000, errbuf);     // Promiscuous mode is off
        handle = pcap_open_live(inf, 65536, 1, 1000, errbuf);       // Promiscuous mode is on
        
        if (handle == NULL) 
        {
            fprintf(stderr, "Couldn't open device %s : %s\n", inf, errbuf);
            return 1;
        }

        // Setting the filter 
        char filter[150];
        strcpy(filter, "");
        if (!tcp_flag && !udp_flag && !icmp_flag && !arp_flag) strcat(filter, "tcp or udp or icmp or arp");
        if (tcp_flag)
        {
            strcat(filter, "tcp");
            if (strcmp(port, " port ") != 0) strcat(filter, port);
            if (tcp_flag && (udp_flag || icmp_flag || arp_flag)) strcat(filter, " or ");
            tcp_flag = false;
        }      
        if (udp_flag)
        {
            strcat(filter, "udp");
            if (strcmp(port, " port ") != 0) strcat(filter, port);
            if (udp_flag && (tcp_flag || icmp_flag || arp_flag)) strcat(filter, " or ");
            udp_flag = false;
        }       
        if (icmp_flag)
        {
            strcat(filter, "icmp or icmp6");
            if (icmp_flag && (udp_flag || tcp_flag || arp_flag)) strcat(filter, " or ");
            icmp_flag = false;
        }       
        if (arp_flag)
        {
            strcat(filter, "arp");
            if (arp_flag && (udp_flag || icmp_flag || tcp_flag)) strcat(filter, " or ");
            arp_flag = false;
        }

        // Compile the filter expression
        // source: https://www.tcpdump.org/manpages/pcap_compile.3pcap.html
        if(pcap_compile(handle, &fp, filter, 0, pNet))	
        {
            fprintf(stderr, "\npcap_compile() failed\n");
            printf("pcap_compile(): %s\n", pcap_geterr(handle));
            return 1;
        }
        // Apply the compiled filter
        if(pcap_setfilter(handle, &fp) == -1)
        {
            fprintf(stderr, "pcap_setfilter() failed\n");
            return 1;
        }
        
        // Put the device in sniff loop
        pcap_loop(handle, num, process_packet, NULL);
    }
    return 0;
}

// Checks if ip address of packet is ipv4/ipv6 and for corresponding protocol is called a corresponding function
// MODIFICATED from
// source: https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
// author: Silver Moon
// date: 31st July, 2020
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    print_timestamp();

    // Get frame length
    frame_length = header->len;

    // Get etherent header size
    int size = 0;
    size += sizeof(struct ether_header);

	struct ether_header *p = (struct ether_header *)buffer;
	int protocol_check = 0;
    bool ipv6 = false;
	if (ntohs(p->ether_type) == ETHERTYPE_IPV6) ipv6 = true; // Check if ether_type is ipv6
	
	//Get the IP Header part of this packet , excluding the ethernet header
	if (ipv6 == true)
	{
		struct ip6_hdr *iph = (struct ip6_hdr *)(buffer + size);
		protocol_check = iph->ip6_ctlun.ip6_un1.ip6_un1_nxt;

        // Set ipv6 header size
        size += 40;

        // Get ipv6 source and destination address
		inet_ntop(AF_INET6, &(iph->ip6_src), src_ipv6, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(iph->ip6_dst), dest_ipv6, INET6_ADDRSTRLEN);
	}
	else
	{
		struct ip *iph = (struct ip*)(buffer + size);
		protocol_check = iph->ip_p;

        // Get ipv4 header size
		size += sizeof(struct ip);
		
		// Get ipv4 source and destination address
		inet_ntop(AF_INET, &(iph->ip_src), src_ipv4, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(iph->ip_dst), dest_ipv4, INET_ADDRSTRLEN);  
	}

    //Check the Protocol and do accordingly
	switch (protocol_check) 
	{
		case 1:  // ICMPv4 Protocol
            print_icmp_packet(buffer, ipv6);
			break;
		
		case 6:  // TCP Protocol
			print_tcp_packet(buffer, size, ipv6);
			break;
		
		case 17: // UDP Protocol
			print_udp_packet(buffer, size, ipv6);
			break;

        case 58: // ICMPv6 Protocol
            print_icmp_packet(buffer, ipv6);
            break;
		
		default: // ARP Protocol
            print_arp_frame(buffer, ipv6);
			break;
	}
}

// Print IPv4 or IPv6 address
void print_ip(char *source, char *dest)
{
    printf("src IP: %s \n", source);
    printf("dst IP: %s \n", dest);
}

// Print timestamp
// MODIFICATED from
// source: https://stackoverflow.com/questions/48771851/im-trying-to-build-an-rfc3339-timestamp-in-c-how-do-i-get-the-timezone-offset
// author: chux - Reinstate Monica
// date: 13th February, 2018 
void print_timestamp()
{
    time_t now;
    time(&now);
    struct tm *pt = localtime(&now);
    char timestamp[100];

    // Get miliseconds
    struct timeval time;
    gettimeofday(&time, NULL);

    size_t len = strftime(timestamp, sizeof timestamp - 1, "timestamp: %FT%T%z", pt);
    // Replace last 5 digits
    if (len > 1) {
        char *colon = ":";
        char miliseconds[] = { timestamp[len-5], timestamp[len-4], timestamp[len-3], *colon, timestamp[len-2], timestamp[len-1], '\0'};
        sprintf(timestamp + len - 5, ".%3ld%s", (long int) time.tv_usec, miliseconds);
    }
    printf("\n%s\n", timestamp);
}

// Print source and destination MAC addresses
// MODIFICATED from
// source: https://gist.github.com/fffaraz/7f9971463558e9ea9545
// author: Faraz Fallahi 
// date: 3rd December, 2015
void print_ethernet_header(const u_char *Buffer)
{
    struct ether_header *eth = (struct ether_header *)Buffer;

    printf("src MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n", eth->ether_shost[0] , eth->ether_shost[1] , eth->ether_shost[2] , eth->ether_shost[3] , eth->ether_shost[4] , eth->ether_shost[5] );
    printf("dst MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n", eth->ether_dhost[0] , eth->ether_dhost[1] , eth->ether_dhost[2] , eth->ether_dhost[3] , eth->ether_dhost[4] , eth->ether_dhost[5] );
}

// Print tcp packet
void print_tcp_packet(const u_char * Buffer, int Size, bool Ipv6)
{
    print_ethernet_header(Buffer);
    printf("frame length: %d bytes\n", frame_length);

    if(Ipv6) print_ip(src_ipv6, dest_ipv6);
    else print_ip(src_ipv4, dest_ipv4);

    const struct tcphdr* tcp_header;
    u_int src_port, dst_port;

    // Get tcp header
    tcp_header = (struct tcphdr*)(Buffer + Size);

    // Get source and destination port number
    src_port = ntohs(tcp_header->source);
    dst_port = ntohs(tcp_header->dest);

    printf("src port: %d\n", src_port);
    printf("dst port: %d\n", dst_port);

    print_data(Buffer, frame_length);
}

// Print udp packet
void print_udp_packet(const u_char * Buffer, int Size, bool Ipv6)
{
    print_ethernet_header(Buffer);
    printf("frame length: %d bytes\n", frame_length);

    if(Ipv6) print_ip(src_ipv6, dest_ipv6);
    else print_ip(src_ipv4, dest_ipv4);

    const struct udphdr* udp_header;
    u_int src_port, dst_port;

    // Get udp header
    udp_header = (struct udphdr*)(Buffer + Size);
    
    // Get source and destination port number
    src_port = ntohs(udp_header->source);
    dst_port = ntohs(udp_header->dest);

    printf("src port: %d\n", src_port);
    printf("dst port: %d\n", dst_port);

    print_data(Buffer, frame_length);
}

// Print icmpv4 or icmpv6 packet
void print_icmp_packet(const u_char * Buffer, bool Ipv6)
{
    print_ethernet_header(Buffer);
    printf("frame length: %d bytes\n", frame_length);
    if(Ipv6) print_ip(src_ipv6, dest_ipv6);     // ICMPv6
    else print_ip(src_ipv4, dest_ipv4);         // ICMPv4
    printf("src port:\n");
    printf("dst port:\n");
    print_data(Buffer, frame_length);
}

// Print arp frame
void print_arp_frame(const u_char * Buffer, bool Ipv6)
{
    print_ethernet_header(Buffer);
    printf("frame length: %d bytes\n", frame_length);
    if(Ipv6) print_ip(src_ipv6, dest_ipv6);
    else print_ip(src_ipv4, dest_ipv4);
    printf("src port:\n");
    printf("dst port:\n");
    print_data(Buffer, frame_length);
}

// Print all bytes
// MODIFICATED from
// source: https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
// author: Silver Moon
// date: 31st July, 2020
void print_data(const u_char * Buffer, int Size)
{
    int i , j;
    int line_counter = 1;
    printf("\n");
    printf("0x0000:");

    for(i = 0; i < Size; i++){
        if( i != 0 && i % 16 == 0){   // If one line of hex printing is complete...
            printf("  ");
            
	        for(j = i - 16; j < i; j++){
                if (isprint(Buffer[j])) printf("%c",(unsigned char)Buffer[j]); // If its printable character
                else printf("."); // Otherwise print a dot
                if (j == i - 9) printf(" "); // Print the space between bytes
            }

            printf("\n");
            // Print the number of bytes printed at very start of each line
            if (line_counter < 10) printf("0x00%d:", line_counter++ * 10);
            else if (line_counter < 100) printf("0x0%d:", line_counter++ * 10);
            else printf("0x%d:", line_counter++ * 10);
        }         
        if(i%16 == 0) printf(" ");
        printf(" %02x",(unsigned int)Buffer[i]);
                 
        if(i == Size - 1){  // Print the last spaces
            for(j = 0; j < 15 - i % 16; j++) printf("   "); // Extra spaces
            printf("  ");
             
            for(j = i - i % 16; j <= i; j++){
                if (isprint(Buffer[j])) printf("%c",(unsigned char)Buffer[j]);
                else printf(".");
                if (j == i - (i % 16) + 7) printf (" "); // Print the space between bytes
            }
            printf("\n\n" );
        }
    }
}