/****************************************************************************
 *   IPK                                                                    *
 *                                                                          *
 *   Implementacia snifferu packetov pomocou libcap                         *
 *                                                                          *
 *	 Ondrušek Tomáš	xondru18                                                *
 *                                                                          *
 ****************************************************************************/

#include <iostream>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <cmath>
#include <sstream>
#include <pcap.h>            //pcap
#include <net/ethernet.h>    //struct ether_header
#include <netinet/ip.h>      //struct iphdr, arphdr
#include <netinet/ip_icmp.h> //struct icmphdr
#include <netinet/in.h>
#include <netinet/tcp.h> //struct tcphdr
#include <netinet/udp.h> //struct udphdr
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip6.h> //IPV6
#include <signal.h>

using namespace std;

bool flag_udp, flag_tcp, flag_icmp, flag_arp;
int port = -1;
int packet_process_count = 1;
string interface = "";
string filter = "";
pcap_t *device;
struct bpf_program filter_compiled;

/**
 * @brief Error printout
 *
 * Function prints error message to stderr
 *
 * @param string string to be printed
 *
 */
void print_error_and_exit(string string)
{
    fprintf(stderr, "%s", string.c_str());
    exit(1);
}

/**
 * @brief Function to compare string
 *
 * Function compares std string to pointer string
 *
 * @param str1 std string
 * @param str2 pointer to string
 *
 * @return true if strings are same, false if they are not
 *
 */
bool compare_const_to_char(string str1, char *str2)
{
    if (strcmp(str1.c_str(), str2) == 0)
        return true;
    return false;
}

/**
 * @brief Printing interfaces
 *
 * Function prints out all available interfaces and frees list using pcap_freealldevs()
 *
 * @param interface_list list of interfaces
 *
 */
void print_interfaces(pcap_if_t *interface_list)
{
    while (interface_list->next != NULL)
    {
        printf("%s\n", interface_list->name);
        interface_list = interface_list->next;
    }
    pcap_freealldevs(interface_list);
    exit(0);
}

/**
 * @brief Getting interfaces
 *
 * Function finds all interfaces using pcap_findalldevs() and returns list
 *
 * @return list of interfaces
 *
 */
pcap_if_t *get_interfaces()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interface_list;
    if (pcap_findalldevs(&interface_list, error_buffer) == PCAP_ERROR)
    {
        print_error_and_exit("ERROR: No interfaces available.\n");
    }
    return interface_list;
}

/**
 * @brief Checking interface
 *
 * Function checks if given interface is valid and is in interface list
 *
 * @param interface std string of given interface
 * @param interface_list list of interfaces
 *
 */
void check_existing_interface(string interface, pcap_if_t *interface_list)
{
    bool check = false;
    while (interface_list->next != NULL)
    {
        if (compare_const_to_char(interface, interface_list->name))
        {
            check = true;
        }
        interface_list = interface_list->next;
    }
    if (!check)
    {
        pcap_freealldevs(interface_list);
        print_error_and_exit("ERROR: Invalid interface.\n");
    }
}

/**
 * @brief Printing help
 *
 * Function prints help message to stdout
 *
 *
 */
void print_help()
{
    printf("Packet sniffer 2022\n");
    printf("Usage:");
    printf("  ./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] [--igmp]} {-n num}\n\n");
    printf("Examples:\n");
    printf("./ipk-sniffer -i eth0 -p 23 --tcp -n 2\n");
    printf("./ipk-sniffer -i eth0 --udp\n");
    printf("./ipk-sniffer -i eth0 -n 10\n");
    printf("./ipk-sniffer -i eth0 -p 22 --tcp --udp --icmp --arp \n");
    exit(0);
}

/**
 * @brief Check numeric string
 *
 * Function checks if string contains only numbers
 *
 * @copyright https://stackoverflow.com/questions/4654636/how-to-determine-if-a-string-is-a-number-with-c
 * @param str std string to check
 * @return true if string contains only numbers, false if else
 *
 */
bool is_numeric(string str)
{
    char *p;
    strtol(str.c_str(), &p, 10);
    return *p == 0;
}

/**
 * @brief Parsing args
 *
 * Function checks if any arguments are set, if not, prints out all available interfaces. If arguments are set, checks for -i or --interface and if optional argument
 * is set. If not, prints out all available interfaces. If interface is given, saves it. Then function checks for -h or --help argument and if it finds it, prints
 * out help message. After that function checks for arguments like {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] [--igmp]} {-n num} and sets bool flags or
 * corresponding options. Function checks for correct 'num' and 'port' options. If no protocol is set, all protocols are set to TRUE
 *
 * @param argc Count of arguments
 * @param argv arguments
 *
 */
void parse_args(int argc, char *argv[])
{
    pcap_if_t *interface_list = get_interfaces();
    string arg;

    if (argc == 1)
        print_interfaces(interface_list);

    bool set = false;
    for (int i = 1; i < argc; i++)
    {
        arg = string(argv[i]);
        if (arg == "-i" || arg == "--interface")
        {
            set = true;
            if (i + 1 < argc)
            {
                if (argv[i + 1][0] == '-')
                    print_interfaces(interface_list);
                interface = string(argv[i + 1]);
            }
            else
                print_interfaces(interface_list);
            check_existing_interface(interface, interface_list);
        }
        if (arg == "-h" || arg == "--help")
            print_help();
    }
    if (!set)
        print_interfaces(interface_list);

    for (int i = 1; i < argc; i++)
    {
        arg = string(argv[i]);
        if (arg == "-i" || arg == "--interface")
            i++; // skip next arg
        else if (arg == "-t" || arg == "--tcp")
            flag_tcp = true;
        else if (arg == "-u" || arg == "--udp")
            flag_udp = true;
        else if (arg == "--icmp")
            flag_icmp = true;
        else if (arg == "--arp")
            flag_arp = true;
        else if (arg == "-p")
        {
            if (!is_numeric(argv[i + 1]))
                print_error_and_exit("ERROR: Invalid port number.\n");

            port = std::stoi(string(argv[i + 1]));

            if (port < 0)
                print_error_and_exit("ERROR: Invalid port number.\n");
            i++;
        }
        else if (arg == "-n")
        {
            if (!is_numeric(argv[i + 1]))
                print_error_and_exit("ERROR: Invalid packet count number.\n");

            packet_process_count = std::stoi(string(argv[i + 1]));

            if (packet_process_count < 0)
                print_error_and_exit("ERROR: Invalid packet count number.\n");
            i++;
        }
        else
            print_error_and_exit("ERROR: Invalid entry argument.\n");
    }

    if (!(flag_udp || flag_tcp || flag_icmp || flag_arp))
        flag_udp = flag_tcp = flag_icmp = flag_arp = true;
}

/**
 * @brief Add value to finter
 *
 * Function appends 'or' and 'str' to filter. If filter is empty, function doesn`t append the first 'or'
 *
 * @param str std string containing new filter value
 *
 */
void add_to_filter(string str)
{
    if (strlen(filter.c_str()) == 0)
    {
        filter += str.c_str();
    }
    else
    {
        filter += " or ";
        filter += str.c_str();
    }
}

/**
 * @brief Creating filter
 *
 * Function creates filter that is passed to pcap_compile() to create filter used to filter packets. Function is operated using bool flags of protocols. If flag is set
 * to true, add_to_filter() function is called with corresponding protocol to be appended to filter. Function also processes edge cases like parameter -p num set without udp or tcp option
 * so these are appended to filter automatically. Fuction works with gloval variable filter.
 *
 *
 */
void create_filter()
{
    string port_str = std::to_string(port);
    string str = "";
    if (flag_udp)
    {
        if (port != -1)
        {
            str = "udp port " + port_str;
            add_to_filter(str);
        }
        else
            add_to_filter("udp");
    }
    if (flag_tcp)
    {
        if (port != -1)
        {
            str = "tcp port " + port_str;
            add_to_filter(const_cast<char *>(str.c_str()));
        }
        else
            add_to_filter("tcp");
    }
    if (flag_arp)
    {
        add_to_filter("arp");
    }
    if (flag_icmp)
    {
        add_to_filter("icmp");
        add_to_filter("icmp6");
    }
    if (port != -1 and !flag_tcp and !flag_udp)
    {
        str = "tcp port " + port_str;
        add_to_filter(const_cast<char *>(str.c_str()));
        str = "udp port " + port_str;
        add_to_filter(const_cast<char *>(str.c_str()));
    }
    // printf("FILTER: %s\n", filter.c_str());
}

/**
 * @brief Print formatted data
 *
 * Function prints packet data in 'hexdump' format and changes all unprintable characters to dots.
 *
 * @copyright https://www.programcreek.com/cpp/?code=mq1n%2FNoMercy%2FNoMercy-master%2FSource%2FClient%2FNM_Engine%2FINetworkScanner.cpp
 * @copyright https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
 * @param addr pointer to data
 * @param len length of data
 *
 */
void print_packet_data(const void *addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char *)addr;
    printf("\n");
    for (int i = 0; i < len;)
    {
        int chrcnt = 0;
        printf("0x%04x:  ", i);
        char line[17] = "";
        for (int j = 0; j < 16 && i < len; i++, j++)
        {
            if (j == 8)
                printf(" ");

            printf("%02x ", pc[i]);
            if ((pc[i] < 0x20) || (pc[i] > 0x7e))
                line[j] = '.';
            else
                line[j] = pc[i];
            chrcnt++;
        }
        // printf("space");
        chrcnt = 16 - chrcnt;
        // printf("%d", chrcnt);
        for (int x = 0; x < chrcnt; x++)
        {
            printf("   ");
        }
        if (chrcnt > 8)
            printf(" ");
        printf(" %.8s %.8s\n", line, line + 8);
    }
}

/**
 * @brief Print arp IP address
 *
 * Function prints IP address in arp packet
 *
 * @param addr pointer to ip address
 *
 *
 */
void print_arp_ip(const void *addr)
{
    unsigned char *pc = (unsigned char *)addr;

    printf("src IP: %d.%d.%d.%d\n", pc[28], pc[29], pc[30], pc[31]);
    printf("dst IP: %d.%d.%d.%d\n", pc[38], pc[39], pc[40], pc[41]);
}

/**
 * @brief Print IPv6
 *
 * Function prints IPv6 address in correct format
 *
 * @copyright   https://errorsfixing.com/expand-an-ipv6-address-so-i-can-print-it-to-stdout/
 * @param addr pointer to ip address
 *
 */
void print_ipv6(const struct in6_addr *addr)
{
    printf(" IP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
           (int)addr->s6_addr[0], (int)addr->s6_addr[1],
           (int)addr->s6_addr[2], (int)addr->s6_addr[3],
           (int)addr->s6_addr[4], (int)addr->s6_addr[5],
           (int)addr->s6_addr[6], (int)addr->s6_addr[7],
           (int)addr->s6_addr[8], (int)addr->s6_addr[9],
           (int)addr->s6_addr[10], (int)addr->s6_addr[11],
           (int)addr->s6_addr[12], (int)addr->s6_addr[13],
           (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}

/**
 * @brief Print formatted time
 *
 * Function takes two values from packet header - tv_sec and tv_usec and transforms them into RC3339 time format
 *
 * @copyright https://stackoverflow.com/questions/46757406/how-to-print-timestamp-of-a-packet-read-from-pcap-file
 * @param header packet header
 *
 */
void print_formatted_time(const struct pcap_pkthdr *header)
{
    char timebuffer[30];
    char timebuffer2[30];
    struct tm *tm;
    tm = localtime(&(header->ts.tv_sec));
    strftime(timebuffer, 26, "%Y-%m-%dT%H:%M:%S", tm);
    char sign = ' ';
    if (tm->tm_gmtoff < 0)
        sign = '-';
    else
        sign = '+';
    sprintf(timebuffer2, ".%03d%c%02d:00    ", int(round(header->ts.tv_usec / 1000)), sign, int(abs(tm->tm_gmtoff) / 3600));
    printf("timestamp: %s", timebuffer);
    printf("%s\n", timebuffer2);
}

/**
 * @brief Print MAC address
 *
 * Function prints out source and destination MAC addresses from ethernet header
 *
 * @copyright https://stackoverflow.com/questions/4526576/how-do-i-capture-mac-address-of-access-points-and-hosts-connected-to-it
 * @param ether_header struct ether_header
 *
 */
void print_mac_address(const struct ether_header *ether_header)
{
    printf("src MAC: ");
    for (int i = 0; i <= 4; i++)
    {
        printf("%02x:", ether_header->ether_shost[i]);
    }
    printf("%02x\n", ether_header->ether_shost[5]);
    printf("dst MAC: ");
    for (int i = 0; i <= 4; i++)
    {
        printf("%02x:", ether_header->ether_dhost[i]);
    }
    printf("%02x\n", ether_header->ether_dhost[5]);
}

/**
 * @brief Print IPv4
 *
 * Function prints out IPv4 from ip struct
 *
 * @param ip ip struct
 *
 */
void print_ipv4(struct ip *ip)
{
    printf("src IP: %s\n", inet_ntoa(ip->ip_src));
    printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
}

/**
 * @brief Print UDP port
 *
 * Function prints out souce and destination UDP ports
 *
 * @param udp_hdr struct udp_hdr
 *
 */
void print_udp_port(const struct udphdr *udp_hdr)
{
    printf("src port: %d\n", ntohs(udp_hdr->uh_sport));
    printf("dst port: %d\n", ntohs(udp_hdr->uh_dport));
}

/**
 * @brief Print TCP port
 *
 * Function prints out souce and destination TCP ports
 *
 * @param tcp_hdr struct tcp_hdr
 *
 */
void print_tcp_port(const struct tcphdr *tcp_hdr)
{
    printf("src port: %d\n", ntohs(tcp_hdr->th_sport));
    printf("dst port: %d\n", ntohs(tcp_hdr->th_dport));
}

/**
 * @brief Print packet length
 *
 * Function prints out frame length
 *
 * @param len length of packet
 *
 */
void print_length(int len)
{
    printf("frame length: %d bytes\n", len);
}

/**
 * @brief Sniff packets
 *
 * Function sniffs for packet and prints its contents. First correct values are assigned to structs like ip, iphdr, ip6_hdr, ether_header, udphdr, tcphdr. Then using switch correct protocol is found and processed.
 * Supported protocols are UDP, TCP, ARP, ICMP, ICMPv6.
 * Protocol found is then printed by printing time packet was catched, souce and destination MAC addresses, frame length, source and destionation IP address and then formatted data.
 *
 * @copyright https://www.tcpdump.org/other/sniffex.c
 * @param args pointer to args
 * @param header pointer to struct header
 * @param packet pointer to packet
 *
 */
void sniffer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ip *ip;                           // IP
    const struct iphdr *ip_hdr;              // IP header
    const struct ip6_hdr *ip6_hdr;           // IPv6 header
    const struct ether_header *ether_header; // ethernet struct
    const struct udphdr *udp_hdr;            // UDP struct
    const struct tcphdr *tcp_hdr;            // TCP struct
    // const struct arp_header *arp_hrd;

    ip = (struct ip *)(packet + sizeof(struct ether_header));
    ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
    ip6_hdr = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    // arp_hrd = (struct ether_header *)packet;
    ether_header = (struct ether_header *)packet;

    switch (ntohs(ether_header->ether_type))
    {
    case ETHERTYPE_IP: // IPv4 protocol
        switch (ip_hdr->protocol)
        {
        case IPPROTO_ICMP: // ICMPv4
            printf("ICMP\n");
            print_formatted_time(header);
            print_mac_address(ether_header);
            print_length(header->len);
            print_ipv4(ip);
            print_packet_data(packet, header->len);
            break;
        case IPPROTO_TCP: // TCP
            printf("TCP\n");
            print_formatted_time(header);
            tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip->ip_hl * 4);
            print_mac_address(ether_header);
            print_length(header->len);
            print_ipv4(ip);
            print_tcp_port(tcp_hdr);
            print_packet_data(packet, header->len);
            break;
        case IPPROTO_UDP: // UDP
            printf("UDP\n");
            print_formatted_time(header);
            udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + ip->ip_hl * 4);
            print_mac_address(ether_header);
            print_length(header->len);
            print_ipv4(ip);
            print_udp_port(udp_hdr);
            print_packet_data(packet, header->len);
            break;
        default:
            break;
        }
        break;
    case ETHERTYPE_IPV6: // IPv6 protocol
        switch (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt)
        {
        case IPPROTO_TCP: // TCPv6
            printf("TCP - IPv6\n");
            print_formatted_time(header);
            tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + 40);
            print_mac_address(ether_header);
            print_length(header->len);
            printf("src");
            print_ipv6(&ip6_hdr->ip6_src);
            printf("dst");
            print_ipv6(&ip6_hdr->ip6_dst);
            print_tcp_port(tcp_hdr);
            print_packet_data(packet, header->len);
            break;
        case IPPROTO_UDP: // UDPv6
            printf("UDP - IPv6\n");
            print_formatted_time(header);
            udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + 40);
            print_mac_address(ether_header);
            print_length(header->len);
            printf("src");
            print_ipv6(&ip6_hdr->ip6_src);
            printf("dst");
            print_ipv6(&ip6_hdr->ip6_dst);
            print_udp_port(udp_hdr);
            print_packet_data(packet, header->len);
            break;
        case IPPROTO_ICMPV6: // ICMPv6
            printf("ICMPv6\n");
            print_formatted_time(header);
            print_mac_address(ether_header);
            print_length(header->len);
            printf("src");
            print_ipv6(&ip6_hdr->ip6_src);
            printf("dst");
            print_ipv6(&ip6_hdr->ip6_dst);
            print_packet_data(packet, header->len);
            break;
        default:
            break;
        }
        break;
    case ETHERTYPE_ARP: // ARP
        printf("ARP\n");
        print_formatted_time(header);
        print_mac_address(ether_header);
        print_length(header->len);
        // printf("src IP: %s\n", arp_hrd);
        // printf("dst IP: %d\n", ip->ip_dst.s_addr);
        // print_ipv4(ip);
        print_arp_ip(packet);
        print_packet_data(packet, header->len);
        break;
    }
}

/**
 * @brief Process SIGINT
 *
 * Function processes SIGINT, frees all allocated resources and exits with error
 *
 * @param signal signal to be processed
 *
 */
void catch_sigint(int signal)
{
    printf("\nSIGINT detected... Shutting down sniffer...\n");
    pcap_close(device);
    pcap_freecode(&filter_compiled);
    exit(1);
}

/**
 * @brief Main program
 *
 * Fuction calls correcponding functions to sniff packets successfully
 *
 * @param argc arg count
 * @param argv arguments
 *
 */
int main(int argc, char *argv[])
{
    bpf_u_int32 ip;
    bpf_u_int32 mask;
    char error_buffer[PCAP_ERRBUF_SIZE];

    signal(SIGINT, catch_sigint);

    parse_args(argc, argv);
    create_filter();

    if ((device = pcap_open_live(interface.c_str(), 65535, 1, 1000, error_buffer)) == NULL)
    {
        pcap_close(device);
        print_error_and_exit("ERROR: Failure during opening device.\n");
    }
    if (pcap_lookupnet(interface.c_str(), &ip, &mask, error_buffer) == PCAP_ERROR)
    {
        print_error_and_exit("ERROR: Network can not be found.\n");
    }
    if (pcap_compile(device, &filter_compiled, filter.c_str(), 0, mask) == PCAP_ERROR)
    {
        pcap_close(device);
        pcap_freecode(&filter_compiled);
        print_error_and_exit("ERROR: Filter compile failure.\n");
    }
    if (pcap_setfilter(device, &filter_compiled) == PCAP_ERROR)
    {
        pcap_close(device);
        pcap_freecode(&filter_compiled);
        print_error_and_exit("ERROR: Filter set failure.\n");
    }
    if (pcap_loop(device, packet_process_count, sniffer, NULL) == PCAP_ERROR)
    {
        pcap_close(device);
        print_error_and_exit("ERROR: Failure during processing packets.\n");
    }
    pcap_close(device);
    pcap_freecode(&filter_compiled);
    return 0;
}
/*
    Code is inspired by this examples https://www.tcpdump.org/other/sniffex.c https://www.tcpdump.org/pcap.html

 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 *
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 */