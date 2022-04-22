# Project Title

ZETA variant: Packet sniffer implemented in c++

## Getting Started

A sniffer implemented in C++ language. Sniffer supports packet types like UDP, TCP, ARP, ICMP. Sniffer supports both IPv4 and IPv6 addresses.

### Prerequisites

-   G++

### Installation

```
$ Copy repository into your local directiory
$ Type 'make' into command line, you should get result similar to 'g++ -std=c++17 -Wall -Wno-unused-variable -Wno-unused-parameter -Wextra -pedantic ipk-sniffer.cpp -lpcap -o ipk-sniffer'
$ Now you are ready to start the sniffer
```

## Supported packets types

-   UDP
-   TCP
-   ARP
-   ICMP
-   ICMP6

## Usage

A few examples of useful commands and/or tasks.

```
./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp | -t] [--udp | -u] [--arp] [--icmp]} {-n num}

where
-i eth0 (just one interface to listen on. If this parameter is not specified, or if only -i is specified without a value, a list of active interfaces will be displayed)
-p 23 (will filter packets on the given interface by port; if this parameter is not specified, all ports are considered; if the parameter is specified, the given port can occur in both the source and destination part)
-t or --tcp (display only TCP packets)
-u or --udp (will only display UDP packets)
--icmp (will only display ICMPv4 and ICMPv6 packets)
--arp (will only display ARP frames)
If specific protocols are not specified, all (ie all content, regardless of protocol) are considered for printing.
-n 10 (specifies the number of packets to be displayed, ie the "running time" of the program; if not specified, display only one packet, ie -n 1)
the arguments can be in any order
```

### Example input:

-   ./ipk-sniffer -i eth0 -p 23 --tcp -n 2
-   ./ipk-sniffer -i eth0 --udp
-   ./ipk-sniffer -i eth0 -n 10
-   ./ipk-sniffer -i eth0 -p 22 --tcp --udp --icmp --arp
-   ./ipk-sniffer -i eth0 -p 22
-   ./ipk-sniffer -i eth0

### Example output

#### sudo ./ipk-sniffer --interface my_interface --tcp

```
timestamp: 2022-04-22T22:22:28.794+02:00
src MAC: 94:3f:c2:7:ca:4
dst MAC: f8:e4:3b:42:f:a8
frame length: 94 bytes
src IP: 52.223.202.36
dst IP: 147.229.217.121
src port: 443
dst port: 56736

0x0000:  f8 e4 3b 42 0f a8 94 3f  c2 07 ca 04 08 00 45 00  ..;B...? ......E.
0x0010:  00 50 19 8f 40 00 38 06  bc b6 34 df ca 24 93 e5  .P..@.8. ..4..$..
0x0020:  d9 79 01 bb dd a0 be 79  8e f6 f0 cc 4f b8 80 18  .y.....y ....O...
0x0030:  09 c3 08 b0 00 00 01 01  08 0a 36 76 fb 5d 43 ae  ........ ..6v.]C.
0x0040:  d7 f5 17 03 03 00 17 5c  06 63 1f db d2 7a 9e f1  .......\ .c...z..
0x0050:  69 a7 43 22 0d 72 26 51  55 1d b8 84 85 c1        i.C".r&Q U.....
```

## Author

Tomáš Ondrušek
VUT FIT
2BIT
4.2022
