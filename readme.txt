/*readme.txt
 *CIS 553 Networked systems 
 *Project2
 *Yuding Ai
 *Penn id 31295008
 *
 *This work is inspired by many online resources/tutorials and here is a 
 *helplog of these references:
 *  reference 1: http://www.tcpdump.org/pcap.htmls 
 *  reference 2: http://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 *  reference 3: https://vimeo.com/17585944   
 *  reference 4: http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader.htm
 *  reference 5: http://www.winpcap.org/pipermail/winpcap-users/2007-July/001984.html
 *  reference 6: http://www.roman10.net/2011/11/27/how-to-calculate-iptcpudp-checksumpart-1-theory/
 *
 *2017.3.26 - 2017.4.3: part1
 */

To compile the file: 
    since a makefile is included, so juat type: make

To run the file: 
    since this is Part 1, so there should be no argument,
    so just run as : ./packetparse <target.pcap>

In the terminal, it will display the following information of each packet from the .pcap file:

//- Packet type (TCP, UDP, other)
//- Source and destination MAC address
//- Source and destination IP address (if IP packet)
//- Source and destination ports (if TCP or UDP)
//- Checksum (if TCP) and whether the checksum is valid
//- Payload size

At the end, it print the total number of packets processed and the numbers of
TCP, UDP and non-TCP/UDP packets

Here are some Sample output: (from sampleimf.pcap)
----------------------------------
Packet number: 1
----------------------------------
Packet type: TCP

Ethernet Info:
MAC Destination address   : 00-1B-2F-03-9E-C2 
MAC Source address        : 08-00-46-DB-60-8F 

IP Header Info:
IP Source address         :192.168.1.4
IP Destination address    :217.12.11.66

TCP Header Info:
TCP Source Port        :1470
TCP Destination Port   :587
Checksum               :0x6e98
Calculated Checksum    :0x6e98
Checksum is valid      :true
Payload size           :0 bytes
.
.
.
.
.
----------------------------------
Packet number: 75
----------------------------------
Packet type: TCP

Ethernet Info:
MAC Destination address   : 08-00-46-DB-60-8F 
MAC Source address        : 00-1B-2F-03-9E-C2 

IP Header Info:
IP Source address         :217.12.11.66
IP Destination address    :192.168.1.4

TCP Header Info:
TCP Source Port        :587
TCP Destination Port   :1470
Checksum               :0xc4f1
Calculated Checksum    :0x97ca
Checksum is valid      :false
Payload size           :32 bytes

----------------------------------
Packet number: 76
----------------------------------
Packet type: TCP

Ethernet Info:
MAC Destination address   : 00-1B-2F-03-9E-C2 
MAC Source address        : 08-00-46-DB-60-8F 

IP Header Info:
IP Source address         :192.168.1.4
IP Destination address    :217.12.11.66

TCP Header Info:
TCP Source Port        :1470
TCP Destination Port   :587
Checksum               :0x915e
Calculated Checksum    :0x915e
Checksum is valid      :true
Payload size           :0 bytes

----------------------------------
Packet number: 77
----------------------------------
Packet type: TCP

Ethernet Info:
MAC Destination address   : 08-00-46-DB-60-8F 
MAC Source address        : 00-1B-2F-03-9E-C2 

IP Header Info:
IP Source address         :217.12.11.66
IP Destination address    :192.168.1.4

TCP Header Info:
TCP Source Port        :587
TCP Destination Port   :1470
Checksum               :0x9162
Calculated Checksum    :0x9162
Checksum is valid      :true
Payload size           :6 bytes

----------------------------------
Packet number: 78
----------------------------------
Packet type: TCP

Ethernet Info:
MAC Destination address   : 00-1B-2F-03-9E-C2 
MAC Source address        : 08-00-46-DB-60-8F 

IP Header Info:
IP Source address         :192.168.1.4
IP Destination address    :217.12.11.66

TCP Header Info:
TCP Source Port        :1470
TCP Destination Port   :587
Checksum               :0xd4ba
Calculated Checksum    :0xd4ba
Checksum is valid      :true
Payload size           :0 bytes

Total Numbers of packets processed: 78
Numbers of TCP: 78 
Numbers of UDP: 0 
Numbers of non-TCP/UDP: 0


As always, Thanks very much for your time!
