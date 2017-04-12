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
 *2017.3.26 - 2017.4.3 : part 1
 *2017.4.3  - 2017.4.12: part 2, Noticed that I have switched from c to c++ due to the 
 * 			                     usage of std::vector, further, a c++11 compilier is needed
 */

To compile the file: 
    since a makefile is included, so juat type: make
    (to manually compile:  g++ -std=c++11 packetparse.cpp -o packetparse -lpcap)

To run the file: 
    For Part 1, so there should be no argument,
        so just run as : ./packetparse <target.pcap>
        In the terminal, it will display the following information of each packet from the .pcap file:

        - Packet type (TCP, UDP, other)
        - Source and destination MAC address
        - Source and destination IP address (if IP packet)
        - Source and destination ports (if TCP or UDP)
        - Checksum (if TCP) and whether the checksum is valid
        - Payload size

        At the end, it print the total number of packets processed and the numbers of
        TCP, UDP and non-TCP/UDP packets


    For Part 2, run it as: ./packetparse -t <target.pcap>
        It will print the following info in ternimal:
            -# of responder  
            -# of initiator 
            -# of connction
            -nth initiator has [how many] duplicated packet to drop
            -nth initiator closed? [ 0:no or 1:yes ]
            -nth responder has [how many] duplicated packet to drop
            -nth responder closed? [ 0:no or 1:yes ]

        Then it will produce n*3 files in the working directory, where n stands for the number of connections.
        These are:

        - metadata: named as "n.meta" and contains the following infomation:
            -Initiator IP address
            -Initiator port
            -Responder IP address 
            -Responder port
            -Total Number of packets sent by initiator (including duplicates)
            -Total Number of packets sent by responder (including duplicates)   
            -Total Number of byte sent by initiator    (including duplicates)   
            -Total Number of byte sent by responder    (including duplicates)   
            -Number of duplicate packets sent by initiator      
            -Number of duplicate packets sent by responder       
            -Whether the connection is closed     

        - Data from Initiator names as "n.initiator" and contains:
            -All the ACKed and non-duplicate TCP payload data in the connection 
                sent from the initiator to the responder.

        - Data from Responder names as "n.responder" and contains:
            -All the ACKed and non-duplicate TCP payload data in the connection 
                sent from the responder to the initiator.

        Assumptions I have made to implement part 2:
        // ---------------------------------------------------------------------------------
        // My detection of initiator and responder heavily relies on the 3 way shaking
        // such that this program won't include the connection that has already made before 
        // capture of the packets starts
        // ---------------------------------------------------------------------------------

        // ---------------------------------------------------------------------------------
        // The number of responder and initiator has to match such that 
        // num_of_responder = num_of_initiator = num_of_connections
        // ---------------------------------------------------------------------------------
                

As always, Thanks very much for your time!
