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
 *  reference 7: https://tools.ietf.org/html/rfc821#section-4.1       
 *  reference 8: https://www.port25.com/how-to-check-an-smtp-connection-with-a-manual-telnet-session-2/
 *
 *2017.3.26 - 2017.4.3 : Part 1
 *2017.4.3  - 2017.4.12: Part 2, Noticed that I have switched from c to c++ due to the 
 * 			                     usage of std::vector, further, a c++11 compilier is needed
 *----------------------------------------------------------
 * void write_data(const u_char * data , int Size,FILE *f);    // the one I used for part2
 * void write_dataASC(const u_char * data , int Size,FILE *f); // modified version for part3
 *---------------------------------------------------------- 
 * While keeping my original part 2's printing method for part 2, 
 * (the one prints both ASCii and hex with all tcp payload)
 * I have made a modified version of the printing method and use it
 * for part 3, so the payload STMP data will be prints in the same format
 * as the given example stmp.client.txt and stmp.server.txt
 *----------------------------------------------------------
 *
 *2017.4.13 - 2017.4.24: Part3, this part will first print 2*n txt files 
 *                       named <n.name.client.txt and <n.name.server.txt> in the format
 *                       that our TA Kyle provided to us, i.e. stmp.client.txt
 *                       
 *                       Then the program will analysis those txt file and extract
 *                       information for STMP from it.

 *                       Extra credit: extract cookies from HTTP connections
 */

To compile the program: 
    since a makefile is included, so just type: make
    (to manually compile:  g++ -std=c++11 packetparse.cpp -o packetparse -lpcap)

To run the program: 
    For Part 1, there should be no argument,
        Just run as : ./packetparse <target.pcap>
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

    For Part 3, run it as: ./packetparse -m <target.pcap>
        -This part will first print 2*n txt files, where n is the number of connections,
         named <n.name.client.txt> and  <n.name.server.txt> in the format that our TA Kyle provided 
         to us, i.e. stmp.client.txt
        (so basically similar to redo part 2 except that: A. we filtered server's port number to be
         25 or 587; B. print payload data in plain txt. i.e the same format as the reference file
         stmp.txt)

        -Then the program will analysis those txt files and extract information for STMP 
         and generate a new txt file named <n.mail> containning the following infomation:
            -Sender's Email address: 
            -Recipient's Email address: 
            -The message is [accepted]/[rejected] by the server
            -Blow is the message headers and body:
                DATA
                <message headers and body>
                .

    For Extra credit, run it as: ./packetparse -c <target.pcap>
        -Like part 3, this will first print 2*n txt file except that this time we don't set filter
         on port number
        -Then it will detect if there is any Cookies and then store all the name/value pairs in files
         named 1.cookie, 2.cookie, etc. 
                

As always, Thanks very much for your time!
