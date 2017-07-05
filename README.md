# PacketParser
This is a course Project from class _CIS 553: Networked systems_ at Upenn, where we have wrote a program to parse and interpret captured Ethernet traffic files (`.pcap` file) containing IP datagrams (UDP and TCP), and stores captured email messages sent in that traffic into files. (Using C++)
## Installation
First download/clone it:
```
$ git clone https://github.com/Aieener/PacketParser.git
```
Then compile it through the Makefile
```sh
$ make
```
or manually compile it by:
```sh
$ g++ -std=c++11 packetparse.cpp -o packetparse -lpcap
```

## Run the program: 
This program analyze the online traffic in **4** different ways
### Option 1, run it with out argument:
```sh
$ ./packetparse <target.pcap>
```
In the terminal, it will display the following information of each packet from the .pcap file
- Packet type (TCP, UDP, other)
- Source and destination MAC address
- Source and destination IP address (if IP packet)
- Source and destination ports (if TCP or UDP)
- Checksum (if TCP) and whether the checksum is valid
- Payload size
- Print the total number of packets processed and the numbers of TCP, UDP and non-TCP/UDP packets at the end.

### Option 2, run it as:
```sh
$ ./packetparse -t <target.pcap>
```
It will produce n x 3 files in the working directory, where n stands for the number of connections.
These are:  

**metadata**: named as `<n.meta>` and contains the following infomation :
- Initiator IP address
- Initiator port
- Responder IP address 
- Responder port
- Total Number of packets sent by initiator (including duplicates)
- Total Number of packets sent by responder (including duplicates)   
- Total Number of byte sent by initiator (including duplicates)   
- Total Number of byte sent by responder (including duplicates)   
- Number of duplicate packets sent by initiator      
- Number of duplicate packets sent by responder       
- Whether the connection is closed     

**Initiator**: Data from Initiator names as `<n.initiator>` and contains: All the ACKed and non-duplicate TCP payload data in the connection sent from the initiator to the responder.

**Responder**: Data from Responder names as `<n.responder>` and contains: All the ACKed and non-duplicate TCP payload data in the connection sent from the responder to the initiator.

### Option 3, run it as: 
```sh
$ ./packetparse -m <target.pcap>
```
This will first print 2 x n txt files, where n is the number of connections, named `<n.name.client.txt>` and `<n.name.server.txt>` 
Then the program will analysis those txt files and extract information for STMP and generate a new txt file named `<n.mail>` containning the following infomation:
- Sender's Email address: 
- Recipient's Email address: 
- The message is [accepted]/[rejected] by the server
### Option 4, run it as: 
```sh
$ ./packetparse -c <target.pcap>
```
and it will detect if there is any Cookies and then store all the name/value pairs in files named `1.cookie`, `2.cookie`, etc.
