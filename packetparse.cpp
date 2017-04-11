/*packetparse.cpp
 *CIS 553 Networked systems 
 *Project2
 *Yuding Ai
 *Penn id 31295008
 *2017.3.26 - 2017.4.3: part1
 *2017.4.3  - 2017.4.12: part2 I changed from c to cpp due to usage of <vector>
 */

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <assert.h>
#include <vector>
#include <array>
#include <iostream>
#include <algorithm>

///-----------------------
// part 1: Due 4/3/17
void parsing_packets(const struct pcap_pkthdr header,const u_char *packet);

// part 2: Due 4/12/17
void tcp_flows(const struct pcap_pkthdr header,const u_char *packet);

// part 3: Due 4/24/17
void email_traffic();
///-----------------------

// ------ pseudo_header for TcpCheckSum -----------
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

struct metadata
{
    unsigned int source_ip;
    unsigned int dest_ip;
    unsigned int source_port;
    unsigned int dest_port;
    unsigned int num_packet;
    unsigned int num_byte_dir1;
    unsigned int num_byte_dir2;
    unsigned int num_dup_dir1;
    unsigned int num_dup_dir2;
    bool isclosed;
};

///---- helper functions --------------
void print_MAC(const u_char*);
void print_ip_header(const u_char*);
void print_tcp_packet(const u_char*,int );
void print_udp_packet(const u_char*,int );
void PrintData (const u_char * data , int Size);
/** void get_tcpconnectinfo(const u_char *packet, char *sip, char *dip, unsigned int s_port, unsigned int d_port); */

void analyconnection(std::array<unsigned long, 11> &connect,const std::vector<std::array<unsigned long,14> > init_packetinfo_list,
        const std::vector<std::array<unsigned long,14> > resp_packetinfo_list);

void printconnectinfo(const std::vector<std::array<unsigned long,14> > packetinfolist);

//void get_tcpconnectinfo(const struct pcap_pkthdr header,const u_char *packet,unsigned int* sip, unsigned int* dip, unsigned int *s_port, unsigned int *d_port,unsigned long *sequence, unsigned long *ack_seq,unsigned int *ack,unsigned int *syn,unsigned int *fin,unsigned int *TCPsize);


void get_tcpconnectinfo(const struct pcap_pkthdr header,const u_char *packet,unsigned long* sip, unsigned long* dip, unsigned long *s_port, unsigned long *d_port,unsigned long *sequence, unsigned long *ack_seq,unsigned long *ack,unsigned long *syn,unsigned long *fin,unsigned long *rst, unsigned long *TCPsize,unsigned long *Payload_size, unsigned long *Total_size);

void write_meta(const std::array<unsigned long, 11> connect,int idx);
void write_data(const u_char * data , int Size,FILE *f);

//derived from online source --------
unsigned short TcpCheckSum(const struct iphdr* iph,const struct tcphdr* tcph,const u_char* data,int size);
unsigned short checksum(const u_char *buf, int size); 
//-----------------------------------

//---- global variables --------------
int n_tcp=0, n_udp=0,n_other=0; // the packet counter
struct sockaddr_in source,dest; // the address of source and destination

int main(int argc, char *argv[] )
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pf;
    struct bpf_program fp;
    char select_mail[] = "port 25";
    /** char select_mail[] = "port 80"; */
    struct pcap_pkthdr header;
    const u_char *packet;

    if( argc < 2 ){
        fprintf( stderr, "Usage: %s {pcap-file}\n", argv[0] );
        exit(1);
    }

    if( (pf = pcap_open_offline( argv[1], errbuf )) == NULL ){
        fprintf( stderr, "Can't process pcap file %s: %s\n", argv[1], errbuf );
        exit(1);
    }

    // ------------------ Part 1 ---------------------------

    if(argc ==2){
        //if no arguments, simply display the basic header informations:
        //- Packet type (TCP, UDP, other)
        //- Source and destination MAC address
        //- Source and destination IP address (if IP packet)
        //- Source and destination ports (if TCP or UDP)
        //- Checksum (if TCP) and whether the checksum is valid
        //- Payload size
        int packet_counter = 1;
        while((packet = pcap_next(pf, &header)) != NULL){
            printf("----------------------------------\n");
            printf("Packet number: %d\n",packet_counter);
            printf("----------------------------------\n");
            parsing_packets(header,packet);
            packet_counter++;
        }
        printf("Total Numbers of packets processed: %d\nNumbers of TCP: %d \nNumbers of UDP: %d \nNumbers of non-TCP/UDP: %d\n\n",
                n_tcp + n_udp + n_other,n_tcp,n_udp,n_other);
    }

    // -------------------Part 2 ---------------------------
    // Sorry that I pretty much screwed up with my coding style 
    // at this part, hopefully I could get a more organized 
    // structure in next part.
    // -----------------------------------------------------
    
    if(argc ==3 && !strcmp(argv[2],"-t")){
        //source ip source port, dest ip and dest port uniquely define a TCP connection
        unsigned long sip;
        unsigned long dip;
        unsigned long s_port;
        unsigned long d_port;
        unsigned long sequence;
        unsigned long ack_seq;
        unsigned long ack;
        unsigned long syn;
        unsigned long fin;
        unsigned long rst;
        unsigned long TCPsize;
        unsigned long Total_size;
        unsigned long Payload_size;

        std::vector <std::array<unsigned long,11> > connec_list; //store each connection
        // the structure of connection:[initiator_ip;responder_ip;initiator_port; responder_port;
        // num_sent_by_i; num_sent_by_r;num_byte_sent_by_i;num_byte_sent_by_r;num_ofdul_i; num_ofdul_r;
        // closed]
        
        std::vector<std::array<unsigned long,14> > init_packetinfo_list; // a list to store the infomation per connection
        std::vector<std::array<unsigned long,14> > resp_packetinfo_list; // a list to store the infomation per connection
        // where the sequence number and ack_seq stored here will be the relative version
        // stucture for each packet:[sip,dip,s_port,s_port,sequence, ack_seq,ack,syn,fin,tcpsize,packet_number];
        std::vector<std::array<unsigned long, 14> >remodul_init_packet_list;
        std::vector<std::array<unsigned long, 14> >remodul_resp_packet_list;


        std::vector<std::vector<std::array<unsigned long,14> > > init_full_list; // a list to store the connection info
        std::vector<std::vector<std::array<unsigned long,14> > > resp_full_list; // a list to store the connection info

        unsigned long packet_counter = 1;
        
        unsigned long sip_ref;
        unsigned long dip_ref;
        unsigned long seq_ref = 0;
        unsigned long ack_ref = 0;
        std::vector<unsigned long> sip_reflist;
        std::vector<unsigned long> dip_reflist;
        std::vector<unsigned long> seq_reflist;
        std::vector<unsigned long> ack_reflist;
        unsigned long connection_count = 0;

        std::vector<const u_char *> packetlist;

        while((packet = pcap_next(pf, &header)) != NULL){
            packetlist.push_back(packet);
            const struct iphdr *ip;
            ip = (struct iphdr*)(packet + sizeof(struct ethhdr));


            // since we only cares about tcp connections:
        
            if(ip->protocol == IPPROTO_TCP){
                // first, parse metadata and figure out how many connections
                get_tcpconnectinfo(header,packet,&sip,&dip,&s_port,&d_port,&sequence,&ack_seq,&ack,&syn,&fin,&rst,
                        &TCPsize,&Payload_size,&Total_size);

                //------------------------- compute relative seq_number and ack_number --------------------------
                unsigned long seq_relative = 0; 
                unsigned long ack_relative = 0; 
                // whenever there is a syn. it indicates an attempt for a connection
                if(ack ==0 && syn ==1){
                    seq_ref = sequence;
                    seq_reflist.push_back(sequence);
                    sip_ref = sip;
                    sip_reflist.push_back(sip);
                    dip_ref = dip;
                    dip_reflist.push_back(dip);
                    seq_relative = sequence - seq_ref;
                    ack_relative = ack_seq - ack_ref;
                    std::array<unsigned long, 14> init_packet = {{sip,dip,s_port,d_port,seq_relative,ack_relative,
                        ack,syn,fin,TCPsize,packet_counter,rst,Payload_size,Total_size}};
                    init_packetinfo_list.push_back(init_packet);
                }
                if(ack == 1 && syn ==1){
                    ack_ref = sequence;
                    ack_reflist.push_back(sequence);
                    //indicates a new connection
                    connection_count++;
                }
                for(int j = 0; j<connection_count;j++){
                    if(sip ==sip_reflist[j] && dip == dip_reflist[j] ){
                        seq_relative = sequence - seq_reflist[j];
                        //seq_relative = sequence - seq_ref;
                        //ack_relative = ack_seq - ack_ref;
                        ack_relative = ack_seq - ack_reflist[j];

                        std::array<unsigned long, 14> init_packet = {{sip,dip,s_port,d_port,seq_relative,ack_relative,
                            ack,syn,fin,TCPsize,packet_counter,rst,Payload_size,Total_size}};
                        init_packetinfo_list.push_back(init_packet);
                    }

                    else if(sip == dip_reflist[j] && dip ==sip_reflist[j]){
                        seq_relative = sequence - ack_reflist[j];
                        ack_relative = ack_seq - seq_reflist[j];

                        std::array<unsigned long, 14> resp_packet = {{sip,dip,s_port,d_port,seq_relative,ack_relative,
                            ack,syn,fin,TCPsize,packet_counter,rst,Payload_size,Total_size}};
                        resp_packetinfo_list.push_back(resp_packet);
                    }
                }

                //--------------------finish compute relative seq_number and ack_number --------------------------

                bool new_connection = true;

                for(int i = 0; i<connec_list.size();i++){
                    // source ip, dest ip, source port and dest port uniquely defines a connection
                    // check if this packet's identity matches wish any exist connection
                    int counter = 0;
                    for(int j = 0; j<4;j++){
                        if(sip == connec_list[i][j]){
                            counter++;
                        }
                        if(dip == connec_list[i][j]){
                            counter++;
                        }
                        if(s_port == connec_list[i][j]){
                            counter++;
                        }
                        if(d_port == connec_list[i][j]){
                            counter++;
                        }
                    }
                    if(counter ==4){
                        new_connection = false;
                    }
                }

                if(new_connection){
                    // the structure of connection:[initiator_ip; responder_ip;initiator_port; responder_port;
                    // num_sent_by_i;  num_sent_by_r;   num_byte_sent_by_i;   num_byte_sent_by_r;  num_ofdul_i; num_ofdul_r;
                    // closed]
                    std::array<unsigned long, 11> connect = {{sip,dip,s_port,d_port,0,0,0,0,0,0,0}};
                    connec_list.push_back(connect);
                }

                /** write_meta(1,sip,dip,s_port,d_port); */

            }
            packet_counter++;
        }

        // ------------------------------Sort the paket by sequence number--------------------------------------------
        //sorry it's bubble sort....
        std::array<unsigned long, 14> temp;
        for(int c = 0; c<init_packetinfo_list.size() -1;c++){
            for(int d = 0; d< init_packetinfo_list.size()-c-1;d++){
                if(init_packetinfo_list[d][4]>init_packetinfo_list[d+1][4]){

                    temp = init_packetinfo_list[d];
                    init_packetinfo_list[d] = init_packetinfo_list[d+1];
                    init_packetinfo_list[d+1] = temp;
                }
            }
        }

        for(int c = 0; c<resp_packetinfo_list.size() -1;c++){
            for(int d = 0; d< resp_packetinfo_list.size()-c-1;d++){
                if(resp_packetinfo_list[d][4]>resp_packetinfo_list[d+1][4]){

                    temp = resp_packetinfo_list[d];
                    resp_packetinfo_list[d] = resp_packetinfo_list[d+1];
                    resp_packetinfo_list[d+1] = temp;
                }
            }
        }
        // ------------------------------ Finish sorting the packet --------------------------------------------------
        
        //--------------print info to terminal------------------
        //printconnectinfo(init_packetinfo_list);
        printconnectinfo(resp_packetinfo_list);
        //--------------print info to terminal------------------
        
        // ------------------- Remove the duplicate packet and drop the ones are not ACKed ---------------------------
        remodul_init_packet_list = init_packetinfo_list;
        remodul_resp_packet_list = resp_packetinfo_list;

        // drop the dulpicated packet in initiator direction
        int idropnum= 0;
        for(int i = 0; i<init_packetinfo_list.size();i++){
            unsigned long seqini  =init_packetinfo_list[i][4];
            unsigned long ackini  =init_packetinfo_list[i][5];
            unsigned long tcplenini  =init_packetinfo_list[i][9];

            unsigned long ack = init_packetinfo_list[i][6];
            unsigned long syn = init_packetinfo_list[i][7];
            unsigned long fin = init_packetinfo_list[i][8];
            bool ACKed = false;

            if(ack ==1 &&syn== 0 &&fin ==0){ // make sure it is the packet in between connection
                for(int j = 0; j<resp_packetinfo_list.size();j++){

                    // To get ACKed, (tcplenini + seqini = ackrep  && ackini = seqrep )has to hold at somewhere
                    unsigned long seqrep = resp_packetinfo_list[j][4];
                    unsigned long ackrep = resp_packetinfo_list[j][5];

                    if(tcplenini+ seqini == ackrep && ackini ==seqrep){
                        ACKed = true;
                    }
                }
            }

            if(!ACKed){
                //drop that packet because it is not ACKed, hence a duplicate
                remodul_init_packet_list.erase(remodul_init_packet_list.begin()+i-idropnum);
                idropnum++;
            }
        }
        // drop the dulpicated packet in responser direction
        int rdropnum= 0;
        for(int i = 0; i<resp_packetinfo_list.size();i++){
            unsigned long seqrsp  =resp_packetinfo_list[i][4];
            unsigned long ackrsp  =resp_packetinfo_list[i][5];
            unsigned long tcplenrsp  =resp_packetinfo_list[i][9];

            unsigned long ack = resp_packetinfo_list[i][6];
            unsigned long syn = resp_packetinfo_list[i][7];
            unsigned long fin = resp_packetinfo_list[i][8];
            bool ACKed = false;

            if(ack ==1 &&syn== 0 &&fin ==0){ // make sure it is the packet in between connection
                for(int j = 0; j<resp_packetinfo_list.size();j++){

                    // To get ACKed, (tcplenrsp+ seqrsp == ackini && ackrsp ==seqini)has to hold at somewhere
                    unsigned long seqini = init_packetinfo_list[j][4];
                    unsigned long ackini = init_packetinfo_list[j][5];

                    if(tcplenrsp+ seqrsp == ackini && ackrsp ==seqini){
                        ACKed = true;
                    }
                }
            }

            if(!ACKed){
                //drop that packet because it is not ACKed, hence a duplicate
                remodul_resp_packet_list.erase(remodul_resp_packet_list.begin()+i-rdropnum);
                rdropnum++;
            }
        }

        // ---------- Finishing Remove the duplicate packet and drop the ones are not ACKed ---------------------------


        printf("num of connection = %lu", connec_list.size());
        for(int i = 0; i<connec_list.size();i++ ){
            analyconnection(connec_list[i],init_packetinfo_list,resp_packetinfo_list);
            write_meta(connec_list[i],i+1);
        }
    
        std::cout<<"total connection = "<<connection_count<<"  "<<connec_list.size();

        //=====================================================================
        //--------------------write initiator----------------------------------
        //=====================================================================
        char extention[11]= ".initiator";
        char *filename = (char *) malloc(1+strlen(extention)+sizeof(unsigned int));
        sprintf(filename,"initiator/%d%s",1,extention);
        u_char *payload;                    

        FILE *f1 = fopen(filename, "wb");
        //FILE *f = fopen("meta/1.meta", "wb");
        assert(f1 !=NULL);

        //unsigned long idx = 1;
        if( (pf = pcap_open_offline( argv[1], errbuf )) == NULL ){
            fprintf( stderr, "Can't process pcap file %s: %s\n", argv[1], errbuf );
            exit(1);
        }

        int k = 1;
        while((packet = pcap_next(pf, &header)) != NULL){
        //for(int k = 0; k < packetlist.size();k++){
            ////bool printit = false;
            //remodul_init_packet_list;
            //for(int i = 0; i<init_packetinfo_list.size();i++){
            for(int i = 0; i<remodul_init_packet_list.size();i++){
                //std::cout<<init_packetinfo_list[i][10] <<std::endl;
                //if(k == init_packetinfo_list[i][10]){
                if(k == remodul_init_packet_list[i][10]){
                    ////printit = true;
                    fprintf(f1,"----------------------------------\n");
                    fprintf(f1,"packet number: %d\n",k);
                    fprintf(f1,"----------------------------------\n");
                    //int size = init_packetinfo_list[i][9];

                    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
                    int iphdrlen = iph ->ihl*4; // the length of ip header

                    // since tcp is encapsulated inside of a ip packet, which is inside of a ethernet packet
                    // the total length of tcp header would be packet + iphr length+ ethhdr length
                    struct tcphdr * tcph = (struct tcphdr *)(packet + iphdrlen + sizeof(struct ethhdr));
                    int tcphdrlen = tcph ->doff*4; // the length of tcp header;

                    int header_size = sizeof(struct ethhdr) + iphdrlen + tcphdrlen;
                    //calc the payload size: payload = total_size - header_size
                    payload = (u_char *)(packet + sizeof(struct ethhdr)+iphdrlen + tcphdrlen);
                    int packetsize = header.len;
                    int payload_size = packetsize - header_size;
                    
                    write_data(payload ,payload_size ,f1);
                    //printf("packet number: %d\n",k);
                    //printf("----------------------------------\n");
                    //PrintData(payload ,payload_size);
                    //std::cout<<i<<std::endl;
                    break;
                }
            }
            k++;
        }
        fclose(f1);
    }

    // -------------------Part 3 ---------------------------

    //set filter on port 25 for stmp
    /** if( pcap_compile(pf, &fp, select_mail, 0, 0 ) == -1 ) { */
    /**     fprintf( stderr, "BPF compile errors on %s: %s\n", */
    /**             select_mail, pcap_geterr(pf) ); */
    /**     exit(1); */
    /** } */

    /** if( pcap_setfilter( pf, &fp ) == -1 ){ */
    /**     fprintf( stderr, "Can't install filter '%s': %s\n", select_mail, */
    /**             pcap_geterr(pf) ); */
    /**     exit(1); */
    /** } */

    //clean up
    /** pcap_freecode(&fp); */
    pcap_close(pf);

    return 0;
}

void printconnectinfo(const std::vector<std::array<unsigned long,14> > packetinfolist){
    for(int i = 0; i<packetinfolist.size();i++){

        // stucture for each packet:[sip,dip,s_port,s_port,sequence, ack_seq,ack,syn,fin,tcpsize,packet_number];
        printf("----------------------------------\n");
        printf("Packet number: %lu\n",packetinfolist[i][10]);
        printf("----------------------------------\n");
        unsigned long tsip = packetinfolist[i][0];
        unsigned long tdip = packetinfolist[i][1];
        unsigned long ts_port = packetinfolist[i][2];
        unsigned long td_port = packetinfolist[i][3];
        unsigned long tseq_relative = packetinfolist[i][4];
        unsigned long tack_relative = packetinfolist[i][5];
        unsigned long tack = packetinfolist[i][6];
        unsigned long tsyn = packetinfolist[i][7];
        unsigned long tfin = packetinfolist[i][8];
        unsigned long tTCPsize = packetinfolist[i][9];
        unsigned long trst = packetinfolist[i][11];
        unsigned long tpsize = packetinfolist[i][12];
        unsigned long ttsize = packetinfolist[i][13];


        printf("Initiator IP address  :%lu.%lu.%lu.%lu\n",tsip&0xFF,(tsip>>8)&0xFF,
                (tsip>>16)&0xFF,(tsip>>24)&0xFF);
        printf("Initiator port    :%lu\n", ts_port);
        printf("Responder IP address  :%lu.%lu.%lu.%lu\n",tdip&0xFF,(tdip>>8)&0xFF,
                (tdip>>16)&0xFF,(tdip>>24)&0xFF);
        printf("Responder port    :%lu\n", td_port);
        printf("TCP segment Len   :%lu\n", tTCPsize);
        printf("Sequence number (relative)    :%lu\n", tseq_relative);
        printf("Ack number (relative)         :%lu\n", tack_relative);
        printf("Ack         :%lu\n", tack);
        printf("Syn         :%lu\n", tsyn);
        printf("Fin         :%lu\n", tfin);
        printf("Rst         :%lu\n", trst);
        printf("Total packet size:     %lu\n", ttsize);
        printf("Packet Payload size:   %lu\n", tpsize);
    }
}
void analyconnection(std::array<unsigned long, 11> &connect,const std::vector<std::array<unsigned long,14> > init_packetinfo_list,
        const std::vector<std::array<unsigned long,14> > resp_packetinfo_list){
    // Recall the structure of connection:[initiator_ip; responder_ip;initiator_port; responder_port;
    // num_sent_by_i;  num_sent_by_r;   num_byte_sent_by_i;   num_byte_sent_by_r;  num_ofdul_i; num_ofdul_r;
    // closed]
    
    //number of packet sent by initiator 
    connect[4] = init_packetinfo_list.size();
    //number of packet sent by responser 
    connect[5] = resp_packetinfo_list.size();
    //number of byte send by initiator
    unsigned long inibyte = 0;
    for(int i = 0; i<connect[4];i++){
        inibyte += init_packetinfo_list[i][13]; // concatenate the tcp seg length
    }
    connect[6] = inibyte;

    //number of byte send by responser
    unsigned long responbyte = 0;
    for(int i = 0; i<connect[5];i++){
        responbyte += resp_packetinfo_list[i][13];
    }
    connect[7] = responbyte;

    //number of duplicate packet sent by initiator;
}



void write_meta(const std::array<unsigned long, 11> connect,int idx){
    char extention[6]= ".meta";
    char *filename = (char *) malloc(1+strlen(extention)+sizeof(unsigned int));
    sprintf(filename,"meta/%d%s",idx,extention);

    // Recall the structure of connection:[initiator_ip; responder_ip;initiator_port; responder_port;
    // num_sent_by_i;  num_sent_by_r;   num_byte_sent_by_i;   num_byte_sent_by_r;  num_ofdul_i; num_ofdul_r;
    // closed]

    unsigned long sip = connect[0];
    unsigned long dip = connect[1];
    unsigned long s_port = connect[2];
    unsigned long d_port = connect[3];
    unsigned long num_pi = connect[4];
    unsigned long num_pr = connect[5];
    unsigned long byte_i = connect[6];
    unsigned long byte_r = connect[7];

    FILE *f = fopen(filename, "wb");
    //FILE *f = fopen("meta/1.meta", "wb");
    assert(f !=NULL);
    fprintf(f,"Initiator IP address  :%lu.%lu.%lu.%lu\n",sip&0xFF,(sip>>8)&0xFF,
            (sip>>16)&0xFF,(sip>>24)&0xFF);
    fprintf(f,"Initiator port    :%lu\n", s_port);
    fprintf(f,"Responder IP address  :%lu.%lu.%lu.%lu\n",dip&0xFF,(dip>>8)&0xFF,
            (dip>>16)&0xFF,(dip>>24)&0xFF);
    fprintf(f,"Responder port    :%lu\n", d_port);
    fprintf(f,"Total Number of packets sent by initiator (including duplicates)   :%lu\n", num_pi);
    fprintf(f,"Total Number of packets sent by responder (including duplicates)   :%lu\n", num_pr);
    fprintf(f,"Total Number of byte sent by initiator    (including duplicates)   :%lu\n", byte_i);
    fprintf(f,"Total Number of byte sent by responder    (including duplicates)   :%lu\n", byte_r);
    fclose(f);
}

void get_tcpconnectinfo(const struct pcap_pkthdr header,const u_char *packet,unsigned long* sip, unsigned long* dip, unsigned long *s_port, unsigned long *d_port,unsigned long *sequence, unsigned long *ack_seq,unsigned long *ack,unsigned long *syn,unsigned long *fin,unsigned long *rst, unsigned long *TCPsize,unsigned long *Payload_size, unsigned long *Total_size){
    int size = header.len;
    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
    int iphdrlen = iph ->ihl*4; // the length of ip header
    struct tcphdr * tcph = (struct tcphdr *)(packet + iphdrlen + sizeof(struct ethhdr));
    int tcphdrlen = tcph ->doff*4; // the length of tcp header;

    const u_char *payload;
    int header_size = sizeof(struct ethhdr) + iphdrlen + tcphdrlen;
    //calc the payload size: payload = total_size - header_size
    int payload_size = size - header_size;
    payload = (u_char *)(packet + sizeof(struct ethhdr)+iphdrlen + tcphdrlen);

    //Ok, I might not fully understand this, but whenever the payload has a size of 6  
    //with the first two to be 00 00, the tcp_seg_len is 0 according to my observation at wireshark
    //and that payload is called 'Ethernet padding'
    //therefore I set tcp_seg_len = 0 when payload has its first two segment to be 00 00 
    //otherwise, tcp_seg_len = payload
    int tcp_seg_len=0;
    
    if((unsigned int) payload[0] != 0 &&(unsigned int) payload[1] != 0){
        tcp_seg_len = payload_size;
    }


    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph ->saddr; // assign the ip source addr into source

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph ->daddr; // assign the ip destination addr into dest

    //------------------------------------------------------------
    *sip = iph->saddr;
    *dip = iph->daddr;
    //unsigned int rst;
    *rst = (tcph->rst);

    *s_port = ntohs(tcph->source);
    *d_port = ntohs(tcph->dest);
    *sequence = ntohl(tcph->seq);
    *ack_seq = ntohl(tcph->ack_seq);
    *ack = (tcph->ack);
    *syn = (tcph->syn);
    *fin = (tcph->fin);
    *TCPsize = tcp_seg_len;
    *Payload_size = payload_size;
    *Total_size = size;
    
    /** printf("IP Source address         :%s\n", inet_ntoa(source.sin_addr)); */
    /** printf("IP Destination address    :%s\n", inet_ntoa(dest.sin_addr)); */
    //printf("RST    :%lu\n", *rst);
}

void write_data(const u_char * data , int Size,FILE *f){

    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(f, "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(f, "%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(f, "."); //otherwise print a dot
            }
            fprintf(f,"\n");
        }

        if(i%16==0) fprintf(f,"   ");
        fprintf(f," %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
                fprintf(f, "   "); //extra spaces
            }

            fprintf(f,"         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                    fprintf(f, "%c",(unsigned char)data[j]);
                }
                else
                {
                    fprintf(f, ".");
                }
            }
            fprintf(f, "\n" );
        }
    }
}
void parsing_packets(const struct pcap_pkthdr header,const u_char *packet){
    int size = header.len;
    const struct iphdr *ip;
    ip = (struct iphdr*)(packet + sizeof(struct ethhdr));

    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
    int iphdrlen = iph ->ihl*4; // the length of ip header
    int default_payload_size = size - iphdrlen - sizeof(struct ethhdr);

    switch(ip->protocol) {
        case IPPROTO_TCP:
            printf("Packet type: TCP\n\n");
            print_tcp_packet(packet,size);
            n_tcp++;
            break;

        case IPPROTO_UDP:
            printf("Packet type: UDP\n\n");
            print_udp_packet(packet,size);
            n_udp++;
            break;

        default:
            printf("Packet type: other\n\n");
            print_ip_header(packet);
            printf("Payload size              :%d bytes (packet size - ip header - ethernet header)\n\n", default_payload_size);
            n_other++;
            break;
    }
}

void print_MAC(const u_char* packet){
    struct ethhdr *eth = (struct ethhdr*) packet;

    printf("Ethernet Info:\n");
    printf("MAC Destination address   : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0],
           eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5] );
    printf("MAC Source address        : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0],
           eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5] );
    printf("\n");

}
void print_ip_header(const u_char* packet){
    
    // first print the MAC address since ip packet is encapsulated in
    // side a Ethernet packet
    print_MAC(packet);

    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph ->saddr; // assign the ip source addr into source

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph ->daddr; // assign the ip destination addr into dest
    printf("IP Header Info:\n");
    printf("IP Source address         :%s\n", inet_ntoa(source.sin_addr));
    printf("IP Destination address    :%s\n", inet_ntoa(dest.sin_addr));
    printf("\n");

}
unsigned short checksum(const u_char *buf, int size){
    // this part is derived from online source:
    unsigned sum = 0;
    int i;
    // accumulate the checksum
    for (i = 0; i < size - 1; i += 2){
        if(i != 28 && i != 30){
            // the checksum field and urgent_pointer happens to 
	    // be at 28th and 30th index in TCP header.
            // Since we are manully recalculate the checksum here, 
            // we should not put the checksum field and urgent_pointer in TCP header into count 
            unsigned short word16 = *(unsigned short *) &buf[i];
            sum += word16;
        }
    }

    // handle odd size case
    if (size & 1){
        unsigned short word16 = (unsigned char) buf[i];
        sum += word16;
    }

    // fold to get the ones complement result
    while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

    // Since this methoed is derived from online code where they have
    // big endian so we want to swap big endian to little endian for
    // our purpose of calculation
    unsigned swapped = (sum>>8) | (sum<<8);

    // invert it to get the output checksum
    return ~swapped;
} 

unsigned short TcpCheckSum(const struct iphdr* iph,const struct tcphdr* tcph,const u_char* data,int size){
    int tcphdrlen = tcph ->doff*4; // the length of tcp header;

    // fill the pseudo header for tcp
    struct pseudo_header psd_header;
    psd_header.source_address=iph->saddr;
    psd_header.dest_address=iph->daddr;
    psd_header.placeholder=0;
    psd_header.protocol=IPPROTO_TCP; // which is 0X06
    psd_header.tcp_length = htons(tcphdrlen+size);

    char tcpBuf[65536];
    memcpy(tcpBuf,&psd_header,sizeof(struct pseudo_header));
    memcpy(tcpBuf+sizeof(struct pseudo_header),tcph,tcphdrlen);
    memcpy(tcpBuf+sizeof(struct pseudo_header)+tcphdrlen,data,size);
    /** PrintData(tcpBuf,sizeof(struct pseudo_header)+tcphdrlen + size); */

    return  checksum((unsigned char *)tcpBuf,
                    sizeof(struct pseudo_header)+tcphdrlen + size);
}

void print_tcp_packet(const u_char* packet,int size){
    // first print the ip header since TCP packet is encapsulated in
    // side an ip packet 
    print_ip_header(packet);

    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
    int iphdrlen = iph ->ihl*4; // the length of ip header

    const u_char *payload;

    // since tcp is encapsulated inside of a ip packet, which is inside of a ethernet packet
    // the total length of tcp header would be packet + iphr length+ ethhdr length
    struct tcphdr * tcph = (struct tcphdr *)(packet + iphdrlen + sizeof(struct ethhdr));
    int tcphdrlen = tcph ->doff*4; // the length of tcp header;

    int header_size = sizeof(struct ethhdr) + iphdrlen + tcphdrlen;
    //calc the payload size: payload = total_size - header_size
    int payload_size = size - header_size;
    payload = (u_char *)(packet + sizeof(struct ethhdr)+iphdrlen + tcphdrlen);


    //Ok, I might not fully understand this, but whenever the payload has a size of 6  
    //with the first two to be 00 00, the tcp_seg_len is 0 according to my observation at wireshark
    //and that payload is called 'Ethernet padding'
    //therefore I set tcp_seg_len = 0 when payload has its first two segment to be 00 00 
    //otherwise, tcp_seg_len = payload
    int tcp_seg_len=0;
    
    if((unsigned int) payload[0] != 0 &&(unsigned int) payload[1] != 0){
        tcp_seg_len = payload_size;
    }


    unsigned short CheckSum_calculate = TcpCheckSum(iph,tcph,payload,tcp_seg_len);
    bool valid = CheckSum_calculate ==ntohs(tcph->check);

    printf("TCP Header Info:\n");
    printf("TCP Source Port        :%u\n", ntohs(tcph->source));
    printf("TCP Destination Port   :%u\n", ntohs(tcph->dest));
    printf("Checksum               :0x%x\n", ntohs(tcph->check));
    printf("Calculated Checksum    :0x%x\n", CheckSum_calculate);
    printf("Checksum is valid      :%s\n", valid ? "true" : "false");
    printf("Payload size           :%d bytes\n", payload_size);
    //PrintData (packet, size); 
    PrintData (payload, payload_size); 
    printf("\n");

}

void print_udp_packet(const u_char* packet,int size){
    // first print the ip header since UDP packet is encapsulated in
    // side an ip packet 
    print_ip_header(packet);

    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
    int iphdrlen = iph ->ihl*4; // the length of ip header

    struct udphdr *udph = (struct udphdr *)(packet + iphdrlen + sizeof(struct ethhdr));
    //noticed that unlike tcp, the size of udphder is simply sizeof udph
    int header_size = iphdrlen + sizeof(udph) + sizeof(struct ethhdr);

    int payload_size = size - header_size;

    printf("UDP Header Info:\n");
    printf("UDP Source Port        :%u\n", ntohs(udph->source));
    printf("UDP Destination Port   :%u\n", ntohs(udph->dest));
    printf("Payload size           :%d bytes\n", payload_size);
    /** PrintData (packet, size); */
    printf("\n");
}

void PrintData (const u_char * data , int Size){
    //direcly derived from online source
    //won't show at the final result but I have used it for debugging as well as to 
    //make comparason of my result with the wireshark result
    //http://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf( "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf( "%c",(unsigned char)data[j]); //if its a number or alphabet

                else printf( "."); //otherwise print a dot
            }
            printf("\n");
        }

        if(i%16==0) printf("   ");
        printf(" %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
                printf( "   "); //extra spaces
            }

            printf("         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                    printf( "%c",(unsigned char)data[j]);
                }
                else
                {
                    printf( ".");
                }
            }
            printf( "\n" );
        }
    }
}

