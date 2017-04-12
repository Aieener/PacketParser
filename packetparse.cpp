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

void analyconnection(std::array<unsigned long, 11> &connect,const std::vector<std::array<unsigned long,14> > init_packetinfo_list,
        const std::vector<std::array<unsigned long,14> > resp_packetinfo_list,int idropnum,int rdropnum,int iclosed,int rclosed);
 

void printconnectinfo(const std::vector<std::array<unsigned long,14> > packetinfolist);

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

    if( (pf = pcap_open_offline( argv[argc-1], errbuf )) == NULL ){
        fprintf( stderr, "Can't process pcap file %s: %s\n", argv[1], errbuf );
        exit(1);
    }
    //std::cout<<argv[argc-1]<<"\n";
    //std::cout<<argv[argc-2]<<"\n";

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
    
    if(argc ==3 && !strcmp(argv[argc-2],"-t")){
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
        
        // where the sequence number and ack_seq stored here will be the relative version
        // stucture for each packet:[sip,dip,s_port,s_port,sequence, ack_seq,ack,syn,fin,tcpsize,packet_number];
/*        std::vector<std::array<unsigned long, 14> >remodul_init_packet_list;*/
        //std::vector<std::array<unsigned long, 14> >remodul_resp_packet_list;


        std::vector<std::vector<std::array<unsigned long,14> > > init_full_list; // a list to store the connection info
        std::vector<std::vector<std::array<unsigned long,14> > > resp_full_list; // a list to store the connection info

        std::vector<std::vector<std::array<unsigned long,14> > > remodul_init_full_list; // a list to store the connection info
        std::vector<std::vector<std::array<unsigned long,14> > > remodul_resp_full_list; // a list to store the connection info

        unsigned long packet_counter = 1;

        unsigned long seq_relative = 0; 
        unsigned long ack_relative = 0; 
        unsigned long iseq_ref = 0;
        unsigned long rseq_ref = 0;
        std::vector<unsigned long> iseq_reflist;
        std::vector<unsigned long> rseq_reflist;
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

                // ---------------------------------------------------------------------------------
                // Notice that my implementation can't handle a connection that has already made before capture the packets
                // which means that my detection of initiator and responder heavily relies on the 3 way shaking
                // ---------------------------------------------------------------------------------
                
                if(new_connection &&syn ==1){
                    //------------- initiator initiator ---------------------
                    iseq_ref = sequence;
                    iseq_reflist.push_back(iseq_ref); //record the reference sequence # as to cal relatice reference # later
                    seq_relative = 0; // the initial sequence is 0 for initiator
                    ack_relative = 0; // the initial ack_seq is 0 for initiator

                    std::array<unsigned long, 14> init_packet = {{sip,dip,s_port,d_port,seq_relative,ack_relative,
                        ack,syn,fin,TCPsize,packet_counter,rst,Payload_size,Total_size}};
 
                    std::vector<std::array<unsigned long,14> > init_packetinfo_list; // a list to store the infomation per connection
                    init_packetinfo_list.push_back(init_packet); 

                    init_full_list.push_back(init_packetinfo_list); 
                    // ----------- connection initiation --------
                    // the structure of connection:[initiator_ip; responder_ip;initiator_port; responder_port;
                    // num_sent_by_i;  num_sent_by_r;   num_byte_sent_by_i;   num_byte_sent_by_r;  num_ofdul_i; num_ofdul_r;
                    // closed]
                    std::array<unsigned long, 11> connect = {{sip,dip,s_port,d_port,0,0,0,0,0,0,0}};
                    connec_list.push_back(connect);
                }
                // now handle the responders

                for(int i = 0; i<init_full_list.size();i++){
                    if(ack == 1 && syn == 1){
                        //make sure it is the first piece of message of the responder;
                        if(sip == init_full_list[i][0][1] && s_port == init_full_list[i][0][3] &&
                                dip == init_full_list[i][0][0] && d_port == init_full_list[i][0][2]){
                            // if the sip = dip of initator and s_port = d_port of initiator, 
                            // the dip = sip of initator and d_port = s_port of initiator, 
                            // this means it is the responder for ith connection's initator
                            
                            //------------- responder initiator ---------------------
                            rseq_ref = sequence;
                            rseq_reflist.push_back(rseq_ref); //record the reference sequence # as to cal relative reference # later
                            seq_relative = 0; // the initial sequence is 0 for responder
                            ack_relative = 1; // the initial ack_seq is 1 for responder

                            std::array<unsigned long, 14> resp_packet = {{sip,dip,s_port,d_port,seq_relative,ack_relative,
                                ack,syn,fin,TCPsize,packet_counter,rst,Payload_size,Total_size}};

                            std::vector<std::array<unsigned long,14> > resp_packetinfo_list; // a list to store the infomation per connection
                            resp_packetinfo_list.push_back(resp_packet); 

                            resp_full_list.push_back(resp_packetinfo_list);
                        }
                    }
                }
            }

            packet_counter++;
        }
        std::cout<<"# of responder  = "<< resp_full_list.size()<<std::endl;
        std::cout<<"# of initiator  = "<< init_full_list.size()<<std::endl;
        std::cout<<"# of connction  = "<< connec_list.size()<<std::endl;
        //for(int i = 0 ;i< resp_full_list.size();i++){

            //printconnectinfo(resp_full_list[i]);
            //printconnectinfo(resp_full_list[i][0];
        //}

/*        for(int i = 0 ;i< init_full_list.size();i++){*/
            //printconnectinfo(init_full_list[i]);
        //}

        // Now we know how many conections and the basic info about intiator and responder, 
        // next we redo the loop to analysis it
        // Again, I am sorry for the poor algorithm and poor design(I should have use struct rather than all vectors)

        //--------------------------------------------------------------
        // reload the pcap file
        if( (pf = pcap_open_offline( argv[argc-1], errbuf )) == NULL ){
            fprintf( stderr, "Can't process pcap file %s: %s\n", argv[argc-1], errbuf );
            exit(1);
        }

        packet_counter = 1; // reset packet counter;
        while((packet = pcap_next(pf, &header)) != NULL){
            //packetlist.push_back(packet);
            const struct iphdr *ip;
            ip = (struct iphdr*)(packet + sizeof(struct ethhdr));

            // since we only cares about tcp connections:
            if(ip->protocol == IPPROTO_TCP){
                // first, parse the current packet
                get_tcpconnectinfo(header,packet,&sip,&dip,&s_port,&d_port,&sequence,&ack_seq,&ack,&syn,&fin,&rst,
                        &TCPsize,&Payload_size,&Total_size);

                // figure out which connection it belongs to;
        
                //-------------------- load packet to list --------------------------
                unsigned long seq_relative = 0; 
                unsigned long ack_relative = 0; 

                for(int i=0;i<init_full_list.size();i++){
                    if(syn!=1 && sip == init_full_list[i][0][0]&&
                            dip == init_full_list[i][0][1]&&
                            s_port == init_full_list[i][0][2]&&
                            d_port == init_full_list[i][0][3]){

                        //if match, this packet is belongs to ith initiator
                        seq_relative = sequence - iseq_reflist[i];
                        ack_relative = ack_seq - rseq_reflist[i];
                        std::array<unsigned long, 14> init_packet = {{sip,dip,s_port,d_port,seq_relative,ack_relative,
                            ack,syn,fin,TCPsize,packet_counter,rst,Payload_size,Total_size}};

                        init_full_list[i].push_back(init_packet);
                    }
                }

                for(int i=0;i<resp_full_list.size();i++){
                    if(syn!=1 && sip == resp_full_list[i][0][0]&&
                            dip == resp_full_list[i][0][1]&&
                            s_port == resp_full_list[i][0][2]&&
                            d_port == resp_full_list[i][0][3]){

                        //if match, this packet is belongs to ith initiator
                        seq_relative = sequence - rseq_reflist[i];
                        ack_relative = ack_seq - iseq_reflist[i];
                        std::array<unsigned long, 14> resp_packet = {{sip,dip,s_port,d_port,seq_relative,ack_relative,
                            ack,syn,fin,TCPsize,packet_counter,rst,Payload_size,Total_size}};

                        resp_full_list[i].push_back(resp_packet);
                    }
                }
               
                //--------------------finish load packet to list --------------------------
            }
            packet_counter++;
        }

        // ------------------------------Sort the paket by sequence number--------------------------------------------
/*        //sorry it's bubble sort....*/
        //std::array<unsigned long, 14> temp;
        //for(int c = 0; c<init_packetinfo_list.size() -1;c++){
            //for(int d = 0; d< init_packetinfo_list.size()-c-1;d++){
                //if(init_packetinfo_list[d][4]>init_packetinfo_list[d+1][4]){

                    //temp = init_packetinfo_list[d];
                    //init_packetinfo_list[d] = init_packetinfo_list[d+1];
                    //init_packetinfo_list[d+1] = temp;
                //}
            //}
        //}

        //for(int c = 0; c<resp_packetinfo_list.size() -1;c++){
            //for(int d = 0; d< resp_packetinfo_list.size()-c-1;d++){
                //if(resp_packetinfo_list[d][4]>resp_packetinfo_list[d+1][4]){

                    //temp = resp_packetinfo_list[d];
                    //resp_packetinfo_list[d] = resp_packetinfo_list[d+1];
                    //resp_packetinfo_list[d+1] = temp;
                //}
            //}
        //}

        // ------------------------------ Finish sorting the packet --------------------------------------------------
        
        ////--------------print the full connection info to terminal------------------
        //// this part is just for me to take a closer look
        //// at the data
        ////--------------------------------------------------------------------------
        printf("=========================================\n");
        printf(" Original connection info from Initiator\n");
        printf("=========================================\n");
        for(int i = 0; i<init_full_list.size();i++){
            printf("=========================\n");
            printf(" %dth Initiator:\n",i+1);
            printf("=========================\n");
            printconnectinfo(init_full_list[i]);
        }
        printf("=========================================\n");
        printf(" Original connection info from Responser\n");
        printf("=========================================\n");
        for(int i = 0; i<resp_full_list.size();i++){
            printf("=========================\n");
            printf(" %dth Responser:\n",i+1);
            printf("=========================\n");
            printconnectinfo(resp_full_list[i]);
        }
        ////------finish  print info to terminal------------------
        
        //// -----------------------------------------------------------------------------------------------
        //// Remove the duplicate packet and drop the ones are not ACKed and detect if connection is closed 
        //// -----------------------------------------------------------------------------------------------
    
        std::vector <int> iclosed_list;
        std::vector <int> rclosed_list;
        std::vector <int> idropnum_list;
        std::vector <int> rdropnum_list;

        for(int g = 0; g< init_full_list.size();g++){
            std::vector<std::array<unsigned long, 14> >remodul_init_packet_list = init_full_list[g];
            std::vector<std::array<unsigned long, 14> >remodul_resp_packet_list = resp_full_list[g];
            // drop the dulpicated packet in initiator direction
            int idropnum= 0;
            int closed = 0;
            for(int i = 0; i<init_full_list[g].size();i++){
                unsigned long seqini  = init_full_list[g][i][4];
                unsigned long ackini  = init_full_list[g][i][5];
                unsigned long tcplenini  = init_full_list[g][i][9];

                unsigned long ack = init_full_list[g][i][6];
                unsigned long syn = init_full_list[g][i][7];
                unsigned long fin = init_full_list[g][i][8];
                unsigned long rst = init_full_list[g][i][11];
                bool ACKed = false;
                bool Retrans = false; //actually a "suspect" retransmission
                bool ACKed_duplicate = false;

                //if(ack ==1 &&syn== 0 &&fin ==0){ // make sure it is the packet in between connection
                if(ack ==1){ // make sure it is the packet in between connection
                    for(int j = 0; j<resp_full_list[g].size();j++){

                        // To get ACKed, (tcplenini + seqini = ackrep  && ackini = seqrep )has to hold at somewhere
                        unsigned long seqrep = resp_full_list[g][j][4];
                        unsigned long ackrep = resp_full_list[g][j][5];
                        unsigned long tcplenrep  = resp_full_list[g][j][9];

                        if(tcplenini+ seqini == ackrep && ackini ==seqrep){
                            ACKed = true;
                        }
                        //else if(tcplenrep + seqrep ==ackini && ackrep == seqini){
                        if(tcplenrep + seqrep ==ackini && ackrep == seqini){
                            ACKed = true;
                        }
                        // check if it is just a ACK message
                        //else if(init_full_list[g][j][12] ==6 &&init_full_list[g][j][9] == 0){
                        if(init_full_list[g][j][12] ==6 &&init_full_list[g][j][9] == 0){
                            ACKed = true;
                        }
                    }
                }
                
                // check closing
                if( fin == 1 &&ack ==1){
                    for(int j = 0; j<resp_full_list[g].size();j++){
                        unsigned long seqrep = resp_full_list[g][j][4];
                        unsigned long ackrep = resp_full_list[g][j][5];
                        unsigned long tcplenrep  = resp_full_list[g][j][9];

                        if(tcplenini+ seqini == ackrep && ackini ==seqrep){
                            closed++;
                            ACKed = true;
                        }
                    }
                }
                if(syn ==1){
                    ACKed = true;
                }
                if(rst ==1 &&ack == 1){
                    ACKed = true;
                }

                // Now check retransmission: 
                int counter = 0;
                for(int h = i+1; h<init_full_list[g].size();h++){
                    unsigned long seqh  = init_full_list[g][h][4];
                    unsigned long ackh  = init_full_list[g][h][5];
                    if (seqini >= seqh  && ackini >= ackh ){
                        Retrans = true;
                    }
                    if(seqini ==seqh && ackini ==ackh){
                        // this is to drop the first dulplicated packet even though it has been ACKed (ex. the NO.22 in stmp.pcap)
                        counter = h - i;
                    }
                }
                if(counter >=2){
                    ACKed_duplicate = true;
                    //std::cout<<" Retrans # is" << i<<std::endl;
                }

                if(((!ACKed) && Retrans) || ACKed_duplicate){
                    //drop that packet because it is not ACKed and is suspected as a retransmission, hence a duplicate to drop
                    remodul_init_packet_list.erase(remodul_init_packet_list.begin()+i-idropnum);
                    idropnum++;
                    //std::cout<<" Drop #"<<i<<std::endl;
                }
            }
            remodul_init_full_list.push_back(remodul_init_packet_list);
            idropnum_list.push_back(idropnum);
            iclosed_list.push_back(closed);
            std::cout<<g+1<<"th "<<"initiator has "<<idropnum<<" duplicated packet to drop"<<std::endl;
            std::cout<<g+1<<"th "<<"initiator closed?  "<<closed<<std::endl;
        }
        // drop the dulpicated packet in responser direction
        
        for(int g = 0; g< resp_full_list.size();g++){
            std::vector<std::array<unsigned long, 14> >remodul_init_packet_list = init_full_list[g];
            std::vector<std::array<unsigned long, 14> >remodul_resp_packet_list = resp_full_list[g];
            int rdropnum= 0;
            int closed = 0;
            for(int i = 0; i<resp_full_list[g].size();i++){
                unsigned long seqrsp  = resp_full_list[g][i][4];
                unsigned long ackrsp  = resp_full_list[g][i][5];
                unsigned long tcplenrsp  = resp_full_list[g][i][9];

                unsigned long ack = resp_full_list[g][i][6];
                unsigned long syn = resp_full_list[g][i][7];
                unsigned long fin = resp_full_list[g][i][8];
                unsigned long rst = init_full_list[g][i][11];
                bool ACKed = false;
                bool Retrans = false; //actually the "suspect" retransmission

                //if(ack ==1 &&syn== 0 &&fin ==0){ // make sure it is the packet in between connection
                if(ack ==1){ // make sure it is the packet in between connection
                    for(int j = 0; j<init_full_list[g].size();j++){

                        // To get ACKed, (tcplenrsp+ seqrsp == ackini && ackrsp ==seqini)has to hold at somewhere
                        unsigned long seqini = init_full_list[g][j][4];
                        unsigned long ackini = init_full_list[g][j][5];
                        unsigned long tcplenini  = init_full_list[g][j][9];

                        if(tcplenrsp+ seqrsp == ackini && ackrsp ==seqini){
                            ACKed = true;
                        }

                        //else if(tcplenini+ seqini == ackrsp && ackini ==seqrsp){
                        if(tcplenini+ seqini == ackrsp && ackini ==seqrsp){
                            ACKed = true;
                        }

                        // check if it is a ACK
                        //else if(resp_full_list[g][j][12] ==6 &&resp_full_list[g][j][9] == 0){
                        if(resp_full_list[g][j][12] ==6 &&resp_full_list[g][j][9] == 0){
                            ACKed = true;
                        }
                    }
                }

                // check Fin is send and if Fin is ACKed by the other side
                if( fin == 1 &&ack ==1){
                    for(int j = 0; j<init_full_list[g].size();j++){

                        // To get ACKed, (tcplenrsp+ seqrsp == ackini && ackrsp ==seqini)has to hold at somewhere
                        unsigned long seqini = init_full_list[g][j][4];
                        unsigned long ackini = init_full_list[g][j][5];
                        unsigned long tcplenini  = init_full_list[g][j][9];

                        if(tcplenrsp+ seqrsp == ackini -1 && ackrsp ==seqini - 1){
                            ACKed = true;
                            closed++;
                        }
                    }
                }

                if(syn ==1){
                    ACKed = true;
                }
                if(rst ==1 &&ack == 1){
                    ACKed = true;
                }

                // Now check retransmission: 
                int counter = 0;
                for(int h = i+1; h<init_full_list[g].size();h++){
                    unsigned long seqh  = resp_full_list[g][h][4];
                    unsigned long ackh  = resp_full_list[g][h][5];
                    if (seqrsp >= seqh  && ackrsp >= ackh ){
                        counter ++;
                    }
                }
                if(counter >=1){
                    Retrans = true;
                    //std::cout<<" Retrans # is" << i<<std::endl;
                }

                if((!ACKed) && Retrans){
                    remodul_resp_packet_list.erase(remodul_resp_packet_list.begin()+i-rdropnum);
                    rdropnum++;
                }
            }
            remodul_resp_full_list.push_back(remodul_resp_packet_list);
            rdropnum_list.push_back(rdropnum);
            rclosed_list.push_back(closed);
            std::cout<<g+1<<"th "<<"responder has "<<rdropnum<<" duplicated packet to drop"<<std::endl;
            std::cout<<g+1<<"th "<<"responder closed?  "<<closed<<std::endl;
        }

        //// ---------- Finishing Remove the duplicate packet and drop the ones are not ACKed ---------------------------


        //------------ anaylize and write the meta_data -------------------------
        for(int i = 0; i<connec_list.size();i++ ){
            int rclosed = rclosed_list[i];
            int iclosed = iclosed_list[i];
            int idropnum = idropnum_list[i];
            int rdropnum = rdropnum_list[i];
            //std::cout << rclosed << iclosed<<std::endl;
            analyconnection(connec_list[i],init_full_list[i], resp_full_list[i],idropnum,rdropnum,rclosed,iclosed);
            write_meta(connec_list[i],i+1);
        }
    
        //std::cout<<"total connection = "<<connec_list.size();

        //=====================================================================
        //--------------------write initiator----------------------------------
        //=====================================================================
        for(int inidx=0; inidx < remodul_init_full_list.size();inidx++){
            std::vector<std::array<unsigned long, 14> >remodul_init_packet_list = remodul_init_full_list[inidx];
            std::vector<std::array<unsigned long, 14> >init_packet_list = init_full_list[inidx];
            char extention[11]= ".initiator";
            char *filename = (char *) malloc(1+strlen(extention)+sizeof(unsigned int));
            sprintf(filename,"%d%s",inidx+1,extention);
            u_char *payload;                    

            FILE *f1 = fopen(filename, "wb");
            assert(f1 !=NULL);

            //unsigned long idx = 1;
            if( (pf = pcap_open_offline( argv[argc-1], errbuf )) == NULL ){
                fprintf( stderr, "Can't process pcap file %s: %s\n", argv[argc-1], errbuf );
                exit(1);
            }

            int k = 1;
            while((packet = pcap_next(pf, &header)) != NULL){
                for(int i = 0; i<remodul_init_packet_list.size();i++){
                    if(k == remodul_init_packet_list[i][10]){
                    //if(k == init_packet_list[i][10]){
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
                        break;
                    }
                }
                k++;
            }
            fclose(f1);
        }

        ////=====================================================================
        ////--------------------write responder----------------------------------
        ////=====================================================================
        for(int inidx=0; inidx < remodul_resp_full_list.size();inidx++){
            std::vector<std::array<unsigned long, 14> >remodul_resp_packet_list = remodul_resp_full_list[inidx];
            char extention[11]= ".responder";
            char *filename = (char *) malloc(1+strlen(extention)+sizeof(unsigned int));
            sprintf(filename,"%d%s",inidx+1,extention);
            u_char *payload;                    

            FILE *f1 = fopen(filename, "wb");
            assert(f1 !=NULL);

            //unsigned long idx = 1;
            if( (pf = pcap_open_offline( argv[argc-1], errbuf )) == NULL ){
                fprintf( stderr, "Can't process pcap file %s: %s\n", argv[argc-1], errbuf );
                exit(1);
            }

            int k = 1;
            while((packet = pcap_next(pf, &header)) != NULL){
                for(int i = 0; i<remodul_resp_packet_list.size();i++){
                    if(k == remodul_resp_packet_list[i][10]){
                        ////printit = true;
                        fprintf(f1,"----------------------------------\n");
                        fprintf(f1,"packet number: %d\n",k);
                        fprintf(f1,"----------------------------------\n");

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
                        break;
                    }
                }
                k++;
            }
            fclose(f1);
        }

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
        const std::vector<std::array<unsigned long,14> > resp_packetinfo_list,int idropnum,int rdropnum,int iclosed,int rclosed){
        
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
    connect[8] = idropnum;

    //number of duplicate packet sent by responder;
    connect[9] = rdropnum;

    //whether the connection is closed
    if(iclosed ==1 && rclosed ==1){
        //is closed
        connect[10] = 1;
    }
    else{
        //not closed
        connect[10] = 0;
    }
    
}



void write_meta(const std::array<unsigned long, 11> connect,int idx){
    char extention[6]= ".meta";
    char *filename = (char *) malloc(1+strlen(extention)+sizeof(unsigned int));
    //sprintf(filename,"meta/%d%s",idx,extention);
    sprintf(filename,"%d%s",idx,extention);

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
    unsigned long idrop = connect[8];
    unsigned long rdrop = connect[9];
    unsigned long closed = connect[10];
    bool bclosed = false;
    if(closed == 1){
        bclosed = true;
    }

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
    fprintf(f,"Number of duplicate packets sent by initiator       :%lu\n", idrop);
    fprintf(f,"Number of duplicate packets sent by responder       :%lu\n", rdrop);
    fprintf(f,"Connection is closed      :%s\n", bclosed ? "true" : "false");
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
    for(i=0 ; i < Size ; i++){
        if( i!=0 && i%16==0){
            fprintf(f, "         ");
            for(j=i-16 ; j<i ; j++){
                if(data[j]>=32 && data[j]<=128)
                    fprintf(f, "%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(f, "."); //otherwise print a dot
            }
            fprintf(f,"\n");
        }

        if(i%16==0) fprintf(f,"   ");
        fprintf(f," %02X",(unsigned int)data[i]);

        if( i==Size-1){
            for(j=0;j<15-i%16;j++){
                fprintf(f, "   "); //extra spaces
            }

            fprintf(f,"         ");

            for(j=i-i%16 ; j<=i ; j++){
                if(data[j]>=32 && data[j]<=128){
                    fprintf(f, "%c",(unsigned char)data[j]);
                }
                else{
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
    //PrintData (payload, payload_size); 
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

