/*CIS 553 Networked systems
 *Project2
 *Yuding Ai
 *Penn id 31295008
 *2017.3.26 - 2017.4.3: part1
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


//-----------------------
// part 1: Due 4/3/17
void parsing_packets();

// part 2: Due 4/12/17
void tcp_flows();

// part 3: Due 4/24/17
void email_traffic();
//-----------------------

//----structures --------

/** //MAC info */
/** struct mac_t { */
/**         u_char  ether_dhost[6];    // destination MAC address */
/**         u_char  ether_shost[6];    // souce MAC address */
/** }; */
/**  */
/** // IP info  */
/** struct ip_t { */
/**     u_short ip_len;                 // total length */
/**     u_short ip_id;                  // identification */
/**     struct  in_addr ip_src,ip_dst;  // source and dest address */
/** }; */
/**  */

int main(int argc, char *argv[] )
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pf;
  struct bpf_program fp;
  char select_mail[] = "port 25";
  /** char select_mail[] = "port 80"; */
  struct pcap_pkthdr h;
  const u_char *p;
  int num_packets = 10;
  /** void exit(); */

  if( argc != 2 ){
    fprintf( stderr, "Usage: %s {pcap-file}\n", argv[0] );
    exit(1);
  }

  if( (pf = pcap_open_offline( argv[1], errbuf )) == NULL ){
    fprintf( stderr, "Can't process pcap file %s: %s\n", argv[1], errbuf );
    exit(1);
  }
  
  if( pcap_compile(pf, &fp, select_mail, 0, 0 ) == -1 ) {
    fprintf( stderr, "BPF compile errors on %s: %s\n",
	     select_mail, pcap_geterr(pf) );
    exit(1);
  }

  if( pcap_setfilter( pf, &fp ) == -1 ){
    fprintf( stderr, "Can't install filter '%s': %s\n", select_mail,
	     pcap_geterr(pf) );
    exit(1);
  }

  while( (p = pcap_next(pf, &h )) != NULL ){
      /** printf("%ld.%06ld: %d bytes on Port 25\n", */
      printf("%ld.%06ld: %d bytes on Port 80\n",
       h.ts.tv_sec, h.ts.tv_usec, h.len );
  }

  if(argc ==2){
      //if no arguments, simply display the basic header informations:
      //- Packet type (TCP, UDP, other)
      //- Source and destination MAC address
      //- Source and destination IP address (if IP packet)
      //- Source and destination ports (if TCP or UDP)
      //- Checksum (if TCP) and whether the checksum is valid
      //- Payload size
      pcap_loop(pf,num_packets, parsing_packets, NULL);
  }
	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(pf);



  return 0;
}

void parsing_packets(){
    // keep track of the packet number
    static int count = 1;
    printf("adas");

    // Print Packet type

}

