#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>
#include<net/ethernet.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

// Globals
#define RECVBUFSIZE 65535
FILE *log;

#define wt_log(

void inspect_packet(unsigned char *buf, unsigned long bufsize)
{
    struct iphdr *iph;
    struct in_addr source, dest; 
    
    // Grab the ip header 
    iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
    source.s_addr = iph->saddr;
    dest.s_addr = iph->daddr;

    

int main(void)
{
    unsigned long saddr_size, bufsize;
    struct sockaddr saddr;
    unsigned char buf;
    struct sockaddr_in source, dest;
    int raw_sock;

    buf = malloc(RECVBUFSIZE);
    if (!buf) {
        printf("Failed to alloc receive buffer\n");
        buf = NULL;
        goto error;
    }
    // initialize log file
    log = fopen("log.txt", "w");
    if (!log)
    {
        printf("Unable to create logfile");
        goto error;
    }
    // open our raw socket to collect the packets
    // TODO I wonder if ETH_P_ALL is overkill?
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0)
    {	
        perror("Failed to open Socket");
        goto error;
    }
    // main loop
    // TODO Should we make this a good little daemon for *nix?
    while(1)
    {
        saddrlen = sizeof(struct sockaddr);
        //Receive a packet
        bufsize = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddrlen);
        if(data_size < 0)
        {
            printf("Failed to receive packets\n");
            goto error;
        }
        inspect_packet(buf, bufsize);
    }
// error label 
error:
    if (buf) {
        free(buf);
        return 1;
    }

    return 0;
}
	
