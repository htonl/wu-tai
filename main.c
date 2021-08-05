#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

// Globals
#define RECVBUFSIZE 65535
#define wt_log printf
FILE *logfile;

/**
 * Method for getting hostname of given addr
 * @param addr ipv4 address to lookup
 * @return pointer to allocated buffer containing hostname
 *
 */
char *get_hostname(const struct sockaddr_in *addr)
{
    char *hostname;
    int res;
    
    hostname = (char*)malloc(NI_MAXHOST);
    memset(hostname, 0, NI_MAXHOST);
    if (hostname == NULL)
    {
        wt_log("Unable to allocate buffer for hostname\n");
        goto err;
    }
    res = getnameinfo((struct sockaddr *)addr, sizeof(struct sockaddr),
                      hostname, NI_MAXHOST,
                      NULL, 0, 0);
    if (res)
    {
        printf("error: %s\n", gai_strerror(res));
        goto err;
    }
    return hostname;
err:
    if (hostname) {
        free(hostname);
        hostname = NULL;
    }
    return NULL;
}

void inspect_packet(unsigned char *buf, unsigned long bufsize)
{
    struct iphdr *iph;
    struct sockaddr_in source, dest;
    char *dest_hostname;
    
    // Grab the ip header 
    iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
    // Grab the src/dest addrs
    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;
    // TODO v4 or v6?
    /* TODO: Some thoughts on design:
     *
     * 1 - We get a list of IP's for the hostname, and then use that for
     * matching. This would be faster, but poses the risk of missing a new
     * IP that is added dynamically. We can update the list occasionally to
     * update it. This seems much more reasonable than 2. 
     *
     * 2 - We do a lookup everytime (after checking a cache of known
     * IP->Hostnames, this seems to have unreasonable overhead.
     */
    dest.sin_family = AF_INET;
    dest_hostname = get_hostname(&dest);
    if (dest_hostname != NULL && strcmp(dest_hostname, "localhost"))
    {
        printf("dest_hostname: %s\n", dest_hostname);
        free(dest_hostname);
    }
}

    
int main(void)
{
    unsigned long saddrlen, bufsize;
    struct sockaddr saddr;
    unsigned char *buf;
    struct sockaddr_in source, dest;
    int raw_sock;

    buf = (unsigned char*) malloc(RECVBUFSIZE);
    if (!buf) {
        printf("Failed to alloc receive buffer\n");
        buf = NULL;
        goto error;
    }
    // initialize log file
    logfile = fopen("log.txt", "w");
    if (!logfile)
    {
        printf("Unable to create logfile");
        goto error;
    }
    // open our raw socket to collect the packets
    // TODO I wonder if ETH_P_ALL is overkill?
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0)
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
        bufsize = recvfrom(raw_sock, buf, 65536, 0, &saddr, (socklen_t*)&saddrlen);
        if(bufsize < 0)
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
	
