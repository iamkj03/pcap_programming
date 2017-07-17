#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    static int count = 1;
    struct ether_header *ep;
    struct ip *iph;
    struct tcphdr *tcph;
    u_short ether_type;
    int chcnt = 0;
    int length = pkthdr->len;
    int i = 0;

    ep = (struct ether_header *)packet;

    packet += sizeof(struct ether_header);

    ether_type = ntohs(ep->ether_type);



    if(ether_type == ETHERTYPE_IP)
    {
        printf("ETHER Source Address = ");
        for (i = 0; i<ETH_ALEN; ++i)
            printf("%.2X ", ep->ether_shost[i]);
        printf("\n");
        printf("ETHER Destination Address = ");
        for (i = 0; i<ETH_ALEN;++i)
            printf("%.2X ", ep->ether_dhost[i]);
        printf("\n");

        iph = (struct ip *)packet;
        printf("IP\n");
        printf("Version :%d\n", iph->ip_v);
        printf("Header Len:%d\n", iph->ip_hl);
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

        if(iph->ip_p == IPPROTO_TCP)
        {
            tcph = (struct tcp *) (packet + iph->ip_hl*4);
            printf("Src Port: %d\n", ntohs(tcph->th_sport));
            printf("Dst Port: %d\n", ntohs(tcph->th_dport));
        }
        while(length--)
        {
            printf("%02x", *(packet++));
            if ((++chcnt % 16) == 0)
                printf("\n");
        }
    }
    else{
            printf("NONE IP\n");

    }
    printf("\n");


}

//#define SOCK_PATH "/dev/socket/echo_socket"

int main(int argc, char *argv[])
{
    char *dev, *net, *mask;                      /*Device to sniff on*/
    pcap_t *handle;                 /*session handle*/
    char errbuf[PCAP_ERRBUF_SIZE];  /*error string*/
    struct bpf_program fp;          /*The compiled filter expression*/
    char filter_exp[] = "port 80"; /*The filter expression*/
    bpf_u_int32 maskp;               /*The netmask of our sniffing device*/
    bpf_u_int32 netp;                /*The IP of our sniffing device*/
    struct pcap_pkthdr header;      /*The header that pcap gives us*/
    const u_char *packet;           /*The acutal packet*/

    struct in_addr addr;


    /*Define the device*/
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("DEV: %s\n", dev);

    /*Find the properties for the device*/
    if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s\n", dev);

        return(2);
    }


    printf("NET: %s\n", net);
    /*Open the session in promiscuous mode*/
    handle = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
        }

    /*Compile and apply the filter*/

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter $s: $n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    pcap_loop(handle, filter_exp, callback, NULL);


    return(0);
}
