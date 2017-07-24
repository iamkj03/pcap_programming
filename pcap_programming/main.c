#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>


int main(int argc, char *argv[])
{
    char *dev;                      /*Device to sniff on*/
    pcap_t *handle;                 /*session handle*/
    char errbuf[PCAP_ERRBUF_SIZE];  /*error string*/
    struct bpf_program fp;          /*The compiled filter expression*/
    char filter_exp[] = "port 80";  /*The filter expression*/
    bpf_u_int32 maskp;              /*The netmask of our sniffing device*/
    bpf_u_int32 netp;               /*The IP of our sniffing device*/
    struct pcap_pkthdr *header;      /*The header that pcap gives us*/
    const u_char *pkt_data;           /*The acutal packet*/
    struct ether_header *ep;
    struct ip *iph;
    struct tcphdr *tcph;
    int i = 0;                                     //for for state
    uint16_t ether_type;
    char sbuf[20], dbuf[20];
    int ip_len, tcp_len, j;


    /*Define the device*/
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("DEV: %s\n", dev);

    //Find the properties for the device
    if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s\n", dev);

        return(2);
    }


    /*Open the session in promiscuous mode*/
    handle = pcap_open_live(dev, BUFSIZ, 1, 10000, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    /*Compile and apply the filter*/

    if(pcap_compile(handle, &fp, filter_exp, 0, netp) == -1) {
        fprintf(stderr, "Couldn't parse filter $s: $n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    while((pcap_next_ex(handle, &header, &pkt_data)) == 1){

    // Bring ethernet header
    ep = (struct ether_header *)pkt_data;

    //offset the size of ethernet header
    pkt_data += sizeof(struct ether_header);

    //for the protocol type
    ether_type = ntohs(ep->ether_type);

    //If it is IP packet0
    if(ether_type == ETHERTYPE_IP)
    {
        printf("-------------Information-------------\n");
        printf("Ethernet Src Address = ");
        for (i = 0; i<6; ++i)
            printf("%.2X ", ep->ether_shost[i]);
        printf("\n");                                           //Source Mac Address

        printf("Ethernet Dst Address = ");
        for (i = 0; i<6;++i)
            printf("%.2X ", ep->ether_dhost[i]);
        printf("\n");                                           //Destination Mac Address

        //Data from ip header
        iph = (struct ip *)pkt_data;
        ip_len = ((iph->ip_hl))*4;
        printf("ip_len: %d\n", ip_len);
        printf("IP Src Address : %s\n", inet_ntop(AF_INET, &iph->ip_src, &sbuf, 16));//Source IP address
        printf("IP Dst Address : %s\n", inet_ntop(AF_INET, &iph->ip_dst, &dbuf, 16));//Destination IP address

        //If it is TCP protocol
        if(iph->ip_p == IPPROTO_TCP) //IPPROTO_TCP == 6
        {
            //Data from tcp header after the ip header
            tcph=(struct tcphdr *)(pkt_data + (iph->ip_hl)*4);
            tcp_len = ((tcph->th_off))*4;
            printf("tcp_len: %d\n", tcp_len);
            printf("Src Port: %d\n", ntohs(tcph->th_sport));    //Source port
            printf("Dst Port: %d\n", ntohs(tcph->th_dport));    //Destination port


        }

        //Printing the data start location, size
           for(j=0;j<(header->len)-sizeof(struct ether_header)-ip_len - tcp_len;j++)
           {
               printf("%02x ", *pkt_data);
               pkt_data++;

               if(j%16==0)
                   printf("\n");
           }


    }

    //When there is no IP
    else{
        printf("NONE IP\n");

    }
    printf("\n");
    }
    return(0);
}
