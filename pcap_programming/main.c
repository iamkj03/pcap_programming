#include <stdio.h>
#include <pcap.h>
//#define SOCK_PATH "/dev/socket/echo_socket"

int main(int argc, char *argv[])
{
    char *dev;                      /*Device to sniff on*/
    pcap_t *handle;                 /*session handle*/
    char errbuf[PCAP_ERRBUF_SIZE];  /*error string*/
    struct bpf_program fp;          /*The compiled filter expression*/
    char filter_exp[] = "port 80"; /*The filter expression*/
    bpf_u_int32 mask;               /*The netmask of our sniffing device*/
    bpf_u_int32 net;                /*The IP of our sniffing device*/
    struct pcap_pkthdr *header;      /*The header that pcap gives us*/
    const u_char *packet;           /*The acutal packet*/

    while(1){
    /*Define the device*/
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    /*Find the properties for the device*/
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
        return(2);
    }

    /*Open the session in promiscuous mode*/
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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

    /*Grab a packet */
    packet = pcap_next_ex(handle,&header, &packet);
    /*Print its length */
    printf("Jacked a packet with length of [%d]\n", header->len);
    /*And close the session*/
    pcap_close(handle);
    }
    return(0);
}
