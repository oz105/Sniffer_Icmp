# include <stdio.h>
# include <netinet/ip_icmp.h>
# include <netinet/ip.h>
# include <string.h>
# include <stdlib.h>
# include <netinet/if_ether.h>
# include <sys/socket.h>
# include <arpa/inet.h>



int main()
{
    int raw_sock;
    int num_of_msg = 1;
    int size_of_senderaddr, size_of_data;
    struct sockaddr_in src, dst;
    struct sockaddr senderaddr;
    unsigned char *buf = (unsigned char *)malloc(1024);
    

    printf("Listening...\n\n");

    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // listening to all packets
    if(raw_sock == -1) // check if the sock create
    {
        printf("Error in creating socket !\n");
        return -1;
    }
    while(1) // infinity loop listen all the time to the packts
    {
        size_of_senderaddr = sizeof(senderaddr);
        size_of_data = recvfrom(raw_sock, buf,1024,0,&senderaddr, &size_of_senderaddr);
        if(size_of_data == -1)
        {
            printf("Error in the receive\n");
            return -1;
        }
        struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ethhdr));
        if( ip_header->protocol == 1)
        {
              memset(&src, 0, sizeof(src));
	        src.sin_addr.s_addr = ip_header->saddr;
	
	        memset(&dst, 0, sizeof(dst));
	        dst.sin_addr.s_addr = ip_header->daddr;
            struct icmphdr *icmp_header = (struct icmphdr *)((char *)ip_header + (4 * ip_header->ihl));

            printf("icmp message num: %d\n",num_of_msg++);
            printf("The type is:  %d   The Code is:  %d\n",icmp_header->type,icmp_header->code);
            printf("The Src IP is:   %s\n",inet_ntoa(src.sin_addr));
            printf("The Dest IP is:  %s\n\n",inet_ntoa(dst.sin_addr));

            
        }
    }
    
    
    
    return 0;
}