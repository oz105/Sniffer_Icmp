// icmp.cpp
// Robert Iakobashvili for Ariel uni, license BSD/MIT/Apache
//
// Sending ICMP Echo Requests using Raw-sockets.
//

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h> // gettimeofday()


// ICMP header len for echo req
#define ICMP_HEADER_LENGTH 8

 // IPv4 header len without options
#define IP4_HEADER_LENGTH 20

// Checksum algo
unsigned short calculate_checksum(unsigned short * paddress, int len);

// 1. Change SOURCE_IP and DESTINATION_IP to the relevant
//     for your computer
// 2. Compile it using MSVC compiler or g++
// 3. Run it from the account with administrative permissions,
//    since opening of a raw-socket requires elevated preveledges.
//
//    On Windows, right click the exe and select "Run as administrator"
//    On Linux, run it as a root or with sudo.
//
// 4. For debugging and development, run MS Visual Studio (MSVS) as admin by
//    right-clicking at the icon of MSVS and selecting from the right-click
//    menu "Run as administrator"
//
//  Note. You can place another IP-source address that does not belong to your
//  computer (IP-spoofing), i.e. just another IP from your subnet, and the ICMP
//  still be sent, but do not expect to see ICMP_ECHO_REPLY in most such cases
//  since anti-spoofing is wide-spread.

#define SOURCE_IP "10.0.2.15"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "10.0.2.4"

int main ()
{
    struct ip iphdr; // IPv4 header
    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is the ping.\n";

    int datalen = strlen(data) + 1;

    //==================
    // IP header
    //==================

    // IP protocol version (4 bits)
    iphdr.ip_v = 4;

    // IP header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HEADER_LENGTH / 4; // not the most correct

    // Type of service (8 bits) - not using, zero it.
    iphdr.ip_tos = 0;

    // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
    iphdr.ip_len = htons (IP4_HEADER_LENGTH + ICMP_HEADER_LENGTH + datalen);

    // ID sequence number (16 bits): not in use since we do not allow fragmentation
    iphdr.ip_id = 0;

    // Fragmentation bits - we are sending short packets below MTU-size and without
    // fragmentation
    int ip_flags[4];

    // Reserved bit
    ip_flags[0] = 0;

    // "Do not fragment" bit
    ip_flags[1] = 0;

    // "More fragments" bit
    ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr.ip_off = htons ((ip_flags[0] << 15) + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13) +  ip_flags[3]);

    // TTL (8 bits): 128 - you can play with it: set to some reasonable number
    iphdr.ip_ttl = 128;

    // Upper protocol (8 bits): ICMP is protocol number 1
    iphdr.ip_p = IPPROTO_ICMP;

    // Source IP
    if (inet_pton (AF_INET, SOURCE_IP, &(iphdr.ip_src)) <= 0)
    {
        fprintf (stderr, "inet_pton() failed for source-ip with error: %d", errno);
        return -1;
    }

    // Destination IPv
    if (inet_pton (AF_INET, DESTINATION_IP, &(iphdr.ip_dst)) <= 0)
    {
        fprintf (stderr, "inet_pton() failed for destination-ip with error: %d", errno);
        return -1;
    }

    // IPv4 header checksum (16 bits): set to 0 prior to calculating in order not to include itself.
    iphdr.ip_sum = 0;
    iphdr.ip_sum = calculate_checksum((unsigned short *) &iphdr, IP4_HEADER_LENGTH);


    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet
    char packet[IP_MAXPACKET];

    // First, IP header.
    memcpy (packet, &iphdr, IP4_HEADER_LENGTH);

    // Next, ICMP header
    memcpy ((packet + IP4_HEADER_LENGTH), &icmphdr, ICMP_HEADER_LENGTH);

    // After ICMP header, add the ICMP data.
    memcpy (packet + IP4_HEADER_LENGTH + ICMP_HEADER_LENGTH, data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet + IP4_HEADER_LENGTH), ICMP_HEADER_LENGTH + datalen);
    memcpy ((packet + IP4_HEADER_LENGTH), &icmphdr, ICMP_HEADER_LENGTH);

    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;

    // The port is irrelant for Networking and therefore was zeroed.
    dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;

    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
    {
        fprintf (stderr, "socket() failed with error: %d", errno);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    // This socket option IP_HDRINCL says that we are building IPv4 header by ourselves, and
    // the networking in kernel is in charge only for Ethernet header.
    //
    const int flagOne = 1;
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL,
        &flagOne, // The above casting is important for Windows.
		sizeof (flagOne)) == -1)
    {
        fprintf (stderr, "setsockopt() failed with error: %d", errno);
        return -1;
    }

    struct timeval time1, time2;
    double allTime;
    gettimeofday(&time1, NULL);
    if (sendto (sock, packet, IP4_HEADER_LENGTH + ICMP_HEADER_LENGTH + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)
    {
        fprintf (stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
        int SIZE = 256;
        char buffer[256];
        int recv_b = recv(sock, buffer, SIZE, 0);
        if(recv_b == 0)
        {
            printf("Did not success to receive\n ");
            return 1;
        }
        else if (recv_b== -1)
        {
            printf("problem with the receive\n");
            return 1;
        }
        else
        {
            printf("message received\n");
        }
        bzero(buffer, SIZE);

        gettimeofday(&time2, NULL);
        allTime = (time2.tv_sec - time1.tv_sec) * 1000.0;      // change the sec to micro sec
        allTime += (time2.tv_usec - time1.tv_usec) / 1000.0;
        printf("RTT TIME in mili sec:  %lf\n",allTime);
        printf("RTT TIME in micro sec: %lf\n",allTime*1000.0);
        printf("Send successfully.\n");

  close(sock);
  return 0;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}

