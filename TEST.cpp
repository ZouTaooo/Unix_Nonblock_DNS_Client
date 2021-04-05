#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <arpa/inet.h>

#define BUF_SIZE 1024
#define SRV_PORT 53
#define SRV_IP	"8.8.8.8"

typedef unsigned short u16;

typedef struct
{
    u16 id;
    u16 flags;
    u16 nques;
    u16 nanswer;
    u16 nauth;
    u16 naddi;
}dns_header;

typedef struct
{
    u16 type;
    u16 pclass;
}dns_query;

int isOline(char *argv)
{
    int	connfd, len = 0;
    struct  sockaddr_in servaddr;
    char    buf[BUF_SIZE];
    char    *p;
    int 	i=0;
    struct timeval tv;

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    dns_header  *dnshdr = (dns_header *)buf;
    dns_query   *dnsqer;

    if ((connfd  =  socket(AF_INET, SOCK_DGRAM, 0 ))  <   0 ){
        perror( "socket error!\n " );
        return -1;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SRV_PORT);
    if(inet_pton(AF_INET,SRV_IP,&servaddr.sin_addr) < 0){
        perror("inet_pton error.\n");
        return -1;
    }

    memset(buf, 0, BUF_SIZE);
    dnshdr->id = (u16)1;
    dnshdr->flags = htons(0x0100);
    dnshdr->nques = htons(1);
    dnshdr->nanswer = htons(0);
    dnshdr->nauth = htons(0);
    dnshdr->naddi = htons(0);
    strcpy(buf + sizeof(dns_header) + 1, argv);
    p = buf + sizeof(dns_header) + 1;
    while (p < (buf + sizeof(dns_header) + 1 + strlen(argv))){
        if ( *p == '.'){
            *(p - i - 1) = i;
            i = 0;
        } else{
            i++;
        }

        p++;
    }

    *(p - i - 1) = i;
    dnsqer = (dns_query *)(buf + sizeof(dns_header) + 2 + strlen(argv));
    dnsqer->pclass = htons(1);
    dnsqer->type = htons(1);
    setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if(sendto(connfd, buf, sizeof(dns_header) + sizeof(dns_query) + strlen(argv) + 2, 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
        perror("sendto error.\n");
        return -1;
    }

    i = sizeof(struct sockaddr_in);
    if((len = recvfrom(connfd, buf, BUF_SIZE, 0, (struct sockaddr *)&servaddr, reinterpret_cast<socklen_t *>(&i))) < 0){
        if(errno == EWOULDBLOCK){
            printf("timeout\n");
            return -1;
        }else{
            perror("recvfrom error\n");
            return -1;
        }
    }

    if (dnshdr->nanswer == 0){
        printf("ack error\n");
        return -1;
    }

    p = buf + len -4;
    printf("%s ==> %u.%u.%u.%u\n", argv, (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
    close(connfd);
    return 0;
}

int main()
{
    if(isOline("oi.nju.edu.cn") ==0)
        printf("ok");
    else
        printf("error");
    return 0;
}