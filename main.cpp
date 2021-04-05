#include <malloc.h>
#include <iostream>
#include <string>
#include <cstring>
#include <errno.h>
#include "include/uv.h"


using namespace std;


static void uv_alloc_buf(uv_handle_t *handle,
                         size_t suggested_size,
                         uv_buf_t *buf);

static void on_uv_udp_send_end(uv_udp_send_t *req,
                               int status);

static void after_uv_udp_recv(uv_udp_t *handle,
                              ssize_t nread,
                              const uv_buf_t *buf,
                              const struct sockaddr *addr,
                              unsigned flags);

char *buildDNSQueryMsg(char *buf, char *host_name);

static uv_loop_t *event_loop = NULL;
static uv_udp_t send_handle;

#define BUF_SIZE 1024
#define SRV_PORT 53
#define SRV_IP   "8.8.8.8"

typedef unsigned short u16;

typedef struct DNS_HEADER {
    u16 id;
    u16 flags;
    u16 nques;
    u16 nanswer;
    u16 nauth;
    u16 naddi;
} dns_header;

typedef struct {
    u16 q_type;
    u16 q_class;
} dns_query;


int main(int argc, char **argv) {
    char *host_name = "oi.nju.edu.cn";
    char buf[BUF_SIZE];
    memset((void *) buf, 0, BUF_SIZE);
    char *result = buildDNSQueryMsg(buf, host_name);

    //    DNS SERVER SOCKET
    struct sockaddr_in DNS_SERVER_ADDR, DNS_CLIENT_ADDR;
    uv_ip4_addr("8.8.8.8", 53, &DNS_SERVER_ADDR);
    uv_ip4_addr("0.0.0.0", 30000, &DNS_CLIENT_ADDR);

    event_loop = uv_default_loop();
    memset(&send_handle, 0, sizeof(uv_udp_t));
    uv_udp_init(event_loop, &send_handle);
    uv_udp_bind(&send_handle, (const struct sockaddr *) &DNS_CLIENT_ADDR, 0);
    uv_buf_t w_buf = uv_buf_init(result, sizeof(dns_header) + sizeof(dns_query) + strlen(host_name) + 2);
    auto *req = static_cast<uv_udp_send_t *>(malloc(sizeof(uv_udp_send_t)));


    uv_udp_send(req, &send_handle, &w_buf, 1, (const struct sockaddr *) &DNS_SERVER_ADDR, on_uv_udp_send_end);
    cout << "call udp send." << endl;
    send_handle.data = host_name;
    uv_udp_recv_start(&send_handle, uv_alloc_buf, after_uv_udp_recv);
    cout << "call udp recv." << endl;
    uv_run(event_loop, UV_RUN_DEFAULT);
    return 0;
}

char *buildDNSQueryMsg(char *buf, char *host_name) {
    dns_header *dnshdr = (dns_header *) buf;
    char *p;
    dns_query *dnsqer;
//    build DNS Header
    dnshdr->id = (u16) 1;
    dnshdr->flags = htons(0x0100);
    dnshdr->nques = htons(1);
    dnshdr->nanswer = htons(0);
    dnshdr->nauth = htons(0);
    dnshdr->naddi = htons(0);

//    build Question
    strcpy(buf + sizeof(dns_header) + 1, host_name);
    p = buf + sizeof(dns_header) + 1;
    char i = 0;
    while (p < (buf + sizeof(dns_header) + 1 + strlen(host_name))) {
        if (*p == '.') {

            *(p - i - 1) = i;
            i = 0;
        } else {
            i++;
        }
        p++;
    }
    *(p - i - 1) = i;
    dnsqer = (dns_query *) (buf + sizeof(dns_header) + 2 + strlen(host_name));
    dnsqer->q_class = htons(1);
    dnsqer->q_type = htons(1);
    return buf;
}

static void uv_alloc_buf(uv_handle_t *handle,
                         size_t suggested_size,
                         uv_buf_t *buf) {
    buf->base = static_cast<char *>(calloc(1, suggested_size + 1));
    buf->len = suggested_size;
}

static void on_uv_udp_send_end(uv_udp_send_t *req, int status) {
    cout << "callback udp send success." << endl;
    if (status == 0) {
//        printf("send success\n");
    }
    free(req);
}

static void
after_uv_udp_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    cout << "callback udp recv data." << endl;
    char ip_addr[128];
    uv_ip4_name((struct sockaddr_in *) addr, ip_addr, 128);
    int port = ntohs(((struct sockaddr_in *) addr)->sin_port);
    printf("From %s:%d and recv data num = %ld, ", ip_addr, port, nread);

    dns_header *header = reinterpret_cast<dns_header *>(buf->base);
    if (header->nanswer < 1) {
        cout << "DNS Response Error. No Answer." << endl;
    }
//    DNS Response parse
    char *p = buf->base + nread - 4;
    printf("%s ==> %u.%u.%u.%u\n", (char *) handle->data, (unsigned char) *p, (unsigned char) *(p + 1),
           (unsigned char) *(p + 2),
           (unsigned char) *(p + 3));

    uv_udp_recv_stop(handle);
}
