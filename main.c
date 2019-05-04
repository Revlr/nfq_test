#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <regex.h>

#define  LIBNET_LIL_ENDIAN  1
#include <libnetfilter_queue/libnetfilter_queue.h>
#pragma pack(push, 1)
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>
#pragma pack(pop)

#define  TCP_PORT_HTTP  80

const char *pattern;

void usage(){
    printf("syntax: netfileter_block\n");
    printf("sample: netfileter_clock test.gilgil.net\n");
    printf("preset: iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE\n");
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

int check(u_char *data){
    regex_t    preg;
    int        rc;
    size_t     nmatch = 10;
    regmatch_t pmatch[10];

    if (0 != (rc = regcomp(&preg, pattern, 0))) {
       printf("regcomp() failed, returning nonzero (%d)\n", rc);
       exit(EXIT_FAILURE);
    }

    if (0 != (rc = regexec(&preg, (const char*)data, nmatch, pmatch, 0))) {
        printf("Failed to match http data with '%s',returning 0\n", pattern);
    }
    else {
        printf("Match to %s, returning 1\n", pattern);
        regfree(&preg);
        return 1;
    }
    regfree(&preg);
    return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    u_int32_t id = ntohl(ph->packet_id);
    int ret = nfq_get_payload(nfa, (u_char**)&data);
    dump(data, ret);
    //is tcp
    struct libnet_ipv4_hdr *iphdr = (struct libnet_ipv4_hdr*)data;
    if(iphdr->ip_p == IPPROTO_TCP){
        struct libnet_tcp_hdr *tcphdr = (struct libnet_tcp_hdr*)((u_char*)data + 4*(iphdr->ip_hl));
        if(ntohs(tcphdr->th_dport) == TCP_PORT_HTTP || ntohs(tcphdr->th_sport) == TCP_PORT_HTTP){
            u_char* http_data = (u_char*)tcphdr + tcphdr->th_off*4;
            if(check(http_data)){
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        usage();
        return -1;
    }
    pattern = argv[1];
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = (int)recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
