/*
 * ecr_uncap.c
 *
 *  Created on: Apr 11, 2013
 *      Author: velna
 */

#include "config.h"
#include "ecr_uncap.h"
#include <string.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

int ecr_uncap_eth(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out) {
    if (uc->len < sizeof(struct ethhdr)) {
        return -1;
    }

    struct ethhdr *hdr = hdr_out;
    memcpy(hdr, uc->ptr, sizeof(struct ethhdr));
    r->header_len = sizeof(struct ethhdr);
    r->next_pt = ntohs(hdr->h_proto);
    r->pt = ECR_PT_ETHERNET;
    r->ptr = uc->ptr;
    r->total_len = r->header_len;

    uc->ptr += r->header_len;
    uc->len -= r->header_len;
    return 0;
}

int ecr_uncap_dot1q(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out) {
    if (uc->len < sizeof(struct dot1q_hdr)) {
        return -1;
    }
    struct dot1q_hdr *hdr = hdr_out;
    memcpy(hdr, uc->ptr, sizeof(struct dot1q_hdr));
    r->header_len = sizeof(struct dot1q_hdr);
    r->next_pt = ntohs(hdr->protocol);
    r->pt = ECR_PT_VLAN;
    r->ptr = uc->ptr;
    r->total_len = r->header_len;

    uc->ptr += r->header_len;
    uc->len -= r->header_len;
    return 0;
}

int ecr_uncap_ip(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out) {
    if (uc->len < 1) {
        return -1;
    }
    u_int8_t version = uc->ptr[0] >> 4;
    struct iphdr *ipv4_hdr = hdr_out;
    struct ip6_hdr *ipv6_hdr = hdr_out;
    switch (version) {
    case 4:
        if (uc->len < sizeof(struct iphdr)) {
            return -1;
        }
        memcpy(ipv4_hdr, uc->ptr, sizeof(struct iphdr));
        r->header_len = ipv4_hdr->ihl << 2;
        if (uc->len < r->header_len) {
            return -1;
        }
        r->next_pt = ipv4_hdr->protocol;
        r->pt = ECR_PT_IPV4;
        r->ptr = uc->ptr;
        r->total_len = ntohs(ipv4_hdr->tot_len);
        break;
    case 6:
        if (uc->len < sizeof(struct ip6_hdr)) {
            return -1;
        }
        memcpy(ipv6_hdr, uc->ptr, sizeof(struct ip6_hdr));
        r->header_len = sizeof(struct ip6_hdr);
        if (uc->len < r->header_len) {
            return -1;
        }
        r->next_pt = ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        r->pt = ECR_PT_IPV6;
        r->ptr = uc->ptr;
        r->total_len = ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen + r->header_len;
        break;
    default:
        return -1;
    }

    uc->ptr += r->header_len;
    uc->len -= r->header_len;
    return 0;
}

int ecr_uncap_gre(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out) {
    if (uc->len < sizeof(struct gre_hdr)) {
        return -1;
    }
    struct gre_hdr *hdr = hdr_out;
    memcpy(hdr, uc->ptr, sizeof(struct gre_hdr));
    size_t gre_len = sizeof(struct gre_hdr);
    if ((hdr->flags & 0x80) > 0 || (hdr->flags & 0x40) > 0) {
        gre_len += 4;
    }
    if ((hdr->flags & 0x20) > 0) {
        gre_len += 4;
    }
    if ((hdr->flags & 0x10) > 0) {
        gre_len += 4;
    }

    r->header_len = gre_len;
    if (uc->len < r->header_len) {
        return -1;
    }
    r->next_pt = ntohs(hdr->protocol);
    r->pt = ECR_PT_GRE;
    r->ptr = uc->ptr;
    r->total_len = r->header_len;

    uc->ptr += r->header_len;
    uc->len -= r->header_len;
    return 0;
}

int ecr_uncap_udp(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out) {
    if (uc->len < sizeof(struct udphdr)) {
        return -1;
    }
    struct udphdr * hdr = hdr_out;
    memcpy(hdr, uc->ptr, sizeof(struct udphdr));
    r->header_len = sizeof(struct udphdr);
    r->next_pt = 0;
    r->pt = ECR_PT_UDP;
    r->ptr = uc->ptr;
    r->total_len = ntohs(hdr->len);

    uc->ptr += r->header_len;
    uc->len -= r->header_len;
    return 0;
}

int ecr_uncap_tcp(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out) {
    if (uc->len < sizeof(struct tcphdr)) {
        return -1;
    }
    struct tcphdr * hdr = hdr_out;
    memcpy(hdr, uc->ptr, sizeof(struct tcphdr));
    r->header_len = hdr->doff << 2;
    if (uc->len < r->header_len) {
        return -1;
    }
    r->next_pt = 0;
    r->pt = ECR_PT_TCP;
    r->ptr = uc->ptr;
    r->total_len = r->header_len;

    uc->ptr += r->header_len;
    uc->len -= r->header_len;
    return 0;
}

int ecr_uncap_gtp(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out) {
    if (uc->len < sizeof(struct gtp_hdr)) {
        return -1;
    }
    struct gtp_hdr * hdr = hdr_out;
    memcpy(hdr, uc->ptr, sizeof(struct gtp_hdr));
    if (hdr->version != 1 || hdr->prot != 1 || hdr->reserved) {
        return -1;
    }
    size_t gtp_hdr_len = sizeof(struct gtp_hdr);
    if (hdr->f_next || hdr->f_npdu || hdr->f_seq) {
        gtp_hdr_len += sizeof(struct gtp_opt_hdr);
        if (uc->len < gtp_hdr_len) {
            return -1;
        }
        struct gtp_opt_hdr *opt_hdr = (struct gtp_opt_hdr *) (uc->ptr + sizeof(struct gtp_hdr));
        int next = opt_hdr->next;
        while (next) {
            if (uc->len < gtp_hdr_len + 4 || !uc->ptr[gtp_hdr_len]) {
                return -1;
            }
            gtp_hdr_len += (uc->ptr[gtp_hdr_len] & 0xff) << 2;
            if (uc->len < gtp_hdr_len) {
                return -1;
            }
            next = uc->ptr[gtp_hdr_len - 1];
        }
    }
    r->header_len = gtp_hdr_len;
    r->next_pt = 0;
    r->pt = ECR_PT_GTP;
    r->ptr = uc->ptr;
    r->total_len = ntohs(hdr->len) + sizeof(struct gtp_hdr);

    uc->ptr += r->header_len;
    uc->len -= r->header_len;
    return 0;
}

int ecr_uncap_gtpv2(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out) {
    if (uc->len < sizeof(struct gtpv2_hdr)) {
        return -1;
    }
    struct gtpv2_hdr *hdr = hdr_out;
    memcpy(hdr, uc->ptr, sizeof(struct gtpv2_hdr));
    if (hdr->version != 2 || hdr->spare) {
        return -1;
    }
    size_t hdr_len = sizeof(struct gtpv2_hdr) + 4;
    if (hdr->f_t) {
        hdr_len += 4;
    }
    if (uc->len < hdr_len) {
        return -1;
    }
    r->header_len = hdr_len;
    r->next_pt = 0;
    r->pt = ECR_PT_GTPV2;
    r->ptr = uc->ptr;
    r->total_len = ntohs(hdr->len) + sizeof(struct gtpv2_hdr);

    uc->ptr += r->header_len;
    uc->len -= r->header_len;
    return 0;
}

int ecr_uncap_pppoe(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out) {
    if (uc->len < sizeof(struct pppoe_hdr)) {
        return -1;
    }
    struct pppoe_hdr *hdr = hdr_out;
    memcpy(hdr, uc->ptr, sizeof(struct pppoe_hdr));

    if (hdr->version != 1 || hdr->type != 1) {
        return -1;
    }
    r->header_len = sizeof(struct pppoe_hdr);
    r->next_pt = ntohs(hdr->protocol);
    r->pt = ECR_PT_PPPOE;
    r->ptr = uc->ptr;
    r->total_len = ntohs(hdr->length) + sizeof(struct pppoe_hdr) - 2;
    uc->ptr += r->header_len;
    uc->len -= r->header_len;
    return 0;
}
