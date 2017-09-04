/*
 *ecr_uncap.h
 *
 * Created on: Apr 11, 2013
 *     Author: velna
 */

#ifndef ECR_UNCAP_H_
#define ECR_UNCAP_H_

#include "ecrconf.h"

enum ecr_uncap_protocal_type {
    ECR_PT_UNKONWN = 0, //
    ECR_PT_ETHERNET,
    ECR_PT_IPV4,
    ECR_PT_IPV6,
    ECR_PT_VLAN,
    ECR_PT_TCP,
    ECR_PT_UDP,
    ECR_PT_GRE,
    ECR_PT_GTP,
    ECR_PT_GTPV2,
    ECR_PT_PPPOE
};

typedef struct {
    enum ecr_uncap_protocal_type pt;
    uint32_t next_pt;
    void *ptr;
    size_t total_len;
    size_t header_len;
} ecr_uncap_result_t;

struct gre_hdr {
    uint16_t flags;
    uint16_t protocol;
};

struct gtp_hdr {
    uint8_t f_npdu :1;
    uint8_t f_seq :1;
    uint8_t f_next :1;
    uint8_t reserved :1;
    uint8_t prot :1;
    uint8_t version :3;
    uint8_t msgtype;
    uint16_t len;
    uint32_t teid;
};

struct gtp_opt_hdr {
    uint16_t seq;
    uint8_t npdu;
    uint8_t next;
};

struct gtpv2_hdr {
    uint8_t spare :3;
    uint8_t f_t :1;
    uint8_t f_p :1;
    uint8_t version :3;
    uint8_t msgtype;
    uint16_t len;
};

struct dot1q_hdr {
    u_int16_t tag;
    u_int16_t protocol;
};

struct pppoe_hdr {
    uint8_t version :4;
    uint8_t type :4;
    uint8_t code;
    uint16_t session_id;
    uint16_t length;
    uint16_t protocol;
};

int ecr_uncap_eth(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out);
int ecr_uncap_dot1q(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out);
int ecr_uncap_ip(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out);
int ecr_uncap_gre(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out);
int ecr_uncap_udp(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out);
int ecr_uncap_tcp(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out);
int ecr_uncap_gtp(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out);
int ecr_uncap_gtpv2(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out);
int ecr_uncap_pppoe(ecr_str_t *uc, ecr_uncap_result_t *r, void *hdr_out);

#endif /* ECR_UNCAP_H_ */
