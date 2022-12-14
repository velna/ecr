/*
 * ecr_pcap.h
 *
 *  Created on: May 5, 2015
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_PCAP_H_
#define SRC_ECR_ECR_PCAP_H_

#include "ecrconf.h"
#include "ecr_list.h"
#include "ecr_hashmap.h"
#include <atomic_ops.h>
#include <pthread.h>

#define ECR_PCAP_FAMILY_LIBPCAP         0
#define ECR_PCAP_FAMILY_PFRINGMC        1

typedef struct ecr_pcap_s ecr_pcap_t;
typedef struct ecr_pcap_pool_s ecr_pcap_pool_t;

typedef struct {
    int num_threads;
    char *thread_affinity;
} ecr_pcap_pool_cfg_t;

typedef struct {
    struct timeval ts; /* time stamp */
    u_int32_t caplen; /* length of portion present */
    u_int32_t len; /* length this packet (off wire) */
    u_char *data;
} ecr_pcap_packet_t;

typedef struct {
    u_int64_t ps_recv;
    u_int64_t ps_drop;
    u_int64_t ps_ifdrop;
    u_int64_t bytes_recv;
} ecr_pcap_stat_t;

typedef void (*ecr_pcap_handler)(ecr_pcap_t *pcap, int tid, ecr_pcap_packet_t *pkt, void *user);

typedef struct {
    int buf_size;
    int timeout;
    int snap_len;
    char *bpf_program;
    ecr_pcap_handler pcap_handler;
    void *user;
    int family;
    int promisc;
} ecr_pcap_cfg_t;

typedef struct ecr_pcap_capable_s {
    ecr_pcap_t *pcap;
    void *user;
    int (*cap_func)(ecr_pcap_t *pcap, int tid, void *pcap_user, void *user);
    struct ecr_pcap_capable_s *prev;
    struct ecr_pcap_capable_s *next;
} ecr_pcap_capable_t;

typedef struct {
    ecr_pcap_capable_t *head;
    ecr_pcap_capable_t *tail;
} ecr_pcap_capable_chain_t;

typedef struct {
    int family;
    int (*init)(ecr_pcap_t *pcap, ecr_pcap_pool_t *pool, const char *device, const ecr_pcap_cfg_t *cfg);
    int (*stats)(ecr_pcap_t *pcap, ecr_pcap_stat_t *stat);
    int (*close)(ecr_pcap_t *pcap);
} ecr_pcap_lib_t;

struct ecr_pcap_pool_s {
    ecr_list_t pcap_libs;
    ecr_list_t pcaps;
    int num_threads;
    pthread_t *threads;
    ecr_pcap_capable_chain_t *capable_chains;
    volatile AO_t tid;
    volatile int running;
};

struct ecr_pcap_s {
    ecr_pcap_pool_t *pool;
    char *device;
    int batch_size;
    ecr_pcap_stat_t stat;
    ecr_pcap_cfg_t config;
    volatile AO_t close_confirm;
    int active :1;
    volatile int closed;
    ecr_pcap_lib_t *pcaplib;
    void *pcaplib_ctx;
};

extern ecr_pcap_lib_t ecr_pcap_lib_libpcap;
extern ecr_pcap_lib_t ecr_pcap_lib_libpfring_mc;

ecr_pcap_pool_t * ecr_pcap_pool_init(ecr_pcap_pool_cfg_t *cfg, ecr_pcap_lib_t *pcaplib, ...);

ecr_pcap_t * ecr_pcap_pool_add(ecr_pcap_pool_t *pcap_pool, const char *device, const ecr_pcap_cfg_t *cfg);

int ecr_pcap_active(ecr_pcap_t *pcap);

int ecr_pcap_deactive(ecr_pcap_t *pcap);

int ecr_pcap_close(ecr_pcap_t *pcap);

int ecr_pcap_stats(ecr_pcap_t *pcap, ecr_pcap_stat_t *stat);

ecr_pcap_t * ecr_pcap_pool_find(ecr_pcap_pool_t *pcap_pool, const char *device);

int ecr_pcap_pool_tryjoin(ecr_pcap_pool_t *pcap_pool);

void ecr_pcap_pool_destroy(ecr_pcap_pool_t *pcap_pool);

#endif /* SRC_ECR_ECR_PCAP_H_ */
