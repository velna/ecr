/*
 * ecr_pcap_libpcap.c
 *
 *  Created on: May 10, 2017
 *      Author: velna
 */

#include "config.h"
#include "ecr_pcap.h"
#include "ecr_logger.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pcap.h>

typedef struct {
    ecr_pcap_packet_t *packets;
    int size;
    ecr_pcap_t *pcap;
} ecr_pcap_buf_t;

typedef struct {
    pthread_mutex_t mutex;
    pcap_t *pcap;
    ecr_pcap_buf_t *buf;
    struct pcap_stat last_stat;
    char live :1;
} ecr_pcap_libpcap_t;

static void ecr_pcap_libpcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    ecr_pcap_buf_t *buf = (ecr_pcap_buf_t *) user;
    ecr_pcap_packet_t * packet = &buf->packets[buf->size];

    packet->caplen = h->caplen;
    packet->len = h->len;
    packet->ts = h->ts;
    memcpy(packet->data, bytes, h->caplen);
    buf->size++;
    buf->pcap->stat.bytes_recv += h->len;
}

static int ecr_pcap_libpcap_process(ecr_pcap_t *pcap, int tid, void *pcap_user, void *user) {
    ecr_pcap_buf_t *buf = (ecr_pcap_buf_t*) user;
    ecr_pcap_libpcap_t *pcaplib = pcap->pcaplib_ctx;
    int n, i, rc = 0;

    pthread_mutex_lock(&pcaplib->mutex);
    n = pcap_dispatch(pcaplib->pcap, pcap->batch_size, ecr_pcap_libpcap_callback, (u_char*) buf);
    pthread_mutex_unlock(&pcaplib->mutex);
    if (n > 0) {
        for (i = 0; i < n; i++) {
            pcap->config.pcap_handler(pcap, tid, &buf->packets[i], pcap_user);
        }
        rc = 1;
        buf->size = 0;
    } else if (n == 0) {
        if (!pcaplib->live) {
            pcap->active = 0;
        }
    } else if (n == -1) {
        L_ERROR("pcap_dispatch() error on device %s: %s", pcap->device, pcap_geterr(pcaplib->pcap));
    } else if (n == -2) {
        pcap->active = 0;
    }
    return rc;
}

static int ecr_pcap_libpcap_init(ecr_pcap_t *pcap, ecr_pcap_pool_t *pool, const char *device, const ecr_pcap_cfg_t *cfg) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int rc, i, j;
    struct bpf_program bpf;
    pcap_t *libpcap;
    int live, snap_len;
    ecr_pcap_capable_t *capable;
    ecr_pcap_capable_chain_t *capable_chain;
    ecr_pcap_libpcap_t *pcaplib;

    if (access(device, F_OK) == 0) {
        libpcap = pcap_open_offline(device, errbuf);
        live = 0;
    } else {
        libpcap = pcap_create(device, errbuf);
        live = 1;
    }
    if (NULL == libpcap) {
        L_ERROR("error open libpcap: %s", errbuf);
        return -1;
    }
    if (live) {
        if (cfg->promisc && (rc = pcap_set_promisc(libpcap, 1)) != 0) {
            L_ERROR("pcap_set_promisc() error: %s", pcap_geterr(libpcap));
            pcap_close(libpcap);
            return -1;
        }
        if ((rc = pcap_set_snaplen(libpcap, cfg->snap_len)) != 0) {
            L_ERROR("pcap_set_snaplen() error: %s", pcap_geterr(libpcap));
            pcap_close(libpcap);
            return -1;
        }
        if (cfg->timeout && pcap_set_timeout(libpcap, cfg->timeout)) {
            L_ERROR("pcap_set_timeout() error: %s", pcap_geterr(libpcap));
            pcap_close(libpcap);
            return -1;
        }
        if (cfg->buf_size) {
            if (pcap_set_buffer_size(libpcap, cfg->buf_size)) {
                L_ERROR("pcap_set_buffer_size() error: %s", pcap_geterr(libpcap));
                pcap_close(libpcap);
                return -1;
            }
        }
        if (pcap_activate(libpcap) != 0) {
            L_ERROR("pcap_activate() error: %s", pcap_geterr(libpcap));
            pcap_close(libpcap);
            return -1;
        }
        snap_len = cfg->snap_len;
    } else {
        pcap->batch_size = 1;
        snap_len = 65536;
    }
    if (cfg->bpf_program) {
        if (pcap_compile(libpcap, &bpf, cfg->bpf_program, 1, PCAP_NETMASK_UNKNOWN)) {
            L_ERROR("pcap_compile() error: %s", pcap_geterr(libpcap));
            pcap_close(libpcap);
            return -1;
        } else {
            if (pcap_setfilter(libpcap, &bpf)) {
                L_ERROR("pcap_setfilter() error: %s", pcap_geterr(libpcap));
                pcap_freecode(&bpf);
                pcap_close(libpcap);
                return -1;
            }
            pcap_freecode(&bpf);
        }
    }

    pcaplib = calloc(1, sizeof(ecr_pcap_libpcap_t));
    pcaplib->pcap = libpcap;
    pcaplib->live = live;
    pthread_mutex_init(&pcaplib->mutex, NULL);

    pcaplib->buf = calloc(pool->num_threads, sizeof(ecr_pcap_buf_t));
    for (i = 0; i < pool->num_threads; i++) {
        pcaplib->buf[i].packets = calloc(pcap->batch_size, sizeof(ecr_pcap_packet_t));
        for (j = 0; j < pcap->batch_size; j++) {
            pcaplib->buf[i].packets[j].data = malloc(snap_len);
        }
        pcaplib->buf[i].pcap = pcap;

        capable = calloc(1, sizeof(ecr_pcap_capable_t));
        capable->cap_func = ecr_pcap_libpcap_process;
        capable->pcap = pcap;
        capable->user = &pcaplib->buf[i];
        capable_chain = &pool->capable_chains[i];
        linked_list_push(capable_chain, capable)
        ;
    }
    pcap->pcaplib_ctx = pcaplib;

    return 0;
}

int ecr_pcap_libpcap_stats(ecr_pcap_t *pcap, ecr_pcap_stat_t *stat) {
    struct pcap_stat pstat;
    ecr_pcap_libpcap_t *pcaplib = pcap->pcaplib_ctx;

    if (pcap_stats(pcaplib->pcap, &pstat) == 0) {
        pcap->stat.ps_recv += pstat.ps_recv - pcaplib->last_stat.ps_recv;
        pcap->stat.ps_drop += pstat.ps_drop - pcaplib->last_stat.ps_drop;
        pcap->stat.ps_ifdrop += pstat.ps_ifdrop - pcaplib->last_stat.ps_ifdrop;
        memcpy(&pcaplib->last_stat, &pstat, sizeof(struct pcap_stat));
    }
    memcpy(stat, &pcap->stat, sizeof(ecr_pcap_stat_t));
    return 0;
}

int ecr_pcap_libpcap_close(ecr_pcap_t *pcap) {
    int i, j;
    ecr_pcap_libpcap_t *pcaplib = pcap->pcaplib_ctx;

    if (pcaplib->pcap) {
        pcap_breakloop(pcaplib->pcap);
        pcap_close(pcaplib->pcap);
    }
    if (pcaplib->buf) {
        for (i = 0; i < pcap->pool->num_threads; i++) {
            for (j = 0; j < pcap->batch_size; j++) {
                free_to_null(pcaplib->buf[i].packets[j].data);
            }
            free_to_null(pcaplib->buf[i].packets);
        }
        free_to_null(pcaplib->buf);
    }
    pthread_mutex_destroy(&pcaplib->mutex);
    free_to_null(pcap->pcaplib_ctx);
    return 0;
}

ecr_pcap_lib_t ecr_pcap_lib_libpcap = {
//
        .family = ECR_PCAP_FAMILY_LIBPCAP,
        .init = ecr_pcap_libpcap_init,
        .stats = ecr_pcap_libpcap_stats,
        .close = ecr_pcap_libpcap_close };
