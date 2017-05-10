/*
 * ecr_pcap_libpfring.c
 *
 *  Created on: May 10, 2017
 *      Author: velna
 */

#include "config.h"
#include "ecrconf.h"
#include "ecr_pcap.h"
#include "ecr_logger.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define ECR_MAX_NUM_RX_CHANNELS      64
#define HAVE_RW_LOCK
#include <pfring.h>

typedef struct {
    ecr_pcap_stat_t stat;
    pthread_mutex_t mutex;
    pfring* ring;
} ecr_pcap_pfringmc_channel_t;

typedef struct {
    int num_channels;
    ecr_pcap_pfringmc_channel_t *channels;
} ecr_pcap_pfringmc_t;

static int ecr_pcap_libpfring_mc_process(ecr_pcap_t *pcap, int tid, void *pcap_user, void *user) {
    ecr_pcap_pfringmc_channel_t *channel = (ecr_pcap_pfringmc_channel_t*) user;
    int n, rc = 0;
    u_char *buf = NULL;
    struct pfring_pkthdr hdr;
    ecr_pcap_packet_t packet;

    pthread_mutex_lock(&channel->mutex);
    n = pfring_recv(channel->ring, &buf, 0, &hdr, 0);
    if (n == 1) {
        channel->stat.bytes_recv += hdr.len;
    }
    pthread_mutex_unlock(&channel->mutex);
    switch (n) {
    case 1:
        packet.ts = hdr.ts;
        packet.caplen = hdr.caplen;
        packet.len = hdr.len;
        packet.data = buf;
        pcap->config.pcap_handler(pcap, tid, &packet, pcap_user);
        rc = 1;
        break;
    case -1:
        L_ERROR("pfring_recv() error on %s", pcap->device);
        break;
    }
    return rc;
}

static int ecr_pcap_libpfring_mc_init(ecr_pcap_t *pcap, ecr_pcap_pool_t *pool, const char *device,
        const ecr_pcap_cfg_t *cfg) {
    pfring * rings[ECR_MAX_NUM_RX_CHANNELS];
    ecr_pcap_pfringmc_t *pfringmc;
    u_int32_t flags = PF_RING_DO_NOT_PARSE;
    ecr_pcap_capable_t *capable;
    ecr_pcap_capable_chain_t *capable_chain;
    u_int8_t n;
    int i;

    pfringmc = calloc(1, sizeof(ecr_pcap_pfringmc_t));
    if (cfg->promisc) {
        flags |= PF_RING_PROMISC;
    }
    n = pfring_open_multichannel(device, cfg->snap_len, flags, rings);
    if (n <= 0) {
        L_ERROR("pfring_open_multichannel() error: %hhu", n);
        free(pfringmc);
        return -1;
    }
    L_INFO("%hhu channels opened on device %s.", n, device);

    pfringmc->num_channels = n;
    pfringmc->channels = calloc(n, sizeof(ecr_pcap_pfringmc_channel_t));
    for (i = 0; i < n; i++) {
        if (pfring_set_direction(rings[i], rx_only_direction)) {
            L_ERROR("pfring_set_direction() error.");
            pfring_close(rings[i]);
            free(pfringmc);
            return -1;
        }
        if (pfring_set_socket_mode(rings[i], recv_only_mode)) {
            L_ERROR("pfring_set_socket_mode() error.");
            pfring_close(rings[i]);
            free(pfringmc);
            return -1;
        }
        if (pfring_enable_ring(rings[i])) {
            L_ERROR("pfring_enable_ring() error.");
            pfring_close(rings[i]);
            free(pfringmc);
            return -1;
        }
        pfringmc->channels[i].ring = rings[i];
        pthread_mutex_init(&pfringmc->channels[i].mutex, NULL);

        capable = calloc(1, sizeof(ecr_pcap_capable_t));
        capable->cap_func = ecr_pcap_libpfring_mc_process;
        capable->pcap = pcap;
        capable->user = &pfringmc->channels[i];
        capable_chain = &pool->capable_chains[i % pool->num_threads];
        linked_list_push(capable_chain, capable)
        ;
    }
    pcap->pcaplib_ctx = pfringmc;

    return 0;
}

int ecr_pcap_libpfring_mc_stats(ecr_pcap_t *pcap, ecr_pcap_stat_t *stat) {
    ecr_pcap_pfringmc_t *pfringmc = pcap->pcaplib_ctx;
    ecr_pcap_pfringmc_channel_t *channel;
    pfring_stat pfstat;
    ecr_pcap_stat_t mystat = { 0 };
    int i;
    for (i = 0; i < pfringmc->num_channels; i++) {
        channel = &pfringmc->channels[i];
        if (pfring_stats(channel->ring, &pfstat) == 0) {
            mystat.ps_recv += (channel->stat.ps_recv = pfstat.recv);
            mystat.ps_drop += (channel->stat.ps_drop = pfstat.drop);
            mystat.bytes_recv += channel->stat.bytes_recv;
        }
    }
    memcpy(&pcap->stat, &mystat, sizeof(ecr_pcap_stat_t));
    memcpy(stat, &pcap->stat, sizeof(ecr_pcap_stat_t));
    return 0;
}

int ecr_pcap_libpfring_mc_close(ecr_pcap_t *pcap) {
    ecr_pcap_pfringmc_t *pfringmc = pcap->pcaplib_ctx;
    int i;
    for (i = 0; i < pfringmc->num_channels; i++) {
        pfring_close(pfringmc->channels[i].ring);
        pthread_mutex_destroy(&pfringmc->channels[i].mutex);
    }
    free_to_null(pfringmc->channels);
    free_to_null(pcap->pcaplib_ctx);
    return 0;
}

ecr_pcap_lib_t ecr_pcap_lib_libpfring_mc = {
//
        .family = ECR_PCAP_FAMILY_PFRINGMC,
        .init = ecr_pcap_libpfring_mc_init,
        .stats = ecr_pcap_libpfring_mc_stats,
        .close = ecr_pcap_libpfring_mc_close };
