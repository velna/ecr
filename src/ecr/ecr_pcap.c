/*
 * ecr_pcap.c
 *
 *  Created on: May 5, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_util.h"
#include "ecr_pcap.h"
#include "ecr_logger.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static void * ecr_pcap_routine(void *user) {
    ecr_pcap_pool_t *pool = (ecr_pcap_pool_t *) user;
    ecr_pcap_capable_chain_t *capable_chain;
    ecr_pcap_capable_t *capable, *next;
    int tid, ok;
    struct timespec sleep_time = { 0, 100000 };

    tid = AO_fetch_and_add1(&pool->tid);
    L_INFO("cap thread %d started.", tid);
    ecr_set_thread_name("pcap-%Zd", tid);
    capable_chain = &pool->capable_chains[tid];

    while (pool->running) {
        ok = 0;
        capable = capable_chain->head;
        if (capable) {
            do {
                next = capable->next;
                if (capable->pcap->active) {
                    ok += capable->cap_func(capable->pcap, tid, capable->pcap->config.user, capable->user);
                }
                if (capable->pcap->closed) {
                    AO_fetch_and_add1(&capable->pcap->close_confirm);
                    linked_list_drop(capable_chain, capable);
                    free(capable);
                }
                capable = next;
            } while (capable);
            if (!ok) {
                nanosleep(&sleep_time, NULL);
            }
        } else {
            sleep(1);
        }
    }

    L_INFO("cap thread %d finished.", tid);
    return NULL;
}

ecr_pcap_pool_t * ecr_pcap_pool_init(ecr_pcap_pool_cfg_t *cfg) {
    ecr_pcap_pool_t *pool = calloc(1, sizeof(ecr_pcap_pool_t));
    int i, core_id, num_cores;
    cpu_set_t mask;
    char *smask, *smask_s, *affinity = NULL;

    pool->running = 1;
    pool->num_threads = cfg->num_threads;
    ecr_list_init(&pool->pcaps, 16);

    num_cores = (int) sysconf(_SC_NPROCESSORS_ONLN);
    smask = NULL;
    if (cfg->thread_affinity) {
        affinity = strdup(cfg->thread_affinity);
        smask = strtok_r(affinity, ", ", &smask_s);
    }
    pool->threads = calloc(pool->num_threads, sizeof(pthread_t));
    pool->capable_chains = calloc(pool->num_threads, sizeof(ecr_pcap_capable_chain_t));
    for (i = 0; i < pool->num_threads; i++) {
        pthread_create(&pool->threads[i], NULL, ecr_pcap_routine, pool);
        if (smask) {
            CPU_ZERO(&mask);
            core_id = atoi(smask);
            if (core_id > num_cores) {
                L_WARN("invalid cpu affinity mask: %d, mod to %d", core_id, core_id % num_cores);
                core_id = core_id % num_cores;
            }
            CPU_SET(core_id, &mask);
            if (pthread_setaffinity_np(pool->threads[i], sizeof(cpu_set_t), &mask) == -1) {
                L_ERROR("pthread_setaffinity_np() failed: %s, cpu_num: %d, %d", strerror(errno), num_cores, core_id);
            }
            smask = strtok_r(NULL, ", ", &smask_s);
        }
    }
    free_to_null(affinity);
    return pool;
}

#ifdef ECR_ENABLE_PFRING
static int ecr_pcap_process_pfringmc(ecr_pcap_t *pcap, int tid, void *pcap_user, void *user) {
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

static int ecr_pcap_init_pfringmc(ecr_pcap_t *pcap, ecr_pcap_pool_t *pool, const char *device,
        const ecr_pcap_cfg_t *cfg) {
    pfring * rings[ECR_MAX_NUM_RX_CHANNELS];
    ecr_pcap_pfringmc_t *pfringmc;
    u_int32_t flags = PF_RING_DO_NOT_PARSE;
    ecr_pcap_capable_t *capable;
    ecr_pcap_capable_chain_t *capable_chain;
    u_int8_t n;
    int i;

    pfringmc = &pcap->pfringmc;
    if (cfg->promisc) {
        flags |= PF_RING_PROMISC;
    }
    n = pfring_open_multichannel(device, cfg->snap_len, flags, rings);
    if (n <= 0) {
        L_ERROR("pfring_open_multichannel() error: %hhu", n);
        return -1;
    }
    L_INFO("%hhu channels opened on device %s.", n, device);

    pfringmc->num_channels = n;
    pfringmc->channels = calloc(n, sizeof(ecr_pcap_pfringmc_channel_t));
    for (i = 0; i < n; i++) {
        if (pfring_set_direction(rings[i], rx_only_direction)) {
            L_ERROR("pfring_set_direction() error.");
            pfring_close(rings[i]);
            return -1;
        }
        if (pfring_set_socket_mode(rings[i], recv_only_mode)) {
            L_ERROR("pfring_set_socket_mode() error.");
            pfring_close(rings[i]);
            return -1;
        }
        if (pfring_enable_ring(rings[i])) {
            L_ERROR("pfring_enable_ring() error.");
            pfring_close(rings[i]);
            return -1;
        }
        pfringmc->channels[i].ring = rings[i];
        pthread_mutex_init(&pfringmc->channels[i].mutex, NULL);

        capable = calloc(1, sizeof(ecr_pcap_capable_t));
        capable->cap_func = ecr_pcap_process_pfringmc;
        capable->pcap = pcap;
        capable->user = &pfringmc->channels[i];
        capable_chain = &pool->capable_chains[i % pool->num_threads];
        linked_list_push(capable_chain, capable);
    }

    return 0;
}
#endif

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

static int ecr_pcap_process_libpcap(ecr_pcap_t *pcap, int tid, void *pcap_user, void *user) {
    ecr_pcap_buf_t *buf = (ecr_pcap_buf_t*) user;
    ecr_pcap_libpcap_t *libpcap = &pcap->libpcap;
    int n, i, rc = 0;

    pthread_mutex_lock(&libpcap->mutex);
    n = pcap_dispatch(libpcap->pcap, pcap->batch_size, ecr_pcap_libpcap_callback, (u_char*) buf);
    pthread_mutex_unlock(&libpcap->mutex);
    if (n > 0) {
        for (i = 0; i < n; i++) {
            pcap->config.pcap_handler(pcap, tid, &buf->packets[i], pcap_user);
        }
        rc = 1;
        buf->size = 0;
    } else if (n == 0) {
        if (!libpcap->live) {
            pcap->active = 0;
        }
    } else if (n == -1) {
        L_ERROR("pcap_dispatch() error on device %s: %s", pcap->device, pcap_geterr(libpcap->pcap));
    } else if (n == -2) {
        pcap->active = 0;
    }
    return rc;
}

static int ecr_pcap_init_libpcap(ecr_pcap_t *pcap, ecr_pcap_pool_t *pool, const char *device, const ecr_pcap_cfg_t *cfg) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int rc, i, j;
    struct bpf_program bpf;
    pcap_t *libpcap;
    int live, snap_len;
    ecr_pcap_capable_t *capable;
    ecr_pcap_capable_chain_t *capable_chain;

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

    pcap->libpcap.pcap = libpcap;
    pcap->libpcap.live = live;
    pthread_mutex_init(&pcap->libpcap.mutex, NULL);

    pcap->libpcap.buf = calloc(pool->num_threads, sizeof(ecr_pcap_buf_t));
    for (i = 0; i < pool->num_threads; i++) {
        pcap->libpcap.buf[i].packets = calloc(pcap->batch_size, sizeof(ecr_pcap_packet_t));
        for (j = 0; j < pcap->batch_size; j++) {
            pcap->libpcap.buf[i].packets[j].data = malloc(snap_len);
        }
        pcap->libpcap.buf[i].pcap = pcap;

        capable = calloc(1, sizeof(ecr_pcap_capable_t));
        capable->cap_func = ecr_pcap_process_libpcap;
        capable->pcap = pcap;
        capable->user = &pcap->libpcap.buf[i];
        capable_chain = &pool->capable_chains[i];
        linked_list_push(capable_chain, capable);
    }

    return 0;
}

ecr_pcap_t * ecr_pcap_pool_add(ecr_pcap_pool_t *pool, const char *device, const ecr_pcap_cfg_t *cfg) {
    ecr_pcap_t *pcap = calloc(1, sizeof(ecr_pcap_t));
    int rc = -1;

    if (cfg->snap_len <= 0) {
        free(pcap);
        L_ERROR("invalid pcap snap len: %d", cfg->snap_len);
        return NULL;
    }
    if (cfg->buf_size) {
        pcap->batch_size = cfg->buf_size / cfg->snap_len / pool->num_threads;
    } else {
        pcap->batch_size = 1;
    }
    switch (cfg->family) {
    case ECR_PCAP_FAMILY_LIBPCAP:
        rc = ecr_pcap_init_libpcap(pcap, pool, device, cfg);
        break;
#ifdef ECR_ENABLE_PFRING
    case ECR_PCAP_FAMILY_PFRINGMC:
        rc = ecr_pcap_init_pfringmc(pcap, pool, device, cfg);
        break;
#endif
    default:
        L_ERROR("unknown pcap family: %d", cfg->family);
        break;
    }
    if (rc == 0) {
        pcap->device = strdup(device);
        pcap->pool = pool;
        pcap->config = *cfg;

        ecr_list_add(&pool->pcaps, pcap);
    } else {
        free_to_null(pcap);
    }
    return pcap;
}

int ecr_pcap_active(ecr_pcap_t *pcap) {
    pcap->active = 1;
    return 0;
}

int ecr_pcap_deactive(ecr_pcap_t *pcap) {
    pcap->active = 0;
    return 0;
}

int ecr_pcap_stats(ecr_pcap_t *pcap, ecr_pcap_stat_t *stat) {
#ifdef ECR_ENABLE_PFRING
    ecr_pcap_pfringmc_channel_t *channel;
    pfring_stat pfstat;
    ecr_pcap_stat_t mystat = { 0 };
    int i;
#endif
    struct pcap_stat pstat;

    switch (pcap->config.family) {
    case ECR_PCAP_FAMILY_LIBPCAP:
        if (pcap_stats(pcap->libpcap.pcap, &pstat) == 0) {
            pcap->stat.ps_recv += pstat.ps_recv - pcap->libpcap.last_stat.ps_recv;
            pcap->stat.ps_drop += pstat.ps_drop - pcap->libpcap.last_stat.ps_drop;
            pcap->stat.ps_ifdrop += pstat.ps_ifdrop - pcap->libpcap.last_stat.ps_ifdrop;
            memcpy(&pcap->libpcap.last_stat, &pstat, sizeof(struct pcap_stat));
        }
        break;
#ifdef ECR_ENABLE_PFRING
    case ECR_PCAP_FAMILY_PFRINGMC:
        for (i = 0; i < pcap->pfringmc.num_channels; i++) {
            channel = &pcap->pfringmc.channels[i];
            if (pfring_stats(channel->ring, &pfstat) == 0) {
                mystat.ps_recv += (channel->stat.ps_recv = pfstat.recv);
                mystat.ps_drop += (channel->stat.ps_drop = pfstat.drop);
                mystat.bytes_recv += channel->stat.bytes_recv;
            }
        }
        memcpy(&pcap->stat, &mystat, sizeof(ecr_pcap_stat_t));
        break;
#endif
    }
    memcpy(stat, &pcap->stat, sizeof(ecr_pcap_stat_t));
    return 0;
}

int ecr_pcap_close(ecr_pcap_t *pcap) {
    int i, j;

    if (!pcap) {
        return -1;
    }
    ecr_list_remove(&pcap->pool->pcaps, pcap);
    pcap->closed = 1;
    while (pcap->close_confirm < pcap->pool->num_threads) {
        ;
    }

    switch (pcap->config.family) {
    case ECR_PCAP_FAMILY_LIBPCAP:
        if (pcap->libpcap.pcap) {
            pcap_breakloop(pcap->libpcap.pcap);
            pcap_close(pcap->libpcap.pcap);
        }
        if (pcap->libpcap.buf) {
            for (i = 0; i < pcap->pool->num_threads; i++) {
                for (j = 0; j < pcap->batch_size; j++) {
                    free_to_null(pcap->libpcap.buf[i].packets[j].data);
                }
                free_to_null(pcap->libpcap.buf[i].packets);
            }
            free_to_null(pcap->libpcap.buf);
        }
        pthread_mutex_destroy(&pcap->libpcap.mutex);
        break;
#ifdef ECR_ENABLE_PFRING
    case ECR_PCAP_FAMILY_PFRINGMC:
        for (i = 0; i < pcap->pfringmc.num_channels; i++) {
            pfring_close(pcap->pfringmc.channels[i].ring);
            pthread_mutex_destroy(&pcap->pfringmc.channels[i].mutex);
        }
        free_to_null(pcap->pfringmc.channels)
        break;
#endif
    }
    free_to_null(pcap->device);
    free(pcap);
    return 0;
}

ecr_pcap_t * ecr_pcap_pool_find(ecr_pcap_pool_t *pool, const char *device) {
    int i;
    ecr_pcap_t *pcap;
    for (i = 0; i < ecr_list_size(&pool->pcaps); i++) {
        pcap = ecr_list_get(&pool->pcaps, i);
        if (pcap && strcmp(device, pcap->device) == 0) {
            return pcap;
        }
    }
    return NULL;
}

int ecr_pcap_pool_tryjoin(ecr_pcap_pool_t *pool) {
    int i;
    ecr_pcap_t *pcap;
    for (i = 0; i < ecr_list_size(&pool->pcaps); i++) {
        pcap = ecr_list_get(&pool->pcaps, i);
        if (pcap && pcap->active) {
            return -1;
        }
    }
    return 0;
}

void ecr_pcap_pool_destroy(ecr_pcap_pool_t *pool) {
    int i;
    ecr_pcap_t *pcap;
    ecr_pcap_capable_t *capable, *next;
    ecr_pcap_capable_chain_t *capable_chain;

    L_INFO("destroy pcap pool ...");
    for (i = 0; i < ecr_list_size(&pool->pcaps); i++) {
        pcap = ecr_list_get(&pool->pcaps, i);
        ecr_pcap_close(pcap);
    }
    pool->running = 0;
    L_INFO("wait pcap threads ...");
    for (i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
        capable_chain = &pool->capable_chains[i];
        capable = capable_chain->head;
        while (capable) {
            next = capable->next;
            free(capable);
            capable = next;
        }
    }
    free(pool->threads);
    free(pool->capable_chains);
    ecr_list_destroy(&pool->pcaps, NULL);
    free(pool);
    L_INFO("pcap pool destroied ...");
}
