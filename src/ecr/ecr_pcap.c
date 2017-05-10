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
    ecr_set_thread_name("pcap-%d", tid);
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

ecr_pcap_pool_t * ecr_pcap_pool_init(ecr_pcap_pool_cfg_t *cfg, ecr_pcap_lib_t *pcaplib, ...) {
    va_list ap;
    ecr_pcap_pool_t *pool = calloc(1, sizeof(ecr_pcap_pool_t));
    ecr_pcap_lib_t *pcap_lib;
    int i, core_id, num_cores;
    cpu_set_t mask;
    char *smask, *smask_s, *affinity = NULL;

    pool->running = 1;
    pool->num_threads = cfg->num_threads;
    ecr_list_init(&pool->pcaps, 16);
    ecr_list_init(&pool->pcap_libs, 4);

    if (pcaplib) {
        ecr_list_add(&pool->pcap_libs, pcaplib);
    }
    va_start(ap, pcaplib);
    while ((pcap_lib = va_arg(ap, ecr_pcap_lib_t*))) {
        ecr_list_add(&pool->pcap_libs, pcap_lib);
    }
    va_end(ap);

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

static ecr_pcap_lib_t * ecr_pcap_find_lib(ecr_pcap_pool_t *pool, int family) {
    int i;
    ecr_pcap_lib_t *pcaplib;
    for (i = 0; i < ecr_list_size(&pool->pcap_libs); i++) {
        pcaplib = ecr_list_get(&pool->pcap_libs, i);
        if (pcaplib->family == family) {
            return pcaplib;
        }
    }
    return NULL;
}

ecr_pcap_t * ecr_pcap_pool_add(ecr_pcap_pool_t *pool, const char *device, const ecr_pcap_cfg_t *cfg) {
    ecr_pcap_lib_t *pcaplib;
    ecr_pcap_t *pcap;
    int rc = -1;

    if (cfg->snap_len <= 0) {
        L_ERROR("invalid pcap snap len: %d", cfg->snap_len);
        return NULL;
    }
    pcaplib = ecr_pcap_find_lib(pool, cfg->family);
    if (!pcaplib) {
        L_ERROR("unknown pcap family: %d", cfg->family);
        return NULL;
    }
    pcap = calloc(1, sizeof(ecr_pcap_t));
    pcap->pcaplib = pcaplib;
    if (cfg->buf_size) {
        pcap->batch_size = cfg->buf_size / cfg->snap_len / pool->num_threads;
    } else {
        pcap->batch_size = 1;
    }
    rc = pcaplib->init(pcap, pool, device, cfg);
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
    return pcap->pcaplib->stats(pcap, stat);
}

int ecr_pcap_close(ecr_pcap_t *pcap) {
    int rc;

    if (!pcap) {
        return -1;
    }
    ecr_list_remove(&pcap->pool->pcaps, pcap);
    pcap->closed = 1;
    while (pcap->close_confirm < pcap->pool->num_threads) {
        ;
    }

    rc = pcap->pcaplib->close(pcap);

    free_to_null(pcap->device);
    free(pcap);
    return rc;
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
