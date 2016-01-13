/*
 * ecr_mempool.h
 *
 *  Created on: Oct 14, 2015
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_MEMPOOL_H_
#define SRC_ECR_ECR_MEMPOOL_H_

#include "ecrconf.h"
#include <stdio.h>
#include <pthread.h>

#define ECR_MEMPOOL_LARGE   65537
#define ECR_MEMPOOL_LEVEL   14

typedef struct ecr_mempool_node_s {
    size_t mem_size;
    struct ecr_mempool_node_s *next;
    struct ecr_mempool_node_s *prev;
    u_char mem[];
} ecr_mempool_node_t;

typedef struct {
    size_t mem_size;
    ecr_mempool_node_t *head;
    ecr_mempool_node_t *tail;
    size_t alloc;
    size_t spare;
    pthread_rwlock_t lock;
} ecr_mempool_chain_t;

typedef struct {
    ecr_mempool_chain_t *table[ECR_MEMPOOL_LARGE];
} ecr_mempool_t;

typedef struct {
    struct {
        size_t mem_size;
        size_t spare;
        size_t alloc;
    } levels[ECR_MEMPOOL_LEVEL];
} ecr_mempool_stat_t;

int ecr_mempool_init(ecr_mempool_t *pool);

void * ecr_mempool_alloc(ecr_mempool_t *pool, size_t size);

void * ecr_mempool_realloc(ecr_mempool_t *pool, void *ptr, size_t new_size);

void ecr_mempool_free(ecr_mempool_t *pool, void *ptr);

void ecr_mempool_balance(ecr_mempool_t *pools, int n);

void ecr_mempool_stats(ecr_mempool_t *pool, ecr_mempool_stat_t *stat);

void ecr_mempool_destroy(ecr_mempool_t *pool);

#endif /* SRC_ECR_ECR_MEMPOOL_H_ */
