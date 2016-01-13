/*
 * ecr_mempool.c
 *
 *  Created on: Oct 15, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_mempool.h"
#include "ecr_list.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define ECR_MEMPOOL_MIN     16

#define mempool_for_each(i) for (i = 0; i < ECR_MEMPOOL_LARGE; i = i ? i << 1 : ECR_MEMPOOL_MIN)

int ecr_mempool_init(ecr_mempool_t *pool) {
    int n, i;
    ecr_mempool_chain_t *chain;
    memset(pool, 0, sizeof(ecr_mempool_t));

    i = 0;
    mempool_for_each(n)
    {
        chain = calloc(1, sizeof(ecr_mempool_chain_t));
        chain->mem_size = n;
        pthread_rwlock_init(&chain->lock, NULL);
        while (i <= n) {
            pool->table[i++] = chain;
        }
    }

    return 0;
}

void * ecr_mempool_alloc(ecr_mempool_t *pool, size_t size) {
    ecr_mempool_chain_t *chain;
    ecr_mempool_node_t *node;
    size_t alloc;
    if (size == 0) {
        return NULL;
    }
    alloc = size + sizeof(ecr_mempool_node_t);
    chain = alloc < ECR_MEMPOOL_LARGE ? pool->table[alloc] : pool->table[0];
    pthread_rwlock_rdlock(&chain->lock);
    linked_list_pop(chain, node);
    if (node) {
        chain->spare--;
        memset(node->mem, 0, size);
    } else {
        node = calloc(1, chain->mem_size ? chain->mem_size : alloc);
        if (!node) {
            return NULL;
        }
        node->mem_size = chain->mem_size;
        chain->alloc++;
    }
    pthread_rwlock_unlock(&chain->lock);
    return node->mem;
}

void * ecr_mempool_realloc(ecr_mempool_t *pool, void *ptr, size_t new_size) {
    ecr_mempool_node_t *node;
    void *new_ptr;

    node = (ecr_mempool_node_t*) (((u_char*) ptr) - sizeof(ecr_mempool_node_t));
    if (node->mem_size >= new_size) {
        return ptr;
    }
    ecr_mempool_free(pool, ptr);
    new_ptr = ecr_mempool_alloc(pool, new_size);
    memcpy(new_ptr, ptr, node->mem_size);
    return new_ptr;
}

void ecr_mempool_free(ecr_mempool_t *pool, void *ptr) {
    ecr_mempool_node_t *node;
    ecr_mempool_chain_t *chain;
    if (!ptr) {
        return;
    }
    node = (ecr_mempool_node_t*) (((u_char*) ptr) - sizeof(ecr_mempool_node_t));
    chain = pool->table[node->mem_size];
    pthread_rwlock_rdlock(&chain->lock);
    linked_list_push(chain, node);
    chain->spare++;
    pthread_rwlock_unlock(&chain->lock);
}

static void ecr_mempool_node_list_free(ecr_mempool_chain_t *list) {
    ecr_mempool_node_t *node = list->head, *next;

    while (node) {
        next = node->next;
        free(node);
        node = next;
    }
}

void ecr_mempool_balance(ecr_mempool_t *pools, int n) {
    int i, j;
    ecr_mempool_chain_t *chain, tmp_chain[1];
    ecr_mempool_node_t *node;
    size_t spare, balance;

    mempool_for_each(i)
    {
        spare = 0;
        for (j = 0; j < n; j++) {
            chain = pools[j].table[i];
            pthread_rwlock_wrlock(&chain->lock);
            spare += chain->spare;
        }
        balance = spare / n;
        if (balance) {
            balance++;
            memset(tmp_chain, 0, sizeof(ecr_mempool_chain_t));
            for (j = 0; j < n; j++) {
                chain = pools[j].table[i];
                while (chain->spare > balance) {
                    linked_list_pop(chain, node);
                    if (node) {
                        linked_list_push(tmp_chain, node);
                        chain->spare--;
                    } else {
                        break;
                    }
                }
            }
            for (j = 0; j < n; j++) {
                chain = pools[j].table[i];
                while (chain->spare < balance) {
                    linked_list_pop(tmp_chain, node);
                    if (node) {
                        linked_list_push(chain, node);
                        chain->spare++;
                    } else {
                        break;
                    }
                }
            }
            assert(tmp_chain->head==NULL);
        }
        for (j = 0; j < n; j++) {
            pthread_rwlock_unlock(&pools[j].table[i]->lock);
        }
    }
}

void ecr_mempool_stats(ecr_mempool_t *pool, ecr_mempool_stat_t *stat) {
    int n, level;
    ecr_mempool_chain_t *chain;

    level = 0;
    memset(stat, 0, sizeof(ecr_mempool_stat_t));
    mempool_for_each(n)
    {
        chain = pool->table[n];
        stat->levels[level].mem_size = chain->mem_size;
        stat->levels[level].spare = chain->spare;
        stat->levels[level].alloc = chain->alloc;
        level++;
    }
}

void ecr_mempool_destroy(ecr_mempool_t *pool) {
    int n;
    ecr_mempool_chain_t *chain;

    mempool_for_each(n)
    {
        chain = pool->table[n];
        if (chain) {
            ecr_mempool_node_list_free(chain);
            pthread_rwlock_destroy(&chain->lock);
            free(chain);
            pool->table[n] = NULL;
        }
    }
}
