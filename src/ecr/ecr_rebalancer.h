/*
 * ecr_rebalancer.h
 *
 *  Created on: Aug 15, 2016
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_REBALANCER_H_
#define SRC_ECR_ECR_REBALANCER_H_

#include "ecrconf.h"
#include <pthread.h>

typedef struct ecr_rebalancer_s ecr_rebalancer_t;

typedef struct ecr_rebalance_data_s {
    struct ecr_rebalance_data_s *next;
    struct ecr_rebalance_data_s *prev;
    void *data;
} ecr_rebalance_data_t;

typedef void (*ecr_rebalance_cb)(ecr_rebalancer_t *rebalancer, int tid, ecr_rebalance_data_t *data);
typedef uint32_t (*ecr_reblance_hash_func)(ecr_rebalance_data_t *data);

typedef struct {
    ecr_rebalance_data_t *head;
    ecr_rebalance_data_t *tail;
} ecr_rebalace_queue_t;

typedef struct {
    pthread_mutex_t queue_lock;
    ecr_rebalace_queue_t queue[1];
} ecr_rebalance_worker_t;

struct ecr_rebalancer_s {
    ecr_rebalance_worker_t *workers;
    int num_workers;
    ecr_rebalance_cb rebalance_cb;
    ecr_reblance_hash_func hash_func;
};

int ecr_rebalancer_init(ecr_rebalancer_t *rb, int num_workers, ecr_rebalance_cb rebalance_cb,
        ecr_reblance_hash_func hash_func);

void ecr_rebalance(ecr_rebalancer_t *rb, int tid, ecr_rebalance_data_t *data);

void ecr_rebalancer_destroy(ecr_rebalancer_t *rb);

#endif /* SRC_ECR_ECR_REBALANCER_H_ */
