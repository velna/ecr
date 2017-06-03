/*
 * ecr_worker_pool.h
 *
 *  Created on: May 10, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_WORKER_POOL_H_
#define SRC_ECR_ECR_WORKER_POOL_H_

#include <pthread.h>
#include "ecr_list.h"

typedef struct ecr_worker_s ecr_worker_t;
typedef struct ecr_worker_pool_s ecr_worker_pool_t;

typedef void (*ecr_worker_cb)(ecr_worker_t *worker, void *data);

typedef struct {
    int init_size;
    int min_size;
    int max_size;
} ecr_worker_pool_config_t;

struct ecr_worker_s {
    int id;
    volatile int alive;
    ecr_worker_pool_t *pool;
    pthread_t thread;
};

typedef struct {
    ecr_worker_t worker;
    ecr_worker_cb worker_cb;
    void *data;
} ecr_work_space_t;

struct ecr_worker_pool_s {
    ecr_worker_pool_config_t config;
    pthread_mutex_t lock;
    ecr_list_t work_spaces;
    ecr_list_t listeners;
    ecr_work_space_t sched_work_space;
};

typedef struct {
    void *user;
    void (*init)(ecr_worker_t *worker, void *user);
    void (*destroy)(ecr_worker_t *worker, void *user);
} ecr_worker_pool_listener_t;

int ecr_worker_pool_init(ecr_worker_pool_t *pool, ecr_worker_pool_config_t *config);

void ecr_worker_pool_add_listener(ecr_worker_pool_t *pool, ecr_worker_pool_listener_t *l);

void ecr_worker_pool_run(ecr_worker_pool_t *pool, ecr_worker_cb cb, void *data);

void ecr_worker_pool_destroy(ecr_worker_pool_t *pool);

#endif /* SRC_ECR_ECR_WORKER_POOL_H_ */
