/*
 * ecr_worker_pool.c
 *
 *  Created on: May 10, 2017
 *      Author: velna
 */

#include "config.h"
#include "ecr_worker_pool.h"
#include "ecr_util.h"
#include <stdlib.h>

int ecr_worker_pool_init(ecr_worker_pool_t *pool, ecr_worker_pool_config_t *config) {
    pool->config = *config;
    pool->sched_work_space.worker.alive = 1;
    pool->sched_work_space.worker.pool = pool;
    pool->sched_work_space.worker.id = -1;
    pool->sched_work_space.worker.thread = 0;
    ecr_list_init(&pool->listeners, 4);
    ecr_list_init(&pool->work_spaces, config->init_size);
    pthread_mutex_init(&pool->lock, NULL);
    return 0;
}

void ecr_worker_pool_add_listener(ecr_worker_pool_t *pool, ecr_worker_pool_listener_t *l) {
    ecr_worker_pool_listener_t *listener = calloc(1, sizeof(ecr_worker_pool_listener_t));
    *listener = *l;
    ecr_list_add(&pool->listeners, listener);
}

static void * ecr_worker_routine(void *user) {
    ecr_work_space_t *work_space = user;
    ecr_worker_pool_t *pool = work_space->worker.pool;
    ecr_worker_pool_listener_t *listener;
    int i;

    ecr_set_thread_name("wp-%d", work_space->worker.id);

    pthread_mutex_lock(&pool->lock);
    for (i = 0; i < ecr_list_size(&pool->listeners); i++) {
        listener = ecr_list_get(&pool->listeners, i);
        listener->init(&work_space->worker, listener->user);
    }
    pthread_mutex_unlock(&pool->lock);

    work_space->worker_cb(&work_space->worker, work_space->data);

    pthread_mutex_lock(&pool->lock);
    for (i = 0; i < ecr_list_size(&pool->listeners); i++) {
        listener = ecr_list_get(&pool->listeners, i);
        listener->destroy(&work_space->worker, listener->user);
    }
    pthread_mutex_unlock(&pool->lock);

    return NULL;
}

static int ecr_worker_new(ecr_worker_pool_t *pool, ecr_worker_cb cb, void *data) {
    ecr_work_space_t *work_space;
    size_t n = ecr_list_size(&pool->work_spaces);

    if (n < pool->config.max_size) {
        work_space = calloc(1, sizeof(ecr_work_space_t));
        work_space->worker_cb = cb;
        work_space->data = data;
        work_space->worker.id = ecr_list_size(&pool->work_spaces);
        work_space->worker.pool = pool;
        work_space->worker.alive = 1;
        ecr_list_add(&pool->work_spaces, work_space);
        pthread_create(&work_space->worker.thread, NULL, ecr_worker_routine, work_space);
        return 0;
    } else {
        return -1;
    }
}

static int ecr_worker_die(ecr_worker_pool_t *pool, int force) {
    ecr_work_space_t *work_space;
    size_t n = ecr_list_size(&pool->work_spaces);
    if (force || n > pool->config.min_size) {
        work_space = ecr_list_remove_at(&pool->work_spaces, n - 1);
        work_space->worker.alive = 0;
        pthread_join(work_space->worker.thread, NULL);
        free(work_space);
        return 0;
    } else {
        return -1;
    }
}

static void * ecr_worker_schedule_routine(void *user) {
    ecr_work_space_t *sched_ws = user;
    ecr_worker_pool_t *pool = sched_ws->worker.pool;
    int i;

    ecr_set_thread_name("wp-sched");

    for (i = 0; i < pool->config.init_size; i++) {
        ecr_worker_new(pool, sched_ws->worker_cb, sched_ws->data);
    }

    while (sched_ws->worker.alive) {

    }

    while (ecr_worker_die(pool, 1) == 0) {
        ;
    }

    return NULL;
}

void ecr_worker_pool_run(ecr_worker_pool_t *pool, ecr_worker_cb cb, void *data) {
    if (!pool->sched_work_space.worker.thread) {
        pool->sched_work_space.worker_cb = cb;
        pool->sched_work_space.data = data;
        pthread_create(&pool->sched_work_space.worker.thread, NULL, ecr_worker_schedule_routine,
                &pool->sched_work_space);
    }
}

void ecr_worker_pool_destroy(ecr_worker_pool_t *pool) {
    pool->sched_work_space.worker.alive = 0;
    pthread_join(pool->sched_work_space.worker.thread, NULL);
    ecr_list_destroy(&pool->work_spaces, ecr_list_free_value_handler);
    ecr_list_destroy(&pool->listeners, ecr_list_free_value_handler);
    pthread_mutex_destroy(&pool->lock);
}
