/*
 * ecr_rebalancer.c
 *
 *  Created on: Aug 15, 2016
 *      Author: velna
 */

#include "config.h"
#include "ecr_rebalancer.h"
#include "ecr_list.h"
#include <stdlib.h>

int ecr_rebalancer_init(ecr_rebalancer_t *rb, int num_workers, ecr_rebalance_cb rebalance_cb,
        ecr_reblance_hash_func hash_func) {
    int i;

    rb->num_workers = num_workers;
    rb->hash_func = hash_func;
    rb->rebalance_cb = rebalance_cb;
    rb->workers = calloc(num_workers, sizeof(ecr_rebalance_worker_t));

    for (i = 0; i < num_workers; i++) {
        pthread_mutex_init(&rb->workers[i].queue_lock, NULL);
    }
    return 0;
}

void ecr_rebalance(ecr_rebalancer_t *rb, int tid, ecr_rebalance_data_t *data) {
    uint32_t hash = rb->hash_func(data);
    int i = hash % rb->num_workers;
    ecr_rebalance_worker_t *worker = &rb->workers[i];
    ecr_rebalace_queue_t *queue = worker->queue, polled_queue[1];
    ecr_rebalance_data_t *polled_data;

    pthread_mutex_lock(&worker->queue_lock);
    linked_list_add_last(queue, data);
    if (i != tid) {
        pthread_mutex_unlock(&worker->queue_lock);
        worker = &rb->workers[tid];
        queue = worker->queue;
        if (!queue->head) {
            return;
        }
        pthread_mutex_lock(&worker->queue_lock);
    }
    polled_queue->head = queue->head;
    polled_queue->tail = queue->tail;
    queue->head = NULL;
    queue->tail = NULL;
    pthread_mutex_unlock(&worker->queue_lock);

    linked_list_remove_first(polled_queue, polled_data);
    while (polled_data) {
        rb->rebalance_cb(rb, tid, polled_data);
        linked_list_remove_first(polled_queue, polled_data);
    }
}

void ecr_rebalancer_destroy(ecr_rebalancer_t *rb) {
    int i;
    ecr_rebalance_data_t *data, *next;

    for (i = 0; i < rb->num_workers; i++) {
        data = rb->workers[i].queue->head;
        while (data) {
            next = data->next;
            rb->rebalance_cb(rb, i, data);
            data = next;
        }
    }
    free(rb->workers);
}

