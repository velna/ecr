/*
 * ecr_skiplist.h
 *
 *  Created on: Oct 30, 2015
 *      Author: velna
 */

#ifndef SRC_ECR_SKIPLIST_H_
#define SRC_ECR_SKIPLIST_H_

#include "ecrconf.h"

#define ECR_SKIPLIST_MAXLEVEL   8

typedef struct ecr_skiplist_node_s {
    void *value;
    struct ecr_skiplist_node_s *backward;
    struct ecr_skiplist_level_s {
        struct ecr_skiplist_node_s *forward;
    } level[];
} ecr_skiplist_node_t;

typedef struct {
    ecr_skiplist_node_t *header, *tail;
    size_t size;
    int level;
    ecr_compare_func compare;
} ecr_skiplist_t;

typedef struct {
//    ecr_skiplist_t *sl;
//    ecr_skiplist_node_t *current;
//    ecr_skiplist_node_t *update[ECR_SKIPLIST_MAXLEVEL];
    ecr_skiplist_node_t *next;
} ecr_skiplist_iter_t;

typedef void (*ecr_skiplist_handler_t)(ecr_skiplist_t *, void *value, void *user);

int ecr_skiplist_init(ecr_skiplist_t *sl, ecr_compare_func compare);

void ecr_skiplist_clear(ecr_skiplist_t *sl, ecr_skiplist_handler_t handler, void *user);

void ecr_skiplist_destroy(ecr_skiplist_t *sl, ecr_skiplist_handler_t handler, void *user);

size_t ecr_skiplist_size(ecr_skiplist_t *sl);

void * ecr_skiplist_head(ecr_skiplist_t *sl);

void * ecr_skiplist_tail(ecr_skiplist_t *sl);

void ecr_skiplist_add(ecr_skiplist_t *sl, void *value);

void * ecr_skiplist_set(ecr_skiplist_t *sl, void *value);

int ecr_skiplist_remove(ecr_skiplist_t *sl, void *value);

void * ecr_skiplist_find(ecr_skiplist_t *sl, void *value);

void * ecr_skiplist_find_lte(ecr_skiplist_t *sl, void *value);

void * ecr_skiplist_find_gte(ecr_skiplist_t *sl, void *value);

void ecr_skiplist_free_value_handler(ecr_skiplist_t *, void *value, void *user);

void ecr_skiplist_iter_init(ecr_skiplist_iter_t *iter, ecr_skiplist_t *sl);

void * ecr_skiplist_iter_next(ecr_skiplist_iter_t *iter);

#endif /* SRC_ECR_SKIPLIST_H_ */
