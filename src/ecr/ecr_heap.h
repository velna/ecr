/*
 * ecr_heap.h
 *
 *  Created on: Jul 19, 2013
 *      Author: velna
 */

#ifndef ECR_HEAP_H_
#define ECR_HEAP_H_

#include "ecrconf.h"
#include <stdio.h>

typedef struct {
    u_int32_t value;
    void *data;
} ecr_heap_node_t;

typedef struct {
    ecr_heap_node_t *nodes;
    size_t size;
    size_t capacity;
} ecr_heap_t;

int ecr_heap_init(ecr_heap_t *heap, size_t capacity);

int ecr_heap_push(ecr_heap_t *heap, u_int32_t value, void *data);

int ecr_heap_pop(ecr_heap_t *heap, ecr_heap_node_t *node);

int ecr_heap_remove(ecr_heap_t *heap, int i, ecr_heap_node_t *node);

int ecr_heap_pop_if_le(ecr_heap_t *heap, u_int32_t value, ecr_heap_node_t *node);

int ecr_heap_peek(ecr_heap_t *heap, ecr_heap_node_t *node);

void ecr_heap_print(ecr_heap_t *heap, FILE *out);

void ecr_heap_destroy(ecr_heap_t *heap);

#endif /* ECR_HEAP_H_ */
