/*
 * ecr_heap.c
 *
 *  Created on: Jul 19, 2013
 *      Author: velna
 */

#include "config.h"
#include "ecr_heap.h"
#include <stdlib.h>
#include <string.h>

static inline int ecr_heap_pop0(ecr_heap_t * heap, int i, ecr_heap_node_t * node);

int ecr_heap_init(ecr_heap_t * heap, size_t capacity) {
    heap->capacity = capacity;
    heap->size = 0;
    heap->nodes = malloc(capacity * sizeof(ecr_heap_node_t));
    return 0;
}

int ecr_heap_push(ecr_heap_t * heap, u_int32_t value, void * data) {
    if (heap->size == heap->capacity) {
        heap->capacity = heap->capacity << 1;
        void * p = realloc(heap->nodes, heap->capacity * sizeof(ecr_heap_node_t));
        if (NULL == p) {
            return -1;
        }
        heap->nodes = p;
    }

    heap->nodes[heap->size].value = value;
    heap->nodes[heap->size].data = data;
    heap->size++;

    ecr_heap_node_t t_node;
    int i = heap->size - 1;
    int j = (i - 1) / 2;
    while (j >= 0 && heap->nodes[i].value < heap->nodes[j].value) {
        //Swap the two value
        t_node = heap->nodes[i];
        heap->nodes[i] = heap->nodes[j];
        heap->nodes[j] = t_node;
        i = j;
        j = (i - 1) / 2;
    }

    return 0;
}

#define SWAP(i, j)	\
	t_node = heap->nodes[i]; \
	heap->nodes[i] = heap->nodes[j]; \
	heap->nodes[j] = t_node; \
	i = j;

#define REPLACE(i, j)	\
	heap->nodes[i] = heap->nodes[j]; \
	i = j;

static inline int ecr_heap_pop0(ecr_heap_t * heap, int i, ecr_heap_node_t * node) {
    if (node) {
        *node = heap->nodes[i];
    }
    int i_left, i_right, i_replace, f;
    while (i * 2 < heap->size) {
        i_left = (i * 2 + 1 < heap->size) ? (i * 2 + 1) : 0;
        i_right = (i * 2 + 2 < heap->size) ? (i * 2 + 2) : 0;
        i_replace = i;
        f = 0;
        if (i_left && i_right) { // Both left and right exists.
            if (heap->nodes[i_left].value < heap->nodes[i_right].value) {
                i_replace = i_left;
            } else {
                i_replace = i_right;
            }
        } else if (i_left) { //The i_right must be 0
            i_replace = i_left;
            f = 1;
        } else {
            f = 1;
        }
        if (i_replace != i) {
            if (heap->nodes[i_replace].value < heap->nodes[heap->size - 1].value) {
                REPLACE(i, i_replace);
            } else {
                f = 1;
            }
        }
        if (f) {
            break;
        }
    }
    REPLACE(i, heap->size - 1);
    heap->size--;
    return 0;
}

int ecr_heap_remove(ecr_heap_t * heap, int i, ecr_heap_node_t * node) {
    if (heap->size <= i) {
        return -1;
    }
    return ecr_heap_pop0(heap, i, node);
}

int ecr_heap_pop_if_le(ecr_heap_t * heap, u_int32_t value, ecr_heap_node_t * node) {
    if (heap->size == 0 || heap->nodes[0].value > value) {
        return -1;
    }
    return ecr_heap_pop0(heap, 0, node);
}

int ecr_heap_pop(ecr_heap_t * heap, ecr_heap_node_t * node) {
    if (heap->size == 0) {
        return -1;
    }
    return ecr_heap_pop0(heap, 0, node);
}

int ecr_heap_peek(ecr_heap_t * heap, ecr_heap_node_t * node) {
    if (heap->size == 0) {
        return -1;
    }
    *node = heap->nodes[0];
    return 0;
}

void ecr_heap_print(ecr_heap_t * heap, FILE * out) {
    if (NULL == out) {
        out = stdout;
    }
    size_t i, ln = 2;
    for (i = 0; i < heap->size; i++) {
        if (i == ln - 1) {
            fprintf(out, "\n");
            ln = ln << 1;
        }
        fprintf(out, "%d[%p] ", heap->nodes[i].value, heap->nodes[i].data);
    }
    fprintf(out, "\n\n");
}

void ecr_heap_destroy(ecr_heap_t * heap) {
    free(heap->nodes);
}
