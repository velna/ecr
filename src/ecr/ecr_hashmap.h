/*
 * ecr_hashmap.h
 *
 *  Created on: Nov 20, 2012
 *      Author: velna
 */

#ifndef ECR_HASHMAP_H_
#define ECR_HASHMAP_H_

#include "ecrconf.h"
#include <pthread.h>

#define HASHMAP_NOLOCK      0x01
#define HASHMAP_NOREHASH    0x02
#define HASHMAP_NOCOPYKEY   0x04

typedef struct ecr_hash_node {
    void * key;
    void * value;
    uint32_t hash;
    struct ecr_hash_node * next;
    size_t key_size;
} ecr_hash_node_t;

typedef struct {
    size_t size;
    size_t init_capacity;
    size_t capacity;
    float load_factor;
    uint32_t seed;
    int lock :1;
    int rehash :1;
    int nocopykey :1;
    ecr_hash_node_t **table;
    pthread_rwlock_t rwlock;
} ecr_hashmap_t;

typedef struct {
    ecr_hashmap_t *map;
    size_t index;
    ecr_hash_node_t *cur;
    ecr_hash_node_t *next;
    ecr_hash_node_t *prev;
} ecr_hashmap_iter_t;

typedef void (*ecr_hashmap_handler)(ecr_hashmap_t *map, void *key, size_t key_size, void *value);
typedef void (*ecr_hashmap_handler_ex)(ecr_hashmap_t *map, void *key, size_t key_size, void *value, void *user);

int ecr_hashmap_init(ecr_hashmap_t *map, size_t capacity, int flag);

void * ecr_hashmap_put(ecr_hashmap_t *map, const void *key, size_t key_size, void *value);

void * ecr_hashmap_get(ecr_hashmap_t *map, const void *key, size_t key_size);

void * ecr_hashmap_get_or_create(ecr_hashmap_t *map, const void *key, size_t key_size,
        void*(*create_func)(ecr_hashmap_t *map, const void *key, size_t key_size, void *user), void *user);

void * ecr_hashmap_remove(ecr_hashmap_t *map, const void *key, size_t key_size);

size_t ecr_hashmap_size(ecr_hashmap_t *map);

size_t ecr_hashmap_capacity(ecr_hashmap_t *map);

void ecr_hashmap_clear(ecr_hashmap_t *map, ecr_hashmap_handler handler);

void ecr_hashmap_clear_ex(ecr_hashmap_t *map, ecr_hashmap_handler_ex handler, void *user);

void ecr_hashmap_iterate(ecr_hashmap_t *map, ecr_hashmap_handler handler);

int ecr_hashmap_iter_init(ecr_hashmap_iter_t *i, ecr_hashmap_t *map);

int ecr_hashmap_iter_next(ecr_hashmap_iter_t *i, void **key, size_t *key_size, void **value);

int ecr_hashmap_iter_remove(ecr_hashmap_iter_t *i);

void ecr_hashmap_destroy(ecr_hashmap_t *map, ecr_hashmap_handler handler);

void ecr_hashmap_destroy_ex(ecr_hashmap_t *map, ecr_hashmap_handler_ex handler, void *user);

void ecr_hashmap_free_value_handler(ecr_hashmap_t *map, void *key, size_t key_size, void *value);

#endif /* ECR_HASHMAP_H_ */
