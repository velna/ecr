/*
 * ecr_fixedhashmap.h
 *
 *  Created on: Jun 11, 2014
 *      Author: velna
 */

#ifndef ECR_FIXEDHASHMAP_H_
#define ECR_FIXEDHASHMAP_H_

#include "ecrconf.h"
#include "ecr_hashmap.h"
#include "ecr_list.h"

typedef int64_t ecr_fixedhash_key_t;

typedef struct {
    ecr_hashmap_t key_map;
    ecr_list_t keys;
} ecr_fixedhash_ctx_t;

typedef struct {
    ecr_fixedhash_ctx_t *ctx;
    int capacity;
    void *table[];
} ecr_fixedhash_t;

typedef struct {
    ecr_fixedhash_key_t idx;
    ecr_fixedhash_t *map;
} ecr_fixedhash_iter_t;

int ecr_fixedhash_ctx_init(ecr_fixedhash_ctx_t *ctx, const ecr_str_t* keys, int n);

int ecr_fixedhash_ctx_init_string(ecr_fixedhash_ctx_t *ctx, const char *keys);

size_t ecr_fixedhash_ctx_max_keys(ecr_fixedhash_ctx_t *ctx);

void ecr_fixedhash_ctx_destroy(ecr_fixedhash_ctx_t *ctx);

size_t ecr_fixedhash_sizeof(ecr_fixedhash_ctx_t *ctx);

ecr_fixedhash_t * ecr_fixedhash_init(ecr_fixedhash_ctx_t *ctx, void *mem, size_t mem_size);

int ecr_fixedhash_put(ecr_fixedhash_t *map, ecr_fixedhash_key_t key, void *value);

int ecr_fixedhash_put_original(ecr_fixedhash_t *map, const void *key, size_t key_len, void *value);

void * ecr_fixedhash_get(ecr_fixedhash_t *map, ecr_fixedhash_key_t key);

ecr_fixedhash_key_t ecr_fixedhash_getkey(ecr_fixedhash_ctx_t *ctx, const void *key, size_t key_len);

int ecr_fixedhash_iter_init(ecr_fixedhash_iter_t *iter, ecr_fixedhash_t *map);

void * ecr_fixedhash_iter_next(ecr_fixedhash_iter_t *iter, ecr_fixedhash_key_t *key_out, ecr_str_t *org_key_out);

#endif /* ECR_FIXEDHASHMAP_H_ */
