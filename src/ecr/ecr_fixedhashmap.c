/*
 * ecr_fixedhashmap.c
 *
 *  Created on: Jun 11, 2014
 *      Author: velna
 */

#include "config.h"
#include "ecr_fixedhashmap.h"
#include <string.h>
#include <stdlib.h>

int ecr_fixedhash_ctx_init(ecr_fixedhash_ctx_t *ctx, const ecr_str_t* keys, int n) {
    size_t i;
    ecr_str_t *k;

    ecr_hashmap_init(&ctx->key_map, n, 0);
    ecr_list_init(&ctx->keys, n);
    for (i = 0; i < n; i++) {
        ecr_hashmap_put(&ctx->key_map, keys[i].ptr, keys[i].len, (void*) (i + 1));
        k = malloc(sizeof(ecr_str_t));
        k->ptr = malloc(keys[i].len);
        memcpy(k->ptr, keys[i].ptr, keys[i].len);
        k->len = keys[i].len;
        ecr_list_add(&ctx->keys, k);
    }
    return 0;
}

int ecr_fixedhash_ctx_init_string(ecr_fixedhash_ctx_t *ctx, const char *keys) {
    char *k, *ss = NULL, *str;
    ecr_str_t *key;
    size_t i = 0;

    ecr_list_init(&ctx->keys, 16);
    ecr_hashmap_init(&ctx->key_map, 16, HASHMAP_NOLOCK);
    str = strdup(keys);
    k = strtok_r(str, ", ", &ss);
    while (k) {
        key = malloc(sizeof(ecr_str_t));
        key->ptr = strdup(k);
        key->len = strlen(k);
        ecr_hashmap_put(&ctx->key_map, key->ptr, key->len, (void*) (++i));
        ecr_list_add(&ctx->keys, key);
        k = strtok_r(NULL, ", ", &ss);
    }
    free(str);
    return 0;
}

static void ecr_fixedhash_free_handler(ecr_list_t *l, int i, void* value) {
    ecr_str_t *k = value;
    free_to_null(k->ptr);
    free(value);
}

size_t ecr_fixedhash_sizeof(ecr_fixedhash_ctx_t *ctx) {
    return sizeof(ecr_fixedhash_t) + ecr_list_size(&ctx->keys) * sizeof(void*);
}

size_t ecr_fixedhash_ctx_max_keys(ecr_fixedhash_ctx_t *ctx) {
    return ecr_list_size(&ctx->keys);
}

void ecr_fixedhash_ctx_destroy(ecr_fixedhash_ctx_t *ctx) {
    ecr_hashmap_destroy(&ctx->key_map, NULL);
    ecr_list_destroy(&ctx->keys, ecr_fixedhash_free_handler);
}

ecr_fixedhash_t * ecr_fixedhash_init(ecr_fixedhash_ctx_t *ctx, void *mem, size_t mem_size) {
    ecr_fixedhash_t *map = mem;
    size_t left = mem_size - sizeof(ecr_fixedhash_t);
    if (mem_size <= sizeof(ecr_fixedhash_t)) {
        return NULL;
    }
    memset(mem, 0, mem_size);
    map->capacity = left / sizeof(void*);
    map->capacity = map->capacity > ecr_hashmap_size(&ctx->key_map) ? ecr_hashmap_size(&ctx->key_map) : map->capacity;
    map->ctx = ctx;
    return map;
}

int ecr_fixedhash_put(ecr_fixedhash_t *map, ecr_fixedhash_key_t key, void *value) {
    if (key >= map->capacity || key < 0) {
        return -1;
    }
    map->table[key] = value;
    return 0;
}

int ecr_fixedhash_put_original(ecr_fixedhash_t *map, const void *key, size_t key_len, void *value) {
    ecr_fixedhash_key_t k;

    k = (ecr_fixedhash_key_t) ecr_hashmap_get(&map->ctx->key_map, key, key_len);
    if (k) {
        return ecr_fixedhash_put(map, k - 1, value);
    } else {
        return -1;
    }
}

void * ecr_fixedhash_get(ecr_fixedhash_t *map, ecr_fixedhash_key_t key) {
    if (key >= map->capacity || key < 0) {
        return NULL;
    }
    return map->table[key];
}

ecr_fixedhash_key_t ecr_fixedhash_getkey(ecr_fixedhash_ctx_t *ctx, const void *key, size_t key_len) {
    ecr_fixedhash_key_t k;

    k = (ecr_fixedhash_key_t) ecr_hashmap_get(&ctx->key_map, key, key_len);
    return k ? k - 1 : -1;
}

int ecr_fixedhash_iter_init(ecr_fixedhash_iter_t *iter, ecr_fixedhash_t *map) {
    iter->idx = -1;
    iter->map = map;
    return 0;
}

void * ecr_fixedhash_iter_next(ecr_fixedhash_iter_t *iter, ecr_fixedhash_key_t *key_out, ecr_str_t *org_key_out) {
    void *ret;
    while ((++iter->idx) < iter->map->capacity && iter->idx > 0) {
        ret = iter->map->table[iter->idx];
        if (ret) {
            if (key_out) {
                *key_out = iter->idx;
            }
            if (org_key_out) {
                *org_key_out = *((ecr_str_t*) ecr_list_get(&iter->map->ctx->keys, iter->idx));
            }
            return ret;
        }
    }
    return NULL;
}
