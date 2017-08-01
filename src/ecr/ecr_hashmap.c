/*
 * ecr_hashmap.c
 *
 *  Created on: Nov 20, 2012
 *      Author: root
 */

#include "config.h"
#include "ecr_hashmap.h"
#include "ecr_util.h"
#include <stdlib.h>
#include <string.h>

static inline u_int32_t ecr_x_hash(ecr_hashmap_t *map, const void *key, int key_size, u_int32_t *hash_out) {
    ecr_crc32_hash_mix(key, key_size, map->seed, hash_out);
    return (*hash_out) % map->capacity;
}

int ecr_hashmap_init(ecr_hashmap_t *map, size_t capacity, int flag) {
    memset(map, 0, sizeof(ecr_hashmap_t));
    map->load_factor = .75;
    map->init_capacity = capacity;
    map->capacity = capacity / map->load_factor;
    map->seed = (u_int32_t) time(NULL);
    map->table = calloc(map->capacity, sizeof(ecr_hash_node_t*));
    if ((flag & HASHMAP_NOLOCK) == 0) {
        map->lock = 1;
        pthread_rwlock_init(&map->rwlock, NULL);
    }
    if ((flag & HASHMAP_NOREHASH) == 0) {
        map->rehash = 1;
    }
    if (flag & HASHMAP_NOCOPYKEY) {
        map->nocopykey = 1;
    }
    return 0;
}

static void ecr_re_hash(ecr_hashmap_t *map, size_t newcapacity) {
    int i;
    size_t bucket;
    ecr_hash_node_t *node, *next;
    ecr_hash_node_t **new_table = calloc(newcapacity, sizeof(ecr_hash_node_t*));
    for (i = 0; i < map->capacity; i++) {
        node = map->table[i];
        while (node) {
            next = node->next;
            bucket = node->hash % newcapacity;
            node->next = new_table[bucket];
            new_table[bucket] = node;
            node = next;
        }
    }
    free(map->table);
    map->table = new_table;
    map->capacity = newcapacity;
}

static inline void check_capacity(ecr_hashmap_t *map) {
    double lf = map->size * 1.0 / map->capacity;
    if (lf > map->load_factor) {
        ecr_re_hash(map, map->capacity * 2);
    } else if (map->capacity > map->init_capacity && lf < map->load_factor / 4) {
        ecr_re_hash(map, map->capacity / 2);
    }
}

void * ecr_hashmap_put(ecr_hashmap_t *map, const void *key, size_t key_size, void *value) {
    void *ret = NULL;
    u_int32_t hash;
    size_t bucket;
    ecr_hash_node_t *head;
    ecr_hash_node_t *node;

    if (map->lock) {
        pthread_rwlock_wrlock(&map->rwlock);
    }
    bucket = ecr_x_hash(map, key, key_size, &hash);
    node = head = map->table[bucket];
    while (node) {
        if (hash == node->hash && key_size == node->key_size && memcmp(node->key, key, key_size) == 0) {
            ret = node->value;
            if (map->nocopykey) {
                node->key = (void *) key;
            }
            node->value = value;
            break;
        } else {
            node = node->next;
        }
    }
    if (!node) {
        if (map->nocopykey) {
            node = malloc(sizeof(ecr_hash_node_t));
            node->key = (void *) key;
        } else {
            node = malloc(sizeof(ecr_hash_node_t) + key_size);
            node->key = ((char*) node) + sizeof(ecr_hash_node_t);
            memcpy(node->key, key, key_size);
        }
        node->key_size = key_size;
        node->hash = hash;
        node->value = value;
        node->next = head;
        map->table[bucket] = node;
        map->size++;
        if (map->rehash) {
            check_capacity(map);
        }
    }
    if (map->lock) {
        pthread_rwlock_unlock(&map->rwlock);
    }
    return ret;
}

void ecr_hashmap_put_all(ecr_hashmap_t *src, ecr_hashmap_t *dst) {
    ecr_hash_node_t *node;
    int i;
    if (src->lock) {
        pthread_rwlock_rdlock(&src->rwlock);
    }
    for (i = 0; i < src->capacity; i++) {
        node = src->table[i];
        while (node) {
            ecr_hashmap_put(dst, node->key, node->key_size, node->value);
            node = node->next;
        }
    }
    if (src->lock) {
        pthread_rwlock_unlock(&src->rwlock);
    }
}

void * ecr_hashmap_get(ecr_hashmap_t *map, const void *key, size_t key_size) {
    void *ret = NULL;
    u_int32_t hash;
    size_t bucket;
    ecr_hash_node_t *node;

    if (map->lock) {
        pthread_rwlock_rdlock(&map->rwlock);
    }
    if (map->size) {
        bucket = ecr_x_hash(map, key, key_size, &hash);
        node = map->table[bucket];
        while (node) {
            if (hash == node->hash && key_size == node->key_size && memcmp(node->key, key, key_size) == 0) {
                ret = node->value;
                break;
            } else {
                node = node->next;
            }
        }
    }
    if (map->lock) {
        pthread_rwlock_unlock(&map->rwlock);
    }
    return ret;
}

void * ecr_hashmap_get_or_create(ecr_hashmap_t *map, const void *key, size_t key_size,
        void*(*create_func)(ecr_hashmap_t *map, const void *key, size_t key_size, void *user), void *user) {
    void *ret = NULL;
    u_int32_t hash;
    size_t bucket;
    ecr_hash_node_t *node = NULL;
    ecr_hash_node_t *head;

    if (map->lock) {
        pthread_rwlock_rdlock(&map->rwlock);
    }
    if (map->size) {
        bucket = ecr_x_hash(map, key, key_size, &hash);
        node = head = map->table[bucket];
        while (node) {
            if (hash == node->hash && key_size == node->key_size && memcmp(node->key, key, key_size) == 0) {
                ret = node->value;
                break;
            } else {
                node = node->next;
            }
        }
    }
    if (!node) {
        if (map->lock) {
            pthread_rwlock_unlock(&map->rwlock);
            pthread_rwlock_wrlock(&map->rwlock);
        }
        bucket = ecr_x_hash(map, key, key_size, &hash);
        node = head = map->table[bucket];
        while (node) {
            if (hash == node->hash && key_size == node->key_size && memcmp(node->key, key, key_size) == 0) {
                ret = node->value;
                break;
            } else {
                node = node->next;
            }
        }
        if (!node) {
            if (map->nocopykey) {
                node = malloc(sizeof(ecr_hash_node_t));
                node->key = (void *) key;
            } else {
                node = malloc(sizeof(ecr_hash_node_t) + key_size);
                node->key = ((char*) node) + sizeof(ecr_hash_node_t);
                memcpy(node->key, key, key_size);
            }
            node->key_size = key_size;
            node->hash = hash;
            node->value = ret = create_func(map, node->key, node->key_size, user);
            node->next = head;
            map->table[bucket] = node;
            map->size++;
            if (map->rehash) {
                check_capacity(map);
            }
        }
    }
    if (map->lock) {
        pthread_rwlock_unlock(&map->rwlock);
    }
    return ret;
}

void * ecr_hashmap_remove(ecr_hashmap_t *map, const void *key, size_t key_size) {
    void *ret = NULL;
    u_int32_t hash;
    size_t bucket;
    ecr_hash_node_t *prev = NULL;
    ecr_hash_node_t *node;

    if (map->lock) {
        pthread_rwlock_wrlock(&map->rwlock);
    }
    if (map->size) {
        bucket = ecr_x_hash(map, key, key_size, &hash);
        node = map->table[bucket];
        while (node) {
            if (hash == node->hash && key_size == node->key_size && memcmp(node->key, key, key_size) == 0) {
                ret = node->value;
                if (NULL != prev) {
                    prev->next = node->next;
                } else {
                    map->table[bucket] = node->next;
                }
                map->size--;
                free(node);
                break;
            } else {
                prev = node;
                node = node->next;
            }
        }
    }
    if (map->lock) {
        pthread_rwlock_unlock(&map->rwlock);
    }
    return ret;
}

size_t ecr_hashmap_size(ecr_hashmap_t *map) {
    return map->size;
}

size_t ecr_hashmap_capacity(ecr_hashmap_t *map) {
    return map->capacity;
}

static void ecr_hashmap_ex_handler_adaptor(ecr_hashmap_t *map, void *key, size_t key_size, void *value, void *user) {
    ((ecr_hashmap_handler) user)(map, key, key_size, value);
}

void ecr_hashmap_clear(ecr_hashmap_t *map, ecr_hashmap_handler handler) {
    ecr_hashmap_clear_ex(map, handler ? ecr_hashmap_ex_handler_adaptor : NULL, handler);
}

void ecr_hashmap_clear_ex(ecr_hashmap_t *map, ecr_hashmap_handler_ex handler, void *user) {
    u_int i;
    ecr_hash_node_t *node, *tmp_node;

    if (map->lock) {
        pthread_rwlock_wrlock(&map->rwlock);
    }
    if (map->size) {
        for (i = 0; i < map->capacity; i++) {
            node = map->table[i];
            while (NULL != node) {
                if (NULL != handler) {
                    handler(map, node->key, node->key_size, node->value, user);
                }
                tmp_node = node->next;
                free(node);
                node = tmp_node;
            }
            map->table[i] = NULL;
        }
        map->size = 0;
    }

    if (map->lock) {
        pthread_rwlock_unlock(&map->rwlock);
    }
}

void ecr_hashmap_destroy(ecr_hashmap_t *map, ecr_hashmap_handler handler) {
    ecr_hashmap_destroy_ex(map, handler ? ecr_hashmap_ex_handler_adaptor : NULL, handler);
}

void ecr_hashmap_destroy_ex(ecr_hashmap_t *map, ecr_hashmap_handler_ex handler, void *user) {
    ecr_hashmap_clear_ex(map, handler, user);
    free(map->table);
    if (map->lock) {
        pthread_rwlock_destroy(&map->rwlock);
    }
    memset(map, 0, sizeof(ecr_hashmap_t));
}

void ecr_hashmap_iterate(ecr_hashmap_t *map, ecr_hashmap_handler handler) {
    u_int i;
    ecr_hash_node_t *node;

    if (map->lock) {
        pthread_rwlock_rdlock(&map->rwlock);
    }
    for (i = 0; i < map->capacity; i++) {
        node = map->table[i];
        while (NULL != node) {
            handler(map, node->key, node->key_size, node->value);
            node = node->next;
        }
    }
    if (map->lock) {
        pthread_rwlock_unlock(&map->rwlock);
    }
}

int ecr_hashmap_iter_init(ecr_hashmap_iter_t *i, ecr_hashmap_t *map) {
    memset(i, 0, sizeof(ecr_hashmap_iter_t));
    i->map = map;
    i->index = -1;
    return 0;
}

int ecr_hashmap_iter_remove(ecr_hashmap_iter_t *i) {
    ecr_hashmap_t *map = i->map;
    int rc = -1;
    if (map->lock) {
        pthread_rwlock_wrlock(&map->rwlock);
    }
    if (i->cur) {
        if (i->prev) {
            i->prev->next = i->cur->next;
        } else {
            map->table[i->index] = i->cur->next;
        }
        map->size--;
        free(i->cur);
        i->cur = NULL;
        rc = 0;
    }
    if (map->lock) {
        pthread_rwlock_unlock(&map->rwlock);
    }
    return rc;
}

int ecr_hashmap_iter_next(ecr_hashmap_iter_t *i, void**key, size_t *key_size, void**value) {
    ecr_hashmap_t *map = i->map;
    int rc = -1;

    if (map->lock) {
        pthread_rwlock_rdlock(&map->rwlock);
    }
    if (!i->next) {
        i->prev = NULL;
        i->cur = NULL;
        while (++(i->index) < map->capacity && (i->next = map->table[i->index]) == NULL) {
            ;
        }
    }
    if (i->next) {
        if (i->cur) {
            i->prev = i->cur;
        }
        i->cur = i->next;
        if (key) {
            *key = i->cur->key;
        }
        if (key_size) {
            *key_size = i->cur->key_size;
        }
        if (value) {
            *value = i->cur->value;
        }
        i->next = i->cur->next;
        rc = 0;
    }
    if (map->lock) {
        pthread_rwlock_unlock(&map->rwlock);
    }
    return rc;
}

ECR_INLINE void ecr_hashmap_free_value_handler(ecr_hashmap_t *map, void *key, size_t key_size, void *value) {
    free(value);
}
