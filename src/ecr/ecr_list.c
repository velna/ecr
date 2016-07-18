/*
 * ecr_list.c
 *
 *  Created on: Apr 9, 2013
 *      Author: velna
 */

#include "config.h"
#include "ecr_list.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>

ecr_list_t * ecr_list_new(size_t size) {
    ecr_list_t * l = malloc(sizeof(ecr_list_t));
    ecr_list_init(l, size);
    l->new = 1;
    return l;
}

int ecr_list_init_data(ecr_list_t *l, void **data, size_t size) {
    assert(l && size > 0 && data);
    memset(l, 0, sizeof(ecr_list_t));
    l->data = data;
    l->size = 0;
    l->capacity = size;
    pthread_rwlock_init(&l->rwlock, NULL);
    return 0;
}

int ecr_list_init(ecr_list_t *l, size_t size) {
    assert(l && size > 0);
    void **data = malloc(size * sizeof(void*));
    return ecr_list_init_data(l, data, size);
}

static void ecr_check_capacity(ecr_list_t *l, size_t size) {
    size_t new_capacity = l->capacity;
    while (new_capacity <= size) {
        new_capacity <<= 1;
    }
    if (new_capacity != l->capacity) {
        l->capacity = new_capacity;
        l->data = realloc(l->data, l->capacity * sizeof(void*));
    }
}

void ecr_list_add(ecr_list_t *l, void *value) {
    assert(l && value);
    pthread_rwlock_wrlock(&l->rwlock);
    ecr_check_capacity(l, l->size);
    l->data[l->size++] = value;
    pthread_rwlock_unlock(&l->rwlock);
}

void ecr_list_add_all(ecr_list_t *l, ecr_list_t *add) {
    assert(l && add);
    pthread_rwlock_wrlock(&l->rwlock);
    pthread_rwlock_rdlock(&add->rwlock);
    ecr_check_capacity(l, l->size + add->size);
    memcpy(l->data + l->size, add->data, add->size * sizeof(void*));
    l->size += add->size;
    pthread_rwlock_unlock(&add->rwlock);
    pthread_rwlock_unlock(&l->rwlock);
}

void ecr_list_insert(ecr_list_t *l, int i, void *value) {
    assert(l && value);
    pthread_rwlock_wrlock(&l->rwlock);
    assert(i >= 0 && i <= l->size);
    ecr_check_capacity(l, l->size);
    if (i == l->size) {
        l->data[l->size++] = value;
    } else {
        i = i < 0 ? 0 : i;
        memmove(l->data + i + 1, l->data + i, (l->size - i) * sizeof(void*));
        l->data[i] = value;
        l->size++;
    }
    pthread_rwlock_unlock(&l->rwlock);
}

void * ecr_list_get(ecr_list_t *l, int i) {
    void *ret = NULL;
    assert(l);
    pthread_rwlock_rdlock(&l->rwlock);
    assert(i >= 0 && i < l->size);
    ret = l->data[i];
    pthread_rwlock_unlock(&l->rwlock);
    return ret;
}

void * ecr_list_set(ecr_list_t *l, int i, void *value) {
    void * ret;
    assert(l && value);
    pthread_rwlock_rdlock(&l->rwlock);
    assert(i >= 0 && i < l->size);
    ret = l->data[i];
    l->data[i] = value;
    pthread_rwlock_unlock(&l->rwlock);
    return ret;
}

int ecr_list_remove(ecr_list_t *l, void *value) {
    int rc = -1, i;
    assert(l);
    if (value == NULL) {
        return -1;
    }
    pthread_rwlock_wrlock(&l->rwlock);
    for (i = 0; i < l->size; i++) {
        if (l->data[i] == value) {
            if (i < l->size - 1) {
                memmove(l->data + i, l->data + i + 1, (l->size - i - 1) * sizeof(void*));
            }
            l->size--;
            rc = 0;
            break;
        }
    }
    pthread_rwlock_unlock(&l->rwlock);
    return rc;
}

void * ecr_list_remove_at(ecr_list_t *l, int i) {
    void * ret;
    assert(l);
    pthread_rwlock_wrlock(&l->rwlock);
    assert(i >= 0 && i < l->size);
    ret = l->data[i];
    if (i < l->size - 1) {
        memmove(l->data + i, l->data + i + 1, (l->size - i) * sizeof(void*));
    }
    l->size--;
    pthread_rwlock_unlock(&l->rwlock);
    return ret;
}

int ecr_list_index_of(ecr_list_t *l, void *value) {
    int rc = -1, i;
    assert(l);
    if (value == NULL) {
        return -1;
    }
    pthread_rwlock_rdlock(&l->rwlock);
    for (i = 0; i < l->size; i++) {
        if (l->data[i] == value) {
            rc = i;
            break;
        }
    }
    pthread_rwlock_unlock(&l->rwlock);
    return rc;
}

size_t ecr_list_size(ecr_list_t *l) {
    return l->size;
}

void ecr_list_clear(ecr_list_t *l, ecr_list_handler handler) {
    int i;
    assert(l);
    pthread_rwlock_wrlock(&l->rwlock);
    if (handler) {
        for (i = 0; i < l->size; i++) {
            handler(l, i, l->data[i]);
        }
    }
    l->size = 0;
    pthread_rwlock_unlock(&l->rwlock);
}

void ecr_list_sort(ecr_list_t *l, ecr_compare_func func) {
    assert(l);
    pthread_rwlock_wrlock(&l->rwlock);
    qsort(l->data, l->size, sizeof(void*), func);
    pthread_rwlock_unlock(&l->rwlock);
}

void ecr_list_destroy(ecr_list_t *l, ecr_list_handler handler) {
    assert(l);
    ecr_list_clear(l, handler);
    pthread_rwlock_wrlock(&l->rwlock);
    free(l->data);
    pthread_rwlock_unlock(&l->rwlock);
    pthread_rwlock_destroy(&l->rwlock);
    if (l->new) {
        free(l);
    }
}

void ecr_list_free_value_handler(ecr_list_t *l, int i, void* value) {
    free(value);
}
