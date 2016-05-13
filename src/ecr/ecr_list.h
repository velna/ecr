/*
 * ecr_list.h
 *
 *  Created on: Jan 10, 2013
 *      Author: velna
 */

#ifndef ECR_LIST_H_
#define ECR_LIST_H_

#include "ecrconf.h"
#include <pthread.h>

#define linked_list_add_first(ll, p) \
        do { \
            (p)->next = (ll)->head; \
            (p)->prev = NULL; \
            if((p)->next) { \
                (p)->next->prev = (p); \
            } \
            (ll)->head = (p); \
            if(!(ll)->tail) { \
                (ll)->tail = (p); \
            } \
        } while(0)

#define linked_list_add_last(ll, p) \
        do { \
            (p)->next = NULL; \
            (p)->prev = (ll)->tail; \
            if((p)->prev) { \
                (p)->prev->next = (p); \
            } \
            (ll)->tail = (p); \
            if(!(ll)->head) { \
                (ll)->head = (p); \
            } \
        } while(0)

#define linked_list_remove_first(ll, p) \
        do { \
            if((ll)->head) { \
                p = (ll)->head; \
                (ll)->head = (ll)->head->next; \
                if((ll)->head) { \
                    (ll)->head->prev = NULL; \
                } \
                if((p) == (ll)->tail) { \
                    (ll)->tail = NULL; \
                } \
            } else { \
                p = NULL; \
            } \
        } while(0)

#define linked_list_remove_last(ll, p) \
        do { \
            if((ll)->tail) { \
                p = (ll)->tail; \
                (ll)->tail = (ll)->tail->prev; \
                if((ll)->tail) { \
                    (ll)->tail->next = NULL; \
                } \
                if((p) == (ll)->head) { \
                    (ll)->head = NULL; \
                } \
            } else { \
                p = NULL; \
            } \
        } while(0)

#define linked_list_pop linked_list_remove_last
#define linked_list_push linked_list_add_first

#define linked_list_drop(ll, p) \
        do { \
            if ((p)->prev) { \
                (p)->prev->next = (p)->next; \
            } \
            if ((p)->next) { \
                (p)->next->prev = (p)->prev; \
            } \
            if ((ll)->head == (p)) { \
                (ll)->head = (p)->next; \
            } \
            if ((ll)->tail == (p)) { \
                (ll)->tail = (p)->prev; \
            } \
            (p)->prev = NULL; \
            (p)->next = NULL; \
        } while(0)

typedef struct {
    size_t size;
    size_t capacity;
    void** data;
    pthread_rwlock_t rwlock;
    int new :1;
} ecr_list_t;

typedef void (*ecr_list_handler)(ecr_list_t *list, int i, void* value);

ecr_list_t * ecr_list_new(size_t size);

int ecr_list_init(ecr_list_t *list, size_t size);

int ecr_list_init_data(ecr_list_t *list, void **data, size_t size);

void ecr_list_add(ecr_list_t *list, void *value);

void ecr_list_add_all(ecr_list_t *l, ecr_list_t *add);

void ecr_list_insert(ecr_list_t *list, int i, void *value);

void * ecr_list_get(ecr_list_t *list, int i);

void * ecr_list_set(ecr_list_t *list, int i, void *value);

int ecr_list_remove(ecr_list_t *list, void *value);

void * ecr_list_remove_at(ecr_list_t *list, int i);

int ecr_list_index_of(ecr_list_t *list, void *value);

size_t ecr_list_size(ecr_list_t *list);

void ecr_list_clear(ecr_list_t *list, ecr_list_handler handler);

void ecr_list_sort(ecr_list_t *list, ecr_compare_func func);

void ecr_list_destroy(ecr_list_t *list, ecr_list_handler handler);

void ecr_list_free_value_handler(ecr_list_t *list, int i, void *value);

#endif /* ECR_LIST_H_ */
