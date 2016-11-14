/*
 * ecr_counter.h
 *
 *  Created on: Nov 26, 2014
 *      Author: velna
 */

#ifndef ECR_COUNTER_H_
#define ECR_COUNTER_H_

#include "ecrconf.h"
#include "ecr_list.h"
#include "ecr_hashmap.h"
#include <stdio.h>
#include <atomic_ops.h>

#define ECR_COUNTER_TOTAL_ONLY      0x01
#define ECR_COUNTER_NO_PRINT        0x02
#define ECR_COUNTER_NO_RESET        0x04

typedef struct {
    uint64_t snapshot_timestamp;
    uint64_t last_timestamp;
    uint64_t init_timestamp;
    char *group;
    char *name;
    int opt;
    volatile uint64_t value;
    uint64_t snapshot;
    uint64_t last;
} ecr_counter_t;

typedef struct {
    ecr_list_t counters;
    ecr_hashmap_t countermap;
} ecr_counter_ctx_t;

int ecr_counter_ctx_init(ecr_counter_ctx_t *ctx);

ecr_counter_t* ecr_counter_create(ecr_counter_ctx_t *ctx, const char *group, const char *name, int opt);

int ecr_counter_delete(ecr_counter_ctx_t *ctx, const char *group, const char *name);

void ecr_counter_setopt(ecr_counter_t *counter, int opt);

ecr_counter_t* ecr_counter_get(ecr_counter_ctx_t *ctx, const char *group, const char *name);

ecr_counter_t* ecr_counter_xadd(ecr_counter_ctx_t *ctx, const char *group, const char *name, int64_t value);

ecr_counter_t* ecr_counter_xincr(ecr_counter_ctx_t *ctx, const char *group, const char *name);

ecr_counter_t* ecr_counter_xdecr(ecr_counter_ctx_t *ctx, const char *group, const char *name);

ecr_counter_t* ecr_counter_xstore(ecr_counter_ctx_t *ctx, const char *group, const char *name, uint64_t value);

#define ecr_counter_add(c, v)   AO_fetch_and_add_full(&((c)->value), v)
#define ecr_counter_incr(c)     AO_fetch_and_add1(&((c)->value))
#define ecr_counter_decr(c)     AO_fetch_and_sub1(&((c)->value))
#define ecr_counter_store(c, v) AO_store_full(&((c)->value), v)

void ecr_counter_clear(ecr_counter_t *counter);

void ecr_counter_reset_group(ecr_counter_ctx_t *ctx, const char *group);

void ecr_counter_reset(ecr_counter_ctx_t *ctx);

void ecr_counter_snapshot(ecr_counter_ctx_t *ctx);

int ecr_counter_print(ecr_counter_ctx_t *ctx, FILE *stream);

int ecr_counter_print_all(ecr_counter_ctx_t *ctx, FILE *stream);

void ecr_counter_ctx_destroy(ecr_counter_ctx_t *ctx);

#endif /* ECR_COUNTER_H_ */
