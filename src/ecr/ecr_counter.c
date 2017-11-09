/*
 * ecr_counter.c
 *
 *  Created on: Nov 26, 2014
 *      Author: velna
 */

#include "config.h"
#include "ecr_counter.h"
#include "ecr_util.h"
#include <stdlib.h>
#include <string.h>
#include <atomic_ops.h>

#define DEFAULT_GROUP   "default"

static void ecr_counter_destroy(ecr_counter_t *ctr) {
    free_to_null(ctr->name);
    free_to_null(ctr->group);
    free_to_null(ctr);
}

int ecr_counter_ctx_init(ecr_counter_ctx_t *ctx) {
    memset(ctx, 0, sizeof(ecr_counter_ctx_t));
    ecr_list_init(&ctx->counters, 16);
    ecr_hashmap_init(&ctx->countermap, 16, 0);
    return 0;
}

ecr_counter_t * ecr_counter_create(ecr_counter_ctx_t *ctx, const char *group, const char *name, int opt) {
    ecr_counter_t *ctr = calloc(1, sizeof(ecr_counter_t));
    if (group) {
        asprintf(&ctr->name, "%s.%s", group, name);
        ctr->group = strdup(group);
    } else {
        ctr->name = strdup(name);
        ctr->group = strdup(DEFAULT_GROUP);
    }
    ctr->init_timestamp = ctr->last_timestamp = ecr_current_time();
    ctr->opt = opt;
    ecr_list_add(&ctx->counters, ctr);
    ecr_hashmap_put(&ctx->countermap, ctr->name, strlen(ctr->name), ctr);
    return ctr;
}

int ecr_counter_delete(ecr_counter_ctx_t *ctx, const char *group, const char *name) {
    char *ctr_name, *ctr_group;
    ecr_counter_t *ctr;
    int rc;
    if (group) {
        asprintf(&ctr_name, "%s.%s", group, name);
        ctr_group = strdup(group);
    } else {
        ctr_name = strdup(name);
        ctr_group = strdup(DEFAULT_GROUP);
    }
    if ((ctr = ecr_hashmap_remove(&ctx->countermap, ctr_name, strlen(ctr_name)))) {
        ecr_list_remove(&ctx->counters, ctr);
        ecr_counter_destroy(ctr);
        rc = 0;
    } else {
        rc = -1;
    }
    free(ctr_name);
    free(ctr_group);
    return rc;
}

void ecr_counter_setopt(ecr_counter_t *counter, int opt) {
    counter->opt = opt;
}

ecr_counter_t * ecr_counter_get(ecr_counter_ctx_t *ctx, const char *group, const char *name) {
    ecr_counter_t *ctr = NULL;
    char *key = NULL;
    if (group) {
        asprintf(&key, "%s.%s", group, name);
        ctr = ecr_hashmap_get(&ctx->countermap, key, strlen(key));
        free(key);
    } else {
        ctr = ecr_hashmap_get(&ctx->countermap, name, strlen(name));
    }
    return ctr;
}

ecr_counter_t * ecr_counter_xadd(ecr_counter_ctx_t *ctx, const char *group, const char *name, int64_t value) {
    ecr_counter_t *ctr = ecr_counter_get(ctx, group, name);
    if (ctr) {
        ecr_counter_add(ctr, value);
    }
    return ctr;
}

ecr_counter_t * ecr_counter_xincr(ecr_counter_ctx_t *ctx, const char *group, const char *name) {
    ecr_counter_t *ctr = ecr_counter_get(ctx, group, name);
    if (ctr) {
        ecr_counter_incr(ctr);
    }
    return ctr;
}

ecr_counter_t * ecr_counter_xdecr(ecr_counter_ctx_t *ctx, const char *group, const char *name) {
    ecr_counter_t *ctr = ecr_counter_get(ctx, group, name);
    if (ctr) {
        ecr_counter_decr(ctr);
    }
    return ctr;
}

ecr_counter_t * ecr_counter_xstore(ecr_counter_ctx_t *ctx, const char *group, const char *name, uint64_t value) {
    ecr_counter_t *ctr = ecr_counter_get(ctx, group, name);
    if (ctr) {
        ecr_counter_store(ctr, value);
    }
    return ctr;
}

void ecr_counter_reset_group(ecr_counter_ctx_t *ctx, const char *group) {
    int i;
    ecr_counter_t *ctr;
    if (!group) {
        group = DEFAULT_GROUP;
    }
    for (i = 0; i < ecr_list_size(&ctx->counters); i++) {
        if ((ctr = ecr_list_get(&ctx->counters, i)) != NULL) {
            if (strcmp(group, ctr->group) == 0 && (ctr->opt & ECR_COUNTER_NO_RESET) == 0) {
                ecr_counter_clear(ctr);
            }
        }
    }
}

void ecr_counter_clear(ecr_counter_t *counter) {
    AO_store_full(&counter->value, counter->snapshot = counter->last = 0);
    counter->init_timestamp = counter->snapshot_timestamp = counter->last_timestamp = ecr_current_time();
}

void ecr_counter_reset(ecr_counter_ctx_t *ctx) {
    int i;
    ecr_counter_t *ctr;
    for (i = 0; i < ecr_list_size(&ctx->counters); i++) {
        if ((ctr = ecr_list_get(&ctx->counters, i)) != NULL) {
            if ((ctr->opt & ECR_COUNTER_NO_RESET) == 0) {
                ecr_counter_clear(ctr);
            }
        }
    }
}

void ecr_counter_snapshot(ecr_counter_ctx_t *ctx) {
    int i;
    ecr_counter_t * ctr;
    uint64_t now = ecr_current_time();
    for (i = 0; i < ecr_list_size(&ctx->counters); i++) {
        if ((ctr = ecr_list_get(&ctx->counters, i)) != NULL) {
            ctr->last = ctr->snapshot;
            ctr->last_timestamp = ctr->snapshot_timestamp;
            ctr->snapshot = ctr->value;
            ctr->snapshot_timestamp = now;
        }
    }
}

int ecr_counter_print_all(ecr_counter_ctx_t *ctx, FILE *stream) {
    int i, rc = 0;
    ecr_counter_t *ctr;

    for (i = 0; i < ecr_list_size(&ctx->counters); i++) {
        if ((ctr = ecr_list_get(&ctx->counters, i)) != NULL) {
            rc += fprintf(stream, "%s:\t%lu\n", ctr->name, ctr->value);
        }
    }
    return rc;
}

int ecr_counter_print(ecr_counter_ctx_t *ctx, FILE *stream) {
    int i, rc = 0;
    ecr_counter_t *ctr;
    int64_t diff_total, diff;
    int64_t avg, inst;

    for (i = 0; i < ecr_list_size(&ctx->counters); i++) {
        if ((ctr = ecr_list_get(&ctx->counters, i)) != NULL) {
            if ((ctr->opt & ECR_COUNTER_NO_PRINT) || !ctr->snapshot) {
                continue;
            }
            if (ctr->opt & ECR_COUNTER_TOTAL_ONLY) {
                rc += fprintf(stream, "%s:\t%lu\n", ctr->name, ctr->snapshot);
            } else {
                diff_total = (ctr->snapshot_timestamp - ctr->init_timestamp) / 1000;
                if (diff_total == 0) {
                    diff_total = 1;
                }
                diff = (ctr->snapshot_timestamp - ctr->last_timestamp) / 1000;
                if (diff == 0) {
                    diff = 1;
                }
                avg = ctr->snapshot / diff_total;
                inst = (ctr->snapshot > ctr->last ? ctr->snapshot - ctr->last : -(int64_t) (ctr->last - ctr->snapshot))
                        / diff;
                rc += fprintf(stream, "%s:\t%lu\t%lu\t%ld\n", ctr->name, ctr->snapshot, avg, inst);
            }
        }
    }
    return rc;
}

void ecr_counter_get_all(ecr_counter_ctx_t *ctx, ecr_hashmap_t *map) {
    int i;
    ecr_counter_t *ctr;

    for (i = 0; i < ecr_list_size(&ctx->counters); i++) {
        if ((ctr = ecr_list_get(&ctx->counters, i)) != NULL) {
            ecr_hashmap_put(map, ctr->name, strlen(ctr->name) + 1, NULL + ctr->value);
        }
    }
}

static void ecr_destroy_handler(ecr_list_t *l, int i, void *value) {
    ecr_counter_destroy(value);
}

void ecr_counter_ctx_destroy(ecr_counter_ctx_t *ctx) {
    ecr_list_destroy(&ctx->counters, ecr_destroy_handler);
    ecr_hashmap_destroy(&ctx->countermap, NULL);
}

