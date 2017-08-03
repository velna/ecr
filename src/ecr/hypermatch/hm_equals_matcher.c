/*
 * hm_equals_matcher.c
 *
 *  Created on: Aug 3, 2017
 *      Author: velna
 */

#include "hm.h"
#include "config.h"
#include <stdlib.h>
#include <string.h>

#define ECR_HM_EQUALS  "equals"

typedef struct {
    char *name;
    ecr_hashmap_t items; //<"$field_value", [ecr_hm_user_t]>
} ecr_hm_equals_t;

static void * ecr_hm_equals_init(const char *name) {
    ecr_hm_equals_t *equals = calloc(1, sizeof(ecr_hm_equals_t));
    equals->name = strdup(name);
    ecr_hashmap_init(&equals->items, 16, HASHMAP_NOLOCK);
    return equals;
}

static void ecr_hm_equals_free_users_handler(ecr_hashmap_t *in, void *key, size_t key_size, void *value) {
    ecr_list_destroy((ecr_list_t*) value, NULL);
}

static void ecr_hm_equals_destroy(void *data) {
    ecr_hm_equals_t *equals = data;
    ecr_hashmap_destroy(&equals->items, ecr_hm_equals_free_users_handler);
    free(equals->name);
    free(equals);
}

static int ecr_hm_equals_add_values(void *data, ecr_list_t *values, int expr_id) {
    ecr_hm_equals_t *equals = data;
    ecr_list_t *expr_ids;
    int i;
    ecr_str_t value;

    for (i = 0; i < values->size; i++) {
        value.ptr = values->data[i];
        value.len = strlen(value.ptr);
        if ((expr_ids = ecr_hashmap_get(&equals->items, value.ptr, value.len)) == NULL) {
            expr_ids = ecr_list_new(1);
            ecr_hashmap_put(&equals->items, value.ptr, value.len, expr_ids);
        }
        ecr_list_add(expr_ids, NULL + expr_id);
    }
    return 0;
}

static void ecr_hm_equals_matches(void *data, ecr_hm_match_context_t *match_ctx) {
    ecr_hm_equals_t *equals = data;
    ecr_list_t *expr_ids;
    int i, expr_id;
    expr_ids = ecr_hashmap_get(&equals->items, match_ctx->target->ptr, match_ctx->target->len);
    if (expr_ids) {
        for (i = 0; i < expr_ids->size; i++) {
            expr_id = (int) (expr_ids->data[i] - NULL);
            ecr_hm_matches_add(match_ctx, expr_id);
        }
    }
}

static size_t ecr_hm_equals_size(void *data) {
    ecr_hm_equals_t *equals = data;
    return ecr_hashmap_size(&equals->items);
}

ecr_hm_matcher_reg_t ecr_hm_equals_matcher_reg = {
//
        .name = ECR_HM_EQUALS,
        .has_values = true,
        .init = ecr_hm_equals_init,
        .destroy = ecr_hm_equals_destroy,
        .add_values = ecr_hm_equals_add_values,
        .matches = ecr_hm_equals_matches,
        .size = ecr_hm_equals_size
//
        };
