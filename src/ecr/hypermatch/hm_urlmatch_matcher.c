/*
 * hm_urlmatch_matcher.c
 *
 *  Created on: Aug 3, 2017
 *      Author: velna
 */

#include "hm.h"
#include "../ecr_urlmatch.h"
#include "config.h"
#include <stdlib.h>
#include <string.h>

#define ECR_HM_URLMATCH  "urlmatch"

typedef struct {
    char *name;
    ecr_hashmap_t items; //<"$field_value", [ecr_hm_user_t]>
    ecr_urlmatch_t ctx;
} ecr_hm_matches_t;

static void * ecr_hm_matches_init(const char *name) {
    ecr_hm_matches_t *matches = calloc(1, sizeof(ecr_hm_matches_t));
    matches->name = strdup(name);
    ecr_hashmap_init(&matches->items, 16, HASHMAP_NOLOCK);
    ecr_urlmatch_init(&matches->ctx);
    return matches;
}

static void ecr_hm_matches_free_users_handler(ecr_hashmap_t *in, void *key, size_t key_size, void *value) {
    ecr_list_destroy((ecr_list_t*) value, NULL);
}

static void ecr_hm_matches_destroy(void *data) {
    ecr_hm_matches_t *matches = data;
    ecr_hashmap_destroy(&matches->items, ecr_hm_matches_free_users_handler);
    free(matches->name);
    ecr_urlmatch_destroy(&matches->ctx);
    free(matches);
}

static int ecr_hm_matches_add_values(void *data, ecr_list_t *values, int expr_id) {
    ecr_hm_matches_t *matches = data;
    ecr_list_t *expr_ids;
    ecr_str_t pattern;
    int i;
    char *value;

    for (i = 0; i < values->size; i++) {
        value = values->data[i];
        pattern.ptr = value;
        pattern.len = strlen(value);

        if ((expr_ids = ecr_hashmap_get(&matches->items, (const void *) pattern.ptr, pattern.len)) == NULL) {
            expr_ids = ecr_list_new(1);
            ecr_hashmap_put(&matches->items, (const void *) pattern.ptr, pattern.len, expr_ids);
            ecr_urlmatch_addpattern(&matches->ctx, &pattern);
        }
        ecr_list_add(expr_ids, NULL + expr_id);
    }

    return 0;
}

static void ecr_hm_matches_matches(void *data, ecr_hm_match_context_t *match_ctx) {
    ecr_hm_matches_t *matches = data;
    ecr_str_t * pattern;
    int i, expr_id;
    ecr_list_t *expr_ids;

    if (ecr_urlmatch_match(&matches->ctx, match_ctx->target, &pattern)
            == 1&&(expr_ids = ecr_hashmap_get(&matches->items, pattern->ptr, pattern->len)) != NULL) {
        for (i = 0; i < expr_ids->size; i++) {
            expr_id = (int) (expr_ids->data[i] - NULL);
            ecr_hm_matches_add(match_ctx, expr_id);
        }
    }
}

static size_t ecr_hm_matches_size(void *data) {
    ecr_hm_matches_t *matches = data;
    return ecr_hashmap_size(&matches->items);
}

ecr_hm_matcher_reg_t ecr_hm_urlmatch_matcher_reg = {
//
        .name = ECR_HM_URLMATCH,
        .has_values = 1,
        .init = ecr_hm_matches_init,
        .destroy = ecr_hm_matches_destroy,
        .add_values = ecr_hm_matches_add_values,
        .matches = ecr_hm_matches_matches,
        .size = ecr_hm_matches_size
//
        };
