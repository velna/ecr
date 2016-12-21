/*
 * ecr_bwlist_urlmatch.c
 *
 *  Created on: Dec 20, 2016
 *      Author: jieyuefeng
 */

#include "ecr/ecr_bwlist.h"
#include "ecr/ecr_urlmatch.h"
#include <stdlib.h>

#define ECR_BWL_URLMATCH  "urlmatch"

typedef struct {
    char *name;
    ecr_hashmap_t items; //<"$field_value", [ecr_bwl_user_t]>
    ecr_urlmatch_t ctx;
} ecr_bwl_matches_t;

static void * ecr_bwl_matches_init(const char *name) {
    ecr_bwl_matches_t *matches = calloc(1, sizeof(ecr_bwl_matches_t));
    matches->name = strdup(name);
    ecr_hashmap_init(&matches->items, 16, HASHMAP_NOLOCK);
    ecr_urlmatch_init(&matches->ctx);
    return matches;
}

static void ecr_bwl_matches_free_users_handler(ecr_hashmap_t *in, void *key, size_t key_size, void *value) {
    ecr_list_destroy((ecr_list_t*) value, NULL);
}

static void ecr_bwl_matches_destroy(void *data) {
    ecr_bwl_matches_t *matches = data;
    ecr_hashmap_destroy(&matches->items, ecr_bwl_matches_free_users_handler);
    free(matches->name);
    ecr_urlmatch_destroy(&matches->ctx);
    free(matches);
}

static int ecr_bwl_matches_add_item(void *data, const char *item, int expr_id) {
    ecr_bwl_matches_t *matches = data;
    ecr_list_t *expr_ids;
    ecr_str_t pattern = { .ptr = (char*) item, .len = strlen(item) };

    if ((expr_ids = ecr_hashmap_get(&matches->items, (const void *) pattern.ptr, pattern.len)) == NULL) {
        expr_ids = ecr_list_new(1);
        ecr_hashmap_put(&matches->items, (const void *) pattern.ptr, pattern.len, expr_ids);
        ecr_urlmatch_addpattern(&matches->ctx, &pattern);
    }
    ecr_list_add(expr_ids, NULL + expr_id);
    return 0;
}

static void ecr_bwl_matches_match(void *data, ecr_str_t *hdr, ecr_bwl_result_t *results) {
    ecr_bwl_matches_t *matches = data;
    ecr_str_t * pattern;

    ecr_list_t *users;
    if (ecr_urlmatch_match(&matches->ctx, hdr, &pattern)
            == 1&&(users = ecr_hashmap_get(&matches->items, pattern->ptr, pattern->len)) != NULL) {
        ecr_bwl_add_matched(results, users, pattern);
    }
}

static size_t ecr_bwl_matches_size(void *data) {
    ecr_bwl_matches_t *matches = data;
    return ecr_hashmap_size(&matches->items);
}

ecr_bwl_match_t ecr_bwl_urlmatch = {
//
        .name = ECR_BWL_URLMATCH,
        .has_items = 1,
        .init = ecr_bwl_matches_init,
        .destroy = ecr_bwl_matches_destroy,
        .add_item = ecr_bwl_matches_add_item,
        .match = ecr_bwl_matches_match,
        .size = ecr_bwl_matches_size
//
        };
