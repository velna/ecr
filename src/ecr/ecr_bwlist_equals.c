/*
 * ecr_bwlist_equals.c
 *
 *  Created on: Dec 13, 2016
 *      Author: velna
 */

#include "ecr/ecr_bwlist.h"
#include <stdlib.h>

#define ECR_BWL_EQUALS  "equals"

typedef struct {
    char *name;
    ecr_hashmap_t items; //<"$field_value", [ecr_bwl_user_t]>
} ecr_bwl_equals_t;

static void * ecr_bwl_equals_init(const char *name) {
    ecr_bwl_equals_t *equals = calloc(1, sizeof(ecr_bwl_equals_t));
    equals->name = strdup(name);
    ecr_hashmap_init(&equals->items, 16, HASHMAP_NOLOCK);
    return equals;
}

static void ecr_bwl_equals_free_users_handler(ecr_hashmap_t *in, void *key, size_t key_size, void *value) {
    ecr_list_destroy((ecr_list_t*) value, NULL);
}

static void ecr_bwl_equals_destroy(void *data) {
    ecr_bwl_equals_t *equals = data;
    ecr_hashmap_destroy(&equals->items, ecr_bwl_equals_free_users_handler);
    free(equals->name);
    free(equals);
}

static int ecr_bwl_equals_add_item(void *data, const char *item, int expr_id) {
    ecr_bwl_equals_t *equals = data;
    ecr_list_t *expr_ids;
    if ((expr_ids = ecr_hashmap_get(&equals->items, (const void *) item, strlen(item))) == NULL) {
        expr_ids = ecr_list_new(1);
        ecr_hashmap_put(&equals->items, (const void *) item, strlen(item), expr_ids);
    }
    ecr_list_add(expr_ids, NULL + expr_id);
    return 0;
}

static void ecr_bwl_equals_match(void *data, ecr_str_t *hdr, ecr_bwl_result_t *results) {
    ecr_bwl_equals_t *equals = data;
    ecr_list_t *expr_ids;
    if ((expr_ids = ecr_hashmap_get(&equals->items, hdr->ptr, hdr->len)) != NULL) {
        ecr_bwl_add_matched(results, expr_ids, hdr);
    }
}

static size_t ecr_bwl_equals_size(void *data) {
    ecr_bwl_equals_t *equals = data;
    return ecr_hashmap_size(&equals->items);
}

ecr_bwl_match_t ecr_bwl_equals = {
//
        .name = ECR_BWL_EQUALS,
        .has_items = 1,
        .init = ecr_bwl_equals_init,
        .destroy = ecr_bwl_equals_destroy,
        .add_item = ecr_bwl_equals_add_item,
        .match = ecr_bwl_equals_match,
        .size = ecr_bwl_equals_size
//
        };
