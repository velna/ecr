/*
 * ecr_bwlist_exists.c
 *
 *  Created on: Dec 13, 2016
 *      Author: velna
 */

#include "ecr/ecr_bwlist.h"
#include <stdlib.h>

#define ECR_BWL_EXISTS  "exists"

typedef struct {
    char *name;
    ecr_list_t expr_ids; //<ecr_bwl_user_t>
} ecr_bwl_exists_t;

static void * ecr_bwl_exists_init(const char *name) {
    ecr_bwl_exists_t *exists = calloc(1, sizeof(ecr_bwl_exists_t));
    exists->name = strdup(name);
    ecr_list_init(&exists->expr_ids, 16);
    return exists;
}

static void ecr_bwl_exists_destroy(void *data) {
    ecr_bwl_exists_t *exists = data;
    ecr_list_destroy(&exists->expr_ids, NULL);
    free(exists->name);
    free(exists);
}

static int ecr_bwl_exists_add_item(void *data, const char *item, int expr_id) {
    ecr_bwl_exists_t *exists = data;
    ecr_list_add(&exists->expr_ids, NULL + expr_id);
    return 0;
}

static void ecr_bwl_exists_match(void *data, ecr_str_t *hdr, ecr_bwl_result_t *results) {
    ecr_bwl_exists_t *exists = data;
    ecr_bwl_add_matched(results, &exists->expr_ids, NULL);
}

static size_t ecr_bwl_exists_size(void *data) {
    return 0;
}

ecr_bwl_match_t ecr_bwl_exists = {
//
        .name = ECR_BWL_EXISTS,
        .has_items = 0,
        .init = ecr_bwl_exists_init,
        .destroy = ecr_bwl_exists_destroy,
        .add_item = ecr_bwl_exists_add_item,
        .match = ecr_bwl_exists_match,
        .size = ecr_bwl_exists_size
//
        };
