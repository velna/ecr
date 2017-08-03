/*
 * hm_exists_matcher.c
 *
 *  Created on: Aug 3, 2017
 *      Author: velna
 */

#include "hm.h"
#include "config.h"
#include <stdlib.h>
#include <string.h>

#define ECR_HM_EXISTS  "exists"

typedef struct {
    char *name;
    ecr_list_t expr_ids; //<expr_id:int>
} ecr_hm_exists_t;

static void * ecr_hm_exists_init(const char *name) {
    ecr_hm_exists_t *exists = calloc(1, sizeof(ecr_hm_exists_t));
    exists->name = strdup(name);
    ecr_list_init(&exists->expr_ids, 16);
    return exists;
}

static void ecr_hm_exists_destroy(void *data) {
    ecr_hm_exists_t *exists = data;
    ecr_list_destroy(&exists->expr_ids, NULL);
    free(exists->name);
    free(exists);
}

static int ecr_hm_exists_add_values(void *data, ecr_list_t *values, int expr_id) {
    ecr_hm_exists_t *exists = data;
    ecr_list_add(&exists->expr_ids, NULL + expr_id);
    return 0;
}

static void ecr_hm_exists_matches(void *data, ecr_hm_match_context_t *match_ctx) {
    ecr_hm_exists_t *exists = data;
    int i, expr_id;
    for (i = 0; i < exists->expr_ids.size; i++) {
        expr_id = (int) (exists->expr_ids.data[i] - NULL);
        ecr_hm_matches_add(match_ctx, expr_id);
    }
}

static size_t ecr_hm_exists_size(void *data) {
    return 0;
}

ecr_hm_matcher_reg_t ecr_hm_exists_matcher_reg = {
//
        .name = ECR_HM_EXISTS,
        .has_values = 0,
        .init = ecr_hm_exists_init,
        .destroy = ecr_hm_exists_destroy,
        .add_values = ecr_hm_exists_add_values,
        .matches = ecr_hm_exists_matches,
        .size = ecr_hm_exists_size
//
        };
