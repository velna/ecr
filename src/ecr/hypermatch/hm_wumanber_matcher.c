/*
 * hm_wumanber_matcher.c
 *
 *  Created on: Aug 3, 2017
 *      Author: velna
 */

#include "hm.h"
#include "../ecr_wumanber.h"
#include "config.h"
#include <stdlib.h>
#include <string.h>

#define ECR_HM_WUMANBER  "wumanber"

typedef struct {
    char *name;
    ecr_wm_t wm;
} ecr_hm_wumanber_t;

static void * ecr_hm_wumanber_init(const char *name) {
    ecr_hm_wumanber_t *wumanber = calloc(1, sizeof(ecr_hm_wumanber_t));
    wumanber->name = strdup(name);
    ecr_wm_init(&wumanber->wm, 16);
    return wumanber;
}

static void ecr_hm_wumanber_destroy(void *data) {
    ecr_hm_wumanber_t *wumanber = data;
    ecr_wm_destroy(&wumanber->wm);
    free(wumanber->name);
    free(wumanber);
}

static void ecr_hm_wumanber_compile(void *data) {
    ecr_hm_wumanber_t *wumanber = data;
    ecr_wm_compile(&wumanber->wm);
}

static int ecr_hm_wumanber_add_values(void *data, ecr_list_t *values, int expr_id) {
    ecr_hm_wumanber_t *wumanber = data;
    int i;
    char *value;
    for (i = 0; i < values->size; i++) {
        value = values->data[i];
        ecr_wm_add_pattern(&wumanber->wm, value, strlen(value), NULL + expr_id);
    }
    return 0;
}

static int ecr_hm_wumanber_match_handler(ecr_wm_t *wm, const char *str, size_t len, ecr_wm_pattern_t *pattern,
        void *user) {
    ecr_hm_match_context_t *match_ctx = user;
    int i, expr_id;
    for (i = 0; i < pattern->users.size; i++) {
        expr_id = (int) (pattern->users.data[i] - NULL);
        ecr_hm_matches_add(match_ctx, expr_id);
    }
    return 0;
}

void ecr_hm_wumanber_matches(void *data, ecr_hm_match_context_t *match_ctx) {
    ecr_hm_wumanber_t *wumanber = data;
    ecr_wm_match_ex(&wumanber->wm, match_ctx->target->ptr, match_ctx->target->len, ecr_hm_wumanber_match_handler,
            match_ctx);
}

static size_t ecr_hm_wumanber_size(void *data) {
    ecr_hm_wumanber_t *wumanber = data;
    return wumanber->wm.plist_size;
}

ecr_hm_matcher_reg_t ecr_hm_wumanber_matcher_reg = {
//
        .name = ECR_HM_WUMANBER,
        .has_values = 1,
        .init = ecr_hm_wumanber_init,
        .destroy = ecr_hm_wumanber_destroy,
        .add_values = ecr_hm_wumanber_add_values,
        .matches = ecr_hm_wumanber_matches,
        .size = ecr_hm_wumanber_size,
        .compile = ecr_hm_wumanber_compile
//
        };
