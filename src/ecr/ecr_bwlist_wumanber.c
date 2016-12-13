/*
 * ecr_bwlist_wumanber.c
 *
 *  Created on: Dec 13, 2016
 *      Author: velna
 */

#include "ecr/ecr_bwlist.h"
#include <stdlib.h>

#define ECR_BWL_WUMANBER  "wumanber"

typedef struct {
    char *name;
    ecr_wm_t wm;
} ecr_bwl_wumanber_t;

static void * ecr_bwl_wumanber_init(const char *name) {
    ecr_bwl_wumanber_t *wumanber = calloc(1, sizeof(ecr_bwl_wumanber_t));
    wumanber->name = strdup(name);
    ecr_wm_init(&wumanber->wm, 16);
    return wumanber;
}

static void ecr_bwl_wumanber_destroy(void *data) {
    ecr_bwl_wumanber_t *wumanber = data;
    ecr_wm_destroy(&wumanber->wm);
    free(wumanber->name);
    free(wumanber);
}

static void ecr_bwl_wumanber_compile(void *data) {
    ecr_bwl_wumanber_t *wumanber = data;
    ecr_wm_compile(&wumanber->wm);
}

static int ecr_bwl_wumanber_add_item(void *data, const char *item, void *user) {
    ecr_bwl_wumanber_t *wumanber = data;
    ecr_wm_add_pattern(&wumanber->wm, item, strlen(item), user);
    return 0;
}

static int ecr_bwl_wumanber_match_handler(ecr_wm_t *wm, const char *str, size_t len, ecr_wm_pattern_t *pattern,
        void *user) {
    ecr_bwl_result_t *results = user;
    ecr_bwl_add_matched(results, &pattern->users, &pattern->pattern);
    return 0;
}

static void ecr_bwl_wumanber_match(void *data, ecr_str_t *hdr, ecr_bwl_result_t *results) {
    ecr_bwl_wumanber_t *wumanber = data;
    ecr_wm_match_ex(&wumanber->wm, hdr->ptr, hdr->len, ecr_bwl_wumanber_match_handler, results);
}

static size_t ecr_bwl_wumanber_size(void *data) {
    ecr_bwl_wumanber_t *wumanber = data;
    return wumanber->wm.plist_size;
}

ecr_bwl_match_t ecr_bwl_wumanber = {
//
        .name = ECR_BWL_WUMANBER,
        .has_items = 1,
        .init = ecr_bwl_wumanber_init,
        .destroy = ecr_bwl_wumanber_destroy,
        .add_item = ecr_bwl_wumanber_add_item,
        .match = ecr_bwl_wumanber_match,
        .size = ecr_bwl_wumanber_size,
        .compile = ecr_bwl_wumanber_compile
//
        };
