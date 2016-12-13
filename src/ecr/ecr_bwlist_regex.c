/*
 * ecr_bwlist_regex.c
 *
 *  Created on: Dec 13, 2016
 *      Author: velna
 */

#include "ecr/ecr_bwlist.h"
#include <stdlib.h>
#include <regex.h>

#define ECR_BWL_REGEX  "regex"

typedef struct {
    regex_t regex;
    ecr_str_t pattern;
} ecr_bwl_regex_data_t;

typedef struct {
    char *name;
    ecr_hashmap_t items; //<ecr_bwl_regex_t, [ecr_bwl_user_t]>
} ecr_bwl_regex_t;

static void * ecr_bwl_regex_init(const char *name) {
    ecr_bwl_regex_t *regex = calloc(1, sizeof(ecr_bwl_regex_t));
    regex->name = strdup(name);
    ecr_hashmap_init(&regex->items, 16, HASHMAP_NOLOCK | HASHMAP_NOCOPYKEY);
    return regex;
}

static void ecr_bwl_regex_free_users_handler(ecr_hashmap_t *in, void * key, size_t key_size, void * value) {
    ecr_bwl_regex_data_t *regex = key;
    regfree(&regex->regex);
    free(regex->pattern.ptr);
    free(regex);
    ecr_list_destroy((ecr_list_t*) value, NULL);
}

static void ecr_bwl_regex_destroy(void *data) {
    ecr_bwl_regex_t *regex = data;
    ecr_hashmap_destroy(&regex->items, ecr_bwl_regex_free_users_handler);
    free(regex->name);
    free(regex);
}

static int ecr_bwl_regex_add_item(void *data, const char *item, void *user) {
    ecr_bwl_regex_t *regex = data;
    ecr_bwl_regex_data_t *reg;
    size_t len;
    ecr_list_t *expr_ids;
    int rc = 0;

    reg = calloc(1, sizeof(ecr_bwl_regex_data_t));
    if (regcomp(&reg->regex, item, REG_EXTENDED | REG_NOSUB) == 0) {
        len = strlen(item);
        if ((expr_ids = ecr_hashmap_get(&regex->items, item, len)) == NULL) {
            expr_ids = ecr_list_new(1);
            ecr_hashmap_put(&regex->items, item, len, expr_ids);
            reg->pattern.ptr = strdup(item);
            reg->pattern.len = len;
        } else {
            regfree(&reg->regex);
            free(reg);
        }
    } else {
        free(reg);
        rc = -1;
//        ecr_bwl_log(data->bwl, LOG_ERR, "can not compile regex [%s] in group %s", item, (char *) group->name.ptr);
    }
    return rc;
}

static void ecr_bwl_regex_match(void *data, ecr_str_t *hdr, ecr_bwl_result_t *results) {
    ecr_bwl_regex_t *regex = data;
    ecr_hashmap_iter_t it;
    ecr_bwl_regex_data_t *reg;
    ecr_list_t *users;

    ecr_hashmap_iter_init(&it, &regex->items);
    while (ecr_hashmap_iter_next(&it, (void **) &reg, NULL, (void**) &users) == 0) {
        if (regexec(&reg->regex, hdr->ptr, 0, NULL, 0) == 0) {
            ecr_bwl_add_matched(results, users, &reg->pattern);
        }
    }
}

static size_t ecr_bwl_regex_size(void *data) {
    ecr_bwl_regex_t *regex = data;
    return ecr_hashmap_size(&regex->items);
}

ecr_bwl_match_t ecr_bwl_regex = {
//
        .name = ECR_BWL_REGEX,
        .has_items = 1,
        .init = ecr_bwl_regex_init,
        .destroy = ecr_bwl_regex_destroy,
        .add_item = ecr_bwl_regex_add_item,
        .match = ecr_bwl_regex_match,
        .size = ecr_bwl_regex_size
//
        };
