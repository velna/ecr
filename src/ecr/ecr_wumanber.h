/*
 * ecr_wumanber.h
 *
 *  Created on: Nov 12, 2013
 *      Author: velna
 */

#ifndef ECR_WUMANBER_H_
#define ECR_WUMANBER_H_

#include "ecrconf.h"
#include "ecr_heap.h"
#include "ecr_list.h"
#include "ecr_hashmap.h"

typedef u_int16_t ecr_wm_hash_t;

typedef struct {
    ecr_str_t pattern;
    ecr_str_t org_pattern;
    ecr_str_t suffix;
    int opt;
    ecr_list_t users;
    int64_t users_mask;
    ecr_wm_hash_t hash;
    ecr_wm_hash_t prefix;
} ecr_wm_pattern_t;

typedef struct {
    ecr_wm_pattern_t *plist;
    size_t plist_size;
    size_t plist_capacity;
    size_t min_len;
    u_int16_t *shift;
    int32_t *hash;
    ecr_hashmap_t pmap;
} ecr_wm_t;

typedef int (*ecr_wm_match_handler)(ecr_wm_t *wm, const char *str, size_t len, ecr_list_t *matched_users, void *user);

int ecr_wm_init(ecr_wm_t *wm, size_t init_size);

void ecr_wm_destroy(ecr_wm_t *wm);

int ecr_wm_add_pattern(ecr_wm_t *wm, const char *pattern, size_t len, void *user);

int ecr_wm_compile(ecr_wm_t *wm);

int ecr_wm_match(ecr_wm_t *wm, const char *str, size_t len, ecr_list_t *result);

int ecr_wm_match_ex(ecr_wm_t *wm, const char *str, size_t len, ecr_wm_match_handler handler, void *user);

#endif /* ECR_WUMANBER_H_ */
