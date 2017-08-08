/*
 * hm.c
 *
 *  Created on: Aug 1, 2017
 *      Author: velna
 */

#include "config.h"
#include "hm.h"

#include "hm_private.h"

#include "hm_result.h"
#include "hm_matcher.h"
#include "hm_expr.h"
#include "hm_source_data.h"
#include "hm_source.h"
#include "hm_data.h"

int ecr_hm_init(ecr_hm_t *hm, ecr_fixedhash_ctx_t *fixedhash_ctx) {
    memset(hm, 0, sizeof(ecr_hm_t));
    hm->fixedhash_ctx = fixedhash_ctx;
    pthread_mutex_init(&hm->lock, NULL);
    ecr_hashmap_init(&hm->matcher_registry, 16, 0);
    ecr_hashmap_init(&hm->loader_registry, 16, 0);
    hm->data = ecr_hm_data_new(hm);
    hm->next_data = ecr_hm_data_new(hm);
    hm->tmp_data = ecr_hm_data_new(hm);
    return 0;
}

void ecr_hm_destroy(ecr_hm_t *hm) {
    ecr_hm_data_destroy(hm->data);
    ecr_hm_data_destroy(hm->next_data);
    ecr_hm_data_destroy(hm->tmp_data);
    ecr_hashmap_destroy(&hm->matcher_registry, NULL);
    ecr_hashmap_destroy(&hm->loader_registry, NULL);
    pthread_mutex_destroy(&hm->lock);
}

int ecr_hm_reg_matcher(ecr_hm_t *hm, ecr_hm_matcher_reg_t *matcher_reg) {
    ecr_hashmap_put(&hm->matcher_registry, matcher_reg->name, strlen(matcher_reg->name), matcher_reg);
    return 0;
}

ecr_hm_matcher_reg_t* ecr_hm_get_matcher_reg(ecr_hm_t *hm, const char *name) {
    if (!name) {
        return NULL;
    }
    return ecr_hashmap_get(&hm->matcher_registry, name, strlen(name));
}

int ecr_hm_reg_loader(ecr_hm_t *hm, ecr_hm_loader_t *loader) {
    ecr_hashmap_put(&hm->loader_registry, loader->scheme, strlen(loader->scheme), loader);
    return 0;
}

ecr_hm_loader_t* ecr_hm_find_loader(ecr_hm_t *hm, const char *scheme) {
    if (!scheme) {
        return NULL;
    }
    return ecr_hashmap_get(&hm->loader_registry, scheme, strlen(scheme));
}

ecr_hm_source_t* ecr_hm_add(ecr_hm_t *hm, const char *uri) {
    ecr_hm_source_t *source;
    ecr_hm_data_t *data;

    pthread_mutex_lock(&hm->lock);
    data = hm->next_data;
    if (ecr_hm_data_is_empty(data)) {
        ecr_hm_data_copy_sources(data, hm->data);
    }
    source = ecr_hm_source_new(hm, uri);
    if (source) {
        ecr_hm_data_add(data, source);
    }
    pthread_mutex_unlock(&hm->lock);
    return source;
}

int ecr_hm_remove(ecr_hm_t *hm, int source_id) {
    ecr_hm_source_t *source;
    ecr_hm_data_t *data;

    pthread_mutex_lock(&hm->lock);
    data = hm->next_data;
    if (ecr_hm_data_is_empty(data)) {
        ecr_hm_data_copy_sources(data, hm->data);
    }
    source = ecr_hm_data_remove(data, source_id);
    pthread_mutex_unlock(&hm->lock);
    if (source) {
        ecr_hm_source_free(source);
    }
    return source ? 0 : -1;
}

ecr_hm_status_t ecr_hm_compile(ecr_hm_t *hm) {
    ecr_hm_data_t *data;
    ecr_hm_status_t status;
    pthread_mutex_lock(&hm->lock);
    ecr_hm_data_clear(hm->tmp_data);
    status = ecr_hm_data_compile(hm->next_data, true);
    if (status != HM_ERROR) {
        data = hm->data;
        hm->data = hm->next_data;
        hm->next_data = hm->tmp_data;
        hm->tmp_data = data;
    }
    pthread_mutex_unlock(&hm->lock);
    return status;
}

ecr_hm_status_t ecr_hm_check(ecr_hm_t *hm, bool force_reload) {
    bool my_force_reload = force_reload;
    ecr_hm_status_t status;
    ecr_hm_data_t *data;

    if (force_reload) {
        pthread_mutex_lock(&hm->lock);
    } else {
        if (pthread_mutex_trylock(&hm->lock)) {
            return HM_ERROR;
        }
    }
    ecr_hm_data_clear(hm->tmp_data);
    if (ecr_hm_data_is_empty(hm->next_data)) {
        ecr_hm_data_copy_sources(hm->tmp_data, hm->data);
    } else {
        my_force_reload = true;
        ecr_hm_data_copy_sources(hm->tmp_data, hm->next_data);
    }
    ecr_hm_data_clear(hm->next_data);
    status = ecr_hm_data_compile(hm->tmp_data, my_force_reload);
    if (status != HM_ERROR) {
        data = hm->data;
        hm->data = hm->tmp_data;
        hm->tmp_data = data;
    }
    pthread_mutex_unlock(&hm->lock);
    return status;
}

bool ecr_hm_matches(ecr_hm_t *hm, ecr_fixedhash_t *targets, ecr_hm_result_t* result) {
    if (hm->version != result->version) {
        return false;
    }
    return ecr_hm_data_matches(hm->data, targets, result);
}

void ECR_INLINE ecr_hm_matches_add(ecr_hm_match_context_t *match_ctx, int expr_id) {
    ecr_hm_result_set_expr(match_ctx->result, expr_id, true, &match_ctx->expr->leaf.field, match_ctx->target);
}

ecr_hm_result_t * ecr_hm_result_init_mem(ecr_hm_t *hm, void *mem, size_t mem_size) {
    char *cp = mem;
    ecr_hm_result_t *result;
    result = (ecr_hm_result_t*) cp;
    cp += sizeof(ecr_hm_result_t);
    result->version = hm->version;
    result->expr_match_list_size = hm->data->next_expr_id;
    result->expr_match_list = (ecr_hm_result_kv_t*) cp;
    cp += result->expr_match_list_size * sizeof(ecr_hm_result_kv_t);
    result->source_match_list.len = hm->data->next_sid;
    result->source_match_list.ptr = cp;
    return NULL;
}

size_t ecr_hm_result_mem_size(ecr_hm_t *hm) {
    return sizeof(ecr_hm_result_t) + hm->data->next_expr_id * sizeof(ecr_hm_result_kv_t) + hm->data->next_sid;
}

ecr_hm_result_t * ecr_hm_result_new(ecr_hm_t *hm) {
    unsigned int version;
    size_t mem_size, last_mem_size = 0;
    char *mem = NULL, *cp;
    ecr_hm_result_t *result;

    do {
        version = hm->version;
        mem_size = ecr_hm_result_mem_size(hm);
        if (mem) {
            if (mem_size > last_mem_size) {
                mem = realloc(mem, mem_size);
            }
        } else {
            mem = malloc(mem_size);
        }
        memset(mem, 0, mem_size);
        last_mem_size = mem_size;
        cp = mem;
        result = (ecr_hm_result_t*) cp;
        cp += sizeof(ecr_hm_result_t);
        result->version = version;
        result->expr_match_list_size = hm->data->next_expr_id;
        result->expr_match_list = (ecr_hm_result_kv_t*) cp;
        cp += result->expr_match_list_size * sizeof(ecr_hm_result_kv_t);
        result->source_match_list.len = hm->data->next_sid;
        result->source_match_list.ptr = cp;
    } while (hm->version != version);

    return result;
}

void ecr_hm_result_clear(ecr_hm_result_t *result) {
    memset(result->source_match_list.ptr, 0, result->source_match_list.len);
    memset(result->expr_match_list, 0, result->expr_match_list_size * sizeof(ecr_hm_result_kv_t));
}
