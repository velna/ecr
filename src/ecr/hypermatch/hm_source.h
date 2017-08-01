/*
 * hm_source.h
 *
 *  Created on: Aug 1, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_HYPERMATCH_HM_SOURCE_H_
#define SRC_ECR_HYPERMATCH_HM_SOURCE_H_

#include "hm_private.h"

static ecr_hm_source_t* ecr_hm_source_new(ecr_hm_t *hm, const char *uri) {
    ecr_hm_source_t *source = calloc(1, sizeof(ecr_hm_source_t));
    source->id = 0;
    source->hm = hm;
    source->uri = strdup(uri);
    ecr_hashmap_init(&source->attrs, 16, 0);
    return source;
}

static void ecr_hm_source_free(ecr_hm_source_t *source) {
    free_to_null(source->uri);
    ecr_hashmap_destory(&source->attrs, ecr_hashmap_free_value_handler);
    ecr_hm_expr_free(source->expr);
    free_to_null(source);
}

static ecr_hm_status_t ecr_hm_source_compile(ecr_hm_source_t *source, ecr_hm_data_t *data, int force_reload) {
    ecr_hm_source_data_t *source_data;
    ecr_hm_loader_t *loader;

    loader = ecr_hm_find_loader(source->hm, source->uri, NULL);
    if (!loader) {
        return HM_ERROR;
    }
    source_data = loader->load(source, force_reload);
    if (!source_data) {
        return HM_UNMODIFIED;
    }
    source_data->source = source;
    source->expr = ecr_hm_expr_new(data, source_data);
    return HM_OK;
}

static bool ecr_hm_source_matches(ecr_hm_source_t *source, ecr_fixedhash_t *targets, ecr_hm_result_t *result) {
    if (source->expr && ecr_hm_expr_matches(source->expr, targets, result)) {
        ecr_hm_result_set_source(result, source->id);
        return true;
    } else {
        return false;
    }
}

#endif /* SRC_ECR_HYPERMATCH_HM_SOURCE_H_ */
