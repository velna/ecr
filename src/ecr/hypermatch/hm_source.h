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
    if (ecr_uri_init(&source->uri, uri)) {
        free(source);
        return NULL;
    }
    ecr_hashmap_init(&source->attrs, 16, 0);
    return source;
}

static void ecr_hm_source_free(ecr_hm_source_t *source) {
    ecr_uri_destroy(&source->uri);
    ecr_hashmap_destroy(&source->attrs, ecr_hashmap_free_value_handler);
    ecr_hm_expr_free(source->expr);
    free_to_null(source);
}

static void ecr_hm_source_dump(ecr_hm_source_t *source, ecr_dumper_t *dumper) {
    ecr_hashmap_iter_t iter;
    char *key_str;
    ecr_str_t key;
    void *value;

    ecr_dump_field_format(dumper, "id", "%d", source->id);
    ecr_dump_field_format(dumper, "uri", "%s", source->uri.string);

    ecr_dump_start_field_object(dumper, "attributs");
    ecr_hashmap_iter_init(&iter, &source->attrs);
    while (ecr_hashmap_iter_next(&iter, (void**) &key.ptr, &key.len, (void**) &value) == 0) {
        key_str = strndup(key.ptr, key.len);
        ecr_dump_field_format(dumper, key_str, "%p", value);
        free(key_str);
    }
    ecr_dump_end_field_object(dumper);

    ecr_dump_field_object(dumper, "expr", source->expr, (ecr_dumper_cb) ecr_hm_expr_dump);
}

static ecr_hm_status_t ecr_hm_source_compile(ecr_hm_source_t *source, ecr_hm_data_t *data, int force_reload) {
    ecr_hm_source_data_t source_data;
    ecr_hm_loader_t *loader;
    int rc;

    loader = ecr_hm_find_loader(source->hm, source->uri.scheme);
    if (!loader) {
        ecr_hm_error(source->hm, "can not find loader of schme '%s'.", source->uri.scheme);
        return HM_ERROR;
    }
    ecr_hm_source_data_init(&source_data, source);
    rc = loader->load(source, force_reload, &source_data, loader->user);
    if (rc == -1) {
        ecr_hm_source_data_destroy(&source_data);
        return HM_ERROR;
    }
    if (rc == 0) {
        ecr_hm_source_data_destroy(&source_data);
        return HM_UNMODIFIED;
    }
    rc = ecr_hm_expr_new(data, &source_data, &source->expr);
    ecr_hm_source_data_destroy(&source_data);
    return rc ? HM_ERROR : HM_OK;
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
