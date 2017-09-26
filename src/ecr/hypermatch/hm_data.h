/*
 * hm_data.h
 *
 *  Created on: Aug 1, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_HYPERMATCH_HM_DATA_H_
#define SRC_ECR_HYPERMATCH_HM_DATA_H_

#include "hm_private.h"

static ecr_hm_data_t * ecr_hm_data_new(ecr_hm_t *hm) {
    ecr_hm_data_t *data = calloc(1, sizeof(ecr_hm_data_t));
    data->hm = hm;
    data->compiled = false;
    data->next_sid = 1;
    data->next_expr_id = 1;
    ecr_hashmap_init(&data->expr_id_map, 16, 0);
    ecr_hashmap_init(&data->source_map, 16, 0);
    ecr_hashmap_init(&data->matcher_map, 16, 0);
    return data;
}

static void ecr_hm_data_copy_sources(ecr_hm_data_t *src, ecr_hm_data_t *dst) {
    dst->next_sid = src->next_sid;
    ecr_hashmap_put_all(&dst->source_map, &src->source_map);
}

static void ecr_hm_data_dump(ecr_hm_data_t *data, ecr_dumper_t *dumper) {
    ecr_hashmap_iter_t iter;
    ecr_hm_source_t *source;
    ecr_hm_matcher_t *matcher;
    void *expr_id_ptr;
    char *expr_id_key;
    char *matcher_key;
    int *source_key;

    ecr_dump_field_format(dumper, "next_sid", "%d", data->next_sid);
    ecr_dump_field_format(dumper, "next_expr_id", "%d", data->next_expr_id);

    ecr_dump_start_field_object(dumper, "source_map");
    ecr_hashmap_iter_init(&iter, &data->source_map);
    while (ecr_hashmap_iter_next(&iter, (void**) &source_key, NULL, (void**) &source) == 0) {
        ecr_dump_field_name(dumper, "%d", *source_key);
        ecr_dump_field_value_object(dumper, source, (ecr_dumper_cb) ecr_hm_source_dump);
    }
    ecr_dump_end_field_object(dumper);

    ecr_dump_start_field_object(dumper, "matcher_map");
    ecr_hashmap_iter_init(&iter, &data->matcher_map);
    while (ecr_hashmap_iter_next(&iter, (void**) &matcher_key, NULL, (void**) &matcher) == 0) {
        ecr_dump_field_name(dumper, "%s", matcher_key);
        ecr_dump_field_value_object(dumper, matcher, (ecr_dumper_cb) ecr_hm_matcher_dump);
    }
    ecr_dump_end_field_object(dumper);

    ecr_dump_start_field_object(dumper, "expr_id_map");
    ecr_hashmap_iter_init(&iter, &data->expr_id_map);
    while (ecr_hashmap_iter_next(&iter, (void**) &expr_id_key, NULL, (void**) &expr_id_ptr) == 0) {
        ecr_dump_field_format(dumper, expr_id_key, "%ld", expr_id_ptr - NULL);
    }
    ecr_dump_end_field_object(dumper);
}

static int ecr_hm_data_is_empty(ecr_hm_data_t *data) {
    return data->next_sid == 1;
}

static int ecr_hm_data_add(ecr_hm_data_t *data, ecr_hm_source_t *source) {
    if (data->compiled) {
        return -1;
    }
    source->id = data->next_sid++;
    ecr_hashmap_put(&data->source_map, &source->id, sizeof(int), source);
    return source->id;
}

static ecr_hm_source_t* ecr_hm_data_remove(ecr_hm_data_t *data, int source_id) {
    return ecr_hashmap_remove(&data->source_map, &source_id, sizeof(int));
}

static void ecr_hm_data_free_source_handler(ecr_hashmap_t *map, void *key, size_t key_size, void *value) {
    ecr_hm_source_free(value);
}

static void ecr_hm_data_free_matcher_handler(ecr_hashmap_t *map, void *key, size_t key_size, void *value) {
    ecr_hm_matcher_free(value);
}

static void ecr_hm_data_clear(ecr_hm_data_t *data) {
    data->compiled = false;
    data->next_sid = 1;
    data->next_expr_id = 1;
    ecr_hashmap_clear(&data->expr_id_map, NULL);
    ecr_hashmap_clear(&data->source_map, ecr_hm_data_free_source_handler);
    ecr_hashmap_clear(&data->matcher_map, ecr_hm_data_free_matcher_handler);
}

static ecr_hm_status_t ecr_hm_data_compile(ecr_hm_data_t *data, bool force_reload) {
    ecr_list_t* unmodified_list = ecr_list_new(4);
    ecr_hashmap_iter_t iter;
    ecr_hm_source_t *source;
    ecr_hm_status_t status = HM_UNMODIFIED;
    ecr_hm_matcher_t *matcher;
    int i;

    ecr_hashmap_iter_init(&iter, &data->source_map);
    while (ecr_hashmap_iter_next(&iter, NULL, NULL, (void**) &source) == 0) {
        status = ecr_hm_source_compile(source, data, status == HM_OK ? 1 : force_reload);
        if (status == HM_OK) {
            // do nothing
        } else if (status == HM_UNMODIFIED) {
            ecr_list_add(unmodified_list, source);
        } else {
            goto end;
        }
    }
    if (status == HM_OK) {
        for (i = 0; i < unmodified_list->size; i++) {
            source = unmodified_list->data[i];
            status = ecr_hm_source_compile(source, data, 1);
            if (status == HM_ERROR) {
                goto end;
            }
        }
        ecr_hashmap_iter_init(&iter, &data->matcher_map);
        while (ecr_hashmap_iter_next(&iter, NULL, NULL, (void**) &matcher) == 0) {
            ecr_hm_matcher_compile(matcher);
        }
    }
    data->compiled = true;
    end: {
        ecr_list_destroy(unmodified_list, NULL);
        return status;
    }
}

static bool ecr_hm_data_matches(ecr_hm_data_t *data, ecr_fixedhash_t *targets, ecr_hm_result_t* result) {
    bool matches = false;
    ecr_hashmap_iter_t iter;
    ecr_hm_source_t *source;

    if (!data->compiled) {
        return false;
    }
    ecr_hm_result_clear(result);
    ecr_hashmap_iter_init(&iter, &data->source_map);
    while (ecr_hashmap_iter_next(&iter, NULL, NULL, (void**) &source) == 0) {
        if (ecr_hm_source_matches(source, targets, result)) {
            matches = true;
        }
    }

    return matches;
}

static void ecr_hm_data_destroy(ecr_hm_data_t *data) {
    ecr_hashmap_destroy(&data->expr_id_map, NULL);
    ecr_hashmap_destroy(&data->source_map, ecr_hm_data_free_source_handler);
    ecr_hashmap_destroy(&data->matcher_map, ecr_hm_data_free_matcher_handler);
    free(data);
}

static ecr_hm_matcher_t* ecr_hm_create_matcher(ecr_hm_t *hm, const char *matcher_name) {
    ecr_hm_matcher_reg_t *matcher_reg;

    matcher_reg = ecr_hashmap_get(&hm->matcher_registry, matcher_name, strlen(matcher_name));
    if (!matcher_reg) {
        return NULL;
    }
    return ecr_hm_matcher_new(matcher_reg);
}

static ecr_hm_matcher_t* ecr_hm_data_get_matcher(ecr_hm_data_t *data, const char *field, const char *matcher_name) {
    ecr_str_t key;
    ecr_hm_matcher_t *matcher;

    key.len = asprintf(&key.ptr, "%s %s", field, matcher_name);
    matcher = ecr_hashmap_get(&data->matcher_map, key.ptr, key.len + 1);
    if (!matcher) {
        matcher = ecr_hm_create_matcher(data->hm, matcher_name);
        if (matcher) {
            ecr_hashmap_put(&data->matcher_map, key.ptr, key.len + 1, matcher);
        }
    }
    free(key.ptr);
    return matcher;
}

static int ecr_hm_data_get_expr_id(ecr_hm_data_t *data, int source_id, const char *field, const char *matcher_name,
        const char *var_name) {
    ecr_str_t key;
    int expr_id;

    if (!var_name) {
        key.len = asprintf(&key.ptr, "%d:%s %s", source_id, field, matcher_name);
    } else {
        key.len = asprintf(&key.ptr, "%d:%s %s %s", source_id, field, matcher_name, var_name);
    }
    expr_id = (int) (ecr_hashmap_get(&data->expr_id_map, key.ptr, key.len + 1) - NULL);
    if (!expr_id) {
        expr_id = data->next_expr_id++;
        ecr_hashmap_put(&data->expr_id_map, key.ptr, key.len + 1, (NULL + expr_id));
    }
    free(key.ptr);
    return expr_id;
}

#endif /* SRC_ECR_HYPERMATCH_HM_DATA_H_ */
