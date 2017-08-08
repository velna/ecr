/*
 * hm_source_data.h
 *
 *  Created on: Aug 8, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_HYPERMATCH_HM_SOURCE_DATA_H_
#define SRC_ECR_HYPERMATCH_HM_SOURCE_DATA_H_

#include "hm_private.h"

static int ecr_hm_source_data_init(ecr_hm_source_data_t *source_data, ecr_hm_source_t *source) {
    memset(source_data, 0, sizeof(ecr_hm_source_data_t));
    source_data->source = source;
    source_data->logic = HM_OR;
    ecr_hashmap_init(&source_data->expr_set, 16, 0);
    ecr_hashmap_init(&source_data->values, 16, 0);
    return 0;
}

static void ecr_hm_source_data_free_values_handler(ecr_hashmap_t *map, void *key, size_t key_size, void *value) {
    ecr_list_t *list = value;

    ecr_list_destroy(list, ecr_list_free_value_handler);
}

static void ecr_hm_source_data_destroy(ecr_hm_source_data_t *source_data) {
    ecr_hashmap_destroy(&source_data->expr_set, NULL);
    ecr_hashmap_destroy(&source_data->values, ecr_hm_source_data_free_values_handler);
}

#endif /* SRC_ECR_HYPERMATCH_HM_SOURCE_DATA_H_ */
