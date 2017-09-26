/*
 * hm_loader.h
 *
 *  Created on: Aug 8, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_HYPERMATCH_HM_LOADER_H_
#define SRC_ECR_HYPERMATCH_HM_LOADER_H_

#include "ecrconf.h"
#include "hm.h"

int ecr_hm_load_from_stream(ecr_hm_source_t *source, FILE *stream, ecr_hm_source_data_t *source_data, void *user);

int ecr_hm_load_values_from_stream(ecr_hm_source_t *source, FILE *stream, ecr_list_t *values, void *user);

void ecr_hm_source_data_add_value(ecr_hm_source_data_t *source_data, const char *var_name, const char *value);

ecr_list_t* ecr_hm_source_data_get_values(ecr_hm_source_data_t *source_data, const char *var_name);

void ecr_hm_source_data_add_expr(ecr_hm_source_data_t *source_data, const char *expr);

#endif /* SRC_ECR_HYPERMATCH_HM_LOADER_H_ */
