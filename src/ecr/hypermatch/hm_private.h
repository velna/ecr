/*
 * hm_private.h
 *
 *  Created on: Aug 1, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_HYPERMATCH_HM_PRIVATE_H_
#define SRC_ECR_HYPERMATCH_HM_PRIVATE_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "../ecr_util.h"

static int ecr_hm_data_get_expr_id(ecr_hm_data_t *data, int source_id, const char *field, const char *matcher_name,
        const char *var_name);

static ecr_hm_matcher_t* ecr_hm_data_get_matcher(ecr_hm_data_t *data, const char *field, const char *matcher_name);

#endif /* SRC_ECR_HYPERMATCH_HM_PRIVATE_H_ */
