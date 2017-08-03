/*
 * hm_result.h
 *
 *  Created on: Aug 1, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_HYPERMATCH_HM_RESULT_H_
#define SRC_ECR_HYPERMATCH_HM_RESULT_H_

#include "hm_private.h"

#define ecr_hm_result_set_source(result, source_id) ((result)->source_match_list.ptr[source_id] = 1)

static ECR_INLINE void ecr_hm_result_set_expr(ecr_hm_result_t *result, int expr_id, bool matches, ecr_hm_field_t *field, ecr_str_t *target) {
    ecr_hm_result_kv_t *kv;
    kv = &result->expr_match_list[expr_id];
    kv->field = field;
    kv->target = target;
    kv->status = matches ? HM_MATCH : HM_NOT_MATCH;
}

#define ecr_hm_result_get_expr(result, expr_id) ((result)->expr_match_list[expr_id].status)

#endif /* SRC_ECR_HYPERMATCH_HM_RESULT_H_ */
