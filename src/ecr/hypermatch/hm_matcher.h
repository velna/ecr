/*
 * hm_matcher.h
 *
 *  Created on: Aug 1, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_HYPERMATCH_HM_MATCHER_H_
#define SRC_ECR_HYPERMATCH_HM_MATCHER_H_

#include "hm_private.h"

static ecr_hm_matcher_t* ecr_hm_matcher_new(ecr_hm_matcher_reg_t *reg) {
    ecr_hm_matcher_t *matcher;
    matcher = calloc(1, sizeof(ecr_hm_matcher_t));
    matcher->data = reg->init(reg->name);
    matcher->reg = reg;
    return matcher;
}

static void ecr_hm_matcher_free(ecr_hm_matcher_t *matcher) {
    matcher->reg->destroy(matcher->data);
    free_to_null(matcher);
}

static void ecr_hm_matcher_dump(ecr_hm_matcher_t *matcher, ecr_dumper_t *dumper) {
    ecr_dump_field_format(dumper, "name", "%s", matcher->reg->name);
    ecr_dump_field_format(dumper, "size", "%ld", matcher->reg->size(matcher->data));
}

static void ecr_hm_matcher_compile(ecr_hm_matcher_t *matcher) {
    if (matcher->reg->compile) {
        matcher->reg->compile(matcher->data);
    }
}

static ECR_INLINE void ecr_hm_matcher_matches(ecr_hm_matcher_t *matcher, ecr_hm_match_context_t *match_ctx) {
    matcher->reg->matches(matcher->data, match_ctx);
}

static int ecr_hm_matcher_add_values(ecr_hm_matcher_t *matcher, ecr_list_t *values, int expr_id) {
    return matcher->reg->add_values(matcher->data, values, expr_id);
}

#endif /* SRC_ECR_HYPERMATCH_HM_MATCHER_H_ */
