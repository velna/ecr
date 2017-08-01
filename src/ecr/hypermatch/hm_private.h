/*
 * hm_private.h
 *
 *  Created on: Aug 1, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_HYPERMATCH_HM_PRIVATE_H_
#define SRC_ECR_HYPERMATCH_HM_PRIVATE_H_

#define ecr_hm_error(hm, fmt, ...) snprintf((hm)->errbuf, ECR_HM_ERRBUF_SIZE, fmt, ##__VA_ARGS__)

static ecr_hm_matcher_t* ecr_hm_data_get_matcher(ecr_hm_data_t *data, const char *field, const char *matcher_name);

#endif /* SRC_ECR_HYPERMATCH_HM_PRIVATE_H_ */
