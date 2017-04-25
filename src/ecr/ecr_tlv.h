/*
 * ecr_tlv.h
 *
 *  Created on: Apr 1, 2015
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_TLV_H_
#define SRC_ECR_ECR_TLV_H_

#include "ecrconf.h"
#include "ecr_buf.h"

typedef struct {
    char type_size;
    char len_size;
    char len_inclusive;
    ecr_buf_t *buf;
} ecr_tlv_t;

int ecr_tlv_init(ecr_tlv_t *tlv, char type_size, char len_size, ecr_buf_t *buf);

int ecr_tlv_init_ex(ecr_tlv_t *tlv, char type_size, char len_size, char len_inclusive, ecr_buf_t *buf);

int ecr_tlv_append(ecr_tlv_t *tlv, size_t type, const void *value, size_t value_len);

void * ecr_tlv_get(ecr_tlv_t *tlv, size_t *type, size_t *value_len);

#endif /* SRC_ECR_ECR_TLV_H_ */
