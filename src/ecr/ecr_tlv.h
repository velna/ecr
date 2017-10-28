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
    uint8_t type_size;
    uint8_t len_size;
    bool len_inclusive;
    ecr_buf_t *buf;
    size_t next_value_len;
} ecr_tlv_t;

int ecr_tlv_init(ecr_tlv_t *tlv, uint8_t type_size, uint8_t len_size, ecr_buf_t *buf);

int ecr_tlv_init_ex(ecr_tlv_t *tlv, uint8_t type_size, uint8_t len_size, bool len_inclusive, ecr_buf_t *buf);

int ecr_tlv_append(ecr_tlv_t *tlv, int type, const void *value, size_t value_len);
int ecr_tlv_append_uint8(ecr_tlv_t *tlv, int type, uint8_t i);
int ecr_tlv_append_uint16(ecr_tlv_t *tlv, int type, uint16_t i);
int ecr_tlv_append_uint32(ecr_tlv_t *tlv, int type, uint32_t i);
int ecr_tlv_append_uint64(ecr_tlv_t *tlv, int type, uint64_t i);

int ecr_tlv_next(ecr_tlv_t *tlv, int *type, size_t *value_len);

void * ecr_tlv_get(ecr_tlv_t *tlv);
uint8_t ecr_tlv_get_uint8(ecr_tlv_t *tlv);
uint16_t ecr_tlv_get_uint16(ecr_tlv_t *tlv);
uint32_t ecr_tlv_get_uint32(ecr_tlv_t *tlv);
uint64_t ecr_tlv_get_uint64(ecr_tlv_t *tlv);
int8_t ecr_tlv_get_int8(ecr_tlv_t *tlv);
int16_t ecr_tlv_get_int16(ecr_tlv_t *tlv);
int32_t ecr_tlv_get_int32(ecr_tlv_t *tlv);
int64_t ecr_tlv_get_int64(ecr_tlv_t *tlv);

#endif /* SRC_ECR_ECR_TLV_H_ */
