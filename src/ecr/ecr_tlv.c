/*
 * ecr_tlv.c
 *
 *  Created on: Apr 1, 2015
 *      Author: velna
 */

#include "ecr_tlv.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int ecr_tlv_init_ex(ecr_tlv_t *tlv, uint8_t type_size, uint8_t len_size, bool len_inclusive, ecr_buf_t *buf) {
    if (type_size != 1 && type_size != 2 && type_size != 4) {
        return -1;
    }
    if (len_size != 1 && len_size != 2 && len_size != 4) {
        return -1;
    }
    tlv->type_size = type_size;
    tlv->len_size = len_size;
    tlv->len_inclusive = len_inclusive;
    tlv->buf = buf;
    return 0;
}

int ecr_tlv_init(ecr_tlv_t *tlv, uint8_t type_size, uint8_t len_size, ecr_buf_t *buf) {
    return ecr_tlv_init_ex(tlv, type_size, len_size, false, buf);
}

int ecr_tlv_append(ecr_tlv_t *tlv, int type, const void *value, size_t value_len) {
    size_t len;

    if (value == NULL || value_len <= 0) {
        return 0;
    }
    if (ecr_buf_put(tlv->buf, &type, tlv->type_size)) {
        return -1;
    }
    len = tlv->len_inclusive ? value_len + tlv->type_size + tlv->len_size : value_len;
    if (ecr_buf_put(tlv->buf, &len, tlv->len_size)) {
        return -1;
    }
    if (ecr_buf_put(tlv->buf, value, value_len)) {
        return -1;
    }
    return 0;
}

static ECR_INLINE int ecr_tlv_append_tl(ecr_tlv_t *tlv, int type, size_t len) {
    int rc = -1;
    switch (tlv->type_size) {
    case sizeof(uint8_t):
        rc = ecr_buf_put_int8(tlv->buf, type);
        break;
    case 2:
        rc = ecr_buf_put_int16(tlv->buf, type);
        break;
    case 4:
        rc = ecr_buf_put_int32(tlv->buf, type);
        break;
    }
    if (rc) {
        return rc;
    }
    size_t l = tlv->len_inclusive ? len + tlv->len_size + tlv->type_size : len;
    switch (tlv->len_size) {
    case sizeof(uint8_t):
        rc = ecr_buf_put_int8(tlv->buf, l);
        break;
    case 2:
        rc = ecr_buf_put_int16(tlv->buf, l);
        break;
    case 4:
        rc = ecr_buf_put_int32(tlv->buf, l);
        break;
    }
    return rc;
}

int ecr_tlv_append_uint8(ecr_tlv_t *tlv, int type, uint8_t i) {
    return ecr_tlv_append_tl(tlv, type, sizeof(uint8_t)) || ecr_buf_put_uint8(tlv->buf, i);
}

int ecr_tlv_append_uint16(ecr_tlv_t *tlv, int type, uint16_t i) {
    return ecr_tlv_append_tl(tlv, type, sizeof(uint16_t)) || ecr_buf_put_uint16(tlv->buf, i);
}

int ecr_tlv_append_uint32(ecr_tlv_t *tlv, int type, uint32_t i) {
    return ecr_tlv_append_tl(tlv, type, sizeof(uint32_t)) || ecr_buf_put_uint32(tlv->buf, i);
}

int ecr_tlv_append_uint64(ecr_tlv_t *tlv, int type, uint64_t i) {
    return ecr_tlv_append_tl(tlv, type, sizeof(uint64_t)) || ecr_buf_put_uint64(tlv->buf, i);
}

int ecr_tlv_next(ecr_tlv_t *tlv, int *type, size_t *value_len) {
    size_t len = 0;
    int t;
    tlv->next_value_len = 0;
    if (ecr_buf_size(tlv->buf) < tlv->type_size + tlv->len_size) {
        return -1;
    }
    switch (tlv->type_size) {
    case 1:
        t = ecr_buf_get_int8(tlv->buf);
        break;
    case 2:
        t = ecr_buf_get_int16(tlv->buf);
        break;
    case 4:
        t = ecr_buf_get_int32(tlv->buf);
        break;
    default:
        return -1;
    }
    switch (tlv->len_size) {
    case 1:
        len = ecr_buf_get_uint8(tlv->buf);
        break;
    case 2:
        len = ecr_buf_get_uint16(tlv->buf);
        break;
    case 4:
        len = ecr_buf_get_uint32(tlv->buf);
        break;
    default:
        return -1;
    }
    if (tlv->len_inclusive) {
        if (len < tlv->type_size + tlv->len_size) {
            return -1;
        } else {
            len -= tlv->type_size + tlv->len_size;
        }
    }
    if (ecr_buf_size(tlv->buf) < len) {
        return -1;
    }
    *type = t;
    *value_len = tlv->next_value_len = len;
    return 0;
}

void * ecr_tlv_get(ecr_tlv_t *tlv) {
    if (tlv->next_value_len) {
        return ecr_buf_get(tlv->buf, tlv->next_value_len);
    } else {
        return NULL;
    }
}

#define ecr_tlv_get_int(type, len) \
type##len##_t ecr_tlv_get_##type##len(ecr_tlv_t *tlv) { \
    assert (tlv->next_value_len == sizeof(type##len##_t)); \
    return ecr_buf_get_##type##len(tlv->buf); \
}

ecr_tlv_get_int(uint, 8)
ecr_tlv_get_int(uint, 16)
ecr_tlv_get_int(uint, 32)
ecr_tlv_get_int(uint, 64)

ecr_tlv_get_int(int, 8)
ecr_tlv_get_int(int, 16)
ecr_tlv_get_int(int, 32)
ecr_tlv_get_int(int, 64)
