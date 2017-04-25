/*
 * ecr_tlv.c
 *
 *  Created on: Apr 1, 2015
 *      Author: velna
 */

#include "ecr_tlv.h"
#include <stdlib.h>
#include <string.h>

int ecr_tlv_init_ex(ecr_tlv_t *tlv, char type_size, char len_size, char len_inclusive, ecr_buf_t *buf) {
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

int ecr_tlv_init(ecr_tlv_t *tlv, char type_size, char len_size, ecr_buf_t *buf) {
    return ecr_tlv_init_ex(tlv, type_size, len_size, 0, buf);
}

int ecr_tlv_append(ecr_tlv_t *tlv, size_t type, const void *value, size_t value_len) {
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

void * ecr_tlv_get(ecr_tlv_t *tlv, size_t *type, size_t *value_len) {
    void *v;
    size_t size;
    v = ecr_buf_get(tlv->buf, tlv->type_size);
    if (v) {
        size = 0;
        memcpy(&size, v, tlv->type_size);
        *type = size;
    } else {
        return NULL;
    }
    v = ecr_buf_get(tlv->buf, tlv->len_size);
    if (v) {
        size = 0;
        memcpy(&size, v, tlv->len_size);
        if (size <= tlv->type_size + tlv->len_size) {
            return NULL;
        }
        *value_len = tlv->len_inclusive ? size - tlv->type_size - tlv->len_size : size;
    } else {
        return NULL;
    }
    return ecr_buf_get(tlv->buf, *value_len);
}
