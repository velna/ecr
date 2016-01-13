/*
 * ecr_tlv.c
 *
 *  Created on: Apr 1, 2015
 *      Author: velna
 */

#include "ecr_tlv.h"
#include <stdlib.h>
#include <string.h>

int ecr_tlv_init(ecr_tlv_t *tlv, char type_size, char len_size, ecr_buf_t *buf) {
    if (type_size != 1 && type_size != 2 && type_size != 4) {
        return -1;
    }
    if (len_size != 1 && len_size != 2 && len_size != 4) {
        return -1;
    }
    tlv->type_size = type_size;
    tlv->len_size = len_size;
    tlv->buf = buf;
    return 0;
}

int ecr_tlv_append(ecr_tlv_t *tlv, size_t type, const void *value, size_t value_len) {
    if (value == NULL || value_len <= 0) {
        return 0;
    }
    if (ecr_buf_put(tlv->buf, &type, tlv->type_size)) {
        return -1;
    }
    if (ecr_buf_put(tlv->buf, &value_len, tlv->len_size)) {
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
        *value_len = size;
    } else {
        return NULL;
    }
    return ecr_buf_get(tlv->buf, *value_len);
}
