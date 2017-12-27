/*
 * ecr_buf.c
 *
 *  Created on: Feb 24, 2014
 *      Author: velna
 */

#include "config.h"
#include "ecr_buf.h"
#include <string.h>
#include <endian.h>

int ecr_buf_init(ecr_buf_t *buf, void *data, size_t size) {
    memset(buf, 0, sizeof(ecr_buf_t));
    buf->p = data;
    buf->capacity = size;
    buf->limit = size;
    buf->position = 0;
    buf->order = ECR_LITTLE_ENDIAN;
    return 0;
}

ecr_buf_order_t ecr_buf_set_order(ecr_buf_t *buf, ecr_buf_order_t order) {
    ecr_buf_order_t old = buf->order;
    buf->order = order;
    return old;
}

ecr_buf_order_t ecr_buf_get_order(ecr_buf_t *buf) {
    return buf->order;
}

void * ecr_buf_data(ecr_buf_t *buf) {
    return buf->p + buf->position;
}

size_t ecr_buf_size(ecr_buf_t *buf) {
    return buf->limit - buf->position;
}

size_t ecr_buf_clear(ecr_buf_t *buf) {
    buf->position = 0;
    buf->limit = buf->capacity;
    return buf->limit - buf->position;
}

size_t ecr_buf_flip(ecr_buf_t *buf) {
    buf->limit = buf->position;
    buf->position = 0;
    return buf->limit - buf->position;
}

size_t ecr_buf_rewind(ecr_buf_t *buf) {
    buf->position = 0;
    return buf->limit - buf->position;
}

int ecr_buf_put(ecr_buf_t *buf, const void *from, size_t size) {
    if (buf->limit - buf->position < size) {
        return -1;
    }
    memcpy(buf->p + buf->position, from, size);
    buf->position += size;
    return 0;
}

int ecr_buf_put_uint8(ecr_buf_t *buf, uint8_t i) {
    return ecr_buf_put(buf, &i, sizeof(uint8_t));
}

int ecr_buf_put_uint16(ecr_buf_t *buf, uint16_t u16) {
    uint16_t v = buf->order == ECR_BIG_ENDIAN ? htobe16(u16) : htole16(u16);
    return ecr_buf_put(buf, &v, sizeof(uint16_t));
}

int ecr_buf_put_uint32(ecr_buf_t *buf, uint32_t u32) {
    uint32_t v = buf->order == ECR_BIG_ENDIAN ? htobe32(u32) : htole32(u32);
    return ecr_buf_put(buf, &v, sizeof(uint32_t));
}

int ecr_buf_put_uint64(ecr_buf_t *buf, uint64_t u64) {
    uint64_t v = buf->order == ECR_BIG_ENDIAN ? htobe64(u64) : htole64(u64);
    return ecr_buf_put(buf, &v, sizeof(uint64_t));
}

void * ecr_buf_get(ecr_buf_t *buf, size_t size) {
    if (buf->position + size > buf->limit) {
        return NULL;
    }
    void *p = buf->p + buf->position;
    buf->position += size;
    return p;
}

uint8_t ecr_buf_get_uint8(ecr_buf_t *buf) {
    uint8_t *p = ecr_buf_get(buf, sizeof(uint8_t));
    if (!p) {
        return -1;
    }
    return *p;
}

int8_t ecr_buf_get_int8(ecr_buf_t *buf) {
    int8_t *p = ecr_buf_get(buf, sizeof(int8_t));
    if (!p) {
        return -1;
    }
    return *p;
}

#define ecr_buf_get_int(type, len) \
        type##len##_t ecr_buf_get_##type##len(ecr_buf_t *buf) { \
    uint8_t *p = ecr_buf_get(buf, sizeof(type##len##_t)); \
    if (!p) { \
        return -1; \
    } \
    type##len##_t i; \
    memcpy(&i, p, sizeof(type##len##_t)); \
    return buf->order == ECR_BIG_ENDIAN ? be##len##toh(i) : le##len##toh(i); \
}

ecr_buf_get_int(uint, 16)

ecr_buf_get_int(uint, 32)

ecr_buf_get_int(uint, 64)

ecr_buf_get_int(int, 16)

ecr_buf_get_int(int, 32)

ecr_buf_get_int(int, 64)

float ecr_buf_get_float(ecr_buf_t *buf) {
    uint8_t *p = ecr_buf_get(buf, sizeof(float));
    if (!p) {
        return -1;
    }
    float f;
    memcpy(&f, p, sizeof(float));
    return f;
}

double ecr_buf_get_double(ecr_buf_t *buf) {
    uint8_t *p = ecr_buf_get(buf, sizeof(double));
    if (!p) {
        return -1;
    }
    double d;
    memcpy(&d, p, sizeof(double));
    return d;
}

int ecr_buf_get_str(ecr_buf_t *buf, size_t len_size, ecr_str_t *out) {
    size_t len;
    char *s;
    switch (len_size) {
    case 1:
        len = *((uint8_t*) ecr_buf_get(buf, len_size));
        break;
    case 2:
        len = *((uint16_t*) ecr_buf_get(buf, len_size));
        break;
    case 4:
        len = *((uint32_t*) ecr_buf_get(buf, len_size));
        break;
    case 8:
        len = *((uint64_t*) ecr_buf_get(buf, len_size));
        break;
    default:
        return -1;
    }
    s = ecr_buf_get(buf, len);
    if (!s) {
        return -1;
    }
    out->ptr = strndup(s, len);
    return 0;
}

size_t ecr_buf_copy(ecr_buf_t *buf, void *to, size_t size) {
    if (buf->position + size > buf->limit) {
        return 0;
    }
    memcpy(to, buf->p + buf->position, size);
    buf->position += size;
    return size;
}
