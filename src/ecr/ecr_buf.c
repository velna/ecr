/*
 * ecr_buf.c
 *
 *  Created on: Feb 24, 2014
 *      Author: velna
 */

#include "config.h"
#include "ecr_buf.h"
#include <string.h>

int ecr_buf_init(ecr_buf_t *buf, void *data, size_t size) {
    memset(buf, 0, sizeof(ecr_buf_t));
    buf->p = data;
    buf->capacity = size;
    buf->limit = size;
    buf->position = 0;
    return 0;
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

void * ecr_buf_get(ecr_buf_t *buf, size_t size) {
    if (buf->position + size > buf->limit) {
        return NULL;
    }
    void *p = buf->p + buf->position;
    buf->position += size;
    return p;
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
    memcpy(to, buf->p, size);
    buf->position += size;
    return size;
}
