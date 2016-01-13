/*
 * ecr_buf.h
 *
 *  Created on: Feb 24, 2014
 *      Author: velna
 */

#ifndef ECR_BUF_H_
#define ECR_BUF_H_

#include "ecrconf.h"

#define ecr_buf_get_uint8(buf)      (*((uint8_t*)ecr_buf_get(buf, sizeof(uint8_t))))
#define ecr_buf_get_uint16(buf)     (*((uint16_t*)ecr_buf_get(buf, sizeof(uint16_t))))
#define ecr_buf_get_uint32(buf)     (*((uint32_t*)ecr_buf_get(buf, sizeof(uint32_t))))
#define ecr_buf_get_uint64(buf)     (*((uint64_t*)ecr_buf_get(buf, sizeof(uint64_t))))
#define ecr_buf_get_int8(buf)       (*((int8_t*)ecr_buf_get(buf, sizeof(int8_t))))
#define ecr_buf_get_int16(buf)      (*((int16_t*)ecr_buf_get(buf, sizeof(int16_t))))
#define ecr_buf_get_int32(buf)      (*((int32_t*)ecr_buf_get(buf, sizeof(int32_t))))
#define ecr_buf_get_int64(buf)      (*((int64_t*)ecr_buf_get(buf, sizeof(int64_t))))
#define ecr_buf_get_float(buf)      (*((float*)ecr_buf_get(buf, sizeof(float))))
#define ecr_buf_get_double(buf)     (*((double*)ecr_buf_get(buf, sizeof(double))))

#define ecr_buf_put_uint8(buf, u)   ecr_buf_put(buf, &(u), sizeof(uint8_t))
#define ecr_buf_put_uint16(buf, u)  ecr_buf_put(buf, &(u), sizeof(uint16_t))
#define ecr_buf_put_uint32(buf, u)  ecr_buf_put(buf, &(u), sizeof(uint32_t))
#define ecr_buf_put_uint64(buf, u)  ecr_buf_put(buf, &(u), sizeof(uint64_t))
#define ecr_buf_put_int8(buf, i)    ecr_buf_put(buf, &(i), sizeof(int8_t))
#define ecr_buf_put_int16(buf, i)   ecr_buf_put(buf, &(i), sizeof(int16_t))
#define ecr_buf_put_int32(buf, i)   ecr_buf_put(buf, &(i), sizeof(int32_t))
#define ecr_buf_put_int64(buf, i)   ecr_buf_put(buf, &(i), sizeof(int64_t))
#define ecr_buf_put_float(buf, f)   ecr_buf_put(buf, &(f), sizeof(float))
#define ecr_buf_put_double(buf, d)  ecr_buf_put(buf, &(d), sizeof(double))

typedef struct {
    u_char *p;
    size_t capacity;
    size_t limit;
    size_t position;
} ecr_buf_t;

int ecr_buf_init(ecr_buf_t *buf, void *data, size_t size);

void * ecr_buf_data(ecr_buf_t *buf);

/**
 * return limit - position
 */
size_t ecr_buf_size(ecr_buf_t *buf);

/**
 * return the size after flip
 */
size_t ecr_buf_flip(ecr_buf_t *buf);

/**
 * return the size after rewind
 */
size_t ecr_buf_rewind(ecr_buf_t *buf);

/**
 * return the capacity
 */
size_t ecr_buf_clear(ecr_buf_t *buf);

int ecr_buf_put(ecr_buf_t * buf, const void *from, size_t size);

void * ecr_buf_get(ecr_buf_t *buf, size_t size);

int ecr_buf_get_str(ecr_buf_t *buf, size_t len_size, ecr_str_t *out);

size_t ecr_buf_copy(ecr_buf_t *buf, void *to, size_t size);

#endif /* ECR_BUF_H_ */
