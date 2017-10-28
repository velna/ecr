/*
 * ecr_buf.h
 *
 *  Created on: Feb 24, 2014
 *      Author: velna
 */

#ifndef ECR_BUF_H_
#define ECR_BUF_H_

#include "ecrconf.h"

typedef enum {
    ECR_BIG_ENDIAN = 4321, ECR_LITTLE_ENDIAN = 1234
} ecr_buf_order_t;

typedef struct {
    u_char *p;
    size_t capacity;
    size_t limit;
    size_t position;
    ecr_buf_order_t order;
} ecr_buf_t;

int ecr_buf_init(ecr_buf_t *buf, void *data, size_t size);

ecr_buf_order_t ecr_buf_set_order(ecr_buf_t *buf, ecr_buf_order_t order);

ecr_buf_order_t ecr_buf_get_order(ecr_buf_t *buf);

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
int ecr_buf_put_uint8(ecr_buf_t *buf, uint8_t i);
#define ecr_buf_put_int8(buf, i)    ecr_buf_put_uint8(buf, (uint8_t)i)
int ecr_buf_put_uint16(ecr_buf_t *buf, uint16_t i);
#define ecr_buf_put_int16(buf, i)   ecr_buf_put_uint16(buf, (uint16_t)i)
int ecr_buf_put_uint32(ecr_buf_t *buf, uint32_t i);
#define ecr_buf_put_int32(buf, i)   ecr_buf_put_uint32(buf, (uint32_t)i)
int ecr_buf_put_uint64(ecr_buf_t *buf, uint64_t i);
#define ecr_buf_put_int64(buf, i)   ecr_buf_put_uint64(buf, (uint64_t)i)
#define ecr_buf_put_float(buf, f)   ecr_buf_put(buf, &(f), sizeof(float))
#define ecr_buf_put_double(buf, d)  ecr_buf_put(buf, &(d), sizeof(double))

void * ecr_buf_get(ecr_buf_t *buf, size_t size);
uint8_t ecr_buf_get_uint8(ecr_buf_t *buf);
int8_t ecr_buf_get_int8(ecr_buf_t *buf);
uint16_t ecr_buf_get_uint16(ecr_buf_t *buf);
int16_t ecr_buf_get_int16(ecr_buf_t *buf);
uint32_t ecr_buf_get_uint32(ecr_buf_t *buf);
int32_t ecr_buf_get_int32(ecr_buf_t *buf);
uint64_t ecr_buf_get_uint64(ecr_buf_t *buf);
int64_t ecr_buf_get_int64(ecr_buf_t *buf);
float ecr_buf_get_float(ecr_buf_t *buf);
double ecr_buf_get_double(ecr_buf_t *buf);

int ecr_buf_get_str(ecr_buf_t *buf, size_t len_size, ecr_str_t *out);

size_t ecr_buf_copy(ecr_buf_t *buf, void *to, size_t size);

#endif /* ECR_BUF_H_ */
