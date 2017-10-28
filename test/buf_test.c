/*
 * buf_test.c
 *
 *  Created on: Oct 27, 2017
 *      Author: velna
 */

#include "CUnit/CUnit.h"
#include <ecr/ecr_buf.h>
#include <ecr/ecr_util.h>
#include <string.h>
#include <stdio.h>

static int init(void) {
    return 0;
}

static int cleanup(void) {
    return 0;
}

static void buf_test_endian(ecr_buf_order_t order, int8_t *data_expected) {
    char data[256] = { 0 };

    ecr_buf_t buf;

    ecr_buf_init(&buf, data, 256);
    ecr_buf_set_order(&buf, order);

    CU_ASSERT_EQUAL(ecr_buf_get_order(&buf), order);

    ecr_buf_put_uint8(&buf, 0x01);
    ecr_buf_put_uint16(&buf, 0x1234);
    ecr_buf_put_uint32(&buf, 0x12345678);
    ecr_buf_put_uint64(&buf, 0x1234567890123456L);
    ecr_buf_put_int8(&buf, -0x01);

    CU_ASSERT_EQUAL(memcmp(data, data_expected, 256), 0);

    ecr_buf_flip(&buf);


    CU_ASSERT_EQUAL(ecr_buf_get_uint8(&buf), 0x01);

    CU_ASSERT_EQUAL(ecr_buf_get_uint16(&buf), 0x1234);

    CU_ASSERT_EQUAL(ecr_buf_get_uint32(&buf), 0x12345678);

    CU_ASSERT_EQUAL(ecr_buf_get_uint64(&buf), 0x1234567890123456L);

    CU_ASSERT_EQUAL(ecr_buf_get_int8(&buf), -0x01);

    ecr_binary_dump(stdout, data, 32);
    ecr_binary_dump(stdout, data_expected, 32);
}

static void buf_test_ok() {

    int8_t data_little_endian[256] = {
            0x01,
            0x34,
            0x12,
            0x78,
            0x56,
            0x34,
            0x12,
            0x56,
            0x34,
            0x12,
            0x90,
            0x78,
            0x56,
            0x34,
            0x12,
            -0x01 };

    int8_t data_big_endian[256] = {
            0x01,
            0x12,
            0x34,
            0x12,
            0x34,
            0x56,
            0x78,
            0x12,
            0x34,
            0x56,
            0x78,
            0x90,
            0x12,
            0x34,
            0x56,
            -0x01 };

    buf_test_endian(ECR_LITTLE_ENDIAN, data_little_endian);
    buf_test_endian(ECR_BIG_ENDIAN, data_big_endian);
}

CU_TestInfo buf_cases[] = {
//
        { "buf_test_ok:", buf_test_ok },
        CU_TEST_INFO_NULL };

CU_SuiteInfo buf_suites[] = {
//
        { "buf suites:", init, cleanup, NULL, NULL, buf_cases },
        CU_SUITE_INFO_NULL };
