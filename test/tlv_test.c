/*
 * tlv_test.c
 *
 *  Created on: Oct 27, 2017
 *      Author: velna
 */

#include "CUnit/CUnit.h"
#include <ecr/ecr_tlv.h>
#include <ecr/ecr_util.h>
#include <string.h>
#include <stdio.h>

static int init(void) {
    return 0;
}

static int cleanup(void) {
    return 0;
}

static void tlv_test_ok() {
    uint8_t data[256];
    ecr_buf_t buf;
    ecr_tlv_t tlv;

    ecr_buf_init(&buf, data, 256);
    ecr_tlv_init(&tlv, 2, 2, &buf);

    ecr_tlv_append_uint16(&tlv, 1, 0x1234);
    ecr_tlv_append_uint32(&tlv, 2, 0x56789012);

    ecr_buf_flip(&buf);

    int rc, type;
    size_t len;

    rc = ecr_tlv_next(&tlv, &type, &len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(type, 1);
    CU_ASSERT_EQUAL(len, 2);

    CU_ASSERT_EQUAL(ecr_tlv_get_uint16(&tlv), 0x1234);

    rc = ecr_tlv_next(&tlv, &type, &len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(type, 2);
    CU_ASSERT_EQUAL(len, 4);

    CU_ASSERT_EQUAL(ecr_tlv_get_uint32(&tlv), 0x56789012);

    rc = ecr_tlv_next(&tlv, &type, &len);
    CU_ASSERT_EQUAL(rc, -1);
}

CU_TestInfo tlv_cases[] = {
//
        { "tlv_test_ok:", tlv_test_ok },
        CU_TEST_INFO_NULL };

CU_SuiteInfo tlv_suites[] = {
//
        { "tlv suites:", init, cleanup, NULL, NULL, tlv_cases },
        CU_SUITE_INFO_NULL };
