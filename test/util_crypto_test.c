/*
 * util_crypto_test.c
 *
 *  Created on: Jun 14, 2017
 *      Author: velna
 */

#include "CUnit/CUnit.h"
#include "ecr/ecr_util.h"
#include <stdlib.h>

static void crypto_test_crypto_xor_key_ok_0(ecr_str_t *from, ecr_str_t *to, void *key, int algorithm,
        const char *expected) {
    int rc = ecr_util_encrypt(from, to, key, algorithm);
    ecr_binary_dump(stdout, to->ptr, rc);
    CU_ASSERT_EQUAL(rc, from->len);
    CU_ASSERT_EQUAL(memcmp(to->ptr, expected, rc), 0);
}

static void crypto_test_crypto_xor_key_ok() {
    ecr_crypto_xor_key key = { "aaaa", 4, 0 };
    char buf[256];
    ecr_str_t str = { "123", 3 }, out = { buf, 256 };
    crypto_test_crypto_xor_key_ok_0(&str, &out, &key, ECR_CRYPTO_XOR, "PSR");
}

CU_TestInfo crypto_cases[] = {
//
        { "crypto test crypto xor key ok:", crypto_test_crypto_xor_key_ok },
        CU_TEST_INFO_NULL };

CU_SuiteInfo crypto_suites[] = {
//
        { "crypto suites:", NULL, NULL, NULL, NULL, crypto_cases },
        CU_SUITE_INFO_NULL };
