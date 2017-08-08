/*
 * uri_test.c
 *
 *  Created on: Aug 7, 2017
 *      Author: velna
 */

#include "CUnit/CUnit.h"
#include "ecr/ecr_uri.h"
#include "ecr/ecr_util.h"
#include <stdlib.h>
#include <arpa/inet.h>

static int init(void) {
    return 0;
}

static int cleanup(void) {
    return 0;
}

static void uri_test_ok_1() {
    ecr_uri_t uri, uri2;
    int rc = ecr_uri_init(&uri, "http://velna:123@www.baidu.com:8080/abc/../bcde/def?a=1&b=2#about");
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_STRING_EQUAL(uri.string, "http://velna:123@www.baidu.com:8080/bcde/def?a=1&b=2#about");
    CU_ASSERT_STRING_EQUAL(uri.host, "www.baidu.com");
    CU_ASSERT_STRING_EQUAL(uri.scheme, "http");
    CU_ASSERT_STRING_EQUAL(uri.path, "/bcde/def");
    CU_ASSERT_STRING_EQUAL(uri.query, "a=1&b=2");
    CU_ASSERT_STRING_EQUAL(uri.fragment, "about");
    CU_ASSERT_STRING_EQUAL(uri.user_info, "velna:123");
    CU_ASSERT_EQUAL(uri.port, 8080);
    CU_ASSERT_EQUAL(uri.absolute, true);
    CU_ASSERT_EQUAL(uri.absolute_path, true);

    ecr_uri_resolve(&uri, "bcd.html?a=3", &uri2);

    CU_ASSERT_STRING_EQUAL(uri2.host, "www.baidu.com");
    CU_ASSERT_STRING_EQUAL(uri2.scheme, "http");
    CU_ASSERT_STRING_EQUAL(uri2.path, "/bcde/bcd.html");
    CU_ASSERT_STRING_EQUAL(uri2.query, "a=3");
    CU_ASSERT_EQUAL(uri2.fragment, NULL);
    CU_ASSERT_STRING_EQUAL(uri2.user_info, "velna:123");
    CU_ASSERT_EQUAL(uri2.port, 8080);
    CU_ASSERT_EQUAL(uri2.absolute, true);
    CU_ASSERT_EQUAL(uri2.absolute_path, true);

    ecr_uri_destroy(&uri2);
    ecr_uri_destroy(&uri);
}

CU_TestInfo uri_cases[] = {
//
        { "uri test ok 1:", uri_test_ok_1 },
        CU_TEST_INFO_NULL };

CU_SuiteInfo uri_suites[] = {
//
        { "uri suites:", init, cleanup, NULL, NULL, uri_cases },
        CU_SUITE_INFO_NULL };
