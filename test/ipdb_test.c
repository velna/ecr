/*
 * ipdb_test.c
 *
 *  Created on: Apr 12, 2017
 *      Author: velna
 */

#include "CUnit/CUnit.h"
#include "ecr/ecr_ipdb.h"
#include "ecr/ecr_util.h"
#include <stdlib.h>
#include <arpa/inet.h>

static ecr_ipdb_t ipdb;

static int init(void) {
    return ecr_ipdb_init(&ipdb, "ipdb.txt");
}

static int cleanup(void) {
    ecr_ipdb_destroy(&ipdb);
    return 0;
}

static void ipdb_test_query0(const char *ip, int expected_rc, uint8_t expected_province) {
    uint32_t ipv4;
    inet_pton(AF_INET, ip, &ipv4);
    ecr_ipdb_region_t region;
    memset(&region, 0, sizeof(ecr_ipdb_region_t));
    int rc = ecr_ipdb_query(&ipdb, ipv4, &region);
    CU_ASSERT_EQUAL(rc, expected_rc);
    CU_ASSERT_EQUAL(region.province, expected_province);
}

static void ipdb_test_query() {
    ipdb_test_query0("1.51.112.1", 0, 34);
    ipdb_test_query0("139.122.224.0", 0, 81);
    ipdb_test_query0("139.122.224.255", 0, 81);
    ipdb_test_query0("139.122.233.2", 0, 81);
    ipdb_test_query0("140.1.2.3", -1, 0);
    ipdb_test_query0("1.1.1.1", -1, 0);
    ipdb_test_query0("42.184.3.34", 0, 23);
    ipdb_test_query0("61.240.232.3", 0, 43);
}

CU_TestInfo ipdb_cases[] = {
//
        { "ipdb test ok 1:", ipdb_test_query },
        CU_TEST_INFO_NULL };

CU_SuiteInfo ipdb_suites[] = {
//
        { "ipdb suites:", init, cleanup, NULL, NULL, ipdb_cases },
        CU_SUITE_INFO_NULL };
