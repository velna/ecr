/*
 * hypermatch_test.c
 *
 *  Created on: Sep 12, 2017
 *      Author: velna
 */

#include "CUnit/CUnit.h"
#include <ecr/hypermatch/hm.h>
#include <ecr/hypermatch/hm_mongo_loader.h>

static struct {
    ecr_hm_t hm;
    ecr_fixedhash_ctx_t hash_ctx;
    mongoc_client_pool_t *mongo_pool;
    mongoc_uri_t *mongo_uri;
    ecr_fixedhash_t *hash;
} hm_test;

static int init(void) {
    ecr_fixedhash_ctx_init(&hm_test.hash_ctx);
    ecr_fixedhash_ctx_add_keys(&hm_test.hash_ctx, "host,uri,extension");
    hm_test.mongo_uri = mongoc_uri_new("mongodb://localhost:27017/");
    hm_test.mongo_pool = mongoc_client_pool_new(hm_test.mongo_uri);
    return 0;
}

static int cleanup(void) {
    ecr_fixedhash_ctx_destroy(&hm_test.hash_ctx);
    mongoc_client_pool_destroy(hm_test.mongo_pool);
    mongoc_uri_destroy(hm_test.mongo_uri);
    return 0;
}

static void setup(void) {
    ecr_hm_init(&hm_test.hm, &hm_test.hash_ctx);
    ecr_hm_reg_matcher(&hm_test.hm, &ecr_hm_equals_matcher_reg);
    ecr_hm_reg_matcher(&hm_test.hm, &ecr_hm_exists_matcher_reg);
    ecr_hm_reg_matcher(&hm_test.hm, &ecr_hm_wumanber_matcher_reg);
    ecr_hm_reg_matcher(&hm_test.hm, &ecr_hm_urlmatch_matcher_reg);

    ecr_hm_loader_t *mongo_loader = ecr_hm_mongo_loader_new(hm_test.mongo_pool);
    ecr_hm_reg_loader(&hm_test.hm, mongo_loader);
    ecr_hm_reg_loader(&hm_test.hm, &ecr_hm_file_loader);

    size_t mem_size = ecr_fixedhash_sizeof(&hm_test.hash_ctx);
    void *mem = malloc(mem_size);
    hm_test.hash = ecr_fixedhash_init(&hm_test.hash_ctx, mem, mem_size);
}

static void teardown(void) {
    ecr_hm_destroy(&hm_test.hm);
    free(hm_test.hash);
}

#define ECR_MAKE_STR(s)     {s, strlen(s)}

static void hypermatch_test_ok_1() {
    ecr_hm_source_t *source1 = ecr_hm_add(&hm_test.hm, "test.hm");
    ecr_hm_source_t *source2 = ecr_hm_add(&hm_test.hm, "test2.hm");
    ecr_hm_status_t status = ecr_hm_compile(&hm_test.hm);
    ecr_dumper_t dumper;
    if (status != HM_OK) {
        printf("ERROR: %s\n", hm_test.hm.errbuf);
    } else {
        ecr_dumper_init(&dumper, 0, stdout);
        ecr_hm_dump(&hm_test.hm, &dumper);
    }
    CU_ASSERT_EQUAL(status, HM_OK);
    ecr_str_t v1 = ECR_MAKE_STR("www.sssss.com");
    ecr_str_t v2 = ECR_MAKE_STR("/index.html");
    ecr_str_t v3 = ECR_MAKE_STR("html");

    ecr_fixedhash_put_original(hm_test.hash, "host", 4, &v1);
    ecr_fixedhash_put_original(hm_test.hash, "uri", 3, &v2);
    ecr_fixedhash_put_original(hm_test.hash, "extension", 9, &v3);

    ecr_hm_result_t *result = ecr_hm_result_new(&hm_test.hm);

    bool r = ecr_hm_matches(&hm_test.hm, hm_test.hash, result);
    CU_ASSERT_EQUAL(r, true);
    CU_ASSERT_EQUAL(ecr_hm_result_contains(result, source1->id), false);
    CU_ASSERT_EQUAL(ecr_hm_result_contains(result, source2->id), true);

    free(result);
}

CU_TestInfo hypermatch_cases[] = {
//
        { "hypermatch test ok 1:", hypermatch_test_ok_1 },
        CU_TEST_INFO_NULL };

CU_SuiteInfo hypermatch_suites[] = {
//
        { "hypermatch suites:", init, cleanup, setup, teardown, hypermatch_cases },
        CU_SUITE_INFO_NULL };
