/*
 * template_test.c
 *
 *  Created on: Sep 28, 2016
 *      Author: velna
 */

#include "CUnit/CUnit.h"
#include "ecr/ecr_template.h"
#include <stdlib.h>

static ecr_template_context_t context;
static char errbuf[512];
static struct {
    int SrcIP;
    int DstIP;
    int Host;
    int Url;
    int Referer;
    int Cookie;
} vars;

static struct {
    int Base64;
    int MD5;
    int SHA1;
} funcs;

static int template_var_handler(FILE *stream, void *data, ecr_template_var_t *var);
static int template_func_handler(FILE *stream, void *data, ecr_template_func_t *func, int argc, const char **argv,
        ecr_template_t *body);

static int template_text_handler(FILE *stream, void *data, ecr_str_t *text) {
    if (text->len) {
        if (fwrite(text->ptr, text->len, 1, stream) == 1) {
            return text->len;
        } else {
            return -1;
        }
    } else {
        return 0;
    }
}

static int template_var_handler(FILE *stream, void *data, ecr_template_var_t *var) {
    return fprintf(stream, "%s", var->name);
}

static int template_func_handler(FILE *stream, void *data, ecr_template_func_t *func, int argc, const char **argv,
        ecr_template_t *body) {
    int n = 0;
    int i;
    n += fprintf(stream, "%s(", func->name);
    for (i = 0; i < argc; i++) {
        n += fprintf(stream, "%s", argv[i]);
        if (i < argc - 1) {
            fputc(',', stream);
            n++;
        }
    }
    n += fprintf(stream, "){\n");
    n += ecr_template_write(body, stream, data);
    n += fprintf(stream, "\n}\n");
    return n;
}

#define REG_VAR(var)    vars.var = ecr_template_context_reg_var(&context, #var, template_var_handler)
#define REG_FUNC(func)    funcs.func = ecr_template_context_reg_func(&context, #func, template_func_handler)

static int init(void) {
    ecr_template_context_init(&context, template_text_handler);
    REG_VAR(SrcIP);
    REG_VAR(DstIP);
    REG_VAR(Host);
    REG_VAR(Url);
    REG_VAR(Referer);
    REG_VAR(Cookie);

    REG_FUNC(Base64);
    REG_FUNC(MD5);
    REG_FUNC(SHA1);
    return 0;
}

static int cleanup(void) {
    ecr_template_context_destroy(&context);
    return 0;
}

static void template_test_text_only() {
    ecr_template_t *template = ecr_template_new(&context, "abcdef", errbuf, 512);
    CU_ASSERT_TRUE_FATAL(template!=NULL);

    ecr_str_t bytes;
    int n = ecr_template_to_bytes(template, &bytes, NULL);
    printf("%s", bytes.ptr);
    CU_ASSERT_EQUAL(n, bytes.len);
    CU_ASSERT_STRING_EQUAL("abcdef", bytes.ptr);

    ecr_template_destroy(template);
}

static void template_test_var_only() {
    ecr_template_t *template = ecr_template_new(&context, "${Host}", errbuf, 512);
    CU_ASSERT_TRUE_FATAL(template!=NULL);

    ecr_str_t bytes;
    int n = ecr_template_to_bytes(template, &bytes, NULL);
    printf("%s", bytes.ptr);
    CU_ASSERT_EQUAL(n, bytes.len);
    CU_ASSERT_STRING_EQUAL("Host", bytes.ptr);

    ecr_template_destroy(template);
}

static void template_test_func_only() {
    ecr_template_t *template = ecr_template_new(&context, "${Base64(){}}", errbuf, 512);
    CU_ASSERT_TRUE_FATAL(template!=NULL);

    ecr_str_t bytes;
    int n = ecr_template_to_bytes(template, &bytes, NULL);
    printf("%s", bytes.ptr);
    CU_ASSERT_EQUAL(n, bytes.len);
    CU_ASSERT_STRING_EQUAL("Base64(){\n\n}\n", bytes.ptr);

    ecr_template_destroy(template);
}

static void template_test_x_1() {
    ecr_template_t *template = ecr_template_new(&context,
            "abcdef${Host}${SrcIP},${DstIP}${Base64(){}},${SHA1(abc){111111}}haha${MD5(1,234){}}", errbuf, 512);
    CU_ASSERT_TRUE_FATAL(template!=NULL);

    ecr_str_t bytes;
    int n = ecr_template_to_bytes(template, &bytes, NULL);
    printf("%s", bytes.ptr);
    CU_ASSERT_EQUAL(n, bytes.len);
    CU_ASSERT_STRING_EQUAL("abcdefHostSrcIP,DstIPBase64(){\n\n}\n,SHA1(abc){\n111111\n}\nhahaMD5(1,234){\n\n}\n",
            bytes.ptr);

    ecr_template_destroy(template);
}

static void template_test_error_1() {
    ecr_template_t *template = ecr_template_new(&context, "abcdef${", errbuf, 512);
    printf("\n%s\n", errbuf);
    CU_ASSERT_TRUE_FATAL(template==NULL);
}

static void template_test_error_2() {
    ecr_template_t *template = ecr_template_new(&context, "${abcdef}", errbuf, 512);
    printf("\n%s\n", errbuf);
    CU_ASSERT_TRUE_FATAL(template==NULL);
}

static void template_test_error_3() {
    ecr_template_t *template = ecr_template_new(&context, "bac${SHA1({}}", errbuf, 512);
    printf("\n%s\n", errbuf);
    CU_ASSERT_TRUE_FATAL(template==NULL);
}

static void template_test_error_4() {
    ecr_template_t *template = ecr_template_new(&context, "${MD5()}}", errbuf, 512);
    printf("\n%s\n", errbuf);
    CU_ASSERT_TRUE_FATAL(template==NULL);
}

static void template_test_error_5() {
    ecr_template_t *template = ecr_template_new(&context, "${MD55(){}}", errbuf, 512);
    printf("\n%s\n", errbuf);
    CU_ASSERT_TRUE_FATAL(template==NULL);
}

CU_TestInfo template_cases[] = {
//
        { "template_test_text_only", template_test_text_only },
        { "template_test_var_only", template_test_var_only },
        { "template_test_func_only", template_test_func_only },
        { "template_test_x_1", template_test_x_1 },
        { "template_test_error_1", template_test_error_1 },
        { "template_test_error_2", template_test_error_2 },
        { "template_test_error_3", template_test_error_3 },
        { "template_test_error_4", template_test_error_4 },
        { "template_test_error_5", template_test_error_5 },
        CU_TEST_INFO_NULL };

CU_SuiteInfo template_suites[] = {
//
        { "template suites:", init, cleanup, NULL, NULL, template_cases },
        CU_SUITE_INFO_NULL };
