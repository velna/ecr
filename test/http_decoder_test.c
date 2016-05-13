/*
 * http_decoder_request.c
 *
 *  Created on: May 24, 2016
 *      Author: velna
 */

#include "CUnit/CUnit.h"
#include "ecr/ecr_http_decoder.h"
#include <stdlib.h>

static ecr_http_decoder_t http_decoder;
static ecr_fixedhash_ctx_t hash_ctx;
static ecr_http_message_t *http_message;

static int init(void) {
    ecr_fixedhash_ctx_init_string(&hash_ctx, HTTP_HASH_FIELDS);
    ecr_http_decoder_init(&http_decoder, &hash_ctx, 16);
    return 0;
}

static int cleanup(void) {
    ecr_fixedhash_ctx_destroy(&hash_ctx);
    return 0;
}

static void setup_request(void) {
    http_message = ecr_http_new_request(&http_decoder);
}

static void teardown(void) {
    ecr_http_message_destroy(http_message);
}

static void http_decoder_request(char **message) {
    char *chunk;
    int j, rc = -1;
    j = 0;
    while ((chunk = message[j])) {
        rc = ecr_http_decode(http_message, chunk, strlen(chunk));
        if (rc == HTTP_DECODE_ERR) {
            CU_ASSERT_NOT_EQUAL(rc, HTTP_DECODE_ERR);
        } else if (rc == HTTP_DECODE_OK) {
            if (message[j + 1] != NULL) {
                CU_FAIL("decode error");
            }
        }
        j++;
    }
    CU_ASSERT_EQUAL(rc, HTTP_DECODE_OK);
}

static void http_decoder_request_ok_0(void) {
    char *message[] = {
    //
            "GET / HTTP/1.1\r\n"
                    "Host: www.baidu.com\r\n"
                    "Content-Length: 0\r\n"
                    "\r\n",
            NULL };
    http_decoder_request(message);
}

static void http_decoder_request_ok_1(void) {
    char *message[] = {
    //
            "POST /abc.html HTTP/1.1\r\n"
                    "Host: www.baidu.com\r\n"
                    "Content-Length: 10\r\n"
                    "\r\n"
                    "1234567890",
            NULL };
    http_decoder_request(message);
}

static void http_decoder_request_ok_2(void) {
    char *message[] = {
    //
            "POST /abc.html HTTP/1.1\r\n"
                    "Host: www.baidu.com\r\n"
                    "Content-Length: 20\r\n"
                    "\r\n"
                    "1234567890",
            "0987654321",
            NULL };
    http_decoder_request(message);
}

static void http_decoder_request_ok_3(void) {
    char *message[] = {
    //
            "POST /abc.html HTTP/1.1\r\n"
                    "Host: www.baidu.com\r\n"
                    "Content-Length: 30\r\n"
                    "\r\n"
                    "1234567890",
            "0987654321",
            "abcdefghij",
            NULL };
    http_decoder_request(message);
}

static void http_decoder_request_ok_4(void) {
    char *message[] = {
    //
            "GET /abc.html?abcdefadofijawefiasdlfkjaoweifjlaskdfjoaweijfawefasdfasdfa",
            "&b=sdfwefaewf HTTP/1.1\r\n"
                    "Host: www.baidu.com\r\n"
                    "Content-Length: 0\r\n"
                    "Cookie: a=b;cdef=f;jdsjadfoiajweflasdfjaowefawef",
            "jsdifjwefaljsodifjawelfjsdkfiaweflsdifewal\r\n"
                    "User-Agent: MacOSX\r\n"
                    "\r\n",
            NULL };
    http_decoder_request(message);
}

static void http_decoder_request_ok_5(void) {
    char *message[] = {
    //
            "POST /abc.html HTTP/1.1\r\n"
                    "Host: www.baidu.com\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "\r\n"
                    "a\r\n"
                    "0123456789\r\n",
            "14\r\n"
                    "12345678901234567890\r\n"
                    "0\r\n"
                    "\r\n",
            NULL };
    http_decoder_request(message);
}

static void http_decoder_request_ok_6(void) {
    char *message[] = {
    //
            "POST /abc.html HTTP/1.1\r\n"
                    "Host: www.baidu.com\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "\r\n"
                    "a\r\n"
                    "0123456789\r\n"
                    "14",
            "\r\n"
                    "12345678901",
            "234567890\r\n"
                    "0\r\n"
                    "\r\n",
            NULL };
    http_decoder_request(message);
}

CU_TestInfo http_decoder_request_cases[] = {
//
        { "http decoder request ok 0:", http_decoder_request_ok_0 },
        { "http decoder request ok 1:", http_decoder_request_ok_1 },
        { "http decoder request ok 2:", http_decoder_request_ok_2 },
        { "http decoder request ok 3:", http_decoder_request_ok_3 },
        { "http decoder request ok 4:", http_decoder_request_ok_4 },
        { "http decoder request ok 5:", http_decoder_request_ok_5 },
        { "http decoder request ok 6:", http_decoder_request_ok_6 },
        CU_TEST_INFO_NULL };

CU_SuiteInfo http_decoder_suites[] = {
//
        { "http request decoder suites:", init, cleanup, setup_request, teardown, http_decoder_request_cases },
        CU_SUITE_INFO_NULL };
