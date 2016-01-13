/*
 * ecr_httpparser.h
 *
 *  Created on: Mar 15, 2014
 *      Author: velna
 */

#ifndef ECR_HTTPPARSER_H_
#define ECR_HTTPPARSER_H_

#include "ecrconf.h"
#include "ecr_fixedhashmap.h"

#define ECR_HTTP_KEY_METHOD                     "method"
#define ECR_HTTP_KEY_URI                        "uri"
#define ECR_HTTP_KEY_VERSION                    "version"
#define ECR_HTTP_KEY_HDR_HOST                   "host"
#define ECR_HTTP_KEY_HDR_REFERER                "referer"
#define ECR_HTTP_KEY_HDR_USERAGENT              "user-agent"
#define ECR_HTTP_KEY_HDR_COOKIE                 "cookie"
#define ECR_HTTP_KEY_HDR_ACCEPT                 "accept"
#define ECR_HTTP_KEY_HDR_CONTENTLENGTH          "content-length"
#define ECR_HTTP_KEY_HDR_CONTENTTYPE            "content-type"

#define ECR_HTTP_KEYS               ECR_HTTP_KEY_METHOD "," \
                                    ECR_HTTP_KEY_URI "," \
                                    ECR_HTTP_KEY_VERSION "," \
                                    ECR_HTTP_KEY_HDR_HOST "," \
                                    ECR_HTTP_KEY_HDR_REFERER "," \
                                    ECR_HTTP_KEY_HDR_USERAGENT "," \
                                    ECR_HTTP_KEY_HDR_COOKIE "," \
                                    ECR_HTTP_KEY_HDR_ACCEPT "," \
                                    ECR_HTTP_KEY_HDR_CONTENTLENGTH "," \
                                    ECR_HTTP_KEY_HDR_CONTENTTYPE

typedef enum {
    ECR_HTTP_RESP_10 = 1,
    ECR_HTTP_RESP_11,
    ECR_HTTP_REQ_OPTIONS,
    ECR_HTTP_REQ_GET,
    ECR_HTTP_REQ_HEAD,
    ECR_HTTP_REQ_POST,
    ECR_HTTP_REQ_PUT,
    ECR_HTTP_REQ_DELETE,
    ECR_HTTP_REQ_TRACE,
    ECR_HTTP_REQ_CONNECT
} ecr_http_type_t;

typedef enum {
    ECR_CONTENT_TYPE_UNKNOWN = 0, ECR_APPLICATION_X_WWW_FORM_URLENCODED, ECR_MULTIPART_FORM_DATA,
} ecr_http_content_type_t;

typedef struct {
    ecr_str_t method;
    ecr_http_type_t method_type;
    ecr_str_t uri;
    ecr_str_t version;
    ecr_str_t body;
    ecr_fixedhash_t *headers;
} ecr_http_req_t;

extern ecr_fixedhash_key_t ECR_HTTP_METHOD, ECR_HTTP_URI, ECR_HTTP_VERSION, ECR_HTTP_HDR_HOST, ECR_HTTP_HDR_REFERER,
        ECR_HTTP_HDR_USERAGENT, ECR_HTTP_HDR_COOKIE, ECR_HTTP_HDR_ACCEPT, ECR_HTTP_HDR_CONTENTLENGTH,
        ECR_HTTP_HDR_CONTENTTYPE;

void ecr_httpparser_init(ecr_fixedhash_ctx_t *ctx);

int ecr_http_req_init(ecr_http_req_t *req, ecr_fixedhash_t *hash);

ecr_http_type_t ecr_http_parse_type(char *data, size_t len);

/**
 * return -1 for error, 0 for complete, 1 for incomplete
 */
int ecr_http_req_parse(ecr_http_req_t *req, char *p, size_t size, ecr_str_t *hdr_buf, int hdr_buf_size);

#endif /* ECR_HTTPPARSER_H_ */
