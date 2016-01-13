/*
 * ecr_httpparser.c
 *
 *  Created on: Mar 15, 2014
 *      Author: velna
 */

#include "config.h"
#include "ecr_httpparser.h"
#include "ecr_util.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

ecr_fixedhash_key_t ECR_HTTP_METHOD, ECR_HTTP_URI, ECR_HTTP_VERSION, ECR_HTTP_HDR_HOST, ECR_HTTP_HDR_REFERER,
        ECR_HTTP_HDR_USERAGENT, ECR_HTTP_HDR_COOKIE, ECR_HTTP_HDR_ACCEPT, ECR_HTTP_HDR_CONTENTLENGTH,
        ECR_HTTP_HDR_CONTENTTYPE;

void ecr_httpparser_init(ecr_fixedhash_ctx_t *ctx) {
    ECR_HTTP_METHOD = ecr_fixedhash_getkey(ctx, ECR_HTTP_KEY_METHOD, strlen(ECR_HTTP_KEY_METHOD));
    ECR_HTTP_URI = ecr_fixedhash_getkey(ctx, ECR_HTTP_KEY_URI, strlen(ECR_HTTP_KEY_URI));
    ECR_HTTP_VERSION = ecr_fixedhash_getkey(ctx, ECR_HTTP_KEY_VERSION, strlen(ECR_HTTP_KEY_VERSION));
    ECR_HTTP_HDR_HOST = ecr_fixedhash_getkey(ctx, ECR_HTTP_KEY_HDR_HOST, strlen(ECR_HTTP_KEY_HDR_HOST));
    ECR_HTTP_HDR_REFERER = ecr_fixedhash_getkey(ctx, ECR_HTTP_KEY_HDR_REFERER, strlen(ECR_HTTP_KEY_HDR_REFERER));
    ECR_HTTP_HDR_USERAGENT = ecr_fixedhash_getkey(ctx, ECR_HTTP_KEY_HDR_USERAGENT, strlen(ECR_HTTP_KEY_HDR_USERAGENT));
    ECR_HTTP_HDR_COOKIE = ecr_fixedhash_getkey(ctx, ECR_HTTP_KEY_HDR_COOKIE, strlen(ECR_HTTP_KEY_HDR_COOKIE));
    ECR_HTTP_HDR_ACCEPT = ecr_fixedhash_getkey(ctx, ECR_HTTP_KEY_HDR_ACCEPT, strlen(ECR_HTTP_KEY_HDR_ACCEPT));
    ECR_HTTP_HDR_CONTENTLENGTH = ecr_fixedhash_getkey(ctx, ECR_HTTP_KEY_HDR_CONTENTLENGTH,
            strlen(ECR_HTTP_KEY_HDR_CONTENTLENGTH));
    ECR_HTTP_HDR_CONTENTTYPE = ecr_fixedhash_getkey(ctx, ECR_HTTP_KEY_HDR_CONTENTTYPE,
            strlen(ECR_HTTP_KEY_HDR_CONTENTTYPE));
}

int ecr_http_req_init(ecr_http_req_t *req, ecr_fixedhash_t *hash) {
    memset(req, 0, sizeof(ecr_http_req_t));
    req->headers = hash;
    return 0;
}

#define YEE_TYPE_SPACE  1
#define YEE_TYPE_LINE   2
#define YEE_TYPE_FIELD  3

/**
 * return -1 for error or unexpected end, return -2 for head lines end(\r\n\r\n), return >0 for ok.
 */
static int ecr_get_next_token(ecr_str_t *to, char **pptr, size_t *psize, int type) {
    size_t i = 0, len = 0, size = *psize;
    char *p = *pptr;
    int b = 0;
    while (i < size) {
        switch (type) {
        case YEE_TYPE_SPACE:
            if (i < size && p[i] == ' ') {
                len = i;
                while (i < size && p[i] == ' ') {
                    i++;
                }
                b = 1;
            }
            break;
        case YEE_TYPE_LINE:
            if (p[i] == '\r' && i + 1 < size && p[i + 1] == '\n') {
                len = i;
                i += 2;
                b = 1;
            }
            break;
        case YEE_TYPE_FIELD:
            if (p[i] == ':') {
                len = i++;
                while (i < size && p[i] == ' ') {
                    i++;
                }
                b = 1;
            } else if (p[i] == '\r' && i + 1 < size && p[i + 1] == '\n') {
                if (i == 0) {
                    i = 2;
                    b = -2;
                } else {
                    b = -1;
                }
            } else {
                p[i] = (char) tolower(p[i]);
            }
            break;
        default:
            return -1;
        }
        if (b) {
            break;
        } else {
            i++;
        }
    }
    switch (b) {
    case -2:
        *pptr += i;
        *psize -= i;
        return -2;
    case 1:
        to->ptr = p;
        to->len = len;
        *pptr += i;
        *psize -= i;
        return i;
    default:
        return -1;
    }
}

ecr_http_type_t ecr_http_parse_type(char *data, size_t len) {
    ecr_http_type_t ret = 0;

    if (len <= 0) {
        return ret;
    }
    switch (data[0]) {
    case 'O':
        if (len >= 7 && str7cmp(data, 'O', 'P', 'T', 'I', 'O', 'N', 'S')) {
            ret = ECR_HTTP_REQ_OPTIONS;
        }
        break;
    case 'G':
        if (len >= 3 && str3cmp(data, 'G', 'E', 'T')) {
            ret = ECR_HTTP_REQ_GET;
        }
        break;
    case 'H':
        if (len >= 4 && str4cmp(data, 'H', 'E', 'A', 'D')) {
            ret = ECR_HTTP_REQ_HEAD;
        } else if (len >= 8 && str7cmp(data, 'H', 'T', 'T', 'P', '/', '1', '.')) {
            switch (data[7]) {
            case '0':
                ret = ECR_HTTP_RESP_10;
                break;
            case '1':
                ret = ECR_HTTP_RESP_11;
                break;
            }
        }
        break;
    case 'P':
        if (len >= 4 && str4cmp(data, 'P', 'O', 'S', 'T')) {
            ret = ECR_HTTP_REQ_POST;
        } else if (len >= 3 && str3cmp(data, 'P', 'U', 'T')) {
            ret = ECR_HTTP_REQ_PUT;
        }
        break;
    case 'D':
        if (len >= 6 && str6cmp(data, 'D', 'E', 'L', 'E', 'T', 'E')) {
            ret = ECR_HTTP_REQ_DELETE;
        }
        break;
    case 'T':
        if (len >= 5 && str5cmp(data, 'T', 'R', 'A', 'C', 'E')) {
            ret = ECR_HTTP_REQ_TRACE;
        }
        break;
    case 'C':
        if (len >= 7 && str7cmp(data, 'C', 'O', 'N', 'N', 'E', 'C', 'T')) {
            ret = ECR_HTTP_REQ_CONNECT;
        }
        break;
    }
    return ret;
}

int ecr_http_req_parse(ecr_http_req_t *req, char *p, size_t size, ecr_str_t *hdr_buf, int hdr_buf_size) {
    char *ptr = p, *suri, *uri;
    ecr_str_t key, *value;
    int n, rc, idx = 0, content_length = 0;
    ecr_fixedhash_key_t hashkey;

    n = ecr_get_next_token(&req->method, &ptr, &size, YEE_TYPE_SPACE);
    if (n <= 0) {
        return -1;
    }
    req->method_type = ecr_http_parse_type(req->method.ptr, req->method.len);
    if (!req->method_type) {
        return -1;
    }
    ecr_fixedhash_put(req->headers, ECR_HTTP_METHOD, &req->method);

    n = ecr_get_next_token(&req->uri, &ptr, &size, YEE_TYPE_SPACE);
    if (n <= 0) {
        return -1;
    }
    suri = req->uri.ptr;
    if (suri[0] != '/' && req->uri.len > 7 && str7cmp(suri, 'h', 't', 't', 'p', ':', '/', '/')) {
        uri = memchr(suri + 7, '/', req->uri.len - 7);
        value = hdr_buf + idx;
        if (uri != NULL) {
            value->ptr = suri + 7;
            value->len = uri - value->ptr;
            req->uri.len -= (uri - suri);
            req->uri.ptr = uri;
        } else {
            value->ptr = suri + 7;
            value->len = req->uri.len - 7;
            req->uri.ptr = "/";
            req->uri.len = 1;
        }
        if (ecr_fixedhash_put(req->headers, ECR_HTTP_HDR_HOST, value) == 0) {
            idx++;
        }
    }
    ecr_fixedhash_put(req->headers, ECR_HTTP_URI, &req->uri);

    n = ecr_get_next_token(&req->version, &ptr, &size, YEE_TYPE_LINE);
    if (n <= 0) {
        return -1;
    }
    ecr_fixedhash_put(req->headers, ECR_HTTP_VERSION, &req->version);

    rc = 1;
    while (size > 0 && idx < hdr_buf_size) {
        n = ecr_get_next_token(&key, &ptr, &size, YEE_TYPE_FIELD);
        if (n == -2) {
            rc = 0;
        }
        if (n <= 0) {
            break;
        }
        value = hdr_buf + idx;
        n = ecr_get_next_token(value, &ptr, &size, YEE_TYPE_LINE);
        if (n <= 0) {
            break;
        }
        if (req->method_type == ECR_HTTP_REQ_POST) {
            hashkey = ecr_fixedhash_getkey(req->headers->ctx, key.ptr, key.len);
            if (ecr_fixedhash_put(req->headers, hashkey, value) == 0) {
                if (hashkey == ECR_HTTP_HDR_CONTENTLENGTH) {
                    content_length = atoi(value->ptr);
                }
                idx++;
            }
        } else {
            if (ecr_fixedhash_put_original(req->headers, key.ptr, key.len, value) == 0) {
                idx++;
            }
        }
    }
    if (rc == 0 && req->method_type == ECR_HTTP_REQ_POST) {
        if (size == content_length) {
            if (size > 0) {
                req->body.ptr = ptr;
                req->body.len = size;
            }
        } else {
            rc = 1;
        }
    }
    return rc;
}

//int ecr_http_req_add_header(ecr_http_req_t *req, ecr_fixedhash_key_t key, ecr_str_t *hdr) {
//    ecr_str_t *value;
//    if (req->_hdrbuf_idx < ecr_httpparser_ctx.hdr_buf_size) {
//        value = req->_hdrbuf + req->_hdrbuf_idx;
//        *value = *hdr;
//        if (ecr_fixedhash_put(req->headers, key, value) == 0) {
//            req->_hdrbuf_idx++;
//            return 0;
//        }
//    }
//    return -1;
//}

