/*
 * ecr_http_decoder.h
 *
 *  Created on: May 11, 2016
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_HTTP_DECODER_H_
#define SRC_ECR_ECR_HTTP_DECODER_H_

#include "ecrconf.h"
#include "ecr_fixedhashmap.h"
#include <stdio.h>

// decode status
#define HTTP_DECODE_INIT            -2
#define HTTP_DECODE_OK              0
#define HTTP_DECODE_MORE            1
#define HTTP_DECODE_ERR             -1

// decode error codes
#define HTTP_ERR_DONE               1
#define HTTP_ERR_CHUNK_LEFT         2
#define HTTP_ERR_TYPE               3
#define HTTP_ERR_CRLF               4
#define HTTP_ERR_METHOD             5
#define HTTP_ERR_VERSION            6
#define HTTP_ERR_STATUS             7
#define HTTP_ERR_REASON             8
#define HTTP_ERR_CHUNK_SIZE         9
#define HTTP_ERR_CONTENT_VAR        10
#define HTTP_ERR_DECODE_STATUS      11
#define HTTP_ERR_OUT_OF_BUF         12

#define HTTP_METHOD                 "method"
#define HTTP_URI                    "uri"
#define HTTP_VERSION                "version"
#define HTTP_STATUS                 "status"
#define HTTP_REASON                 "reason"
#define HTTP_HOST                   "host"
#define HTTP_REFERER                "referer"
#define HTTP_USER_AGENT             "user-agent"
#define HTTP_COOKIE                 "cookie"
#define HTTP_ACCEPT                 "accept"
#define HTTP_CONTENT_LENGTH         "content-length"
#define HTTP_CONTENT_TYPE           "content-type"
#define HTTP_TRANSFER_ENCODING      "transfer-encoding"
#define HTTP_CONTENT_ENCODING       "content-encoding"

#define HTTP_HASH_FIELDS            HTTP_METHOD "," \
                                    HTTP_URI "," \
                                    HTTP_VERSION "," \
                                    HTTP_STATUS "," \
                                    HTTP_REASON "," \
                                    HTTP_HOST "," \
                                    HTTP_REFERER "," \
                                    HTTP_USER_AGENT "," \
                                    HTTP_COOKIE "," \
                                    HTTP_ACCEPT "," \
                                    HTTP_CONTENT_LENGTH "," \
                                    HTTP_CONTENT_TYPE "," \
                                    HTTP_TRANSFER_ENCODING "," \
                                    HTTP_CONTENT_ENCODING

typedef struct {
    ecr_fixedhash_key_t Method;
    ecr_fixedhash_key_t Uri;
    ecr_fixedhash_key_t Version;
    ecr_fixedhash_key_t Status;
    ecr_fixedhash_key_t Reason;
    ecr_fixedhash_key_t Host;
    ecr_fixedhash_key_t Referer;
    ecr_fixedhash_key_t User_Agent;
    ecr_fixedhash_key_t Cookie;
    ecr_fixedhash_key_t Accept;
    ecr_fixedhash_key_t Content_Length;
    ecr_fixedhash_key_t Content_Type;
    ecr_fixedhash_key_t Transfer_Encoding;
    ecr_fixedhash_key_t Content_Encoding;
} ecr_http_keys_t;

typedef enum {
    HTTP_TYPE_UNKNOWN = 1, HTTP_REQUEST, HTTP_RESPONSE
} ecr_http_message_type_t;

typedef enum {
    HTTP_VERSION_UNKNOWN = 1, HTTP_10, HTTP_11
} ecr_http_version_t;

typedef enum {
    HTTP_METHOD_UNKNOWN = 1,
    HTTP_OPTIONS,
    HTTP_GET,
    HTTP_HEAD,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_TRACE,
    HTTP_CONNECT
} ecr_http_method_t;

/**
 * for both Transfer-Encoding and Content-Encoding
 */
typedef enum {
    HTTP_ENCODING_NULL = 0, HTTP_ENCODING_UNKNOWN, HTTP_CHUNKED, HTTP_GZIP, HTTP_COMPRESS, HTTP_DEFLATE, HTTP_IDENTITY
} ecr_http_encoding_t;

typedef enum {
    HTTP_BUF_UNKNOWN = 0, HTTP_BUF_HEADER, HTTP_BUF_CONTENT
} ecr_http_buf_type_t;

typedef struct ecr_http_chunk_s {
    struct ecr_http_chunk_s *prev;
    struct ecr_http_chunk_s *next;
    ecr_str_t data;
    char _data[];
} ecr_http_chunk_t;

typedef struct {
    ecr_http_chunk_t *head;
    ecr_http_chunk_t *tail;
} ecr_http_chunks_t;

typedef struct {
    ecr_http_buf_type_t type;
    ecr_str_t data;
} ecr_http_buf_t;

typedef struct {
    ecr_fixedhash_ctx_t *hash_ctx;
    ecr_http_keys_t keys;
    size_t max_content_chunks;
} ecr_http_decoder_t;

typedef struct ecr_http_message_s {
    ecr_http_message_type_t type;
    ecr_http_version_t version;
    ecr_str_t version_str;
    union {
        struct {
            ecr_http_method_t method;
            ecr_str_t method_str;
            ecr_str_t uri;
        } request;
        struct {
            ecr_http_method_t request_method;
            int status;
            ecr_str_t status_str;
            ecr_str_t reason;
        } response;
    };
    ecr_fixedhash_t *headers;
    ecr_http_chunks_t *content;
    ecr_http_decoder_t *decoder;
    int8_t error_no;
    int8_t decode_status;

    //private fields
    int8_t _status;
    int8_t _next_status;
    int _chunk_used;
    int _content_buf_idx;
    int _buf_size;
    int _buf_idx;
    ecr_str_t *_transfer_encoding;
    ecr_str_t *_content_encoding;
    ecr_http_chunks_t _chunks[1];
    size_t _chunk_left;
    size_t _content_length;
    ecr_http_buf_t _buf[];
} ecr_http_message_t;

#undef HTTP_MESSAGE_FIELDS

void ecr_http_decoder_init(ecr_http_decoder_t *decoder, ecr_fixedhash_ctx_t *ctx, size_t max_content_chunks);

ecr_http_message_t * ecr_http_new_request(ecr_http_decoder_t *decoder);

ecr_http_message_t * ecr_http_new_response(ecr_http_decoder_t *decoder, ecr_http_method_t request_method);

ecr_http_message_type_t ecr_http_guess(char *data, size_t size);

/**
 * return HTTP_DECODE_OK for complete, HTTP_DECODE_MORE for incomplete, HTTP_DECODE_ERR for error
 */
int ecr_http_decode(ecr_http_message_t *message, char *data, size_t size);

int ecr_http_message_make_content(ecr_http_message_t *message, ecr_str_t *content_out);

void ecr_http_message_dump(ecr_http_message_t *message, FILE *stream);

void ecr_http_message_reset(ecr_http_message_t *message);

void ecr_http_message_destroy(ecr_http_message_t *message);

#endif /* SRC_ECR_ECR_HTTP_DECODER_H_ */
