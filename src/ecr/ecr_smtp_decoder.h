/*
 * ecr_smtp_decoder.h
 *
 *  Created on: Feb 21, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_SMTP_DECODER_H_
#define SRC_ECR_ECR_SMTP_DECODER_H_

#include "ecrconf.h"
#include "ecr_fixedhashmap.h"
#include <stdio.h>

// decode status
#define SMTP_DECODE_INIT            -2
#define SMTP_DECODE_OK              0
#define SMTP_DECODE_MORE            1
#define SMTP_DECODE_ERR             -1

#define SMTP_ERR_DONE               1
#define SMTP_ERR_CHUNK_LEFT         2
#define SMTP_ERR_TYPE               3
#define SMTP_ERR_CRLF               4
#define SMTP_ERR_HELLO              5
#define SMTP_ERR_MAIL               6
#define SMTP_ERR_RCPT               7
#define SMTP_ERR_DECODE_STATUS      11
#define SMTP_ERR_OUT_OF_BUF         12

typedef struct {
    ecr_fixedhash_key_t Hello;
    ecr_fixedhash_key_t Auth_User;
    ecr_fixedhash_key_t Auth_Pwd;
    ecr_fixedhash_key_t Mail_From;
    ecr_fixedhash_key_t Rcpt_To;
    ecr_fixedhash_key_t User_Agent;
    ecr_fixedhash_key_t Date;
    ecr_fixedhash_key_t Subject;
    ecr_fixedhash_key_t From;
    ecr_fixedhash_key_t To;
    ecr_fixedhash_key_t Message_ID;
    ecr_fixedhash_key_t Thread_Topic;
    ecr_fixedhash_key_t Mime_Version;
    ecr_fixedhash_key_t Content_Type;
} ecr_smtp_keys_t;

typedef enum {
    SMTP_TYPE_UNKNOWN, SMTP_REQUEST, SMTP_RESPONSE
} ecr_smtp_message_type_t;

typedef enum {
    SMTP_BUF_UNKNOWN = 0, SMTP_BUF_HEADER, SMTP_BUF_CONTENT
} ecr_smtp_buf_type_t;

typedef struct ecr_smtp_chunk_s {
    struct ecr_smtp_chunk_s *prev;
    struct ecr_smtp_chunk_s *next;
    ecr_str_t data;
    char _data[];
} ecr_smtp_chunk_t;

typedef struct {
    ecr_smtp_chunk_t *head;
    ecr_smtp_chunk_t *tail;
} ecr_smtp_chunks_t;

typedef struct {
    ecr_smtp_buf_type_t type;
    ecr_str_t data;
} ecr_smtp_buf_t;

typedef struct {
    ecr_fixedhash_ctx_t *hash_ctx;
    ecr_smtp_keys_t keys;
    size_t max_content_chunks;
} ecr_smtp_decoder_t;

typedef struct {
    ecr_smtp_message_type_t type;
    union {
        struct {
            ecr_str_t hello;
            ecr_str_t auth_user;
            ecr_str_t auth_pwd;
            ecr_str_t mail_from;
            ecr_str_t rcpt_to;
            struct {
                ecr_fixedhash_t *headers;
            } data;
        } request;
        struct {

        } response;
    };
    ecr_fixedhash_t *headers;
    ecr_smtp_chunks_t *content;
    ecr_smtp_decoder_t *decoder;
    int8_t error_no;
    int8_t decode_status;

    //private fields
    int8_t _status;
    int8_t _next_status;
    int _chunk_used;
    int _content_buf_idx;
    int _buf_size;
    int _buf_idx;
    ecr_smtp_chunks_t _chunks[1];
    size_t _chunk_left;
    ecr_smtp_buf_t _buf[];
} ecr_smtp_message_t;

void ecr_smtp_decoder_init(ecr_smtp_decoder_t *decoder, ecr_fixedhash_ctx_t *ctx, size_t max_content_chunks);

ecr_smtp_message_t * ecr_smtp_new_request(ecr_smtp_decoder_t *decoder);

ecr_smtp_message_type_t ecr_smtp_guess(char *data, size_t size);

void ecr_smtp_message_dump(ecr_smtp_message_t *message, FILE *stream);

/**
 * return SMTP_DECODE_OK for complete, SMTP_DECODE_MORE for incomplete, SMTP_DECODE_ERR for error
 */
int ecr_smtp_decode(ecr_smtp_message_t *message, char *data, size_t size);

void ecr_smtp_message_destroy(ecr_smtp_message_t *message);

#endif /* SRC_ECR_ECR_SMTP_DECODER_H_ */
