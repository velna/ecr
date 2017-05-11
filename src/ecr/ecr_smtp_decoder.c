/*
 * ecr_smtp_decoder.c
 *
 *  Created on: Mar 9, 2017
 *      Author: velna
 */

#include "config.h"
#include "ecr_smtp_decoder.h"
#include "ecr_util.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define SMTP_EHLO           "ehlo"
#define SMTP_AUTH_USER      "auth-user"
#define SMTP_AUTH_PWD       "auth-pwd"
#define SMTP_MAIL_FROM      "mail-from"
#define SMTP_RCPT_TO        "rcpt-to"
#define SMTP_USER_AGENT     "user-agent"
#define SMTP_DATE           "date"
#define SMTP_SUBJECT        "subject"
#define SMTP_FROM           "from"
#define SMTP_TO             "to"
#define SMTP_MESSAGE_ID     "message-id"
#define SMTP_THREAD_TOPIC   "thread-topic"
#define SMTP_MIME_VERSION   "mime-version"
#define SMTP_CONTENT_TYPE   "content-type"

#define SMTP_HASH_FIELDS    SMTP_EHLO "," \
                            SMTP_AUTH_USER "," \
                            SMTP_AUTH_PWD "," \
                            SMTP_MAIL_FROM "," \
                            SMTP_RCPT_TO "," \
                            SMTP_USER_AGENT "," \
                            SMTP_DATE "," \
                            SMTP_SUBJECT "," \
                            SMTP_FROM "," \
                            SMTP_TO "," \
                            SMTP_MESSAGE_ID "," \
                            SMTP_THREAD_TOPIC "," \
                            SMTP_MIME_VERSION "," \
                            SMTP_CONTENT_TYPE

#define DECODE_INIT             0
#define DECODE_CMD              1
#define DECODE_HEADER           2
#define DECODE_CRLF             3
#define DECODE_SKIP_LINE        4
#define DECODE_AUTH_USER        5
#define DECODE_AUTH_PWD         6
#define DECODE_CONTENT          7

#define CMD_PREFIX_HELO     0x4f4c4548
#define CMD_PREFIX_EHLO     0x4f4c4845
#define CMD_PREFIX_AUTH     0x48545541
#define CMD_PREFIX_MAIL     0x4c49414d
#define CMD_PREFIX_RCPT     0x54504352
#define CMD_PREFIX_DATA     0x41544144
#define CMD_PREFIX_RSET     0x54455352
#define CMD_PREFIX_VRFY     0x59465256
#define CMD_PREFIX_EXPN     0x4e505845
#define CMD_PREFIX_HELP     0x504c4548
#define CMD_PREFIX_NOOP     0x504f4f4e
#define CMD_PREFIX_QUIT     0x54495551

static int ecr_smtp_token_line(ecr_str_t *to, ecr_str_t *data) {
    char *s = data->ptr, *end = data->ptr + data->len, *cp;
    int sp = 0;

    if (data->len >= 2 && str2cmp(s, '\r', '\n')) {
        data->ptr += 2;
        data->len -= 2;
        return -2;
    }
    while (s < end && (*s == ' ' || *s == '\t')) {
        s++;
    }
    cp = s;
    while (s + 1 < end && !str2cmp(s, '\r', '\n')) {
        if (*s == ' ' || *s == '\t') {
            sp++;
        } else {
            sp = 0;
        }
        s++;
    }
    if (s + 1 < end) {
        to->ptr = cp;
        to->len = s - cp - sp;
        data->len -= s - data->ptr + 2;
        data->ptr = s + 2;
        return 0;
    } else {
        return -1;
    }
}

/**
 * return -2 for \r\n at very begin of data
 * return -1 for no key or value
 * return 0 for complete key and value
 * return 1 for incomplete value
 */
static int ecr_smtp_token_header(ecr_str_t *key_out, ecr_str_t *value_out, ecr_str_t *data) {
    char *s = data->ptr, *end = data->ptr + data->len;
    int sp;
    ecr_str_t key, value;

    if (data->len >= 2 && str2cmp(s, '\r', '\n')) {
        data->ptr += 2;
        data->len -= 2;
        return -2;
    }
    while (s < end && (*s == ' ' || *s == '\t')) {
        s++;
    }
    if (s >= end) {
        return -1;
    }
    key.ptr = s;
    while (s < end && *s != ':') {
        *s = (char) tolower(*s);
        s++;
    }
    if (s >= end) {
        return -1;
    }
    key.len = s - key.ptr;
    s++;
    while (s < end && (*s == ' ' || *s == '\t')) {
        s++;
    }
    if (s >= end) {
        return -1;
    }
    value.ptr = s;
    sp = 0;
    do {
        while (s + 1 < end && !str2cmp(s, '\r', '\n')) {
            if (*s == ' ' || *s == '\t') {
                sp++;
            } else {
                sp = 0;
            }
            s++;
        }
        value.len = s - value.ptr - sp;
        if (value.len == 0) {
            return -1;
        }
        s += 2;
    } while (s + 1 < end && value.ptr[value.len - 1] == ';');
    *key_out = key;
    *value_out = value;
    if (str2cmp(s - 2, '\r', '\n') && value.ptr[value.len - 1] != ';') {
        data->len -= s - data->ptr;
        data->ptr = s;
        return 0;
    } else {
        return 1;
    }
}

void ecr_smtp_decoder_init(ecr_smtp_decoder_t *decoder, ecr_fixedhash_ctx_t *ctx, size_t max_content_chunks) {
    ecr_fixedhash_ctx_add_keys(ctx, SMTP_HASH_FIELDS);
    decoder->keys.Hello = ecr_fixedhash_getkey(ctx, SMTP_EHLO, strlen(SMTP_EHLO));
    decoder->keys.Auth_User = ecr_fixedhash_getkey(ctx, SMTP_AUTH_USER, strlen(SMTP_AUTH_USER));
    decoder->keys.Auth_Pwd = ecr_fixedhash_getkey(ctx, SMTP_AUTH_PWD, strlen(SMTP_AUTH_PWD));
    decoder->keys.Mail_From = ecr_fixedhash_getkey(ctx, SMTP_MAIL_FROM, strlen(SMTP_MAIL_FROM));
    decoder->keys.Rcpt_To = ecr_fixedhash_getkey(ctx, SMTP_RCPT_TO, strlen(SMTP_RCPT_TO));
    decoder->keys.User_Agent = ecr_fixedhash_getkey(ctx, SMTP_USER_AGENT, strlen(SMTP_USER_AGENT));
    decoder->keys.Date = ecr_fixedhash_getkey(ctx, SMTP_DATE, strlen(SMTP_DATE));
    decoder->keys.Subject = ecr_fixedhash_getkey(ctx, SMTP_SUBJECT, strlen(SMTP_SUBJECT));
    decoder->keys.From = ecr_fixedhash_getkey(ctx, SMTP_FROM, strlen(SMTP_FROM));
    decoder->keys.To = ecr_fixedhash_getkey(ctx, SMTP_TO, strlen(SMTP_TO));
    decoder->keys.Message_ID = ecr_fixedhash_getkey(ctx, SMTP_MESSAGE_ID, strlen(SMTP_MESSAGE_ID));
    decoder->keys.Thread_Topic = ecr_fixedhash_getkey(ctx, SMTP_THREAD_TOPIC, strlen(SMTP_THREAD_TOPIC));
    decoder->keys.Mime_Version = ecr_fixedhash_getkey(ctx, SMTP_MIME_VERSION, strlen(SMTP_MIME_VERSION));
    decoder->keys.Content_Type = ecr_fixedhash_getkey(ctx, SMTP_CONTENT_TYPE, strlen(SMTP_CONTENT_TYPE));
    decoder->max_content_chunks = max_content_chunks;
    decoder->hash_ctx = ctx;
}

ecr_smtp_message_t * ecr_smtp_new_request(ecr_smtp_decoder_t *decoder) {
    ecr_smtp_message_t *message;
    size_t hdr_buf_size, hash_size, hash_offset;

    hash_size = ecr_fixedhash_sizeof(decoder->hash_ctx);
    hdr_buf_size = ecr_fixedhash_ctx_max_keys(decoder->hash_ctx) + decoder->max_content_chunks;
    hash_offset = sizeof(ecr_smtp_message_t) + hdr_buf_size * sizeof(ecr_smtp_buf_t);
    message = calloc(1, hash_offset + hash_size);
    message->headers = ecr_fixedhash_init(decoder->hash_ctx, ((char *) message) + hash_offset, hash_size);
    message->_buf_size = hdr_buf_size;
    message->decoder = decoder;
    message->decode_status = SMTP_DECODE_INIT;
    message->_status = DECODE_INIT;
    message->type = SMTP_REQUEST;
    return message;
}

ecr_smtp_message_type_t ecr_smtp_guess(char *data, size_t size) {
    ecr_smtp_message_type_t type = SMTP_TYPE_UNKNOWN;
    int cmd_prefix;
    if (size < 4) {
        return type;
    }

    cmd_prefix = *((int*) data);
    switch (cmd_prefix) {
    case CMD_PREFIX_HELO:
    case CMD_PREFIX_EHLO:
    case CMD_PREFIX_AUTH:
    case CMD_PREFIX_MAIL:
    case CMD_PREFIX_RCPT:
    case CMD_PREFIX_DATA:
    case CMD_PREFIX_RSET:
    case CMD_PREFIX_VRFY:
    case CMD_PREFIX_EXPN:
    case CMD_PREFIX_HELP:
    case CMD_PREFIX_NOOP:
    case CMD_PREFIX_QUIT:
        type = SMTP_REQUEST;
        break;
    default:
        if (data[0] > '0' && data[0] <= '9') {
            type = SMTP_RESPONSE;
        }
        break;
    }
    return type;
}

void ecr_smtp_message_dump(ecr_smtp_message_t *message, FILE *stream) {
    ecr_smtp_chunk_t *chunk;
    ecr_fixedhash_iter_t iter;
    ecr_str_t key, *value;

    fprintf(stream, "{===\n");
    fprintf(stream, "[decode_status: %hhd, "
            "error_no: %hhd, "
            "_status: %hhd]\n", message->decode_status, message->error_no, message->_status);

    ecr_fixedhash_iter_init(&iter, message->headers);
    while ((value = ecr_fixedhash_iter_next(&iter, NULL, &key))) {
        fprintf(stream, "%s: [", key.ptr);
        fwrite(value->ptr, value->len, 1, stream);
        fprintf(stream, "]\n");
    }

    chunk = message->_chunks->head;
    while (chunk) {
        ecr_binary_dump(stream, chunk->data.ptr, chunk->data.len);
        chunk = chunk->next;
    }
    if (message->content) {
        chunk = message->content->head;
        while (chunk) {
            ecr_binary_dump(stream, chunk->data.ptr, chunk->data.len);
            chunk = chunk->next;
        }
    }
    fprintf(stream, "===}\n");
}

static int ecr_smtp_make_content(ecr_smtp_message_t *message, ecr_str_t *data) {
    ecr_smtp_buf_t *buf;
    size_t data_len;
    int i = 0, rc;

    if (message->_buf_idx >= message->_buf_size) {
        return -1;
    }
//    printf("message: %p, _buf_idx: %d\n", message, message->_buf_idx);
    rc = 1;
    data_len = data->len;
    while (i + 5 <= data->len) {
        if (str5cmp(data->ptr + i, '\r', '\n', '.', '\r', '\n')) {
            rc = 0;
            data_len = i;
            break;
        }
        i++;
    }
    buf = message->_buf + message->_buf_idx;
    buf->data.ptr = data->ptr;
    buf->data.len = data_len;
    buf->type = SMTP_BUF_CONTENT;
    if (!message->_content_buf_idx) {
        message->_content_buf_idx = message->_buf_idx;
    }
    message->_buf_idx++;
    if (rc == 0) {
        data_len += 5;
    }
    data->ptr += data_len;
    data->len -= data_len;
    return rc;
}

/**
 * return SMTP_DECODE_OK for complete, SMTP_DECODE_MORE for incomplete, SMTP_DECODE_ERR for error
 */
int ecr_smtp_decode(ecr_smtp_message_t *message, char *ptr, size_t size) {
    int token_rc, cmd_prefix;
    ecr_smtp_chunk_t *chunk, *last_chunk;
    ecr_str_t data, key;
    ecr_smtp_buf_t *buf;
    ecr_smtp_keys_t *smtp_keys = &message->decoder->keys;

#define ecr_smtp_decode_err(msg, e) \
    msg->error_no = e; \
    msg->decode_status = SMTP_DECODE_ERR;

    if (message->error_no) {
        return SMTP_DECODE_ERR;
    } else if (message->decode_status == SMTP_DECODE_OK) {
        ecr_smtp_decode_err(message, SMTP_ERR_DONE)
        return SMTP_DECODE_ERR;
    } else if (message->_chunk_used > message->decoder->max_content_chunks) {
        ecr_smtp_decode_err(message, SMTP_ERR_OUT_OF_BUF)
        return SMTP_DECODE_ERR;
    }

    message->_chunk_used++;
    last_chunk = message->_chunks->tail;
    if (message->_chunk_left) {
        if (last_chunk) {
            chunk = malloc(sizeof(ecr_smtp_chunk_t) + message->_chunk_left + size);
            chunk->data.len = message->_chunk_left + size;
            chunk->data.ptr = chunk->_data;
            memcpy(chunk->_data, last_chunk->_data + last_chunk->data.len - message->_chunk_left, message->_chunk_left);
            memcpy(chunk->_data + message->_chunk_left, ptr, size);
        } else {
            ecr_smtp_decode_err(message, SMTP_ERR_CHUNK_LEFT)
            return SMTP_DECODE_ERR;
        }
    } else {
        chunk = malloc(sizeof(ecr_smtp_chunk_t) + size);
        chunk->data.len = size;
        chunk->data.ptr = chunk->_data;
        memcpy(chunk->_data, ptr, size);
    }
    linked_list_add_last(message->_chunks, chunk);
    data = chunk->data;

    message->decode_status = SMTP_DECODE_INIT;
    while (message->decode_status == SMTP_DECODE_INIT) {
        switch (message->_status) {
        case DECODE_INIT:
            switch (message->type) {
            case SMTP_REQUEST:
                message->_status = DECODE_CMD;
                break;
            case SMTP_RESPONSE:
                ecr_smtp_decode_err(message, SMTP_ERR_TYPE)
                break;
            default:
                ecr_smtp_decode_err(message, SMTP_ERR_TYPE)
                break;
            }
            break;
        case DECODE_CMD:
            if (data.len < 4) {
                message->decode_status = SMTP_DECODE_MORE;
                break;
            }
            cmd_prefix = *((int*) data.ptr);
            data.ptr += 4;
            data.len -= 4;
            switch (cmd_prefix) {
            case CMD_PREFIX_HELO:
            case CMD_PREFIX_EHLO:
                if (ecr_smtp_token_line(&message->request.hello, &data)) {
                    message->decode_status = SMTP_DECODE_MORE;
                } else {
                    ecr_fixedhash_put(message->headers, smtp_keys->Hello, &message->request.hello);
                }
                break;
            case CMD_PREFIX_AUTH:
                message->_status = DECODE_SKIP_LINE;
                message->_next_status = DECODE_AUTH_USER;
                break;
            case CMD_PREFIX_MAIL:
                if (data.len >= 10 && str6cmp(data.ptr, ' ', 'F', 'R', 'O', 'M', ':')) {
                    data.ptr += 6;
                    data.len -= 6;
                    if (ecr_smtp_token_line(&message->request.mail_from, &data)) {
                        message->decode_status = SMTP_DECODE_MORE;
                    } else {
                        ecr_fixedhash_put(message->headers, smtp_keys->Mail_From, &message->request.mail_from);
                    }
                } else {
                    ecr_smtp_decode_err(message, SMTP_ERR_MAIL)
                }
                break;
            case CMD_PREFIX_RCPT:
                if (data.len >= 4 && str4cmp(data.ptr, ' ', 'T', 'O', ':')) {
                    data.ptr += 4;
                    data.len -= 4;
                    if (ecr_smtp_token_line(&message->request.rcpt_to, &data)) {
                        message->decode_status = SMTP_DECODE_MORE;
                    } else {
                        ecr_fixedhash_put(message->headers, smtp_keys->Rcpt_To, &message->request.rcpt_to);
                    }
                } else {
                    ecr_smtp_decode_err(message, SMTP_ERR_RCPT)
                }
                break;
            case CMD_PREFIX_DATA:
                message->_status = DECODE_SKIP_LINE;
                message->_next_status = DECODE_HEADER;
                break;
            default:
                message->_status = DECODE_SKIP_LINE;
                message->_next_status = DECODE_CMD;
                break;
            }
            if (message->decode_status == SMTP_DECODE_MORE) {
                data.ptr -= 4;
                data.len += 4;
            }
            break;
        case DECODE_AUTH_USER:
            if (ecr_smtp_token_line(&message->request.auth_user, &data)) {
                message->decode_status = SMTP_DECODE_MORE;
            } else {
                ecr_fixedhash_put(message->headers, smtp_keys->Auth_User, &message->request.auth_user);
                message->_status = DECODE_AUTH_PWD;
            }
            break;
        case DECODE_AUTH_PWD:
            if (ecr_smtp_token_line(&message->request.auth_pwd, &data)) {
                message->decode_status = SMTP_DECODE_MORE;
            } else {
                ecr_fixedhash_put(message->headers, smtp_keys->Auth_Pwd, &message->request.auth_pwd);
                message->_status = DECODE_CMD;
            }
            break;
        case DECODE_HEADER:
            if (message->_buf_idx < message->_buf_size) {
                buf = message->_buf + message->_buf_idx;
                token_rc = ecr_smtp_token_header(&key, &buf->data, &data);
            } else {
                token_rc = ecr_smtp_token_header(&key, &key, &data);
                buf = NULL;
            }
            if (token_rc == -2) {
                message->_status = DECODE_CONTENT;
            } else {
                // put the header into headers no matter the header is complete
                if (token_rc >= 0 && buf
                        && ecr_fixedhash_put_original(message->headers, key.ptr, key.len, &buf->data) == 0) {
                    buf->type = SMTP_BUF_HEADER;
                }
                if (token_rc) {
                    message->decode_status = SMTP_DECODE_MORE;
                } else if (buf) {
                    // increase the _buf_idx if the header is complete
                    message->_buf_idx++;
                }
            }
            break;
        case DECODE_CONTENT:
            token_rc = ecr_smtp_make_content(message, &data);
            if (token_rc == -1) {
                ecr_smtp_decode_err(message, SMTP_ERR_OUT_OF_BUF)
            } else if (token_rc == 0) {
                message->decode_status = SMTP_DECODE_OK;
            } else {
                message->decode_status = SMTP_DECODE_MORE;
            }
            break;
        case DECODE_SKIP_LINE:
            while (data.len >= 2) {
                if (str2cmp(data.ptr, '\r', '\n')) {
                    data.ptr += 2;
                    data.len -= 2;
                    message->_status = message->_next_status;
                    break;
                } else {
                    data.ptr++;
                    data.len--;
                }
            }
            if (message->_status == DECODE_SKIP_LINE) {
                message->decode_status = SMTP_DECODE_MORE;
            }
            break;
        }
    }
    message->_chunk_left = data.len;
    return message->decode_status;
#undef ecr_smtp_decode_err
}

static void ecr_smtp_free_chunks(ecr_smtp_chunks_t *chunks) {
    ecr_smtp_chunk_t *chunk, *next;
    chunk = chunks->head;
    while (chunk) {
        next = chunk->next;
        free(chunk);
        chunk = next;
    }
    chunks->head = chunks->tail = NULL;
}

void ecr_smtp_message_destroy(ecr_smtp_message_t *message) {
    ecr_smtp_free_chunks(message->_chunks);
    if (message->content) {
        ecr_smtp_free_chunks(message->content);
        free_to_null(message->content);
    }
    free(message);
}
