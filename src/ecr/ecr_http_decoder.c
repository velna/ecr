/*
 * ecr_http_decoder.c
 *
 *  Created on: May 11, 2016
 *      Author: velna
 */

#include "config.h"
#include "ecr_http_decoder.h"
#include "ecr_util.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <zlib.h>

#define DECODE_INIT             0

#define DECODE_CRLF             1

#define DECODE_REQ_METHOD       11
#define DECODE_REQ_URI          12
#define DECODE_REQ_VERSION      13

#define DECODE_RESP_VERSION     21
#define DECODE_RESP_STATUS      22
#define DECODE_RESP_REASON      23

#define DECODE_HEADER           31
#define DECODE_TRAILER          32

#define DECODE_CONTENT          40
#define DECODE_CONTENT_CHUNKED  41
#define DECODE_CONTENT_LENGTHED 42
#define DECODE_CONTENT_VAR      43

static int ecr_http_token_sp(ecr_str_t *to, ecr_str_t *data, size_t limit) {
    char *s = data->ptr, *end, *cp;

    end = data->ptr + (limit ? (limit > data->len ? data->len : limit) : data->len);
    while (s < end && (*s == ' ' || *s == '\t')) {
        s++;
    }
    cp = s;
    while (s < end && *s != ' ' && *s != '\t') {
        s++;
    }
    if (s < end) {
        to->ptr = cp;
        to->len = s - cp;
        data->len -= s - data->ptr + 1;
        data->ptr = s + 1;
        return 0;
    } else {
        return -1;
    }
}

static int ecr_http_token_line(ecr_str_t *to, ecr_str_t *data) {
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

static int ecr_http_token_kv(ecr_str_t *key_out, ecr_str_t *value_out, ecr_str_t *data) {
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
    key.ptr = s;
    while (s < end && *s != ':') {
        *s = (char) tolower(*s);
        s++;
    }
    key.len = s - key.ptr;
    s++;
    while (s < end && (*s == ' ' || *s == '\t')) {
        s++;
    }
    value.ptr = s;
    sp = 0;
    while (s + 1 < end && !str2cmp(s, '\r', '\n')) {
        if (*s == ' ' || *s == '\t') {
            sp++;
        } else {
            sp = 0;
        }
        s++;
    }
    value.len = s - value.ptr - sp;
    *key_out = key;
    *value_out = value;
    if (s + 1 < end) {
        data->len -= s - data->ptr + 2;
        data->ptr = s + 2;
        return 0;
    } else {
        return -1;
    }
}

static ecr_http_version_t ecr_http_parse_version(ecr_str_t *data) {
    ecr_http_version_t ret = HTTP_VERSION_UNKNOWN;

    if (data->len >= 8 && str7cmp(data->ptr, 'H', 'T', 'T', 'P', '/', '1', '.')) {
        switch (data->ptr[7]) {
        case '0':
            ret = HTTP_10;
            break;
        case '1':
            ret = HTTP_11;
            break;
        }
    }
    return ret;
}

static ecr_http_method_t ecr_http_parse_method(ecr_str_t *data) {
    ecr_http_method_t ret = HTTP_METHOD_UNKNOWN;

    if (data->len <= 0) {
        return ret;
    }
    switch (data->ptr[0]) {
    case 'O':
        if (data->len >= 7 && str7cmp(data->ptr, 'O', 'P', 'T', 'I', 'O', 'N', 'S')) {
            ret = HTTP_OPTIONS;
        }
        break;
    case 'G':
        if (data->len >= 3 && str3cmp(data->ptr, 'G', 'E', 'T')) {
            ret = HTTP_GET;
        }
        break;
    case 'H':
        if (data->len >= 4 && str4cmp(data->ptr, 'H', 'E', 'A', 'D')) {
            ret = HTTP_HEAD;
        }
        break;
    case 'P':
        if (data->len >= 4 && str4cmp(data->ptr, 'P', 'O', 'S', 'T')) {
            ret = HTTP_POST;
        } else if (data->len >= 3 && str3cmp(data->ptr, 'P', 'U', 'T')) {
            ret = HTTP_PUT;
        }
        break;
    case 'D':
        if (data->len >= 6 && str6cmp(data->ptr, 'D', 'E', 'L', 'E', 'T', 'E')) {
            ret = HTTP_DELETE;
        }
        break;
    case 'T':
        if (data->len >= 5 && str5cmp(data->ptr, 'T', 'R', 'A', 'C', 'E')) {
            ret = HTTP_TRACE;
        }
        break;
    case 'C':
        if (data->len >= 7 && str7cmp(data->ptr, 'C', 'O', 'N', 'N', 'E', 'C', 'T')) {
            ret = HTTP_CONNECT;
        }
        break;
    }
    return ret;
}

static ecr_http_encoding_t ecr_http_parse_encoding(ecr_str_t *data) {
    ecr_http_encoding_t ret = HTTP_ENCODING_UNKNOWN;

    if (data->len <= 0) {
        return ret;
    }
    switch (data->ptr[0]) {
    case 'c':
        if (data->len >= 8 && str8cmp(data->ptr, 'c', 'o', 'm', 'p', 'r', 'e', 's', 's')) {
            ret = HTTP_COMPRESS;
        } else if (data->len >= 7 && str7cmp(data->ptr, 'c', 'h', 'u', 'n', 'k', 'e', 'd')) {
            ret = HTTP_CHUNKED;
        }
        break;
    case 'g':
        if (data->len >= 4 && str4cmp(data->ptr, 'g', 'z', 'i', 'p')) {
            ret = HTTP_GZIP;
        }
        break;
    case 'd':
        if (data->len >= 7 && str7cmp(data->ptr, 'd', 'e', 'f', 'l', 'a', 't', 'e')) {
            ret = HTTP_DEFLATE;
        }
        break;
    case 'i':
        if (data->len >= 8 && str8cmp(data->ptr, 'i', 'd', 'e', 'n', 't', 'i', 't', 'y')) {
            ret = HTTP_IDENTITY;
        }
        break;
    case 'x':
        if (data->len >= 6 && str6cmp(data->ptr, 'x', '-', 'g', 'z', 'i', 'p')) {
            ret = HTTP_GZIP;
        } else if (data->len >= 9 && str9cmp(data->ptr, 'x', '-', 'd', 'e', 'f', 'l', 'a', 't', 'e')) {
            ret = HTTP_DEFLATE;
        }
        break;
    }
    return ret;
}

static int ecr_http_get_int_header(ecr_fixedhash_t *headers, ecr_fixedhash_key_t key, int default_value) {
    ecr_str_t *value = ecr_fixedhash_get(headers, key);
    return (value && value->len) ? atoi(value->ptr) : default_value;
}

static int ecr_http_check_content(ecr_http_message_t *message) {
    ecr_str_t *value, data, out;
    ecr_http_keys_t *http_keys = &message->decoder->keys;
    int content_length;

    // Transfer-Encoding
    value = ecr_fixedhash_get(message->headers, http_keys->Transfer_Encoding);
    message->_transfer_encoding0 = message->_transfer_encoding1 = HTTP_ENCODING_UNKNOWN;
    if (value) {
        data = *value;
        if (ecr_str_tok(&data, ", ", &out)) {
            message->_transfer_encoding0 = ecr_http_parse_encoding(&out);
            if (ecr_str_tok(&data, ", ", &out)) {
                message->_transfer_encoding1 = ecr_http_parse_encoding(&out);
            }
        }
    }

    if (message->_transfer_encoding0 != HTTP_ENCODING_UNKNOWN) { // using Transfer_Encoding
        message->_content_length = 0;
        return DECODE_CONTENT_CHUNKED;
    } else if ((content_length = ecr_http_get_int_header(message->headers, http_keys->Content_Length, -1)) >= 0) { // using Content-Length
        message->_content_length = content_length;
        return DECODE_CONTENT_LENGTHED;
    } else {
        if ((message->type == HTTP_RESPONSE // response
                && (message->response.request_method == HTTP_HEAD // head
                || message->response.status / 100 == 1 // 1xx
                || message->response.status == 204 || message->response.status == 304
                        || (message->response.request_method == HTTP_CONNECT && message->response.status / 100 == 2) // 2xx to CONNECT
                )) || message->type == HTTP_REQUEST // else if is a request
                ) {
            message->_content_length = 0;
            return DECODE_CONTENT_LENGTHED;
        }
        // should keep reading until end of connection
        return DECODE_CONTENT_VAR;
    }
}

static int ecr_http_make_content(ecr_http_message_t *message, ecr_str_t *data) {
    ecr_http_buf_t *buf;
    size_t data_len;

    if (message->_buf_idx >= message->_buf_size) {
        return -1;
    }
    data_len = message->_content_length > data->len ? data->len : message->_content_length;
    buf = message->_buf + message->_buf_idx;
    buf->data.ptr = data->ptr;
    buf->data.len = data_len;
    buf->type = HTTP_BUF_CONTENT;
    if (!message->_content_buf_idx) {
        message->_content_buf_idx = message->_buf_idx;
    }
    message->_buf_idx++;
    data->ptr += data_len;
    data->len -= data_len;
    message->_content_length -= data_len;
    return 0;
}

#define ecr_http_decode_err(msg, e) \
    msg->error_no = e; \
    msg->decode_status = HTTP_DECODE_ERR;

int ecr_http_decode(ecr_http_message_t *message, char *ptr, size_t size) {
    int token_rc;
    ecr_http_chunk_t *chunk, *last_chunk;
    ecr_str_t data, key;
    ecr_http_buf_t *buf;
    char *tailptr;
    ecr_http_keys_t *http_keys = &message->decoder->keys;

    if (message->error_no) {
        return HTTP_DECODE_ERR;
    } else if (message->decode_status == HTTP_DECODE_OK) {
        ecr_http_decode_err(message, HTTP_ERR_DONE)
        return HTTP_DECODE_ERR;
    }

    last_chunk = message->_chunks->tail;
    if (message->_chunk_left) {
        if (last_chunk) {
//            if (last_chunk->size == message->_chunk_left) {
//                linked_list_drop(message->_chunks, last_chunk);
//                chunk = realloc(last_chunk, sizeof(ecr_http_chunk_t) + last_chunk->size + size);
//                memcpy(chunk->data + chunk->size, ptr, size);
//                chunk->size += size;
//            } else {
            chunk = malloc(sizeof(ecr_http_chunk_t) + message->_chunk_left + size);
            chunk->data.len = message->_chunk_left + size;
            chunk->data.ptr = chunk->_data;
            memcpy(chunk->_data, last_chunk->_data + last_chunk->data.len - message->_chunk_left, message->_chunk_left);
            memcpy(chunk->_data + message->_chunk_left, ptr, size);
//            }
        } else {
            ecr_http_decode_err(message, HTTP_ERR_CHUNK_LEFT)
            return HTTP_DECODE_ERR;
        }
    } else {
        chunk = malloc(sizeof(ecr_http_chunk_t) + size);
        chunk->data.len = size;
        chunk->data.ptr = chunk->_data;
        memcpy(chunk->_data, ptr, size);
    }
    linked_list_add_last(message->_chunks, chunk);
    data = chunk->data;

    message->decode_status = HTTP_DECODE_INIT;
    while (message->decode_status == HTTP_DECODE_INIT) {
        switch (message->_status) {
        case DECODE_INIT:
            switch (message->type) {
            case HTTP_REQUEST:
                message->_status = DECODE_REQ_METHOD;
                break;
            case HTTP_RESPONSE:
                message->_status = DECODE_RESP_VERSION;
                break;
            default:
                ecr_http_decode_err(message, HTTP_ERR_TYPE)
                break;
            }
            break;
        case DECODE_CRLF:
            if (data.len >= 2) {
                if (str2cmp(data.ptr, '\r', '\n')) {
                    data.ptr += 2;
                    data.len -= 2;
                    message->_status = message->_next_status;
                } else {
                    ecr_http_decode_err(message, HTTP_ERR_CRLF)
                }
            } else {
                message->decode_status = HTTP_DECODE_MORE;
            }
            break;
        case DECODE_REQ_METHOD:
            if (ecr_http_token_sp(&message->request.method_str, &data, 8)) {
                ecr_http_decode_err(message, HTTP_ERR_METHOD)
            } else {
                message->request.method = ecr_http_parse_method(&message->request.method_str);
                if (message->request.method == HTTP_METHOD_UNKNOWN) {
                    ecr_http_decode_err(message, HTTP_ERR_METHOD)
                } else {
                    ecr_fixedhash_put(message->headers, http_keys->Method, &message->request.method_str);
                    message->_status = DECODE_REQ_URI;
                }
            }
            break;
        case DECODE_REQ_URI:
            if (ecr_http_token_sp(&message->request.uri, &data, 0)) {
                message->decode_status = HTTP_DECODE_MORE;
            } else {
                ecr_fixedhash_put(message->headers, http_keys->Uri, &message->request.uri);
                message->_status = DECODE_REQ_VERSION;
            }
            break;
        case DECODE_REQ_VERSION:
            if (ecr_http_token_line(&message->version_str, &data)) {
                message->decode_status = HTTP_DECODE_MORE;
            } else {
                message->version = ecr_http_parse_version(&message->version_str);
                if (message->version == HTTP_VERSION_UNKNOWN) {
                    ecr_http_decode_err(message, HTTP_ERR_VERSION)
                } else {
                    ecr_fixedhash_put(message->headers, http_keys->Version, &message->version_str);
                    message->_status = DECODE_HEADER;
                }
            }
            break;
        case DECODE_RESP_VERSION:
            if (ecr_http_token_sp(&message->version_str, &data, 9)) {
                // status line must not cross packet
                ecr_http_decode_err(message, HTTP_ERR_VERSION)
            } else {
                message->version = ecr_http_parse_version(&message->version_str);
                if (message->version == HTTP_VERSION_UNKNOWN) {
                    ecr_http_decode_err(message, HTTP_ERR_VERSION)
                } else {
                    ecr_fixedhash_put(message->headers, http_keys->Version, &message->version_str);
                    message->_status = DECODE_RESP_STATUS;
                }
            }
            break;
        case DECODE_RESP_STATUS:
            if (ecr_http_token_sp(&message->response.status_str, &data, 4) || message->response.status_str.len != 3) {
                // status line must not cross packet, status code must be length of 3
                ecr_http_decode_err(message, HTTP_ERR_STATUS)
            } else {
                message->response.status = atoi(message->response.status_str.ptr);
                ecr_fixedhash_put(message->headers, http_keys->Status, &message->response.status_str);
                message->_status = DECODE_RESP_REASON;
            }
            break;
        case DECODE_RESP_REASON:
            if (ecr_http_token_line(&message->response.reason, &data)) {
                // status line must not cross packet
                ecr_http_decode_err(message, HTTP_ERR_REASON)
            } else {
                ecr_fixedhash_put(message->headers, http_keys->Reason, &message->response.reason);
                message->_status = DECODE_HEADER;
            }
            break;
        case DECODE_HEADER:
        case DECODE_TRAILER:
            if (message->_buf_idx < message->_buf_size) {
                buf = message->_buf + message->_buf_idx;
                token_rc = ecr_http_token_kv(&key, &buf->data, &data);
            } else {
                token_rc = ecr_http_token_kv(&key, &key, &data);
                buf = NULL;
            }
            if (token_rc == -2) {
                if (message->_status == DECODE_TRAILER) {
                    message->decode_status = HTTP_DECODE_OK;
                } else {
                    message->_status = ecr_http_check_content(message);
                }
            } else {
                // put the header into headers no matter the header is complete
                if (buf && ecr_fixedhash_put_original(message->headers, key.ptr, key.len, &buf->data) == 0) {
                    buf->type = HTTP_BUF_HEADER;
                }
                if (token_rc) {
                    message->decode_status = HTTP_DECODE_MORE;
                } else {
                    // increase the _buf_idx if the header is complete
                    message->_buf_idx++;
                }
            }
            break;
        case DECODE_CONTENT_CHUNKED:
            if (message->_content_length == 0) {
                token_rc = ecr_http_token_line(&key, &data);
                if (token_rc == -2) {
                    ecr_http_decode_err(message, HTTP_ERR_CHUNK_SIZE)
                } else if (token_rc) {
                    message->decode_status = HTTP_DECODE_MORE;
                } else {
                    message->_content_length = strtol(key.ptr, &tailptr, 16);
                    if (tailptr == key.ptr) {
                        // empty chunk size
                        ecr_http_decode_err(message, HTTP_ERR_CHUNK_SIZE)
                    } else if (message->_content_length == 0) { // last chunk
                        message->_status = DECODE_TRAILER;
                    }
                }
            }
            if (message->_content_length) {
                if (ecr_http_make_content(message, &data)) {
                    ecr_http_decode_err(message, HTTP_ERR_OUT_OF_BUF)
                } else {
                    if (message->_content_length == 0) {
                        message->_next_status = DECODE_CONTENT_CHUNKED;
                        message->_status = DECODE_CRLF;
                    } else {
                        message->decode_status = HTTP_DECODE_MORE;
                    }
                }
            }
            break;
        case DECODE_CONTENT_LENGTHED:
            if (message->_content_length) {
                if (ecr_http_make_content(message, &data)) {
                    ecr_http_decode_err(message, HTTP_ERR_OUT_OF_BUF)
                } else if (message->_content_length) {
                    message->decode_status = HTTP_DECODE_MORE;
                } else {
                    message->decode_status = HTTP_DECODE_OK;
                }
            } else {
                message->decode_status = HTTP_DECODE_OK;
            }
            break;
        case DECODE_CONTENT_VAR:
            ecr_http_decode_err(message, HTTP_ERR_CONTENT_VAR)
            break;
        default:
            ecr_http_decode_err(message, HTTP_ERR_DECODE_STATUS)
            break;
        }
    }
    message->_chunk_left = data.len;
    return message->decode_status;
}

void ecr_http_decoder_init(ecr_http_decoder_t *decoder, ecr_fixedhash_ctx_t *ctx, size_t max_content_chunks) {
    ecr_fixedhash_ctx_add_keys(ctx, HTTP_HASH_FIELDS);
    decoder->keys.Method = ecr_fixedhash_getkey(ctx, HTTP_METHOD, strlen(HTTP_METHOD));
    decoder->keys.Uri = ecr_fixedhash_getkey(ctx, HTTP_URI, strlen(HTTP_URI));
    decoder->keys.Version = ecr_fixedhash_getkey(ctx, HTTP_VERSION, strlen(HTTP_VERSION));
    decoder->keys.Status = ecr_fixedhash_getkey(ctx, HTTP_STATUS, strlen(HTTP_STATUS));
    decoder->keys.Reason = ecr_fixedhash_getkey(ctx, HTTP_REASON, strlen(HTTP_REASON));
    decoder->keys.Host = ecr_fixedhash_getkey(ctx, HTTP_HOST, strlen(HTTP_HOST));
    decoder->keys.Referer = ecr_fixedhash_getkey(ctx, HTTP_REFERER, strlen(HTTP_REFERER));
    decoder->keys.User_Agent = ecr_fixedhash_getkey(ctx, HTTP_USER_AGENT, strlen(HTTP_USER_AGENT));
    decoder->keys.Cookie = ecr_fixedhash_getkey(ctx, HTTP_COOKIE, strlen(HTTP_COOKIE));
    decoder->keys.Accept = ecr_fixedhash_getkey(ctx, HTTP_ACCEPT, strlen(HTTP_ACCEPT));
    decoder->keys.Content_Length = ecr_fixedhash_getkey(ctx, HTTP_CONTENT_LENGTH, strlen(HTTP_CONTENT_LENGTH));
    decoder->keys.Content_Type = ecr_fixedhash_getkey(ctx, HTTP_CONTENT_TYPE, strlen(HTTP_CONTENT_TYPE));
    decoder->keys.Transfer_Encoding = ecr_fixedhash_getkey(ctx, HTTP_TRANSFER_ENCODING, strlen(HTTP_TRANSFER_ENCODING));
    decoder->keys.Content_Encoding = ecr_fixedhash_getkey(ctx, HTTP_CONTENT_ENCODING, strlen(HTTP_CONTENT_ENCODING));
    decoder->hash_ctx = ctx;
    decoder->max_content_chunks = max_content_chunks;
}

static ecr_http_message_t * ecr_http_message_new(ecr_http_decoder_t *decoder) {
    ecr_http_message_t *message;
    size_t hdr_buf_size, hash_size, hash_offset;

    hash_size = ecr_fixedhash_sizeof(decoder->hash_ctx);
    hdr_buf_size = ecr_fixedhash_ctx_max_keys(decoder->hash_ctx) + decoder->max_content_chunks;
    hash_offset = sizeof(ecr_http_message_t) + hdr_buf_size * sizeof(ecr_str_t);
    message = calloc(1, hash_offset + hash_size);
    message->headers = ecr_fixedhash_init(decoder->hash_ctx, ((char *) message) + hash_offset, hash_size);
    message->_buf_size = hdr_buf_size;
    message->decoder = decoder;
    message->decode_status = HTTP_DECODE_INIT;
    message->_status = DECODE_INIT;
    return message;
}

ecr_http_message_t * ecr_http_new_request(ecr_http_decoder_t *decoder) {
    ecr_http_message_t *message = ecr_http_message_new(decoder);
    message->type = HTTP_REQUEST;
    return message;
}

ecr_http_message_t * ecr_http_new_response(ecr_http_decoder_t *decoder, ecr_http_method_t request_method) {
    ecr_http_message_t *message = ecr_http_message_new(decoder);
    message->type = HTTP_RESPONSE;
    message->response.request_method = request_method;
    return message;
}

ecr_http_message_type_t ecr_http_guess(char *data, size_t size) {
    ecr_str_t str = { data, size };
    return ecr_http_parse_method(&str) == HTTP_METHOD_UNKNOWN ?
            (ecr_http_parse_version(&str) == HTTP_VERSION_UNKNOWN ? HTTP_TYPE_UNKNOWN : HTTP_RESPONSE) : HTTP_REQUEST;
}

static void ecr_http_free_chunks(ecr_http_chunks_t *chunks) {
    ecr_http_chunk_t *chunk, *next;
    chunk = chunks->head;
    while (chunk) {
        next = chunk->next;
        free(chunk);
        chunk = next;
    }
    chunks->head = chunks->tail = NULL;
}

static int ecr_http_uncompress(ecr_http_chunks_t *from, ecr_http_chunks_t *to) {
    return -1;
}

static int ecr_http_inflate(ecr_http_chunks_t *from, ecr_http_chunks_t *to) {
    return -1;
}

static int ecr_http_gunzip(ecr_http_chunks_t *from, ecr_http_chunks_t *to) {
    int rc = Z_STREAM_END;
    z_stream strm;
    ecr_http_chunk_t *chunk_in, *chunk_out;
    size_t out_size;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    if (inflateInit2(&strm, 15 + 32) != Z_OK) {
        return -1;
    }
    chunk_in = from->head;
    while (chunk_in) {
        if ((strm.avail_in = chunk_in->data.len) == 0) {
            chunk_in = chunk_in->next;
            continue;
        }
        strm.next_in = (Bytef*) chunk_in->data.ptr;

        /* run inflate() on input until output buffer not full */
        do {
            out_size = chunk_in->data.len << 1;
            chunk_out = calloc(1, sizeof(ecr_http_chunk_t) + out_size);
            chunk_out->data.ptr = chunk_out->_data;
            chunk_out->data.len = out_size;
            linked_list_add_last(to, chunk_out);

            strm.avail_out = out_size;
            strm.next_out = (Bytef*) chunk_out->data.ptr;
            rc = inflate(&strm, Z_NO_FLUSH);
            switch (rc) {
            case Z_NEED_DICT:
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                inflateEnd(&strm);
                ecr_http_free_chunks(to);
                return -1;
            }
            chunk_out->data.len = out_size - strm.avail_out;
        } while (strm.avail_out == 0);
        /* done when inflate() says it's done */
        chunk_in = chunk_in->next;
    }
    /* clean up and return */
    inflateEnd(&strm);
    if (rc == Z_STREAM_END) {
        return 0;
    } else {
        ecr_http_free_chunks(to);
        return -1;
    }
}

static int ecr_http_decode_content(ecr_http_encoding_t encoding, ecr_http_chunks_t *from, ecr_http_chunks_t *to) {
    switch (encoding) {
    case HTTP_COMPRESS:
        return ecr_http_uncompress(from, to);
    case HTTP_DEFLATE:
        return ecr_http_inflate(from, to);
    case HTTP_GZIP:
        return ecr_http_gunzip(from, to);
    default:
        *to = *from;
        return 0;
    }
}

int ecr_http_message_make_content(ecr_http_message_t *message, ecr_str_t *content_out) {
    ecr_http_chunk_t *chunk;
    ecr_http_chunks_t from[1] = { { NULL } }, to[1] = { { NULL } }, zero = { NULL };
    ecr_http_encoding_t encoding;
    ecr_str_t *value, data, out;
    int i, rc;
    char *ptr;

    if (message->decode_status != HTTP_DECODE_OK) {
        return -1;
    }
    if (!message->content) {
        for (i = message->_content_buf_idx; message->_buf[i].type == HTTP_BUF_CONTENT; i++) {
            chunk = calloc(1, sizeof(ecr_http_chunk_t));
            chunk->data = message->_buf[i].data;
            linked_list_add_last(from, chunk);
        }
        if (ecr_http_decode_content(message->_transfer_encoding0, from, to) < 0) {
            return -1;
        }
        // switch from and to
        *from = *to;
        *to = zero;

        value = ecr_fixedhash_get(message->headers, message->decoder->keys.Content_Encoding);
        if (value) {
            data = *value;
            while (ecr_str_tok(&data, ", ", &out)) {
                encoding = ecr_http_parse_encoding(&out);
                rc = ecr_http_decode_content(encoding, from, to);
                ecr_http_free_chunks(from);
                if (rc < 0) {
                    return -1;
                }
                *from = *to;
                *to = zero;
            }
        }
        message->content = malloc(sizeof(ecr_http_chunks_t));
        *message->content = *from;
    }
    chunk = message->content->head;
    i = 0;
    while (chunk) {
        i += (int) chunk->data.len;
        chunk = chunk->next;
    }
    if (content_out && i > 0) {
        ptr = content_out->ptr = malloc(content_out->len = i);
        chunk = message->content->head;
        while (chunk) {
            ptr = mempcpy(ptr, chunk->data.ptr, chunk->data.len);
            chunk = chunk->next;
        }
    }
    return i;
}

void ecr_http_message_dump(ecr_http_message_t *message, FILE *stream) {
    ecr_http_chunk_t *chunk;
    ecr_fixedhash_iter_t iter;
    ecr_str_t key, *value;

    fprintf(stream, "{===\n");
    fprintf(stream, "[decode_status: %hhd, "
            "error_no: %hhd, "
            "_status: %hhd, "
            "content_length: %zd, "
            "transfer_encoding0: %d, "
            "transfer_encoding1: %d]\n", message->decode_status, message->error_no, message->_status,
            message->_content_length, message->_transfer_encoding0, message->_transfer_encoding1);

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

void ecr_http_message_reset(ecr_http_message_t *message) {
    ecr_fixedhash_t *headers = message->headers;
    size_t buf_size = message->_buf_size;
    ecr_http_decoder_t *decoder = message->decoder;
    ecr_http_message_type_t type = message->type;
    ecr_http_method_t request_method = message->response.request_method;

    ecr_http_free_chunks(message->_chunks);
    if (message->content) {
        ecr_http_free_chunks(message->content);
        free_to_null(message->content);
    }
    ecr_fixedhash_clear(headers);
    memset(message, 0, sizeof(ecr_http_message_t));

    message->type = type;
    message->decoder = decoder;
    message->headers = headers;
    message->_buf_size = buf_size;
    if (type == HTTP_RESPONSE) {
        message->response.request_method = request_method;
    }
}

void ecr_http_message_destroy(ecr_http_message_t *message) {
    ecr_http_free_chunks(message->_chunks);
    if (message->content) {
        ecr_http_free_chunks(message->content);
        free_to_null(message->content);
    }
    free(message);
}
