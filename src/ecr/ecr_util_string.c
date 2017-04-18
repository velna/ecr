/*
 * ecr_util_string.c
 *
 *  Created on: Jun 25, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_util.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static char * ecr_str_tok_0(ecr_str_t *str, const char *delims, char replace_ch, int replace, ecr_str_t *out) {
    int i = 0, f;
    const char *d;
    char *ret = NULL;
    while (i < str->len) {
        d = delims;
        f = 0;
        do {
            if (*d == str->ptr[i]) {
                if (replace) {
                    str->ptr[i] = replace_ch;
                }
                f = 1;
                break;
            } else if (!ret) {
                ret = str->ptr + i;
            }
        } while (*(++d));
        if (ret && f) {
            break;
        }
        i++;
    }
    if (out) {
        out->ptr = ret;
        out->len = str->ptr + i - ret;
    }
    str->ptr += i + 1;
    str->len -= i == str->len ? i : i + 1;
    return ret;
}

char * ecr_str_tok(ecr_str_t *str, const char *delims, ecr_str_t *out) {
    return ecr_str_tok_0(str, delims, 0, 0, out);
}

char * ecr_str_tok_replace(ecr_str_t *str, const char *delims, char replace_ch, ecr_str_t *out) {
    return ecr_str_tok_0(str, delims, replace_ch, 1, out);
}

char *ecr_str_trim(char * s) {
    char * cp = s;
    int i = strlen(s) - 1;
    if (i < 0) {
        return cp;
    }
    while (*cp && isspace(*cp)) {
        cp++;
    }
    while (i >= 0 && isspace(s[i])) {
        s[i--] = '\0';
    }
    return cp;
}

void ecr_string_trim(ecr_str_t *str, ecr_str_t *out) {
    char *cp = str->ptr;
    size_t i = str->len - 1;

    while (*cp && isspace(*cp)) {
        cp++;
    }
    while (i >= 0 && isspace(str->ptr[i])) {
        i--;
    }
    if (out) {
        out->ptr = cp;
        out->len = i + 1;
    } else {
        str->ptr = cp;
        str->len = i + 1;
    }
}

inline char *ecr_str_tolower(char *s) {
    char * p = s;
    while (*p != '\0') {
        *p = tolower(*p);
        p++;
    }
    return s;
}

inline size_t ecr_str_rcspn(const char *string, size_t from, const char *stopset) {
    register const char *p, *s;
    register char c;

    for (s = string + from, c = *s; s >= string; s--, c = *s) {
        for (p = stopset; *p != 0; p++) {
            if (c == *p) {
                return s - string;
            }
        }
    }
    return s - string;
}

inline size_t ecr_mem_cspn(const void *mem, size_t n, const char *stopset) {
    register size_t i;
    register const char *p, *s;
    for (s = ((const char*) mem), i = 0; i < n; s++, i++) {
        for (p = stopset; *p != 0; p++) {
            if (*s == *p) {
                return i;
            }
        }
    }
    return i;
}

inline size_t ecr_mem_rcspn(const void *mem, size_t n, const char *stopset) {
    register size_t i;
    register const char *p, *s;
    for (s = ((const char*) mem) + n - 1, i = 0; i < n; s--, i++) {
        for (p = stopset; *p != 0; p++) {
            if (*s == *p) {
                return s - (const char*) mem;
            }
        }
    }
    return s - (const char*) mem;
}

ecr_str_t* ecr_str_dup(ecr_str_t *to, ecr_str_t *from) {
    ecr_str_t *ret = to;
    if (!from || !from->ptr) {
        return NULL;
    }
    if (!to) {
        ret = malloc(sizeof(ecr_str_t));
    }
    ret->ptr = malloc(from->len);
    if (!ret->ptr) {
        if (!to) {
            free(ret);
        }
        return NULL;
    }
    memcpy(ret->ptr, from->ptr, from->len);
    ret->len = from->len;
    return ret;
}

int ecr_str_cast(const char *str, ecr_type_t type, void *out) {
    int m = 1;

    if (type == ECR_STRING || type == ECR_POINTER) {
        *((const char**) out) = str;
        return 0;
    }
    size_t len = strlen(str);
    if (len == 0) {
        return -1;
    }
    char ch = str[len - 1];
    switch (ch) {
    case 'k':
        m = 1000;
        break;
    case 'K':
        m = 1024;
        break;
    case 'm':
        m = 1000 * 1000;
        break;
    case 'M':
        m = 1024 * 1024;
        break;
    case 'g':
        m = 1000 * 1000 * 1000;
        break;
    case 'G':
        m = 1024 * 1024 * 1024;
        break;
    case 's':
    case 'S':
        m = 1;
        break;
    case 'T':
    case 't':
        m = 60;
        break;
    case 'H':
    case 'h':
        m = 60 * 60;
        break;
    case 'd':
        m = 60 * 60 * 24;
        break;
    case 'w':
        m = 60 * 60 * 24 * 7;
        break;
    }
    switch (type) {
    case ECR_CHAR:
        *((char*) out) = str[0];
        break;
    case ECR_INT8:
        *((int8_t*) out) = (int8_t) (strtol(str, NULL, 0) * m);
        break;
    case ECR_UINT8:
        *((uint8_t*) out) = (uint8_t) (strtol(str, NULL, 0) * m);
        break;
    case ECR_INT16:
        *((int16_t*) out) = (int16_t) (strtol(str, NULL, 0) * m);
        break;
    case ECR_UINT16:
        *((uint16_t*) out) = (uint16_t) (strtol(str, NULL, 0) * m);
        break;
    case ECR_INT32:
        *((int*) out) = (int) (strtol(str, NULL, 0) * m);
        break;
    case ECR_UINT32:
        *((u_int32_t*) out) = (u_int32_t) (strtoul(str, NULL, 0) * m);
        break;
    case ECR_INT64:
        *((int64_t*) out) = (int64_t) (strtoll(str, NULL, 0) * m);
        break;
    case ECR_UINT64:
        *((u_int64_t*) out) = (u_int64_t) (strtouq(str, NULL, 0) * m);
        break;
    case ECR_FLOAT:
        *((float*) out) = strtof(str, NULL) * m;
        break;
    case ECR_DOUBLE:
        *((double*) out) = strtod(str, NULL) * m;
        break;
    default:
        return -1;
    }
    return 0;
}
