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
    while (isspace(*cp)) {
        cp++;
    }
    while (i >= 0 && isspace(s[i])) {
        s[i--] = '\0';
    }
    return cp;
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
