/*
 * ecr_wumanber.c
 *
 *  Created on: Nov 12, 2013
 *      Author: velna
 */

#include "config.h"
#include "ecr_wumanber.h"
#include "ecr_logger.h"
#include <stdlib.h>
#include <string.h>

#define WM_MATCH_ALL        0
#define WM_MATCH_PREFIX     1
#define WM_MATCH_SUFFIX     2
#define WM_MATCH_FULL       3

#define WM_MIN_BLOCK        2
#define WM_HASH(ptr)        *((u_int16_t*) (ptr))
#define WM_TABLE_SIZE       65536

int ecr_wm_init(ecr_wm_t * wm, size_t init_size) {
    memset(wm, 0, sizeof(ecr_wm_t));
    wm->plist_capacity = init_size;
    wm->plist = malloc(wm->plist_capacity * sizeof(ecr_wm_pattern_t));
    if (NULL == wm->plist) {
        return -1;
    }
    ecr_hashmap_init(&wm->pmap, 16, 0);
    return 0;
}

void ecr_wm_destroy(ecr_wm_t * wm) {
    int i;
    if (wm) {
        if (wm->plist) {
            for (i = 0; i < wm->plist_size; i++) {
                free(wm->plist[i].org_pattern.ptr);
                ecr_list_destroy(&wm->plist[i].users, NULL);
            }
            free(wm->plist);
            wm->plist = NULL;
        }
        if (wm->hash) {
            free(wm->hash);
            wm->hash = NULL;
        }
        if (wm->shift) {
            free(wm->shift);
            wm->shift = NULL;
        }
        ecr_hashmap_destroy(&wm->pmap, NULL);
    }
}

int ecr_wm_add_pattern(ecr_wm_t *wm, const char *pattern, size_t len, void *user) {
    char c0, cn;
    size_t plen, pb;
    ecr_wm_pattern_t *p;
    int opt = 0;

    if (len < WM_MIN_BLOCK || wm->shift != NULL) {
        return -1;
    }
    c0 = pattern[0];
    cn = pattern[len - 1];
    pb = 0;
    plen = len;
    switch (c0) {
    case '^':
        pb++;
        plen--;
        switch (cn) {
        case '$':
            opt |= WM_MATCH_FULL;
            plen--;
            break;
        case '*':
            opt |= WM_MATCH_PREFIX;
            plen--;
            break;
        default:
            opt |= WM_MATCH_PREFIX;
            break;
        }
        break;
    case '*':
        pb++;
        plen--;
        switch (cn) {
        case '$':
            opt |= WM_MATCH_SUFFIX;
            plen--;
            break;
        case '*':
            opt |= WM_MATCH_ALL;
            plen--;
            break;
        default:
            opt |= WM_MATCH_ALL;
            break;
        }
        break;
    default:
        switch (cn) {
        case '$':
            opt |= WM_MATCH_SUFFIX;
            plen--;
            break;
        case '*':
            opt |= WM_MATCH_ALL;
            plen--;
            break;
        default:
            opt |= WM_MATCH_ALL;
            break;
        }
        break;
    }

    if (plen < WM_MIN_BLOCK) {
        return -1;
    }
    if ((p = ecr_hashmap_get(&wm->pmap, pattern + pb, plen)) == NULL) {
        if (wm->plist_size == wm->plist_capacity) {
            wm->plist_capacity = wm->plist_capacity << 1;
            void * tmp = realloc(wm->plist, wm->plist_capacity * sizeof(ecr_wm_pattern_t));
            if (NULL == wm->plist) {
                return -1;
            }
            wm->plist = tmp;
        }
        p = wm->plist + wm->plist_size;
        p->users_mask = 0;
        p->org_pattern.ptr = strndup(pattern, len);
        p->org_pattern.len = len;
        p->pattern.ptr = p->org_pattern.ptr + pb;
        p->pattern.len = plen;
        if (opt & WM_MATCH_FULL) {
            p->suffix.ptr = memchr(p->pattern.ptr, '*', plen);
            if (p->suffix.ptr) {
                p->suffix.ptr = p->suffix.ptr + 1;
                p->suffix.len = p->pattern.ptr + p->pattern.len - p->suffix.ptr;
                p->pattern.len -= p->suffix.len + 1;
            }
        } else {
            p->suffix.ptr = NULL;
            p->suffix.len = 0;
        }
        p->prefix = WM_HASH(p->pattern.ptr);
        p->opt = opt;
        ecr_list_init(&p->users, 1);
        wm->plist_size++;
        if (wm->min_len) {
            wm->min_len = wm->min_len > plen ? plen : wm->min_len;
        } else {
            wm->min_len = plen;
        }
    }
    if (user) {
        ecr_list_add(&p->users, user);
        p->users_mask |= (int64_t) user;
    }
    return 0;
}

static void ecr_wm_sort(ecr_wm_t * wm) {
    int i, j, f;
    ecr_wm_pattern_t tmp;
    for (i = 0; i < wm->plist_size; i++) {
        wm->plist[i].hash = WM_HASH(wm->plist[i].pattern.ptr + wm->min_len - WM_MIN_BLOCK);
    }
    for (i = wm->plist_size - 1, f = 1; i >= 0 && f; i--) {
        f = 0;
        for (j = 0; j < i; j++) {
            if (wm->plist[j + 1].hash < wm->plist[j].hash) {
                f = 1;
                memcpy(&tmp, &(wm->plist[j + 1]), sizeof(ecr_wm_pattern_t));
                memcpy(&(wm->plist[j + 1]), &(wm->plist[j]), sizeof(ecr_wm_pattern_t));
                memcpy(&(wm->plist[j]), &tmp, sizeof(ecr_wm_pattern_t));
            }
        }
    }
}

static void ecr_wm_calc_shift(ecr_wm_t * wm) {
    char * ptr;
    int i, k, j;
    u_int16_t shift;

    wm->shift = malloc(WM_TABLE_SIZE * sizeof(u_int16_t));
    for (i = 0; i < WM_TABLE_SIZE; i++) {
        wm->shift[i] = wm->min_len - WM_MIN_BLOCK + 1;
    }

    for (j = 0; j < wm->plist_size; j++) {
        for (i = 0; i < wm->min_len - WM_MIN_BLOCK + 1; i++) {
            ptr = wm->plist[j].pattern.ptr + i;
            shift = wm->min_len - i - WM_MIN_BLOCK;
            k = WM_HASH(ptr);
            if (shift < wm->shift[k]) {
                wm->shift[k] = shift;
            }
        }
    }
}

static void ecr_wm_calc_hash(ecr_wm_t * wm) {
    int i;

    wm->hash = malloc(WM_TABLE_SIZE * sizeof(int32_t));
    for (i = 0; i < WM_TABLE_SIZE; i++) {
        wm->hash[i] = -1;
    }

    for (i = wm->plist_size - 1; i >= 0; i--) {
        wm->hash[wm->plist[i].hash] = i;
    }
}

int ecr_wm_compile(ecr_wm_t * wm) {
    if (wm->shift != NULL) {
        return -1;
    }
    ecr_wm_sort(wm);
    ecr_wm_calc_shift(wm);
    ecr_wm_calc_hash(wm);
    return 0;
}

static int ecr_wm_default_match_handler(ecr_wm_t *wm, const char *str, size_t len, ecr_wm_pattern_t *pattern,
        void *user) {
    ecr_list_t *result = user;
    ecr_list_add_all(result, &pattern->users);
    return 0;
}

int ecr_wm_match_ex(ecr_wm_t *wm, const char *str, size_t len, ecr_wm_match_handler handler, void *user) {
    int shift, c = 0, idx, prefix, hash, ok;
    const char *p, *p_end, *p0, *s_end;
    ecr_wm_pattern_t * pattern, *pattern_end;

    if (len < wm->min_len) {
        return 0;
    }

    p = str + wm->min_len - WM_MIN_BLOCK;
    p_end = str + len;
    s_end = p_end - WM_MIN_BLOCK + 1;
    pattern_end = wm->plist + wm->plist_size;

    //L_INFO("min_len=%d", wm->min_len);
    while (p < s_end) {
        while ((shift = wm->shift[WM_HASH(p)])) {
            p += shift;
            if (p >= s_end) {
                return c;
            }
        }
        hash = WM_HASH(p);
        idx = wm->hash[hash];
        if (idx == -1) {
            continue;
        }
        p0 = p - wm->min_len + WM_MIN_BLOCK;
        prefix = WM_HASH(p0);
        pattern = wm->plist + idx;
        //L_INFO("p0=%s, p=%s", p0, p);
        while (pattern < pattern_end && hash == pattern->hash) {
            if (prefix != pattern->prefix) {
                pattern++;
                continue;
            }
            ok = 1;
            //L_INFO("pattern=%s", pattern->org_pattern);
            switch (pattern->opt) {
            case WM_MATCH_ALL:
                break;
            case WM_MATCH_PREFIX:
                if (p0 != str || pattern->pattern.len > len) {
                    //L_INFO("[prefix] - not match");
                    ok = 0;
                }
                break;
            case WM_MATCH_SUFFIX:
                if (p0 + pattern->pattern.len != p_end || pattern->pattern.len > len) {
                    //L_INFO("[suffix] - not match");
                    ok = 0;
                }
                break;
            case WM_MATCH_FULL:
                if (p0 != str) {
                    ok = 0;
                } else {
                    if (pattern->suffix.ptr) {
                        if ((pattern->suffix.len + pattern->pattern.len >= len)
                                || (pattern->suffix.len
                                        && memcmp(str + len - pattern->suffix.len, pattern->suffix.ptr,
                                                pattern->suffix.len))
                                || (memchr(str + pattern->pattern.len, '/',
                                        len - pattern->pattern.len - pattern->suffix.len))) {
                            ok = 0;
                        }
                    } else {
                        if (pattern->pattern.len != len) {
                            ok = 0;
                        }
                    }
                }
                break;
            }
            if (ok && memcmp(p0, pattern->pattern.ptr, pattern->pattern.len) == 0) {
                //L_INFO("match");
                if (handler) {
                    c++;
                    if (handler(wm, str, len, pattern, user)) {
                        return c;
                    }
                } else {
                    return 1;
                }
            }
            pattern++;
        }
        p++;
    }
    return c;
}

int ecr_wm_match(ecr_wm_t *wm, const char *str, size_t len, ecr_list_t *result) {
    return ecr_wm_match_ex(wm, str, len, result ? ecr_wm_default_match_handler : NULL, result);
}
