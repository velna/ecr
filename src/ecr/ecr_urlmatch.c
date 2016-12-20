/*
 * ecr_urlmatch.c
 *
 *  Created on: Aug 31, 2016
 *      Author: dev
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ecr_list.h"
#include "ecr_urlmatch.h"

int ecr_urlmatch_init(ecr_urlmatch_t * in) {
    ecr_hashmap_init((ecr_hashmap_t *) in, 16, 0);
    return 0;
}

static inline ecr_list_t * build_split_list(ecr_str_t * in) {
    char * url = strndup(in->ptr, in->len);

    char * p;
    if ((p = strchr(url, '?'))) {
        *p = 0;
    }
    if ((p = strchr(url, '#'))) {
        *p = 0;
    }

    ecr_list_t * split = ecr_list_new(8);
    while ((p = strchr(url, '/'))) {
        *p = 0;
        ecr_list_add(split, url);
        url = p + 1;
    }
    ecr_list_add(split, url);
    return split;
}

static inline void free_split_list(ecr_list_t * split) {
    if (!split) {
        return;
    }
    if (ecr_list_size(split) > 0) {
        free(ecr_list_get(split, 0));
    }
    ecr_list_destroy(split, NULL);
}

void ecr_urlmatch_addpattern(ecr_urlmatch_t * in, ecr_str_t * pattern) {
    ecr_hashmap_t * map = in;
    int i, size;
    char * str, *host;

    ecr_list_t * split = build_split_list(pattern);
    if ((size = ecr_list_size(split)) == 0) {
        free_split_list(split);
        return;
    }

    host = ecr_list_get(split, 0);
    ecr_urlmatch_node_t head = { .next = NULL }, *next = NULL;
    for (i = 1; i < size; i++) {
        str = ecr_list_get(split, i);
        if (strcmp(str, "*") == 0) {
            continue;
        }
        if (!next) {
            next = &head;
        }
        next = next->next = calloc(1, sizeof(ecr_urlmatch_node_t));
        next->index = i;
        next->str = strdup(str);

        char *p;
        if ((p = strchr(str, '*'))) {
            if (p > str) {
                next->prefix = calloc(1, sizeof(ecr_str_t));
                next->prefix->len = p - str;
                next->prefix->ptr = strndup(str, p - str);
            }
            if (strlen(p + 1) > 0) {
                next->suffix = calloc(1, sizeof(ecr_str_t));
                next->suffix->len = strlen(p + 1);
                next->suffix->ptr = strdup(p + 1);
            }
        } else {
            next->all = 1;
        }
    }

    ecr_list_t * list;
    if (!(list = ecr_hashmap_get(map, host, strlen(host)))) {
        ecr_hashmap_put(map, host, strlen(host), list = ecr_list_new(8));
    }

    ecr_urlmatch_url_t * u = calloc(1, sizeof(ecr_urlmatch_url_t));
    u->size = size;
    u->pattern.ptr = strndup(pattern->ptr, pattern->len);
    u->pattern.len = pattern->len;
    u->next = head.next;
    ecr_list_add(list, u);

    free_split_list(split);
}

void ecr_urlmatch_print(ecr_urlmatch_t * in, FILE* out) {
    ecr_hashmap_iter_t it;
    ecr_hashmap_iter_init(&it, (ecr_hashmap_t *) in);

    int i;
    ecr_str_t host;
    ecr_list_t * list;
    while (ecr_hashmap_iter_next(&it, (void **) &host.ptr, &host.len, (void **) &list) == 0) {
        fprintf(out, "====[%.*s]===\n", (int) host.len, host.ptr);
        for (i = 0; i < ecr_list_size(list); i++) {
            ecr_urlmatch_url_t * u = ecr_list_get(list, i);
            fprintf(out, "[size: %d]%s\n", u->size, u->pattern.ptr);
            ecr_urlmatch_node_t * next = u->next;
            while (next) {
                fprintf(out, "i: %d, str: %s", next->index, next->str);
                if (next->all) {
                    fprintf(out, ", [all]");
                }
                if (next->prefix) {
                    fprintf(out, ", [prefix: %s/%lu]", next->prefix->ptr, next->prefix->len);
                }
                if (next->suffix) {
                    fprintf(out, ", [suffix: %s/%lu]", next->suffix->ptr, next->suffix->len);
                }
                fprintf(out, "\n");
                next = next->next;
            }
            fprintf(out, "\n");
        }
    }
}

int ecr_urlmatch_match(ecr_urlmatch_t * in, ecr_str_t * url, ecr_str_t ** pattern) {
    ecr_hashmap_t * map = in;

    int ret = 0, i, size;
    char * host;

    ecr_list_t * split = build_split_list(url);
    if ((size = ecr_list_size(split)) == 0) {
        free_split_list(split);
        return ret;
    }
    host = ecr_list_get(split, 0);

    ecr_list_t * list = ecr_hashmap_get(map, host, strlen(host));
    if (list) {
        for (i = 0; i < ecr_list_size(list); i++) {
            ecr_urlmatch_url_t * u = ecr_list_get(list, i);
            if (u->size != size) {
                continue;
            }
            char ok = 1;
            ecr_urlmatch_node_t *next = u->next;
            while (next) {
                char * v = ecr_list_get(split, next->index);
                if (next->all && strcmp(v, next->str) != 0) {
                    ok = 0;
                    break;
                }
                if (next->prefix) {
                    if (strncmp(v, next->prefix->ptr, next->prefix->len) != 0) {
                        ok = 0;
                        break;
                    }
                }
                if (next->suffix) {
                    if (strncmp(v + (strlen(v) - next->suffix->len), next->suffix->ptr, next->suffix->len) != 0) {
                        ok = 0;
                        break;
                    }
                }
                next = next->next;
            }
            if (ok) {
                ret = 1;
                if (pattern) {
                    *pattern = &u->pattern;
                }
                break;
            }
        }
    }

    free_split_list(split);

    return ret;
}

static void ecr_urlmatch_url_handler(ecr_list_t *list, int i, void* value) {
    ecr_urlmatch_url_t * u = value;
    ecr_urlmatch_node_t * next = u->next, *nnext;
    while (next) {
        free(next->str);
        if (next->prefix) {
            free(next->prefix->ptr);
            free(next->prefix);
        }
        if (next->suffix) {
            free(next->suffix->ptr);
            free(next->suffix);
        }
        nnext = next->next;
        free(next);
        next = nnext;
    }
    free(u->pattern.ptr);
    free(u);
}

static void ecr_urlmatch_handler(ecr_hashmap_t *map, void *key, size_t key_size, void *value) {
    ecr_list_destroy((ecr_list_t*) value, ecr_urlmatch_url_handler);
}

void ecr_urlmatch_clear(ecr_urlmatch_t * in) {
    ecr_hashmap_clear((ecr_hashmap_t *) in, ecr_urlmatch_handler);
}

void ecr_urlmatch_destroy(ecr_urlmatch_t * in) {
    ecr_hashmap_destroy((ecr_hashmap_t *) in, ecr_urlmatch_handler);
}
