/*
 * ecr_skiplist.c
 *
 *  Created on: Oct 30, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_skiplist.h"
#include "ecr_util.h"
#include <stdlib.h>
#include <string.h>

void ecr_skiplist_free_value_handler(ecr_skiplist_t *sl, void *value) {
    free(value);
}

static int ecr_skiplist_default_compare_func(const void *a, const void *b) {
    return a - b;
}

static ecr_skiplist_node_t *ecr_skiplist_new_node(int level, void *value) {
    ecr_skiplist_node_t * sn = calloc(1, sizeof(ecr_skiplist_node_t) + level * sizeof(struct ecr_skiplist_level_s));
    sn->value = value;
    return sn;
}

int ecr_skiplist_init(ecr_skiplist_t *sl, ecr_compare_func compare) {
    sl->compare = compare ? compare : ecr_skiplist_default_compare_func;
    sl->level = 1;
    sl->size = 0;
    sl->header = ecr_skiplist_new_node(ECR_SKIPLIST_MAXLEVEL, NULL);
    sl->header->backward = NULL;
    sl->tail = NULL;
    return 0;
}

static void ecr_skiplist_free_node(ecr_skiplist_node_t *sn) {
    free(sn);
}

size_t ecr_skiplist_size(ecr_skiplist_t *sl) {
    return sl->size;
}

void ecr_skiplist_clear(ecr_skiplist_t *sl, ecr_skiplist_handler_t handler) {
    ecr_skiplist_node_t *node = sl->header->level[0].forward, *next;
    int j;

    while (node) {
        next = node->level[0].forward;
        if (handler) {
            handler(sl, node->value);
        }
        ecr_skiplist_free_node(node);
        node = next;
    }
    sl->level = 1;
    sl->size = 0;
    for (j = 0; j < ECR_SKIPLIST_MAXLEVEL; j++) {
        sl->header->level[j].forward = NULL;
    }
    sl->header->value = NULL;
    sl->header->backward = NULL;
    sl->tail = NULL;
}

void ecr_skiplist_destroy(ecr_skiplist_t *sl, ecr_skiplist_handler_t handler) {
    ecr_skiplist_clear(sl, handler);
    free(sl->header);
}

static int ecr_skiplist_random_level(void) {
    int level = 1;
    while ((ecr_random_next() & 0xFFFF) < (0.5 * 0xFFFF))
        level += 1;
    return (level < ECR_SKIPLIST_MAXLEVEL) ? level : ECR_SKIPLIST_MAXLEVEL;
}

static void ecr_skiplist_add0(ecr_skiplist_t *sl, void *value, ecr_skiplist_node_t **update) {
    register int i;
    ecr_skiplist_node_t *node;
    int level;

    level = ecr_skiplist_random_level();
    if (level > sl->level) {
        for (i = sl->level; i < level; i++) {
            update[i] = sl->header;
        }
        sl->level = level;
    }
    node = ecr_skiplist_new_node(level, value);
    for (i = 0; i < level; i++) {
        node->level[i].forward = update[i]->level[i].forward;
        update[i]->level[i].forward = node;
    }

    node->backward = (update[0] == sl->header ? NULL : update[0]);
    if (node->level[0].forward)
        node->level[0].forward->backward = node;
    else
        sl->tail = node;
    sl->size++;
}

void ecr_skiplist_add(ecr_skiplist_t *sl, void *value) {
    ecr_skiplist_node_t *update[ECR_SKIPLIST_MAXLEVEL];
    register ecr_skiplist_node_t *node;
    register int i;

    node = sl->header;
    for (i = sl->level - 1; i >= 0; i--) {
        while (node->level[i].forward && sl->compare(node->level[i].forward->value, value) < 0) {
            node = node->level[i].forward;
        }
        update[i] = node;
    }
    ecr_skiplist_add0(sl, value, update);
}

void * ecr_skiplist_set(ecr_skiplist_t *sl, void *value) {
    ecr_skiplist_node_t *update[ECR_SKIPLIST_MAXLEVEL];
    register ecr_skiplist_node_t *node;
    register int i;
    void *ret;

    node = sl->header;
    for (i = sl->level - 1; i >= 0; i--) {
        while (node->level[i].forward && sl->compare(node->level[i].forward->value, value) < 0) {
            node = node->level[i].forward;
        }
        update[i] = node;
    }
    node = node->level[0].forward;
    if (node && sl->compare(value, node->value) == 0) {
        ret = node->value;
        node->value = value;
        return ret;
    } else {
        ecr_skiplist_add0(sl, value, update);
        return NULL;
    }
}

void * ecr_skiplist_head(ecr_skiplist_t *sl) {
    return sl->header->level[0].forward ? sl->header->level[0].forward->value : NULL;
}

void * ecr_skiplist_tail(ecr_skiplist_t *sl) {
    return sl->tail ? sl->tail->value : NULL;
}

static void ecr_skiplist_remove0(ecr_skiplist_t *sl, ecr_skiplist_node_t *x, ecr_skiplist_node_t **update) {
    register int i;
    for (i = 0; i < sl->level; i++) {
        if (update[i]->level[i].forward == x) {
            update[i]->level[i].forward = x->level[i].forward;
        }
    }
    if (x->level[0].forward) {
        x->level[0].forward->backward = x->backward;
    } else {
        sl->tail = x->backward;
    }
    while (sl->level > 1 && sl->header->level[sl->level - 1].forward == NULL)
        sl->level--;
    sl->size--;
}

int ecr_skiplist_remove(ecr_skiplist_t *sl, void *value) {
    ecr_skiplist_node_t *update[ECR_SKIPLIST_MAXLEVEL];
    register ecr_skiplist_node_t *node;
    register int i;

    node = sl->header;
    for (i = sl->level - 1; i >= 0; i--) {
        while (node->level[i].forward && sl->compare(node->level[i].forward->value, value) < 0) {
            node = node->level[i].forward;
        }
        update[i] = node;
    }
    node = node->level[0].forward;
    if (node && sl->compare(value, node->value) == 0) {
        ecr_skiplist_remove0(sl, node, update);
        ecr_skiplist_free_node(node);
        return 0;
    } else {
        return -1;
    }
}

void * ecr_skiplist_find_lte(ecr_skiplist_t *sl, void *value) {
    register ecr_skiplist_node_t *node;
    register int i;
    void *ret;

    node = sl->header;
    for (i = sl->level - 1; i >= 0; i--) {
        while (node->level[i].forward && sl->compare(node->level[i].forward->value, value) < 0) {
            node = node->level[i].forward;
        }
    }
    ret = node->value;
    node = node->level[0].forward;
    if (node && sl->compare(value, node->value) <= 0) {
        ret = node->value;
    }
    return ret;
}

void * ecr_skiplist_find_gte(ecr_skiplist_t *sl, void *value) {
    register ecr_skiplist_node_t *node;
    register int i;

    node = sl->header;
    for (i = sl->level - 1; i >= 0; i--) {
        while (node->level[i].forward && sl->compare(node->level[i].forward->value, value) <= 0) {
            node = node->level[i].forward;
        }
    }
    return node->value;
}

void * ecr_skiplist_find(ecr_skiplist_t *sl, void *value) {
    register ecr_skiplist_node_t *node;
    register int i;

    node = sl->header;
    for (i = sl->level - 1; i >= 0; i--) {
        while (node->level[i].forward && sl->compare(node->level[i].forward->value, value) < 0) {
            node = node->level[i].forward;
        }
    }
    node = node->level[0].forward;
    if (node && sl->compare(value, node->value) == 0) {
        return node->value;
    } else {
        return NULL;
    }
}

void ecr_skiplist_iter_init(ecr_skiplist_iter_t *iter, ecr_skiplist_t *sl) {
    iter->next = sl->header->level[0].forward;
}

void * ecr_skiplist_iter_next(ecr_skiplist_iter_t *iter) {
    void *ret = NULL;
    if (iter->next) {
        ret = iter->next->value;
        iter->next = iter->next->level[0].forward;
    }
    return ret;
}
