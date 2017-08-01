/*
 * hm_expr.h
 *
 *  Created on: Aug 1, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_HYPERMATCH_HM_EXPR_H_
#define SRC_ECR_HYPERMATCH_HM_EXPR_H_

#include "hm_private.h"

static ecr_hm_expr_t* ecr_hm_expr_new_leaf(int id, ecr_fixedhash_ctx_t *hash_ctx, const char *field,
        ecr_hm_matcher_t *matcher) {
    ecr_hm_expr_t *expr = calloc(1, sizeof(ecr_hm_expr_t));
    expr->type = HM_LEAF;
    expr->leaf.id = id;
    expr->leaf.field.str = field;
    expr->leaf.field.key = ecr_fixedhash_getkey(hash_ctx, field, strlen(field));
    expr->leaf.matcher = matcher;
    return expr;
}

static ecr_hm_expr_t* ecr_hm_expr_new_composite(ecr_hm_logic_t logic, ecr_hm_expr_t *left, ecr_hm_expr_t *right) {
    ecr_hm_expr_t * expr = calloc(1, sizeof(ecr_hm_expr_t));
    expr->type = HM_COMPOSITE;
    expr->composite.logic = logic;
    expr->composite.left = left;
    expr->composite.right = right;
    return expr;
}

static char * ecr_hm_expr_normalize(const char *str) {
    char *expr = malloc(strlen(str) * 4);
    const char *s;
    char prev = 0, *e;
    for (s = str, e = expr; *s; s++, e++) {
        switch (*s) {
        case '(':
        case ')':
        case '!':
            if (prev && prev != ' ' && prev != '\t') {
                *e++ = ' ';
            }
            break;
        case ' ':
        case '\t':
            break;
        case '\r':
        case '\n':
            e--;
            continue;
        default:
            if (prev && (prev == '(' || prev == ')' || prev == '!')) {
                *e++ = ' ';
            }
            break;
        }
        *e = *s == '@' ? ' ' : *s;
        prev = *e;
    }
    *e = '\0';
    return expr;
}

static void ecr_hm_expr_free(ecr_hm_expr_t *expr) {
    if (expr) {
        switch (expr->type) {
        case HM_LEAF:
            break;
        case HM_COMPOSITE:
            switch (expr->composite.logic) {
            case BWL_AND:
            case BWL_OR:
                ecr_hm_expr_free(expr->composite.left);
                ecr_hm_expr_free(expr->composite.right);
                break;
            case BWL_NOT:
                ecr_hm_expr_free(expr->composite.left);
                break;
            }
            break;
        }
        free(expr);
    }
}

static ecr_hm_expr_t * ecr_hm_expr_parse_leaf(ecr_hm_data_t *data, ecr_hm_source_data_t *source_data, char *field,
        char **expr_save) {
    char *matcher_name, *var_name;
    ecr_hm_matcher_t *matcher;
    ecr_list_t *values;
    int i;
    int expr_id;

    if (!field) {
        ecr_hm_error(data->hm, "null field");
        return NULL;
    }
    matcher_name = strtok_r(NULL, " \t", expr_save);
    if (!matcher_name) {
        ecr_hm_error(data->hm, "null match type of filed '%s'.", field);
        return NULL;
    }
    matcher = ecr_hm_data_get_matcher(data, field, matcher_name);
    if (!matcher) {
        ecr_hm_error(data->hm, "invalid match type: '%s'", matcher_name);
        return NULL;
    }
    if (matcher->reg->has_values) {
        var_name = strtok_r(NULL, " \t", expr_save);
        if (!var_name) {
            ecr_hm_error(data->hm, "unexpected end while search for var name.");
            return NULL;
        }
    } else {
        var_name = NULL;
    }

    expr_id = ecr_hm_data_get_expr_id(data, source_data->source->id, field, matcher_name, var_name);
    if (matcher->reg->has_values) {
        values = ecr_hashmap_get(&source_data->values, var_name, strlen(var_name));
        if (!values) {
            ecr_hm_error(data->hm, "undefined var: %s", var_name);
            return NULL;
        }
        ecr_hm_matcher_add_values(matcher, values, expr_id);
    } else {
        ecr_hm_matcher_add_values(matcher, NULL, expr_id);
    }
    return ecr_hm_expr_new_leaf(expr_id, data->hm->fixedhash_ctx, field, matcher);
}

static ecr_hm_expr_t* ecr_hm_expr_parse(ecr_hm_data_t *data, ecr_hm_source_data_t *source_data, char **expr_save,
        ecr_hm_expr_t *expr_left) {
    char *token;
    ecr_hm_expr_t *expr_new, *expr_right;
    ecr_hm_logic_t logic;

    token = strtok_r(NULL, " \t", expr_save);
    if (!token) {
        ecr_hm_error(data->hm, "unexpected end of expression at %s", *expr_save);
        return NULL;
    }
    if (expr_left) {
        if (strcasecmp(token, "and") == 0 || strcmp(token, "&&") == 0 || strcmp(token, "&") == 0) {
            logic = HM_AND;
        } else if (strcasecmp(token, "or") == 0 || strcmp(token, "||") == 0 || strcmp(token, "|") == 0) {
            logic = HM_OR;
        } else {
            ecr_hm_error(data->hm, "undefined logic %s at [%s]", token, *expr_save);
            return NULL;
        }
        expr_right = ecr_hm_expr_parse(data, source_data, expr_save, NULL);
        if (!expr_right) {
            return NULL;
        }
        expr_new = ecr_hm_expr_new_composite(logic, expr_left, expr_right);
    } else {
        if (strcmp("(", token) == 0) {
            do {
                expr_new = ecr_hm_expr_parse(data, source_data, expr_save, expr_left);
                if (!expr_new) {
                    return NULL;
                }
                if (**expr_save == ')') {
                    token = strtok_r(NULL, " \t", expr_save);
                    return expr_new;
                } else {
                    expr_left = expr_new;
                }
            } while (**expr_save);
            ecr_hm_error(data->hm, "missing right brace at [%s]", *expr_save);
            return NULL;
        } else if (strcasecmp("not", token) == 0 || strcmp("!", token) == 0) {
            expr_right = ecr_hm_expr_parse(data, source_data, expr_save, NULL);
            if (!expr_right) {
                return NULL;
            }
            expr_new = ecr_hm_expr_new_composite(HM_NOT, expr_right, NULL);
        } else {
            expr_new = ecr_hm_expr_parse_leaf(data, source_data, token, expr_save);
        }
    }
    return expr_new;

}

static ecr_hm_expr_t* ecr_hm_expr_new(ecr_hm_data_t *data, ecr_hm_source_data_t *source_data) {
    ecr_hm_expr_t *expr, *expr_new, *expr_parent;
    char *expr_str, *expr_dup, *s;
    ecr_hashmap_iter_t iter;
    char *expr_str;

    ecr_hashmap_iter_init(&iter, &source_data->expr_set);
    while (ecr_hashmap_iter_next(&iter, (void**) &expr_str, NULL, NULL) == 0) {

        expr_dup = ecr_hm_expr_normalize(expr_str);
        s = ecr_str_trim(expr_dup);
        expr_new = expr = NULL;
        while (*s) {
            expr_new = ecr_hm_expr_parse(data, source_data, &s, expr);
            if (!expr_new) {
                free(expr_dup);
                ecr_hm_expr_free(expr);
                return -1;
            }
            expr = expr_new;
        }
        free(expr_dup);
        if (expr_parent) {
            expr_parent = ecr_hm_expr_new_composite(source_data->logic, expr_parent, expr_new);
        } else {
            expr_parent = expr_new;
        }
    }
    return expr_parent;
}

static bool ecr_hm_expr_matches(ecr_hm_expr_t *expr, ecr_fixedhash_t *targets, ecr_hm_result_t *result) {
    bool matches = false;
    ecr_hm_match_status_t match_status;
    ecr_list_t *match_expr_id_list;
    ecr_str_t *target;
    int i, expr_id;

    switch (expr->type) {
    case HM_LEAF:
        match_status = ecr_hm_result_get_expr(result, expr->leaf.id);
        target = ecr_fixedhash_get(targets, expr->leaf.field.key);
        switch (match_status) {
        case HM_UNDEF:
            match_expr_id_list = ecr_hm_matcher_matches(expr->leaf.matcher, target);
            for (i = 0; i < match_expr_id_list->size; i++) {
                expr_id = (int) (match_expr_id_list->data[i] - NULL);
                if (expr_id == expr->leaf.id) {
                    matches = true;
                }
                ecr_hm_result_set_expr(result, expr_id, true, &expr->leaf.field, target);
            }
            if (!matches) {
                ecr_hm_result_set_expr(result, expr->leaf.id, false, &expr->leaf.field, target);
            }
            break;
        case HM_MATCH:
            matches = true;
            break;
        case HM_NOT_MATCH:
            matches = false;
            break;
        }
        break;
    case HM_COMPOSITE:
        switch (expr->composite.logic) {
        case HM_AND:
            matches = ecr_hm_expr_matches(expr->composite.left, targets, result)
                    && ecr_hm_expr_matches(expr->composite.right, targets, result);
            break;
        case HM_OR:
            matches = ecr_hm_expr_matches(expr->composite.left, targets, result)
                    || ecr_hm_expr_matches(expr->composite.right, targets, result);
            break;
        case HM_NOT:
            matches = !ecr_hm_expr_matches(expr->composite.left, targets, result);
            break;
        }
        break;
    }
    return matches;
}

#endif /* SRC_ECR_HYPERMATCH_HM_EXPR_H_ */
