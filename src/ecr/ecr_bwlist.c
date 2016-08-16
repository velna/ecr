/*
 * ecr_bwlist.c
 *
 *  Created on: Dec 2, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_bwlist.h"
#include "ecr_logger.h"
#include "ecr_util.h"
#include "ecr_pkware.h"
#include <time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <regex.h>

typedef struct {
    regex_t regex;
    ecr_str_t pattern;
} ecr_bwl_regex_t;

#define ecr_bwl_log(list, level, fmt, ...) \
    if(list->opts.log_handler) { \
        char buf[4096]; \
        snprintf(buf, 4096, fmt, ##__VA_ARGS__); \
        list->opts.log_handler(list, level, buf); \
    } else { \
        L_LOG(level, fmt, ##__VA_ARGS__); \
    }

static void ecr_bwl_free_group_item_handler(ecr_hashmap_t *map, void *key, size_t key_size, void *value) {
    ecr_list_destroy((ecr_list_t*) value, ecr_list_free_value_handler);
}

static void ecr_bwl_free_users_handler(ecr_hashmap_t *in, void *key, size_t key_size, void *value) {
    ecr_list_destroy((ecr_list_t*) value, NULL);
}

static void ecr_bwl_free_regex_users_handler(ecr_hashmap_t *in, void * key, size_t key_size, void * value) {
    ecr_bwl_regex_t *regex = key;
    regfree(&regex->regex);
    free(regex->pattern.ptr);
    free(regex);
    ecr_list_destroy((ecr_list_t*) value, NULL);
}

static void ecr_bwl_free_user_handler(ecr_hashmap_t *map, void *key, size_t key_size, void *value) {
    ecr_bwl_user_t *user = value;
    free_to_null(user->tag);
    free(value);
}

static void ecr_bwl_source_free(ecr_bwl_source_t *bwsource) {
    free_to_null(bwsource->source);
    free(bwsource);
}

static void ecr_bwl_free_source_handler(ecr_list_t *l, int i, void *value) {
    ecr_bwl_source_free(value);
}

/**
 * return -1 for error, else return 0
 */
static int ecr_bwl_add_item(ecr_bwl_data_t *data, ecr_bwl_type_t type, const char *nm, const char *value, void *user) {
    ecr_bwl_group_t *group;
    ecr_list_t *expr_ids = NULL;
    ecr_bwl_regex_t *reg;
    int rc = 0;
    size_t len;

    char *name = strdup(nm);

    name = ecr_str_tolower(name);
    group = data->groups;
    while (group) {
        if (strcmp(group->name.ptr, name) == 0 && group->type == type) {
            break;
        }
        group = group->next;
    }
    if (!group) {
        group = calloc(1, sizeof(ecr_bwl_group_t));
        group->name.ptr = strdup(name);
        group->name.len = strlen(name);
        if (data->bwl->opts.fixedhash_ctx) {
            group->name_key = ecr_fixedhash_getkey(data->bwl->opts.fixedhash_ctx, group->name.ptr, group->name.len);
        }
        group->type = type;
        switch (type) {
        case BWL_EQUALS:
            ecr_hashmap_init(&group->items.equals, 16, HASHMAP_NOLOCK);
            break;
        case BWL_WUMANBER:
            ecr_wm_init(&group->items.wumanber, 16);
            break;
        case BWL_EXISTS:
            ecr_list_init(&group->items.exists, 16);
            break;
        case BWL_REGEX:
            ecr_hashmap_init(&group->items.regex, 16, HASHMAP_NOLOCK | HASHMAP_NOCOPYKEY);
            break;
        }
        group->next = data->groups;
        data->groups = group;
    }
    switch (type) {
    case BWL_EQUALS:
        if ((expr_ids = ecr_hashmap_get(&group->items.equals, (const void *) value, strlen(value))) == NULL) {
            expr_ids = ecr_list_new(1);
            ecr_hashmap_put(&group->items.equals, (const void *) value, strlen(value), expr_ids);
        }
        break;
    case BWL_WUMANBER:
        ecr_wm_add_pattern(&group->items.wumanber, value, strlen(value), user);
        break;
    case BWL_EXISTS:
        expr_ids = &group->items.exists;
        break;
    case BWL_REGEX:
        reg = calloc(1, sizeof(ecr_bwl_regex_t));
        if (regcomp(&reg->regex, value, REG_EXTENDED | REG_NOSUB) == 0) {
            len = strlen(value);
            if ((expr_ids = ecr_hashmap_get(&group->items.regex, value, len)) == NULL) {
                expr_ids = ecr_list_new(1);
                ecr_hashmap_put(&group->items.regex, value, len, expr_ids);
                reg->pattern.ptr = strdup(value);
                reg->pattern.len = len;
            } else {
                regfree(&reg->regex);
                free(reg);
            }
        } else {
            free(reg);
            rc = -1;
            ecr_bwl_log(data->bwl, LOG_ERR, "can not compile regex [%s] in group %s", value, (char * ) group->name.ptr);
        }
        break;
    }
    if (expr_ids) {
        ecr_list_add(expr_ids, user);
    }
    free(name);
    return rc;
}

static const char *ecr_bwl_type_to_string(ecr_bwl_type_t type) {
    switch (type) {
    case BWL_EQUALS:
        return ECR_BWL_NAME_EQUALS;
    case BWL_WUMANBER:
        return ECR_BWL_NAME_WUMANBER;
    case BWL_EXISTS:
        return ECR_BWL_NAME_EXISTS;
    case BWL_REGEX:
        return ECR_BWL_NAME_REGEX;
    default:
        return "unknown";
    }
}

static int ecr_bwl_type_parse(ecr_bwl_t *list, const char *str, ecr_bwl_type_t *bwtype) {
    ecr_bwl_type_t type;
    if (strcasecmp(str, ECR_BWL_NAME_EQUALS) == 0) {
        type = BWL_EQUALS;
    } else if (strcasecmp(str, ECR_BWL_NAME_WUMANBER) == 0) {
        type = BWL_WUMANBER;
    } else if (strcasecmp(str, ECR_BWL_NAME_EXISTS) == 0) {
        type = BWL_EXISTS;
    } else if (strcasecmp(str, ECR_BWL_NAME_REGEX) == 0) {
        type = BWL_REGEX;
    } else {
        ecr_bwl_log(list, LOG_ERR, "invalid match type: '%s'", str);
        return -1;
    }
    if (bwtype) {
        *bwtype = type;
    }
    return 0;
}

static int ecr_bwl_make_expr(ecr_bwl_data_t *data, ecr_bwl_source_data_t *source_data, const char *name,
        const char *match_type, ecr_bwl_type_t *bwtype, ecr_list_t **group_items_out) {
    char *expr, *group;
    ecr_list_t *group_items;

    if (ecr_bwl_type_parse(data->bwl, match_type, bwtype)) {
        return -1;
    }
    expr = group = NULL;
    if (*bwtype == BWL_EXISTS) {
        asprintf(&expr, "@%s %s", name, match_type);
        expr = ecr_hashmap_put(&source_data->expr_map, expr, strlen(expr), expr);
        free_to_null(expr);
    } else {
        asprintf(&group, "$__%s_%s__", name, match_type);
        group_items = ecr_hashmap_get(&source_data->item_groups, group, strlen(group));
        if (!group_items) {
            group_items = ecr_list_new(16);
            ecr_hashmap_put(&source_data->item_groups, group, strlen(group), group_items);
        }
        *group_items_out = group_items;
        asprintf(&expr, "@%s %s %s", name, match_type, group);
        expr = ecr_hashmap_put(&source_data->expr_map, expr, strlen(expr), expr);
        free_to_null(expr);
        free(group);
    }
    return 0;
}

static void ecr_bwl_expr_destroy(ecr_bwl_expr_t *expr) {
    if (expr) {
        switch (expr->logic) {
        case BWL_AND:
        case BWL_OR:
            ecr_bwl_expr_destroy(expr->left);
            ecr_bwl_expr_destroy(expr->right);
            break;
        case BWL_NOT:
            ecr_bwl_expr_destroy(expr->left);
            break;
        default:
            break;
        }
        free(expr);
    }
}

static ecr_bwl_user_t * ecr_bwl_make_user(ecr_bwl_data_t *data, ecr_bwl_source_data_t *source_data, const char *field,
        const char *match_type, const char *group) {
    char *expr_id_key;
    ecr_bwl_user_t *bwuser;

    if (group) {
        asprintf(&expr_id_key, "%d:%s %s %s", source_data->id, field, match_type, group);
    } else {
        asprintf(&expr_id_key, "%d:%s %s", source_data->id, field, match_type);
    }
    bwuser = ecr_hashmap_get(&data->user_map, expr_id_key, strlen(expr_id_key) + 1);
    if (!bwuser) {
        bwuser = malloc(sizeof(ecr_bwl_user_t));
        bwuser->expr_id = data->next_expr_id++;
        bwuser->tag = NULL;
        bwuser->user = source_data->user;
        ecr_hashmap_put(&data->user_map, expr_id_key, strlen(expr_id_key) + 1, bwuser);
    }
    free(expr_id_key);

    return bwuser;
}

static ecr_bwl_expr_t * ecr_bwl_expr_parse_leaf(ecr_bwl_data_t *data, ecr_bwl_source_data_t *source_data, char *field,
        char **expr_save, ecr_hashmap_t *expr_user_map) {
    char *match_type, *group;
    ecr_bwl_type_t bwtype;
    ecr_list_t *items;
    int i;
    ecr_bwl_expr_t *expr_new;
    ecr_bwl_user_t *user;

    if (!field) {
        ecr_bwl_log(data->bwl, LOG_ERR, "null field");
        return NULL;
    }
    match_type = strtok_r(NULL, " \t", expr_save);
    if (!match_type) {
        ecr_bwl_log(data->bwl, LOG_ERR, "null match type of filed '%s'.", field);
        return NULL;
    }
    if (ecr_bwl_type_parse(data->bwl, match_type, &bwtype)) {
        ecr_bwl_log(data->bwl, LOG_ERR, "invalid match type: '%s'", match_type);
        return NULL;
    }
    if (bwtype != BWL_EXISTS) {
        group = strtok_r(NULL, " \t", expr_save);
        if (!group) {
            ecr_bwl_log(data->bwl, LOG_ERR, "unexpected end while search for group.");
            return NULL;
        }
    } else {
        group = NULL;
    }

    user = ecr_bwl_make_user(data, source_data, field, match_type, group);
    if (bwtype == BWL_EXISTS) {
        if (ecr_bwl_add_item(data, bwtype, field, NULL, user) == -1) {
            return NULL;
        }
    } else {
        items = ecr_hashmap_get(&source_data->item_groups, group, strlen(group));
        if (!items) {
            ecr_bwl_log(data->bwl, LOG_ERR, "undefined group: %s", group);
            return NULL;
        }
        for (i = 0; i < ecr_list_size(items); i++) {
            if (ecr_bwl_add_item(data, bwtype, field, ecr_list_get(items, i), user) == -1) {
                return NULL;
            }
        }
    }
    expr_new = calloc(1, sizeof(ecr_bwl_expr_t));
    expr_new->id = user->expr_id;
    expr_new->logic = BWL_NONE;
    return expr_new;
}

static ecr_bwl_expr_t * ecr_bwl_expr_parse0(ecr_bwl_data_t *data, ecr_bwl_source_data_t *source_data, char **expr_save,
        ecr_bwl_expr_t *expr_left, ecr_hashmap_t *expr_user_map) {
    char *token;
    ecr_bwl_expr_t *expr_new, *expr_right;
    ecr_bwl_logic_t logic;

    token = strtok_r(NULL, " \t", expr_save);
    if (!token) {
        ecr_bwl_log(data->bwl, LOG_ERR, "unexpected end of expression at %s", *expr_save);
        return NULL;
    }
    if (expr_left) {
        if (strcasecmp(token, "and") == 0 || strcmp(token, "&&") == 0 || strcmp(token, "&") == 0) {
            logic = BWL_AND;
        } else if (strcasecmp(token, "or") == 0 || strcmp(token, "||") == 0 || strcmp(token, "|") == 0) {
            logic = BWL_OR;
        } else {
            ecr_bwl_log(data->bwl, LOG_ERR, "undefined logic %s at [%s]", token, *expr_save);
            return NULL;
        }
        expr_right = ecr_bwl_expr_parse0(data, source_data, expr_save, NULL, expr_user_map);
        if (!expr_right) {
            return NULL;
        }
        expr_new = calloc(1, sizeof(ecr_bwl_expr_t));
        expr_new->logic = logic;
        expr_new->left = expr_left;
        expr_new->right = expr_right;
    } else {
        if (strcmp("(", token) == 0) {
            do {
                expr_new = ecr_bwl_expr_parse0(data, source_data, expr_save, expr_left, expr_user_map);
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
            ecr_bwl_log(data->bwl, LOG_ERR, "missing right brace at [%s]", *expr_save);
            return NULL;
        } else if (strcasecmp("not", token) == 0 || strcmp("!", token) == 0) {
            expr_right = ecr_bwl_expr_parse0(data, source_data, expr_save, NULL, expr_user_map);
            if (!expr_right) {
                return NULL;
            }
            expr_new = calloc(1, sizeof(ecr_bwl_expr_t));
            expr_new->logic = BWL_NOT;
            expr_new->left = expr_right;
        } else {
            expr_new = ecr_bwl_expr_parse_leaf(data, source_data, token, expr_save, expr_user_map);
        }
    }
    return expr_new;
}

static char * ecr_bwl_expr_normalize(const char *str) {
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

static int ecr_bwl_expr_parse(ecr_bwl_data_t *data, ecr_bwl_source_data_t *source_data) {
    ecr_bwl_expr_t *expr, *expr_new, *expr_parent;
    char *expr_str, *expr_dup, *s;
    ecr_hashmap_iter_t iter;
    ecr_hashmap_t expr_user_map;

    expr_parent = NULL;
    ecr_hashmap_init(&expr_user_map, 16, 0);
    ecr_hashmap_iter_init(&iter, &source_data->expr_map);
    while (ecr_hashmap_iter_next(&iter, NULL, NULL, (void**) &expr_str) == 0) {
        s = expr_dup = ecr_bwl_expr_normalize(expr_str);
        expr_str = ecr_str_trim(expr_str);
        expr_new = expr = NULL;
        while (*s) {
            expr_new = ecr_bwl_expr_parse0(data, source_data, &s, expr, &expr_user_map);
            if (!expr_new) {
                free(expr_dup);
                ecr_bwl_expr_destroy(expr);
                ecr_hashmap_destroy(&expr_user_map, NULL);
                return -1;
            }
            expr = expr_new;
        }
        free(expr_dup);
        if (expr_parent) {
            expr = calloc(1, sizeof(ecr_bwl_expr_t));
            expr->logic = source_data->source->logic;
            expr->left = expr_parent;
            expr->right = expr_new;
            expr_parent = expr;
        } else {
            expr_parent = expr_new;
        }
    }
    ecr_hashmap_destroy(&expr_user_map, NULL);
    source_data->expr = expr_parent;
    return 0;
}

static int ecr_bwl_expr_eval(ecr_bwl_expr_t *expr, ecr_bwl_result_t *result) {
    int rc = 0;
    switch (expr->logic) {
    case BWL_NONE:
        rc = result->exprs.ptr[expr->id];
        break;
    case BWL_NOT:
        rc = !ecr_bwl_expr_eval(expr->left, result);
        break;
    case BWL_AND:
        rc = ecr_bwl_expr_eval(expr->right, result) && ecr_bwl_expr_eval(expr->left, result);
        break;
    case BWL_OR:
        rc = ecr_bwl_expr_eval(expr->right, result) || ecr_bwl_expr_eval(expr->left, result);
        break;
    }
    return rc;
}

static void ecr_bwl_expr_dump(ecr_bwl_expr_t *expr, FILE *stream) {
    if (!expr) {
        fprintf(stream, "### err ###");
        return;
    }
    switch (expr->logic) {
    case BWL_NONE:
        fprintf(stream, "%d", expr->id);
        break;
    case BWL_AND:
        fprintf(stream, "(");
        ecr_bwl_expr_dump(expr->left, stream);
        fprintf(stream, " and ");
        ecr_bwl_expr_dump(expr->right, stream);
        fprintf(stream, ")");
        break;
    case BWL_OR:
        fprintf(stream, "(");
        ecr_bwl_expr_dump(expr->left, stream);
        fprintf(stream, " or ");
        ecr_bwl_expr_dump(expr->right, stream);
        fprintf(stream, ")");
        break;
    case BWL_NOT:
        fprintf(stream, "not ");
        ecr_bwl_expr_dump(expr->left, stream);
        break;
    default:
        fprintf(stream, "!!! err !!!");
        break;
    }
}

static ecr_bwl_source_data_t * ecr_bwl_source_data_init(ecr_bwl_source_t *bwsource) {
    ecr_bwl_source_data_t *source_data = calloc(1, sizeof(ecr_bwl_source_data_t));
    source_data->id = bwsource->id;
    source_data->user = bwsource->user;
    source_data->source = bwsource;
    ecr_hashmap_init(&source_data->expr_map, 16, 0);
    ecr_hashmap_init(&source_data->item_groups, 16, 0);
    return source_data;
}

static void ecr_bwl_source_data_destroy(ecr_bwl_source_data_t *source_data) {
    ecr_bwl_expr_destroy(source_data->expr);
    ecr_hashmap_destroy(&source_data->item_groups, ecr_bwl_free_group_item_handler);
    ecr_hashmap_destroy(&source_data->expr_map, ecr_hashmap_free_value_handler);
    if (source_data->id != source_data->source->id) {
        free_to_null(source_data->user);
    }
    free(source_data);
}

static int ecr_bwl_source_data_add(ecr_bwl_source_data_t *source_data, ecr_bwl_data_t *data) {
    if (ecr_bwl_expr_parse(data, source_data)) {
        return -1;
    }
    ecr_hashmap_clear(&source_data->item_groups, ecr_bwl_free_group_item_handler);
    ecr_hashmap_clear(&source_data->expr_map, ecr_hashmap_free_value_handler);

    source_data->next = data->source_data;
    data->source_data = source_data;
    return 0;
}

static int ecr_bwl_load_item_from_file(ecr_bwl_data_t *data, ecr_list_t *group_items, const char *file, int crypt) {
    char *line, *value, *file_name;
    size_t len;
    ssize_t nread;
    FILE *fd;
    int rc = 0;

    file_name = NULL;
    if (data->bwl->opts.basepath) {
        asprintf(&file_name, "%s/%s", data->bwl->opts.basepath, file);
    } else {
        file_name = strdup(file);
    }
    fd = fopen(file_name, "r");
    if (NULL == fd) {
        ecr_bwl_log(data->bwl, LOG_ERR, "can not open file for read: %s", file_name);
        free(file_name);
        return -1;
    }
    if (crypt) {
        if (!data->bwl->opts.cfile_pwd) {
            ecr_bwl_log(data->bwl, LOG_ERR, "can not open cfile: %s", file_name);
            free(file_name);
            return -1;
        }
        fd = ecr_pkware_fdecrypt(fd, data->bwl->opts.cfile_pwd);
        if (!fd) {
            ecr_bwl_log(data->bwl, LOG_ERR, "invalid cfile: %s", file_name);
            free(file_name);
            return -1;
        }
    }
    free(file_name);
    len = 256;
    line = calloc(1, len);
    while ((nread = getline(&line, &len, fd)) > 0) {
        value = ecr_str_trim(line);
        ecr_list_add(group_items, strdup(value));
        rc++;
    }
    free(line);
    fclose(fd);
    return rc;
}

static int ecr_bwl_load_stream(ecr_bwl_data_t *data, FILE *stream, ecr_bwl_source_t *source, int crypt) {
    char *line, *oline, ch, *token, *save, *name, *value, *expr;
    ecr_list_t *group_items;
    size_t len;
    ssize_t nread;
    int rc, frc, ln;
    ecr_bwl_type_t bwtype;
    ecr_bwl_source_data_t *source_data;

    len = 256;
    line = calloc(1, len);
    rc = 0;
    ln = 0;
    name = value = NULL;
    group_items = NULL;
    oline = NULL;
    source_data = ecr_bwl_source_data_init(source);
    while ((nread = getline(&line, &len, stream)) > 0) {
        ln++;
        if (nread == 0 || line[0] == '#' || line[0] == '\n') {
            continue;
        }
        free_to_null(oline);
        oline = strdup(line);
        ch = line[0];
        if (isblank(ch)) {
            if (name == NULL || !group_items) {
                rc = -1;
                ecr_bwl_log(data->bwl, LOG_ERR, "ecr_bwlist syntax error, no group found at line %d: %s", ln,
                        source->source);
                break;
            }
            value = ecr_str_trim(line);
            ecr_list_add(group_items, strdup(value));
            rc++;
        } else {
            token = strtok_r(line, " \t\n\r", &save);
            if (!token) {
                rc = -1;
                ecr_bwl_log(data->bwl, LOG_ERR, "ecr_bwlist syntax error, group name expected at line %d: %s", ln,
                        source->source);
                break;
            }
            if (name) {
                free(name);
            }
            name = strdup(token);
            if (name[0] == '@') {
                expr = ecr_hashmap_put(&source_data->expr_map, oline, strlen(oline), strdup(oline));
                free_to_null(expr);
            } else {
                if (name[0] == '$') {
                    if (ecr_hashmap_get(&source_data->item_groups, name, strlen(name))) {
                        ecr_bwl_log(data->bwl, LOG_ERR, "duplicated group: %s", name);
                        rc = -1;
                        break;
                    }
                    group_items = ecr_list_new(16);
                    ecr_hashmap_put(&source_data->item_groups, name, strlen(name), group_items);
                } else {
                    group_items = NULL;
                    token = strtok_r(NULL, " \t\n\r", &save);
                    if (!token) {
                        rc = -1;
                        ecr_bwl_log(data->bwl, LOG_ERR, "ecr_bwlist syntax error, group type expected at line %d: %s",
                                ln, source->source);
                        break;
                    }
                    if (ecr_bwl_make_expr(data, source_data, name, token, &bwtype, &group_items)) {
                        rc = -1;
                        ecr_bwl_log(data->bwl, LOG_ERR,
                                "ecr_bwlist syntax error, unknown group type [%s] at line %d: %s", token, ln,
                                source->source);
                        break;
                    }
                    if (bwtype == BWL_EXISTS) {
                        rc++;
                    }
                }
                token = strtok_r(NULL, " \t\n\r", &save);
                if (token && group_items) {
                    frc = ecr_bwl_load_item_from_file(data, group_items, token, crypt);
                    if (-1 == frc) {
                        rc = -1;
                        break;
                    }
                    rc += frc;
                }
            }
        }
    }
    if (rc != -1) {
        if (ecr_bwl_source_data_add(source_data, data)) {
            ecr_bwl_source_data_destroy(source_data);
            rc = -1;
        }
    } else {
        ecr_bwl_source_data_destroy(source_data);
    }
    free_to_null(name);
    free_to_null(oline);
    free_to_null(line);
    return rc;
}

static int ecr_bwl_load_file(ecr_bwl_data_t *data, ecr_bwl_source_t *bwsource, int force, int crypt) {
    struct stat st;
    FILE *stream;
    int rc;

    if (stat(bwsource->source, &st) == 0 && !force
            && memcmp(&st.st_mtim, &bwsource->status.file_m_date, sizeof(struct timespec)) == 0) {
        return -2;
    }
    stream = fopen(bwsource->source, "r");
    if (NULL == stream) {
        ecr_bwl_log(data->bwl, LOG_ERR, "can not open %s for read: %s", bwsource->source, strerror(errno));
        return -1;
    }
    if (crypt) {
        if (!data->bwl->opts.cfile_pwd) {
            ecr_bwl_log(data->bwl, LOG_ERR, "can not open cfile: %s", bwsource->source);
            return -1;
        }
        stream = ecr_pkware_fdecrypt(stream, data->bwl->opts.cfile_pwd);
        if (!stream) {
            ecr_bwl_log(data->bwl, LOG_ERR, "invalid cfile: %s", bwsource->source);
            return -1;
        }
    }
    rc = ecr_bwl_load_stream(data, stream, bwsource, crypt);
    if (rc != -1) {
        bwsource->status.file_m_date = st.st_mtim;
        ecr_bwl_log(data->bwl, LOG_INFO, "load %d items from file %s", rc, bwsource->source);
    }
    fclose(stream);
    return rc;
}

static int ecr_bwl_load_string(ecr_bwl_data_t *data, ecr_bwl_source_t *bwsource, int force) {
    FILE *stream;
    int rc;

    if (!force && bwsource->status.string_ok) {
        return -2;
    }
    stream = fmemopen(bwsource->source, strlen(bwsource->source), "r");
    if (NULL == stream) {
        ecr_bwl_log(data->bwl, LOG_ERR, "fmemopen() error: %s", strerror(errno));
        return -1;
    }
    rc = ecr_bwl_load_stream(data, stream, bwsource, 0);
    if (rc != -1) {
        bwsource->status.string_ok = 1;
        ecr_bwl_log(data->bwl, LOG_INFO, "load %d items from string %s", rc, bwsource->source);
    }
    fclose(stream);
    return rc;
}

static int ecr_bwl_load_mongo(ecr_bwl_data_t *data, ecr_bwl_source_t *bwsource, int force) {
    ecr_bwl_type_t bwtype;
    const char *field, *match_type, *tag;
    int rc = 0, idx;
    char *db_name, *collection_name;
    int64_t count = 0, m_date = 0, n;
    bson_error_t err;
    bson_t query, bson, items;
    const bson_t *doc;
    mongoc_cursor_t *cursor = NULL;
    bson_iter_t i, si;
    uint32_t items_len;
    const uint8_t *items_buf;
    mongoc_collection_t *collection;
    mongoc_client_t *client;
    ecr_list_t *group_items;
    ecr_bwl_source_data_t *source_data, *source_data_tmp;

    if (!data->bwl->opts.mongo_pool) {
        ecr_bwl_log(data->bwl, LOG_ERR, "no mongo pool configured.");
        return -1;
    }

    source_data_tmp = NULL;
    source_data = ecr_bwl_source_data_init(bwsource);
    idx = strcspn(bwsource->source, ".");
    db_name = strndup(bwsource->source, idx);
    collection_name = bwsource->source + idx + 1;
    client = mongoc_client_pool_pop(data->bwl->opts.mongo_pool);
    collection = mongoc_client_get_collection(client, db_name, collection_name);
    free(db_name);

    count = mongoc_collection_count(collection, MONGOC_QUERY_SLAVE_OK, NULL, 0, 1, NULL, &err);
    if (count == -1) {
        ecr_bwl_log(data->bwl, LOG_ERR, "mongo connection error: %s[%d]", err.message, err.code);
        rc = -1;
        goto l_end;
    }
    if (count == bwsource->status.mongo.doc_count) {
        bson_init(&bson);
        bson_append_date_time(&bson, "$gt", -1, bwsource->status.mongo.m_date);
        bson_init(&query);
        bson_append_document(&query, "m_date", -1, &bson);
        n = mongoc_collection_count(collection, MONGOC_QUERY_SLAVE_OK, &query, 0, 1, NULL, &err);
        bson_destroy(&query);
        bson_destroy(&bson);
        if (n == -1) {
            ecr_bwl_log(data->bwl, LOG_ERR, "mongo connection error: %s[%d]", err.message, err.code);
            rc = -1;
            goto l_end;
        }
        if (!force && n == 0) {
            rc = -2;
            goto l_end;
        }
    }

    bson_init(&query);
    cursor = mongoc_collection_find(collection, MONGOC_QUERY_SLAVE_OK, 0, 0, 0, &query, NULL, NULL);
    bson_destroy(&query);
    while (!mongoc_cursor_error(cursor, &err) && mongoc_cursor_more(cursor)) {
        if (mongoc_cursor_next(cursor, &doc)) {
            if (!bson_iter_init_find(&i, doc, "match_type") || bson_iter_type(&i) != BSON_TYPE_UTF8) {
                ecr_bwl_log(data->bwl, LOG_ERR, "can not find field 'match_type' of type string");
                rc = -1;
                goto l_end;
            }
            match_type = bson_iter_utf8(&i, NULL);
            if (!bson_iter_init_find(&i, doc, "field") || bson_iter_type(&i) != BSON_TYPE_UTF8) {
                ecr_bwl_log(data->bwl, LOG_ERR, "can not find field 'field' of type string");
                rc = -1;
                goto l_end;
            }
            field = bson_iter_utf8(&i, NULL);
            if (bson_iter_init_find(&i, doc, "tag") && bson_iter_type(&i) == BSON_TYPE_UTF8) {
                tag = bson_iter_utf8(&i, NULL);
            } else {
                tag = NULL;
            }
            if (!bson_iter_init_find(&i, doc, "m_date") || bson_iter_type(&i) != BSON_TYPE_DATE_TIME) {
                ecr_bwl_log(data->bwl, LOG_ERR, "can not find field 'm_date' of type datetime");
                rc = -1;
                goto l_end;
            }
            m_date = m_date > bson_iter_date_time(&i) ? m_date : bson_iter_date_time(&i);
            if (tag) {
                source_data_tmp = source_data;
                source_data = ecr_bwl_source_data_init(bwsource);
                source_data->id = data->next_sid++;
                source_data->user = strdup(tag);
            }
            if (ecr_bwl_make_expr(data, source_data, field, match_type, &bwtype, &group_items)) {
                ecr_bwl_log(data->bwl, LOG_ERR, "invalid match_type: '%s'", match_type);
                rc = -1;
                goto l_end;
            }
            switch (bwtype) {
            case BWL_EQUALS:
            case BWL_WUMANBER:
            case BWL_REGEX:
                if (!bson_iter_init_find(&i, doc, "items") || bson_iter_type(&i) != BSON_TYPE_ARRAY) {
                    ecr_bwl_log(data->bwl, LOG_ERR, "can not find field 'items' of type array");
                    rc = -1;
                    goto l_end;
                }
                bson_iter_array(&i, &items_len, &items_buf);
                bson_init_static(&items, items_buf, items_len);
                bson_iter_init(&si, &items);
                while (bson_iter_next(&si) && bson_iter_type(&si) == BSON_TYPE_UTF8) {
                    ecr_list_add(group_items, strdup(bson_iter_utf8(&si, NULL)));
                    rc++;
                }
                bson_destroy(&items);
                break;
            case BWL_EXISTS:
                rc++;
                break;
            }
            if (tag) {
                if (ecr_bwl_source_data_add(source_data, data)) {
                    ecr_bwl_source_data_destroy(source_data);
                    source_data = source_data_tmp;
                    rc = -1;
                    goto l_end;
                }
                source_data = source_data_tmp;
            }
        }
    }

    if (mongoc_cursor_error(cursor, &err)) {
        ecr_bwl_log(data->bwl, LOG_ERR, "mongo cursor error: %s[%d]", err.message, err.code);
        rc = -1;
        goto l_end;
    }
    l_end: {
        if (rc >= 0) {
            if (ecr_bwl_source_data_add(source_data, data)) {
                ecr_bwl_source_data_destroy(source_data);
                rc = -1;
            }
        } else {
            ecr_bwl_source_data_destroy(source_data);
        }
        if (cursor) {
            mongoc_cursor_destroy(cursor);
        }
        mongoc_collection_destroy(collection);
        mongoc_client_pool_push(data->bwl->opts.mongo_pool, client);
        if (rc >= 0) {
            bwsource->status.mongo.doc_count = count;
            bwsource->status.mongo.m_date = m_date;
            ecr_bwl_log(data->bwl, LOG_INFO, "load %d items from mongo collection %s", rc, bwsource->source);
        }
        return rc;
    }
}

static ecr_bwl_data_t * ecr_bwl_data_new(ecr_bwl_t *list) {
    ecr_bwl_data_t *data = calloc(1, sizeof(ecr_bwl_data_t));
    data->bwl = list;
    data->next_sid = 1;
    data->next_expr_id = 1;
    ecr_list_init(&data->source_list, 16);
    ecr_hashmap_init(&data->user_map, 16, 0);
    return data;
}

static void ecr_bwl_data_copy(ecr_bwl_data_t *src, ecr_bwl_data_t *dst) {
    int i;
    ecr_bwl_source_t *bwsource;

    dst->next_sid = src->next_sid;
    for (i = 0; i < ecr_list_size(&src->source_list); i++) {
        bwsource = malloc(sizeof(ecr_bwl_source_t));
        *bwsource = *(ecr_bwl_source_t*) ecr_list_get(&src->source_list, i);
        bwsource->source = strdup(bwsource->source);
        ecr_list_add(&dst->source_list, bwsource);
    }
}

static void ecr_bwl_data_clear(ecr_bwl_data_t *data) {
    ecr_bwl_group_t *group, *next_group;
    ecr_bwl_source_data_t *source_data, *next_source_data;

    group = data->groups;
    while (group) {
        next_group = group->next;
        free((void*) group->name.ptr);
        switch (group->type) {
        case BWL_EQUALS:
            ecr_hashmap_destroy(&group->items.equals, ecr_bwl_free_users_handler);
            break;
        case BWL_WUMANBER:
            ecr_wm_destroy(&group->items.wumanber);
            break;
        case BWL_EXISTS:
            ecr_list_destroy(&group->items.exists, NULL);
            break;
        case BWL_REGEX:
            ecr_hashmap_destroy(&group->items.regex, ecr_bwl_free_regex_users_handler);
            break;
        }
        free(group);
        group = next_group;
    }
    data->groups = NULL;

    source_data = data->source_data;
    while (source_data) {
        next_source_data = source_data->next;
        ecr_bwl_source_data_destroy(source_data);
        source_data = next_source_data;
    }
    data->source_data = NULL;

    ecr_hashmap_clear(&data->user_map, ecr_bwl_free_user_handler);
    ecr_list_clear(&data->source_list, ecr_bwl_free_source_handler);
    data->next_expr_id = 1;
    data->next_sid = 1;
}

static void ecr_bwl_data_destroy(ecr_bwl_data_t *data) {
    if (data) {
        ecr_bwl_data_clear(data);
        ecr_list_destroy(&data->source_list, ecr_bwl_free_source_handler);
        ecr_hashmap_destroy(&data->user_map, ecr_bwl_free_user_handler);
        free_to_null(data);
    }
}

/**
 * return 0 for ok, -2 for un-modified, -1 for error
 */
static int ecr_bwl_compile_0(ecr_bwl_data_t *data, int force) {
    ecr_bwl_source_t *bwsource;
    ecr_bwl_group_t *group;
    int rc, modified = 0, i;
    ecr_list_t unmodified_sources;

    ecr_list_init(&unmodified_sources, 16);
    for (i = 0; i < ecr_list_size(&data->source_list); i++) {
        bwsource = ecr_list_get(&data->source_list, i);
        switch (bwsource->source_type) {
        case BWL_FILE:
            rc = ecr_bwl_load_file(data, bwsource, force, 0);
            break;
        case BWL_CFILE:
            rc = ecr_bwl_load_file(data, bwsource, force, 1);
            break;
        case BWL_MONGO:
            rc = ecr_bwl_load_mongo(data, bwsource, force);
            break;
        case BWL_STRING:
            rc = ecr_bwl_load_string(data, bwsource, force);
            break;
        default:
            ecr_bwl_data_clear(data);
            ecr_list_destroy(&unmodified_sources, NULL);
            return -1;
        }
        if (rc == -1) {
            ecr_bwl_data_clear(data);
            ecr_list_destroy(&unmodified_sources, NULL);
            return -1;
        } else if (rc >= 0) {
            modified = 1;
        } else if (rc == -2) {
            ecr_list_add(&unmodified_sources, bwsource);
        }
    }

    if (!modified) {
        ecr_list_destroy(&unmodified_sources, NULL);
        return -2;
    }
    for (i = 0; i < ecr_list_size(&unmodified_sources); i++) {
        bwsource = ecr_list_get(&unmodified_sources, i);
        switch (bwsource->source_type) {
        case BWL_FILE:
            rc = ecr_bwl_load_file(data, bwsource, 1, 0);
            break;
        case BWL_CFILE:
            rc = ecr_bwl_load_file(data, bwsource, 1, 1);
            break;
        case BWL_MONGO:
            rc = ecr_bwl_load_mongo(data, bwsource, 1);
            break;
        case BWL_STRING:
            rc = ecr_bwl_load_string(data, bwsource, 1);
            break;
        default:
            ecr_bwl_data_clear(data);
            ecr_list_destroy(&unmodified_sources, NULL);
            return -1;
        }
    }
    ecr_list_destroy(&unmodified_sources, NULL);

    group = data->groups;
    while (group) {
        if (group->type == BWL_WUMANBER) {
            ecr_wm_compile(&group->items.wumanber);
        }
        group = group->next;
    }
    return 0;
}

int ecr_bwl_compile(ecr_bwl_t *list) {
    int rc;
    ecr_bwl_data_t *data;
    pthread_mutex_lock(&list->lock);
    rc = ecr_bwl_compile_0(list->next_data, 1);
    if (rc == 0) {
        data = list->data;
        list->data = list->next_data;
        list->next_data = list->tmp_data;
        list->tmp_data = data;
        list->version++;
    }
    pthread_mutex_unlock(&list->lock);
    return rc;
}

int ecr_bwl_reload_0(ecr_bwl_t *list, int force) {
    ecr_bwl_data_t *data;
    int rc;
    if (force) {
        pthread_mutex_lock(&list->lock);
    } else {
        if (pthread_mutex_trylock(&list->lock)) {
            return -1;
        }
    }
    ecr_bwl_data_clear(list->tmp_data);
    ecr_bwl_data_clear(list->next_data); // free memory
    ecr_bwl_data_copy(list->data, list->tmp_data);
    rc = ecr_bwl_compile_0(list->tmp_data, force);
    if (rc == 0) {
        data = list->data;
        list->data = list->tmp_data;
        list->tmp_data = data;
        list->version++;
    }
    pthread_mutex_unlock(&list->lock);
    return rc;
}

int ecr_bwl_reload(ecr_bwl_t *list) {
    return ecr_bwl_reload_0(list, 1);
}

int ecr_bwl_check(ecr_bwl_t *list) {
    return ecr_bwl_reload_0(list, 0);
}

int ecr_bwl_init(ecr_bwl_t *list, ecr_bwl_opt_t *opt) {
    memset(list, 0, sizeof(ecr_bwl_t));

    if (opt) {
        if (opt->basepath) {
            list->opts.basepath = strdup(opt->basepath);
        }
        if (opt->mongo_pool) {
            list->opts.mongo_pool = opt->mongo_pool;
        }
        if (opt->fixedhash_ctx) {
            list->opts.fixedhash_ctx = opt->fixedhash_ctx;
        }
        if (opt->log_handler) {
            list->opts.log_handler = opt->log_handler;
        }
        if (opt->cfile_pwd) {
            list->opts.cfile_pwd = strdup(opt->cfile_pwd);
        }
    }

    pthread_mutex_init(&list->lock, NULL);
    list->data = ecr_bwl_data_new(list);
    list->tmp_data = ecr_bwl_data_new(list);
    list->next_data = ecr_bwl_data_new(list);
    return 0;
}

void ecr_bwl_destroy(ecr_bwl_t *list) {
    ecr_bwl_data_destroy(list->data);
    ecr_bwl_data_destroy(list->tmp_data);
    ecr_bwl_data_destroy(list->next_data);
    free_to_null(list->opts.basepath);
    free_to_null(list->opts.cfile_pwd);
    pthread_mutex_destroy(&list->lock);
}

static int ecr_bwl_remove_0(ecr_bwl_data_t *data, int id) {
    int i, rc = -1;
    ecr_bwl_source_t *source;
    for (i = 0; i < ecr_list_size(&data->source_list); i++) {
        source = ecr_list_get(&data->source_list, i);
        if (source->id == id) {
            ecr_list_remove_at(&data->source_list, i);
            ecr_bwl_source_free(source);
            rc = 0;
            break;
        }
    }
    return rc;
}

int ecr_bwl_add(ecr_bwl_t *list, const char *source, ecr_bwl_logic_t logic, void *user, int *id_out) {
    ecr_bwl_source_t *bwsource;
    ecr_bwl_data_t *data;

    if (logic != BWL_AND && logic != BWL_OR) {
        ecr_bwl_log(list, LOG_ERR, "invalid logic: %d", logic);
        return -1;
    }

    bwsource = calloc(1, sizeof(ecr_bwl_source_t));
    bwsource->logic = logic;
    bwsource->user = user;

    if (strncmp(source, ECR_BWL_SOURCE_FILE, strlen(ECR_BWL_SOURCE_FILE)) == 0) {
        bwsource->source_type = BWL_FILE;
        bwsource->source = strdup(source + strlen(ECR_BWL_SOURCE_FILE));
    } else if (strncmp(source, ECR_BWL_SOURCE_CFILE, strlen(ECR_BWL_SOURCE_CFILE)) == 0) {
        bwsource->source_type = BWL_CFILE;
        bwsource->source = strdup(source + strlen(ECR_BWL_SOURCE_CFILE));
    } else if (strncmp(source, ECR_BWL_SOURCE_MONGODB, strlen(ECR_BWL_SOURCE_MONGODB)) == 0) {
        bwsource->source_type = BWL_MONGO;
        bwsource->source = strdup(source + strlen(ECR_BWL_SOURCE_MONGODB));
    } else if (strncmp(source, ECR_BWL_SOURCE_STRING, strlen(ECR_BWL_SOURCE_STRING)) == 0) {
        bwsource->source_type = BWL_STRING;
        bwsource->source = strdup(source + strlen(ECR_BWL_SOURCE_STRING));
    } else {
        ecr_bwl_log(list, LOG_ERR, "invalid source: %s", source);
        free(bwsource);
        return -1;
    }

    pthread_mutex_lock(&list->lock);
    data = list->next_data;
    if (data->next_sid == 1) {
        ecr_bwl_data_copy(list->data, data);
    }
    if (id_out && *id_out) {
        bwsource->id = *id_out;
        ecr_bwl_remove_0(data, *id_out);
    } else {
        bwsource->id = data->next_sid++;
        if (id_out) {
            *id_out = bwsource->id;
        }
    }
    ecr_list_add(&data->source_list, bwsource);
    pthread_mutex_unlock(&list->lock);
    return 0;
}

int ecr_bwl_remove(ecr_bwl_t *list, int id) {
    int rc = -1;
    ecr_bwl_data_t *data;

    pthread_mutex_lock(&list->lock);
    data = list->next_data;
    if (data->next_sid == 1) {
        ecr_bwl_data_copy(list->data, data);
    }
    ecr_bwl_remove_0(data, id);
    pthread_mutex_unlock(&list->lock);
    return rc;
}

ecr_bwl_result_t * ecr_bwl_result_init_mem(ecr_bwl_t *list, void *mem) {
    ecr_bwl_result_t *ret;
    char *chmem = mem;

    ret = mem;
    chmem += sizeof(ecr_bwl_result_t);
    ret->exprs.ptr = chmem;
    chmem += (ret->exprs.len = list->data->next_expr_id);
    ret->sources.ptr = chmem;
    chmem += (ret->users_size = ret->sources.len = list->data->next_sid);
    ret->users = (void**) chmem;
    chmem += ret->users_size * sizeof(void*);
    ret->expr_items = (ecr_str_t**) chmem;
    ret->version = list->version;

    return ret;
}

ecr_bwl_result_t * ecr_bwl_result_init(ecr_bwl_t *list) {
    ecr_bwl_result_t *ret = calloc(1, sizeof(ecr_bwl_result_t));
    ret->exprs.len = list->data->next_expr_id;
    ret->exprs.ptr = calloc(1, ret->exprs.len);
    ret->users_size = ret->sources.len = list->data->next_sid;
    ret->sources.ptr = calloc(1, ret->sources.len);
    ret->users = calloc(ret->users_size, sizeof(void*));
    ret->expr_items = calloc(ret->exprs.len, sizeof(ecr_str_t*));
    ret->version = list->version;
    return ret;
}

void ecr_bwl_result_clear(ecr_bwl_result_t *result) {
    memset(result->sources.ptr, 0, result->sources.len);
    memset(result->exprs.ptr, 0, result->exprs.len);
    memset(result->users, 0, result->users_size * sizeof(void*));
    memset(result->expr_items, 0, result->exprs.len * sizeof(ecr_str_t*));
}

void ecr_bwl_result_destroy(ecr_bwl_result_t *result) {
    free(result->users);
    free(result->sources.ptr);
    free(result->exprs.ptr);
    free(result->expr_items);
    free(result);
}

static inline void ecr_bwl_add_matched(ecr_bwl_result_t *result, ecr_list_t *users, ecr_str_t *item) {
    int i, expr_id;
    size_t size;

    size = ecr_list_size(users);
    for (i = 0; i < size; i++) {
        expr_id = ((ecr_bwl_user_t*) users->data[i])->expr_id;
        result->exprs.ptr[expr_id] = 1;
        result->expr_items[expr_id] = item;
    }
}

static int ecr_bwl_wm_match_handler(ecr_wm_t *wm, const char *str, size_t len, ecr_wm_pattern_t *pattern, void *user) {
    ecr_bwl_result_t *results = user;
    ecr_bwl_add_matched(results, &pattern->users, &pattern->pattern);
    return 0;
}

static void ecr_bwl_match_one(ecr_bwl_group_t *group, ecr_str_t *hdr, ecr_bwl_result_t *results) {
    ecr_list_t *users;
    ecr_hashmap_iter_t it;
    ecr_bwl_regex_t *reg;

    switch (group->type) {
    case BWL_EQUALS:
        if ((users = ecr_hashmap_get(&group->items.equals, hdr->ptr, hdr->len)) != NULL) {
            ecr_bwl_add_matched(results, users, hdr);
        }
        break;
    case BWL_WUMANBER:
        ecr_wm_match_ex(&group->items.wumanber, hdr->ptr, hdr->len, ecr_bwl_wm_match_handler, results);
        break;
    case BWL_EXISTS:
        ecr_bwl_add_matched(results, &group->items.exists, NULL);
        break;
    case BWL_REGEX:
        ecr_hashmap_iter_init(&it, &group->items.regex);
        while (ecr_hashmap_iter_next(&it, (void **) &reg, NULL, (void**) &users) == 0) {
            if (regexec(&reg->regex, hdr->ptr, 0, NULL, 0) == 0) {
                ecr_bwl_add_matched(results, users, &reg->pattern);
            }
        }
        break;
    default:
        break;
    }
}

int ecr_bwl_matches_fixed(ecr_bwl_t *list, ecr_fixedhash_t *hash, ecr_bwl_result_t *result) {
    ecr_bwl_group_t *group;
    ecr_str_t *hdr;
    ecr_bwl_source_data_t *source_data;
    int n;
    ecr_bwl_data_t *data;

    if (!list->opts.fixedhash_ctx) {
        ecr_bwl_log(list, LOG_ERR, "no fixedhash context specified.");
        return -1;
    }

    data = list->data;

    if (result->version != list->version) {
        return -1;
    }

    group = data->groups;
    while (group) {
        if ((hdr = ecr_fixedhash_get(hash, group->name_key)) != NULL) {
            ecr_bwl_match_one(group, hdr, result);
        }
        group = group->next;
    }
    n = 0;
    source_data = data->source_data;
    while (source_data) {
        if (source_data->expr && ecr_bwl_expr_eval(source_data->expr, result)) {
            n++;
            result->sources.ptr[source_data->id] = 1;
            result->users[source_data->id] = source_data->user;
        }
        source_data = source_data->next;
    }
    return n;
}

void ecr_bwl_dump(ecr_bwl_t *list, FILE *stream) {
    ecr_bwl_data_t *data;
    ecr_bwl_source_data_t *source_data;
    ecr_bwl_group_t *group;
    ecr_bwl_user_t *user;
    ecr_hashmap_iter_t iter;
    char *expr_user_key;
    size_t size;

    data = list->data;

    fprintf(stream, "=== b/w list dump begin ===\n");
    fprintf(stream, "\n--- groups ---\n");
    group = data->groups;
    while (group) {
        switch (group->type) {
        case BWL_EQUALS:
            size = ecr_hashmap_size(&group->items.equals);
            break;
        case BWL_WUMANBER:
            size = group->items.wumanber.plist_size;
            break;
        case BWL_EXISTS:
            size = 0;
            break;
        case BWL_REGEX:
            size = ecr_hashmap_size(&group->items.regex);
            break;
        default:
            size = 0;
            break;
        }
        fprintf(stream, "%s %s: %lu\n", group->name.ptr, ecr_bwl_type_to_string(group->type), size);
        group = group->next;
    }

    fprintf(stream, "\n--- expression id map ---\n");
    ecr_hashmap_iter_init(&iter, &data->user_map);
    while (ecr_hashmap_iter_next(&iter, (void*) &expr_user_key, NULL, (void**) &user) == 0) {
        fprintf(stream, "%d:\t{group=[%s], user=%p}\n", user->expr_id, expr_user_key, user->user);
    }

    fprintf(stream, "\n--- expressions ---\n");
    source_data = data->source_data;
    while (source_data) {
        fprintf(stream, "expression of %s:[%d]\n", source_data->source->source, source_data->id);
        ecr_bwl_expr_dump(source_data->expr, stream);
        fprintf(stream, "\n\n");
        source_data = source_data->next;
    }
    fprintf(stream, "=== b/w list dump end ===\n");
}
