/*
 * hm_loader.c
 *
 *  Created on: Aug 8, 2017
 *      Author: velna
 */

#include "config.h"
#include "hm_loader.h"
#include "ecr_util.h"

#include <stdlib.h>
#include <string.h>

void ecr_hm_source_data_add_value(ecr_hm_source_data_t *source_data, const char *var_name, const char *value) {
    ecr_list_t *values = ecr_hm_source_data_get_values(source_data, var_name);
    ecr_list_add(values, strdup(value));
}

ecr_list_t* ecr_hm_source_data_get_values(ecr_hm_source_data_t *source_data, const char *var_name) {
    ecr_list_t *values;
    values = ecr_hashmap_get(&source_data->values, var_name, strlen(var_name));
    if (!values) {
        values = ecr_list_new(4);
        ecr_hashmap_put(&source_data->values, var_name, strlen(var_name), values);
    }
    return values;
}

void ecr_hm_source_data_add_expr(ecr_hm_source_data_t *source_data, const char *expr) {
    ecr_hashmap_put(&source_data->expr_set, expr, strlen(expr), NULL);
}

int ecr_hm_load_from_stream(ecr_hm_source_t *source, FILE *stream, ecr_hm_source_data_t *source_data) {
    char *line, *oline, *token, *save, *name, *value, *expr, *var_name, *matcher_name;
    size_t len;
    ssize_t nread;
    int rc, frc, ln, next_var_id = 0;
    ecr_hm_matcher_reg_t *matcher_reg;
    ecr_uri_t uri;
    ecr_hm_loader_t *loader;

    len = 256;
    line = calloc(1, len);
    rc = 0;
    ln = 0;
    oline = name = value = var_name = NULL;
    while ((nread = getline(&line, &len, stream)) > 0) {
        ln++;
        if (nread == 0 || line[0] == '#' || line[0] == '\n' || (nread > 1 && line[0] == '\r' && line[1] == '\n')) {
            continue;
        }
        value = ecr_str_trim(line);
        free_to_null(oline);
        oline = strdup(value);
        if (isblank(line[0])) {
            if (!var_name) {
                rc = -1;
                ecr_hm_error(source->hm, "syntax error at line %d: [%s].", ln, oline);
                break;
            }
            ecr_hm_source_data_add_value(source_data, var_name, value);
            rc++;
        } else if (line[0] == '@') {
            if (strlen(value) == 1) {
                rc = -1;
                ecr_hm_error(source->hm, "syntax error at line %d: [%s].", ln, oline);
                break;
            }
            ecr_hm_source_data_add_expr(source_data, value);
        } else {
            name = strtok_r(line, " \t\n\r", &save);
            if (!name) {
                rc = -1;
                ecr_hm_error(source->hm, "syntax error at line %d: [%s].", ln, oline);
                break;
            }
            free_to_null(var_name);
            if (name[0] == '$') {
                if (strlen(name) == 1) {
                    rc = -1;
                    ecr_hm_error(source->hm, "syntax error, empty variable name at line %d: [%s].", ln, oline);
                    break;
                }
                var_name = strdup(name);
            } else {
                matcher_name = strtok_r(NULL, " \t\n\r", &save);
                if (!matcher_name) {
                    rc = -1;
                    ecr_hm_error(source->hm, "syntax error, matcher type expected at line %d: [%s].", ln, oline);
                    break;
                }
                matcher_reg = ecr_hm_get_matcher_reg(source->hm, matcher_name);
                if (!matcher_reg) {
                    rc = -1;
                    ecr_hm_error(source->hm, "syntax error, unkown matcher type at line %d: [%s].", ln, oline);
                    break;
                }
                if (matcher_reg->has_values) {
                    asprintf(&var_name, "#$var_%d", ++next_var_id);
                    asprintf(&expr, "@%s %s %s", name, matcher_name, var_name);
                } else {
                    rc++;
                    asprintf(&expr, "@%s %s", name, matcher_name);
                }
                ecr_hm_source_data_add_expr(source_data, expr);
                free(expr);
            }
            token = strtok_r(NULL, " \t\n\r", &save);
            if (token && var_name) {
                if (ecr_uri_init(&uri, token)) {
                    rc = -1;
                    ecr_hm_error(source->hm, "syntax error, invalid uri at line %d: [%s].", ln, oline);
                    break;
                }
                loader = ecr_hm_find_loader(source->hm, uri.scheme ? uri.scheme : source->uri.scheme);
                if (!loader) {
                    ecr_uri_destroy(&uri);
                    rc = -1;
                    ecr_hm_error(source->hm, "can not find loader at line %d: [%s].", ln, oline);
                    break;
                }
                frc = loader->load_values(source, &uri, ecr_hm_source_data_get_values(source_data, var_name));
                ecr_uri_destroy(&uri);
                if (-1 == frc) {
                    rc = -1;
                    break;
                }
                rc += frc;
            }
        }
    }
    free_to_null(oline);
    free_to_null(var_name);
    free_to_null(line);
    return rc;
}

int ecr_hm_load_values_from_stream(ecr_hm_source_t *source, FILE *stream, ecr_list_t *values) {
    char *line, *value;
    int n;
    size_t len;
    ssize_t nread;

    n = 0;
    len = 256;
    line = calloc(1, len);
    while ((nread = getline(&line, &len, stream)) > 0) {
        if (nread == 0 || line[0] == '#' || line[0] == '\n' || (nread > 1 && line[0] == '\r' && line[1] == '\n')) {
            continue;
        }
        value = ecr_str_trim(line);
        ecr_list_add(values, strdup(value));
        n++;
    }
    free_to_null(line);
    return n;
}
