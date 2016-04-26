/*
 * ecr_config.c
 *
 *  Created on: Nov 19, 2012
 *      Author: velna
 */

#include "config.h"
#include "ecr_config.h"
#include "ecr_logger.h"
#include "ecr_util.h"
#include "ecr_hashmap.h"
#include <string.h>
#include <stdlib.h>

static int ecr_str_to_number(const char * value, enum ecr_config_type t, void * out) {
    int m = 1;
    size_t len = strlen(value);
    char ch = value[len - 1];
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
    switch (t) {
    case ECR_CFG_INT:
    case ECR_CFG_INT32:
        *((int*) out) = (int) (strtol(value, NULL, 0) * m);
        break;
    case ECR_CFG_UINT32:
        *((u_int32_t*) out) = (u_int32_t) (strtoul(value, NULL, 0) * m);
        break;
    case ECR_CFG_INT64:
        *((int64_t*) out) = (int64_t) (strtoll(value, NULL, 0) * m);
        break;
    case ECR_CFG_UINT64:
        *((u_int64_t*) out) = (u_int64_t) (strtouq(value, NULL, 0) * m);
        break;
    case ECR_CFG_FLOAT:
        *((float*) out) = strtof(value, NULL) * m;
        break;
    case ECR_CFG_DOUBLE:
        *((double*) out) = strtod(value, NULL) * m;
        break;
    default:
        return -1;
    }
    return 0;
}

int ecr_config_init_str(ecr_config_t *cfg, const char *str) {
    ecr_config_value_t *cvalue;
    char *ss = NULL, *name, *value;
    char *s;
    int rc = 0;

    ecr_hashmap_init(&cfg->properties, 16, 0);
    if (!str) {
        return 0;
    }
    s = strdup(str);
    name = strtok_r(s, ", &", &ss);
    while (name) {
        if ((value = strchr(name, '='))) {
            value[0] = '\0';
            value = strdup(value + 1);
        } else {
            value = strdup("1");
        }
        cvalue = calloc(1, sizeof(ecr_config_value_t));
        cvalue->value = value;
        cvalue = ecr_hashmap_put(&cfg->properties, name, strlen(name) + 1, cvalue);
        if (cvalue) {
            free_to_null(cvalue->value);
            free_to_null(cvalue);
        }
        name = strtok_r(NULL, ", &", &ss);
    }
    free(s);

    return rc;
}

void ecr_config_print(FILE *out, ecr_config_line_t *lines) {
    int i = 0;
    ecr_config_line_t * config_lines = (ecr_config_line_t*) lines;

    while (config_lines[i].name != NULL) {
        switch (config_lines[i].type) {
        case ECR_CFG_CHAR:
            fprintf(out, "%s=%c\n", config_lines[i].name, *((char*) config_lines[i].value));
            break;
        case ECR_CFG_INT:
        case ECR_CFG_INT32:
            fprintf(out, "%s=%d\n", config_lines[i].name, *((int32_t*) config_lines[i].value));
            break;
        case ECR_CFG_UINT32:
            fprintf(out, "%s=%u\n", config_lines[i].name, *((u_int32_t*) config_lines[i].value));
            break;
        case ECR_CFG_INT64:
            fprintf(out, "%s=%ld\n", config_lines[i].name, *((int64_t*) config_lines[i].value));
            break;
        case ECR_CFG_UINT64:
            fprintf(out, "%s=%lu\n", config_lines[i].name, *((u_int64_t*) config_lines[i].value));
            break;
        case ECR_CFG_FLOAT:
            fprintf(out, "%s=%f\n", config_lines[i].name, *((float*) config_lines[i].value));
            break;
        case ECR_CFG_DOUBLE:
            fprintf(out, "%s=%f\n", config_lines[i].name, *((double*) config_lines[i].value));
            break;
        case ECR_CFG_STRING:
            fprintf(out, "%s=%s\n", config_lines[i].name, *((char**) config_lines[i].value));
            break;
        case ECR_CFG_POINTER:
            fprintf(out, "%s=%p\n", config_lines[i].name, *((void**) config_lines[i].value));
            break;
        }
        i++;
    }
    fflush(out);
}

static int ecr_config_load_file(ecr_config_t *cfg, const char *cfg_file) {
    FILE *file;
    char *line = NULL, *name, *value, *s;
    ecr_str_t line0 = { 0 };
    int lineno = 0, line_len, rc = 0;
    ecr_config_value_t *cvalue;
    size_t n = 0, i;

    file = fopen(cfg_file, "r");
    if (NULL == file) {
        L_ERROR("Cannot open config file [%s] !", cfg_file);
        return -1;
    }

    while (getline(&line, &n, file) != -1) {
        lineno++;
        line_len = strlen(line);

        if (!line0.ptr) {
            line0.len = line_len;
            line0.ptr = malloc(line0.len + 1);
        } else if (line0.len < line_len) {
            line0.len = line_len;
            line0.ptr = realloc(line0.ptr, line0.len + 1);
        }
        strcpy(line0.ptr, line);
        s = NULL;
        i = strspn(line0.ptr, " =\t\r\n");
        name = line0.ptr + i;
        i = strcspn(name, " =\t\r\n");
        name[i] = '\0';
        if (name[0] == '\0' || name[0] == '#') {
            continue;
        }

        value = name + i + 1;
        i = strspn(value, " =\t\r\n");
        value = ecr_str_trim(value + i);
        if (value[0] == '\0') {
            L_ERROR("Error parse config file[%s] at line %d(len %d): [%s]", cfg_file, lineno, line_len, line);
            rc = -1;
            goto end;
        }

        if (strcmp(name, "@include") == 0) {
            if (ecr_config_load_file(cfg, value)) {
                rc = -1;
                goto end;
            }
        } else {
            cvalue = calloc(1, sizeof(ecr_config_value_t));
            cvalue->value = strdup(value);
            cvalue = ecr_hashmap_put(&cfg->properties, name, strlen(name) + 1, cvalue);
            if (cvalue) {
                free_to_null(cvalue->value);
                free_to_null(cvalue);
            }
        }
    }
    end: {
        free_to_null(line0.ptr);
        free_to_null(line);
        if (file) {
            fclose(file);
        }
    }
    return rc;

}

int ecr_config_init(ecr_config_t *cfg, const char *cfg_file) {
    ecr_hashmap_init(&cfg->properties, 16, 0);
    return ecr_config_load_file(cfg, cfg_file);
}

char ** ecr_config_names(ecr_config_t *cfg) {
    ecr_hashmap_iter_t iter;
    char **ret, *name;
    int i = 0;

    ret = calloc(ecr_hashmap_size(&cfg->properties) + 1, sizeof(char*));
    ecr_hashmap_iter_init(&iter, &cfg->properties);
    while (ecr_hashmap_iter_next(&iter, (void**) &name, NULL, NULL) == 0) {
        ret[i] = name;
    }
    return ret;
}

int ecr_config_get0(ecr_config_t *cfg, const char *group, const char *name, enum ecr_config_type type, void *value_out) {
    int rc = -1;
    char *key, *value;
    ecr_config_value_t *cvalue;

    if (group) {
        asprintf(&key, "%s.%s", group, name);
    } else {
        key = strdup(name);
    }
    if ((cvalue = ecr_hashmap_get(&cfg->properties, key, strlen(key) + 1)) != NULL) {
        rc = 0;
        value = cvalue->value;
        switch (type) {
        case ECR_CFG_INT:
        case ECR_CFG_INT32:
        case ECR_CFG_UINT32:
        case ECR_CFG_INT64:
        case ECR_CFG_UINT64:
        case ECR_CFG_FLOAT:
        case ECR_CFG_DOUBLE:
            ecr_str_to_number(value ? value : "0", type, value_out);
            break;
        case ECR_CFG_CHAR:
            if (value) {
                *((char *) value_out) = *value;
            } else {
                *((char *) value_out) = 0;
            }
            break;
        case ECR_CFG_STRING:
            *((char **) value_out) = value;
            break;
        case ECR_CFG_POINTER:
            *((const void **) value_out) = cvalue->pointer;
            break;
        default:
            L_ERROR("unknown type:", type);
            rc = -1;
            break;
        }
        if (rc == 0) {
            cvalue->used = 1;
        }
    }
    free(key);
    return rc;
}

int ecr_config_get(ecr_config_t *cfg, const char *group, const char *name, enum ecr_config_type type, void *value_out) {
    return ecr_config_get0(cfg, group, name, type, value_out);
}

int ecr_config_put(ecr_config_t *cfg, const char *group, const char *name, enum ecr_config_type type, const void *value) {
    char *key;
    ecr_config_value_t *cvalue = calloc(1, sizeof(ecr_config_value_t));
    switch (type) {
    case ECR_CFG_INT:
    case ECR_CFG_INT32:
        asprintf(&cvalue->value, "%d", *((int32_t*) value));
        break;
    case ECR_CFG_UINT32:
        asprintf(&cvalue->value, "%u", *((uint32_t*) value));
        break;
    case ECR_CFG_INT64:
        asprintf(&cvalue->value, "%ld", *((int64_t*) value));
        break;
    case ECR_CFG_UINT64:
        asprintf(&cvalue->value, "%lu", *((uint64_t*) value));
        break;
    case ECR_CFG_FLOAT:
        asprintf(&cvalue->value, "%f", *((float*) value));
        break;
    case ECR_CFG_DOUBLE:
        asprintf(&cvalue->value, "%f", *((double*) value));
        break;
    case ECR_CFG_CHAR:
        asprintf(&cvalue->value, "%c", *((char*) value));
        break;
    case ECR_CFG_STRING:
        cvalue->value = strdup((const char *) value);
        break;
    case ECR_CFG_POINTER:
        cvalue->pointer = value;
        break;
    default:
        return -1;
    }
    if (group) {
        asprintf(&key, "%s.%s", group, name);
    } else {
        key = strdup(name);
    }
    cvalue = ecr_hashmap_put(&cfg->properties, key, strlen(key) + 1, cvalue);
    if (cvalue) {
        free_to_null(cvalue->value);
        free_to_null(cvalue);
    }
    free_to_null(key);
    return 0;
}

int ecr_config_load(ecr_config_t *cfg, const char *group, ecr_config_line_t *config_lines) {
    int i;

    i = 0;
    while (config_lines[i].name != NULL) {
        if (ecr_config_get0(cfg, group, config_lines[i].name, config_lines[i].type, config_lines[i].value)) {
            switch (config_lines[i].type) {
            case ECR_CFG_INT:
                *((int*) config_lines[i].value) = config_lines[i].dv.i;
                break;
            case ECR_CFG_INT32:
                *((int32_t*) config_lines[i].value) = config_lines[i].dv.i32;
                break;
            case ECR_CFG_UINT32:
                *((u_int32_t*) config_lines[i].value) = config_lines[i].dv.u32;
                break;
            case ECR_CFG_INT64:
                *((int64_t*) config_lines[i].value) = config_lines[i].dv.i64;
                break;
            case ECR_CFG_UINT64:
                *((u_int64_t*) config_lines[i].value) = config_lines[i].dv.u64;
                break;
            case ECR_CFG_FLOAT:
                *((float*) config_lines[i].value) = config_lines[i].dv.f;
                break;
            case ECR_CFG_DOUBLE:
                *((double*) config_lines[i].value) = config_lines[i].dv.d;
                break;
            case ECR_CFG_CHAR:
                *((char*) config_lines[i].value) = config_lines[i].dv.ch;
                break;
            case ECR_CFG_STRING:
                *((char**) config_lines[i].value) = config_lines[i].dv.s;
                break;
            case ECR_CFG_POINTER:
                *((void**) config_lines[i].value) = config_lines[i].dv.ptr;
                break;
            default:
                L_ERROR("unknown type:", config_lines[i].type);
                return -1;
            }
        }
        i++;
    }
    return 0;
}

int ecr_config_print_unused(FILE *out, ecr_config_t *cfg) {
    ecr_hashmap_iter_t i;
    char *name;
    ecr_config_value_t *value;
    int c = 0;

    ecr_hashmap_iter_init(&i, &cfg->properties);
    while (ecr_hashmap_iter_next(&i, (void**) &name, NULL, (void**) &value) == 0) {
        if (!value->used) {
            c++;
            if (out) {
                fprintf(out, "%s=%s", name, value->value);
            } else {
                L_WARN("unknown config: %s=%s", name, value->value);
            }
        }
    }
    return c;
}

static void ecr_config_free_value_handler(ecr_hashmap_t *in, void * key, size_t key_size, void * value) {
    ecr_config_value_t *cvalue = (ecr_config_value_t*) value;
    free_to_null(cvalue->value);
    free_to_null(cvalue);
}

void ecr_config_destroy(ecr_config_t *cfg) {
    ecr_hashmap_destroy(&cfg->properties, ecr_config_free_value_handler);
}
