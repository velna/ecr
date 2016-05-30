/*
 * ecr_config.h
 *
 *  Created on: Nov 16, 2012
 *      Author: velna
 */

#ifndef ECR_CONFIG_H_
#define ECR_CONFIG_H_

#include "ecrconf.h"
#include "ecr_hashmap.h"
#include <stdio.h>

#define CFG_REQUIRED        0x1
#define _CFG_VALUE_SET      0x10000
#define _CFG_USE_DEFAULT    0x20000

//#define CFG_VAR_PREFIX &my_ctx.config
#define CFG_MAKE_LINE_START(v)      ecr_config_line_t v[] = {
#define CFG_MAKE_LINE(f, type, ...) { #f, CFG_VAR_PREFIX.f, type, ##__VA_ARGS__ },
#define CFG_MAKE_LINE_END()         { 0 } };
//#undef CFG_VAR_PREFIX

enum ecr_config_type {
    ECR_CFG_INT = 0,
    ECR_CFG_CHAR,
    ECR_CFG_INT32,
    ECR_CFG_UINT32,
    ECR_CFG_INT64,
    ECR_CFG_UINT64,
    ECR_CFG_FLOAT,
    ECR_CFG_DOUBLE,
    ECR_CFG_STRING,
    ECR_CFG_POINTER
};

typedef struct {
    char *name;
    void *value;
    enum ecr_config_type type;
    union {
        int i;
        int32_t i32;
        uint32_t u32;
        int64_t i64;
        uint64_t u64;
        float f;
        double d;
        char ch;
        char *s;
        void *ptr;
    } dv;
} ecr_config_line_t;

typedef struct {
    char *value;
    const void *pointer;
    char used;
} ecr_config_value_t;

typedef struct {
    ecr_hashmap_t properties;
} ecr_config_t;

int ecr_config_init(ecr_config_t *cfg, const char *cfg_file);

int ecr_config_init_str(ecr_config_t *cfg, const char *str);

int ecr_config_get(ecr_config_t *cfg, const char *group, const char *name, enum ecr_config_type type, void *value_out);

int ecr_config_put(ecr_config_t *cfg, const char *group, const char *name, enum ecr_config_type type, const void *value);

char ** ecr_config_names(ecr_config_t *cfg);

int ecr_config_load(ecr_config_t *cfg, const char *group, ecr_config_line_t *lines);

void ecr_config_print(FILE *out, ecr_config_line_t *config_lines);

int ecr_config_print_unused(FILE *out, ecr_config_t *cfg);

void ecr_config_destroy(ecr_config_t *cfg);

#endif /* ECR_CONFIG_H_ */
