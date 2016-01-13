/*
 * ecr_template.h
 *
 *  Created on: Sep 9, 2015
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_TEMPLATE_H_
#define SRC_ECR_ECR_TEMPLATE_H_

#include "ecrconf.h"
#include "ecr_fixedhashmap.h"
#include <stdio.h>

typedef int (*ecr_template_handler)(FILE *stream, const char *data, size_t size);

typedef enum {
    ecr_template_var, ecr_template_func
} ecr_template_type_t;

typedef struct {
    ecr_fixedhash_ctx_t *var_hash_ctx;
    ecr_hashmap_t *func_handler_map;
} ecr_template_config_t;

typedef struct ecr_template_s {
    ecr_str_t value;
    ecr_template_type_t type;
    union {
        ecr_fixedhash_key_t var_key;
        ecr_template_handler func_handler;
    };
    struct ecr_template_s *inner;
    struct ecr_template_s *next;
} ecr_template_t;

ecr_template_t * ecr_template_init(ecr_template_config_t *config, const char *text);

int ecr_template_process(ecr_template_t *template, FILE *stream);

#endif /* SRC_ECR_ECR_TEMPLATE_H_ */
