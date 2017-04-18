/*
 * ecr_template.h
 *
 *  Created on: Sep 9, 2015
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_TEMPLATE_H_
#define SRC_ECR_ECR_TEMPLATE_H_

#include "ecrconf.h"
#include "ecr_list.h"
#include <stdio.h>

#define ECR_TEMPLATE_VAR_END    {0, NULL, NULL}
#define ECR_TEMPLATE_FUNC_END    {0, NULL, NULL}

typedef struct ecr_template_var_s ecr_template_var_t;
typedef struct ecr_template_func_s ecr_template_func_t;
typedef struct ecr_template_s ecr_template_t;

typedef int (*ecr_template_text_handler)(FILE *stream, void *data, ecr_str_t *text);
typedef int (*ecr_template_var_handler)(FILE *stream, void *data, ecr_template_var_t *var);
typedef int (*ecr_template_func_handler)(FILE *stream, void *data, ecr_template_func_t *func, int argc,
        const char**argv, ecr_template_t *body);

typedef struct {
    ecr_template_text_handler text_handler;
    ecr_list_t vars;
    ecr_list_t funcs;
} ecr_template_context_t;

struct ecr_template_var_s {
    int id;
    char *name;
    ecr_template_var_handler handler;
};

struct ecr_template_func_s {
    int id;
    char *name;
    ecr_template_func_handler handler;
};

typedef enum {
    ECR_TEMPLATE_TEXT, ECR_TEMPLATE_VAR, ECR_TEMPLATE_FUNC
} ecr_template_type_t;

struct ecr_template_s {
    ecr_template_context_t *context;
    FILE *stream;
    ecr_str_t stream_data;
    ecr_str_t string;
    ecr_template_type_t type;
    union {
        ecr_str_t text;
        ecr_template_var_t *var;
        struct {
            ecr_template_func_t *func;
            ecr_list_t args;
            struct ecr_template_s *body;
        } func;
    };
    struct ecr_template_s *next;
    struct ecr_template_s *prev;
};

int ecr_template_context_init(ecr_template_context_t *ctx, ecr_template_text_handler text_handler);

int ecr_template_context_reg_var(ecr_template_context_t *ctx, const char *name, ecr_template_var_handler handler);

int ecr_template_context_reg_func(ecr_template_context_t *ctx, const char *name, ecr_template_func_handler handler);

ecr_template_t * ecr_template_new(ecr_template_context_t *ctx, const char *text, char *errbuf, size_t errbuf_size);

int ecr_template_write(ecr_template_t *template, FILE *stream, void *data);

int ecr_template_to_bytes(ecr_template_t *template, ecr_str_t *bytes_out, void *data);

void ecr_template_destroy(ecr_template_t *template);

void ecr_template_context_destroy(ecr_template_context_t *ctx);

#endif /* SRC_ECR_ECR_TEMPLATE_H_ */
