/*
 * ecr_template.c
 *
 *  Created on: Sep 9, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_template.h"
#include "ecr_util.h"
#include <string.h>
#include <stdlib.h>

int ecr_template_context_init(ecr_template_context_t *ctx, ecr_template_text_handler text_handler) {
    memset(ctx, 0, sizeof(ecr_template_context_t));
    ctx->text_handler = text_handler;
    ecr_list_init(&ctx->vars, 16);
    ecr_list_init(&ctx->funcs, 16);
    return 0;
}

int ecr_template_context_reg_var(ecr_template_context_t *ctx, const char *name, ecr_template_var_handler handler) {
    ecr_template_var_t *var = calloc(1, sizeof(ecr_template_var_t));
    var->id = ecr_list_size(&ctx->vars);
    var->name = strdup(name);
    var->handler = handler;
    ecr_list_add(&ctx->vars, var);
    return var->id;
}

int ecr_template_context_reg_func(ecr_template_context_t *ctx, const char *name, ecr_template_func_handler handler) {
    ecr_template_func_t *func = calloc(1, sizeof(ecr_template_func_t));
    func->id = ecr_list_size(&ctx->funcs);
    func->name = strdup(name);
    func->handler = handler;
    ecr_list_add(&ctx->funcs, func);
    return func->id;
}

int ecr_template_func_add_param(ecr_template_t *template, const char *from, size_t n) {
    char *str = strndup(from, n);
    char *s = ecr_str_trim(str);
    ecr_list_add(&template->func.args, strdup(s));
    free(str);
    return 0;
}

ecr_template_t * ecr_template_new_text(ecr_template_context_t *ctx, ecr_str_t *text) {
    ecr_template_t *template;

    template = calloc(1, sizeof(ecr_template_t));
    template->context = ctx;
    template->string.ptr = strndup(text->ptr, text->len);
    template->string.len = text->len;
    template->stream = open_memstream(&template->stream_data.ptr, &template->stream_data.len);
    template->type = ECR_TEMPLATE_TEXT;
    template->text = template->string;
    return template;
}

ecr_template_t * ecr_template_new_func(ecr_template_context_t *ctx, const char *from, size_t n) {
    ecr_template_t *template;
    ecr_template_func_t *func;
    ecr_str_t name = { (char*) from, n };
    int i;

    ecr_string_trim(&name, NULL);
    template = NULL;
    for (i = 0; i < ecr_list_size(&ctx->funcs); i++) {
        func = ecr_list_get(&ctx->funcs, i);
        if (strlen(func->name) == name.len && memcmp(func->name, name.ptr, name.len) == 0) {
            template = calloc(1, sizeof(ecr_template_t));
            template->context = ctx;
            template->string.ptr = strndup(from, n);
            template->string.len = n;
            template->stream = open_memstream(&template->stream_data.ptr, &template->stream_data.len);
            template->type = ECR_TEMPLATE_FUNC;
            template->func.func = func;
            ecr_list_init(&template->func.args, 16);
            break;
        }
    }
    return template;
}

ecr_template_t * ecr_template_new_var(ecr_template_context_t *ctx, const char *from, size_t n) {
    ecr_template_t *template;
    ecr_template_var_t *var;
    ecr_str_t name = { (char*) from, n };
    int i;

    ecr_string_trim(&name, NULL);
    template = NULL;
    for (i = 0; i < ecr_list_size(&ctx->vars); i++) {
        var = ecr_list_get(&ctx->vars, i);
        if (strlen(var->name) == name.len && memcmp(var->name, name.ptr, name.len) == 0) {
            template = calloc(1, sizeof(ecr_template_t));
            template->context = ctx;
            template->string.ptr = strndup(from, n);
            template->string.len = n;
            template->stream = open_memstream(&template->stream_data.ptr, &template->stream_data.len);
            template->type = ECR_TEMPLATE_VAR;
            template->var = var;
            break;
        }
    }
    return template;
}

#define STATUS_INIT             0
#define STATUS_VAR_NAME         1
#define STATUS_PARAM_NAME       2
#define STATUS_FUNC_BODY_START  3
#define STATUS_FUNC_BODY_END    4
#define STATUS_END              5

static ecr_template_t * ecr_template_new_0(ecr_template_context_t *ctx, char **str, char *errbuf, size_t errbuf_size,
        int has_parent) {
    struct {
        ecr_template_t *head;
        ecr_template_t *tail;
    } tpl_list[1] = { { NULL, NULL } };
    ecr_template_t *new_tpl = NULL;
    char ch, last_ch = '\0';
    int status = STATUS_INIT;
    ecr_str_t text;

    text.ptr = *str;
    while ((ch = **str)) {
        switch (status) {
        case STATUS_INIT:
            switch (ch) {
            case '{':
                if (last_ch == '$') {
                    text.len = (*str) - text.ptr - 1;
                    if (text.len) {
                        new_tpl = ecr_template_new_text(ctx, &text);
                        linked_list_add_last(tpl_list, new_tpl);
                    }
                    text.ptr = (*str) + 1;
                    status = STATUS_VAR_NAME;
                }
                break;
            case '}':
                if (has_parent) {
                    text.len = (*str) - text.ptr;
                    new_tpl = ecr_template_new_text(ctx, &text);
                    linked_list_add_last(tpl_list, new_tpl);
                    (*str)--;
                    return tpl_list->head;
                }
                break;
            }
            break;
        case STATUS_END:
            if (ch != '}') {
                snprintf(errbuf, errbuf_size, "expect '}' but find: %s", *str);
                ecr_template_destroy(tpl_list->head);
                return NULL;
            }
            text.ptr = (*str) + 1;
            status = STATUS_INIT;
            break;
        case STATUS_VAR_NAME:
            switch (ch) {
            case '(':
                text.len = (*str) - text.ptr;
                new_tpl = ecr_template_new_func(ctx, text.ptr, text.len);
                if (!new_tpl) {
                    snprintf(errbuf, errbuf_size, "unknown function name at: %s", text.ptr);
                    return NULL;
                }
                linked_list_add_last(tpl_list, new_tpl);
                text.ptr = (*str) + 1;
                status = STATUS_PARAM_NAME;
                break;
            case '}':
                text.len = (*str) - text.ptr;
                new_tpl = ecr_template_new_var(ctx, text.ptr, text.len);
                if (!new_tpl) {
                    snprintf(errbuf, errbuf_size, "unknown var name at: %s", text.ptr);
                    return NULL;
                }
                linked_list_add_last(tpl_list, new_tpl);
                text.ptr = (*str) + 1;
                status = STATUS_INIT;
                break;
            }
            break;
        case STATUS_PARAM_NAME:
            switch (ch) {
            case ',':
            case ')':
                text.len = (*str) - text.ptr;
                if (ecr_template_func_add_param(new_tpl, text.ptr, text.len)) {
                    ecr_template_destroy(tpl_list->head);
                    return NULL;
                }
                text.ptr = (*str) + 1;
                if (ch == ')') {
                    status = STATUS_FUNC_BODY_START;
                }
                break;
            }
            break;
        case STATUS_FUNC_BODY_START:
            if (ch == '{') {
                (*str)++;
                new_tpl->func.body = ecr_template_new_0(ctx, str, errbuf, errbuf_size, 1);
                if (!new_tpl->func.body) {
                    ecr_template_destroy(tpl_list->head);
                    return NULL;
                }
                status = STATUS_FUNC_BODY_END;
            } else if (!isspace(ch)) {
                snprintf(errbuf, errbuf_size, "expect '{', but find: %s", *str);
                ecr_template_destroy(tpl_list->head);
                return NULL;
            }
            break;
        case STATUS_FUNC_BODY_END:
            if (ch == '}') {
                status = STATUS_END;
            } else if (!isspace(ch)) {
                snprintf(errbuf, errbuf_size, "expect '}', but find: %s", *str);
                ecr_template_destroy(tpl_list->head);
                return NULL;
            }
            break;
        }
        last_ch = ch;
        (*str)++;
    }
    if (status != STATUS_INIT) {
        snprintf(errbuf, errbuf_size, "incomplete template.");
        ecr_template_destroy(tpl_list->head);
        return NULL;
    }
    text.len = (*str) - text.ptr;
    if (text.len) {
        new_tpl = ecr_template_new_text(ctx, &text);
        linked_list_add_last(tpl_list, new_tpl);
    }
    return tpl_list->head;
}

ecr_template_t * ecr_template_new(ecr_template_context_t *ctx, const char *str, char *errbuf, size_t errbuf_size) {
    return ecr_template_new_0(ctx, (char**) &str, errbuf, errbuf_size, 0);
}

int ecr_template_to_bytes(ecr_template_t *template, ecr_str_t *bytes_out, void *data) {
    int n;
    rewind(template->stream);
    n = ecr_template_write(template, template->stream, data);
    if (n < 0) {
        return -1;
    }
    fflush(template->stream);
    *bytes_out = template->stream_data;
    return n;
}

int ecr_template_write(ecr_template_t *template, FILE *stream, void *data) {
    ecr_template_t *tpl = template;
    int n = 0, rc;

    while (tpl) {
        rc = 0;
        switch (tpl->type) {
        case ECR_TEMPLATE_TEXT:
            if (tpl->context->text_handler) {
                rc = tpl->context->text_handler(stream, data, &tpl->text);
            }
            break;
        case ECR_TEMPLATE_VAR:
            rc = tpl->var->handler(stream, data, tpl->var);
            break;
        case ECR_TEMPLATE_FUNC:
            rc = tpl->func.func->handler(stream, data, tpl->func.func, (int) tpl->func.args.size,
                    (const char**) tpl->func.args.data, tpl->func.body);
            break;
        default:
            return -1;
        }
        if (rc > 0) {
            n += rc;
        } else if (rc < 0) {
            return -1;
        }
        tpl = tpl->next;
    }

    return n;
}

void ecr_template_destroy(ecr_template_t *template) {
    ecr_template_t *tpl = template;

    while (tpl) {
        free_to_null(tpl->string.ptr);
        if (tpl->type == ECR_TEMPLATE_FUNC) {
            ecr_template_destroy(tpl->func.body);
            free_to_null(tpl->func.body);
            ecr_list_destroy(&tpl->func.args, ecr_list_free_value_handler);
        }
        fclose(tpl->stream);
        free_to_null(tpl->stream_data.ptr);
        tpl = tpl->next;
    }
}

static void ecr_template_free_var_handler(ecr_list_t *l, int i, void* value) {
    ecr_template_var_t *var = value;
    free(var->name);
    free(var);
}

static void ecr_template_free_func_handler(ecr_list_t *l, int i, void* value) {
    ecr_template_func_t *func = value;
    free(func->name);
    free(func);
}

void ecr_template_context_destroy(ecr_template_context_t *ctx) {
    ecr_list_destroy(&ctx->vars, ecr_template_free_var_handler);
    ecr_list_destroy(&ctx->funcs, ecr_template_free_func_handler);
}
