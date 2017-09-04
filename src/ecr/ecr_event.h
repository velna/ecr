/*
 * ecr_event_module.h
 *
 *  Created on: Aug 29, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_EVENT_H_
#define SRC_ECR_ECR_EVENT_H_

#include "ecrconf.h"
#include "ecr_config.h"

typedef struct ecr_event_context_s ecr_event_context_t;

typedef enum {
    ECR_MODULE_IGNORE = 0, ECR_MODULE_OK, ECR_MODULE_ERROR
} ecr_module_rc_t;

typedef void (*ecr_event_cb_t)(ecr_event_context_t *ctx, void *event);

#define ECR_EVENT_MODULE_FIELDS \
    const char *name; \
    size_t data_size; \
    bool default_disable; \
    ecr_module_rc_t _init_rc; \
    size_t _data_offset; \
    ecr_module_rc_t (*init_cb)(ecr_event_context_t *ctx, int module_id); \
    void (*destroy_cb)(ecr_event_context_t *ctx);

typedef struct {
    ECR_EVENT_MODULE_FIELDS
} ecr_event_module_t;

struct ecr_event_context_s {
    char *id;
    ecr_event_module_t **modules;
    size_t data_size;
};

#define ecr_event_fire(ctx, type, event_cb, event) \
        ecr_event_fire_full(ctx, offset_of(type, event_cb), event)

#define ecr_event_data(ctx, base, module_id) ((void*)(((u_char*)(base))+(ctx)->modules[module_id]->_data_offset))

int ecr_event_context_init(ecr_event_context_t *ctx, const char *id, ecr_event_module_t **modules);

int ecr_event_module_init(ecr_event_context_t *ctx, ecr_config_t *conf);

void ecr_event_module_destroy(ecr_event_context_t *ctx);

void ecr_event_fire_full(ecr_event_context_t *ctx, size_t cb_offset, void *event);

#endif /* SRC_ECR_ECR_EVENT_H_ */
