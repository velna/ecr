/*
 * ecr_event.c
 *
 *  Created on: Aug 29, 2017
 *      Author: velna
 */

#include "config.h"
#include "ecr_event.h"
#include "ecr_logger.h"
#include <string.h>
#include <stdlib.h>

int ecr_event_context_init(ecr_event_context_t *ctx, const char *id, ecr_event_module_t **modules) {
    ctx->modules = modules;
    ctx->id = id ? strdup(id) : NULL;
    return 0;
}

int ecr_event_module_init(ecr_event_context_t *ctx, ecr_config_t *conf) {
    ecr_event_module_t *module;
    int i = 0, module_id, module_enable, module_disable, has_enable, has_disable;
    char *enable_conf_name, *disable_conf_name, *module_name;
    ctx->data_size = 0;
    while ((module = ctx->modules[i])) {
        module_id = i++;
        if (ctx->id) {
            asprintf(&module_name, "%s.%s", ctx->id, module->name);
            asprintf(&enable_conf_name, "%s.%s.%s", ctx->id, module->name, "enable");
            asprintf(&disable_conf_name, "%s.%s.%s", ctx->id, module->name, "disable");
        } else {
            module_name = strdup(module->name);
            asprintf(&enable_conf_name, "%s.%s", module->name, "enable");
            asprintf(&disable_conf_name, "%s.%s", module->name, "disable");
        }
        has_enable = ecr_config_get(conf, module->name, enable_conf_name, ECR_CFG_INT, &module_enable) == 0;
        has_disable = ecr_config_get(conf, module->name, disable_conf_name, ECR_CFG_INT, &module_disable) == 0;
        if (has_enable && has_disable) {
            L_ERROR("can not define both configuration of %s and %s", enable_conf_name, disable_conf_name);
            free(enable_conf_name);
            free(disable_conf_name);
            free(module_name);
            return -1;
        }
        free(enable_conf_name);
        free(disable_conf_name);
        if ((has_enable && module_enable) || (has_disable && !module_disable) || (!module->default_disable)) {
            module->_init_rc = module->init_cb ? module->init_cb(ctx, module_id) : ECR_MODULE_OK;
        } else {
            module->_init_rc = ECR_MODULE_IGNORE;
        }
        switch (module->_init_rc) {
        case ECR_MODULE_IGNORE:
            L_INFO("%s module ignored.", module_name);
            break;
        case ECR_MODULE_OK:
            L_INFO("%s module load ok.", module_name);
            if (module->data_size) {
                module->_data_offset = ctx->data_size;
                ctx->data_size += module->data_size;
            } else {
                module->_data_offset = 0;
            }
            break;
        case ECR_MODULE_ERROR:
            L_INFO("error load module %s.", module_name);
            break;
        }
        free(module_name);
        if (module->_init_rc == ECR_MODULE_ERROR) {
            return -1;
        }
    }
    return 0;
}

void ecr_event_module_destroy(ecr_event_context_t *ctx) {
    ecr_event_module_t *module;
    int i = 0;
    char *module_name;

    while ((module = ctx->modules[i])) {
        if (module->_init_rc == ECR_MODULE_OK) {
            if (module->destroy_cb) {
                module->destroy_cb(ctx);
            }
            if (ctx->id) {
                asprintf(&module_name, "%s.%s", ctx->id, module->name);
            } else {
                module_name = strdup(module->name);
            }
            L_INFO("%s module destroied.", module_name);
            free(module_name);
        }
        i++;
    }
}

void ecr_event_fire_full(ecr_event_context_t *ctx, size_t cb_offset, void *event) {
    ecr_event_module_t *module;
    int i = 0;
    ecr_event_cb_t cb;

    while ((module = ctx->modules[i])) {
        if (module->_init_rc == ECR_MODULE_OK) {
            cb = *((ecr_event_cb_t*) (((u_char*) module) + cb_offset));
            if (cb) {
                cb(ctx, event);
            }
        }
        i++;
    }
}
