/*
 * ecr_template.c
 *
 *  Created on: Sep 9, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_template.h"

static ecr_template_t * ecr_template_compile(ecr_template_config_t *config, const char *text) {

}

ecr_template_t * ecr_template_init(ecr_template_config_t *config, const char *text) {
    return ecr_template_compile(config, text);
}

int ecr_template_process(ecr_template_t *template, FILE *stream) {

}
