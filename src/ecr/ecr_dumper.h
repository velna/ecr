/*
 * ecr_dumper.h
 *
 *  Created on: Sep 26, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_DUMPER_H_
#define SRC_ECR_ECR_DUMPER_H_

#include <ecrconf.h>
#include <stdio.h>

typedef struct {
    int level;
    FILE *stream;
} ecr_dumper_t;

typedef void (*ecr_dumper_cb)(const void *obj, ecr_dumper_t *dumper);

int ecr_dumper_init(ecr_dumper_t *dumper, int level, FILE *stream);

void ecr_dump_field_format(ecr_dumper_t *dumper, const char *field, const char *fmt, ...);

void ecr_dump_field_object(ecr_dumper_t *dumper, const char *name, const void *obj, ecr_dumper_cb cb);

void ecr_dump_start_field_object(ecr_dumper_t *dumper, const char *name);

void ecr_dump_end_field_object(ecr_dumper_t *dumper);

void ecr_dump_field_name(ecr_dumper_t *dumper, const char *fmt, ...);

void ecr_dump_field_value_format(ecr_dumper_t *dumper, const char *fmt, ...);

void ecr_dump_field_value_object(ecr_dumper_t *dumper, const void *obj, ecr_dumper_cb cb);

#endif /* SRC_ECR_ECR_DUMPER_H_ */
