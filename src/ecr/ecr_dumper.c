/*
 * ecr_dumper.c
 *
 *  Created on: Sep 26, 2017
 *      Author: velna
 */

#include "config.h"
#include "ecr_dumper.h"
#include <stdarg.h>

int ecr_dumper_init(ecr_dumper_t *dumper, int level, FILE *stream) {
    dumper->level = level;
    dumper->stream = stream;
    return 0;
}

static void ecr_dump_pad(int level, FILE *stream) {
    int i;
    fputc('\n', stream);
    if (level > 0) {
        for (i = 0; i < level; i++) {
            fputs("  ", stream);
        }
    }
}

void ecr_dump_field_format(ecr_dumper_t *dumper, const char *field, const char *fmt, ...) {
    va_list args;
    ecr_dump_pad(dumper->level, dumper->stream);
    fprintf(dumper->stream, "\"%s\": ", field);
    va_start(args, fmt);
    vfprintf(dumper->stream, fmt, args);
    va_end(args);
}

void ecr_dump_field_object(ecr_dumper_t *dumper, const char *name, const void *obj, ecr_dumper_cb cb) {
    ecr_dump_start_field_object(dumper, name);
    cb(obj, dumper);
    ecr_dump_end_field_object(dumper);
}

void ecr_dump_start_field_object(ecr_dumper_t *dumper, const char *name) {
    ecr_dump_pad(dumper->level, dumper->stream);
    fprintf(dumper->stream, "\"%s\": {", name);
    dumper->level++;
}

void ecr_dump_end_field_object(ecr_dumper_t *dumper) {
    dumper->level--;
    ecr_dump_pad(dumper->level, dumper->stream);
    fputc('}', dumper->stream);
}

void ecr_dump_field_name(ecr_dumper_t *dumper, const char *fmt, ...) {
    va_list args;
    ecr_dump_pad(dumper->level, dumper->stream);
    fputc('\"', dumper->stream);
    va_start(args, fmt);
    vfprintf(dumper->stream, fmt, args);
    va_end(args);
    fputs("\": ", dumper->stream);
}

void ecr_dump_field_value_format(ecr_dumper_t *dumper, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(dumper->stream, fmt, args);
    va_end(args);
}

void ecr_dump_field_value_object(ecr_dumper_t *dumper, const void *obj, ecr_dumper_cb cb) {
    fputs("{", dumper->stream);
    dumper->level++;
    cb(obj, dumper);
    ecr_dump_end_field_object(dumper);
}
