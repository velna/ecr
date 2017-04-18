/*
 * ecrconf.h
 *
 *  Created on: Aug 3, 2015
 *      Author: velna
 */

#ifndef SRC_ECRCONF_H_
#define SRC_ECRCONF_H_

#include <inttypes.h>
#include <stddef.h>
#include <sys/types.h>

typedef enum {
    ECR_UNDEF = 0,
    ECR_CHAR,
    ECR_INT8,
    ECR_UINT8,
    ECR_INT16,
    ECR_UINT16,
    ECR_INT32,
    ECR_UINT32,
    ECR_INT64,
    ECR_UINT64,
    ECR_FLOAT,
    ECR_DOUBLE,
    ECR_STRING,
    ECR_POINTER
} ecr_type_t;

#define free_to_null(p) \
    do { \
        if(p) { \
            free(p); \
            (p) = NULL; \
        } \
    } while(0)

typedef struct {
    char * ptr;
    size_t len;
} ecr_str_t;

#define ECR_STR_T

typedef int (*ecr_compare_func)(const void *a, const void *b);

#define ECR_INLINE __attribute__((always_inline))

static inline const char *ecr_type_string(ecr_type_t type) {
    switch (type) {
    case ECR_UNDEF:
        return "ECR_UNDEF";
    case ECR_CHAR:
        return "ECR_CHAR";
    case ECR_INT8:
        return "ECR_INT8";
    case ECR_UINT8:
        return "ECR_UINT8";
    case ECR_INT16:
        return "ECR_INT16";
    case ECR_UINT16:
        return "ECR_UINT16";
    case ECR_INT32:
        return "ECR_INT32";
    case ECR_UINT32:
        return "ECR_UINT32";
    case ECR_INT64:
        return "ECR_INT64";
    case ECR_UINT64:
        return "ECR_UINT64";
    case ECR_FLOAT:
        return "ECR_FLOAT";
    case ECR_DOUBLE:
        return "ECR_DOUBLE";
    case ECR_STRING:
        return "ECR_STRING";
    case ECR_POINTER:
        return "ECR_POINTER";
    default:
        return NULL;
    }
}

const char * ecr_commit_sha();

#endif /* SRC_ECRCONF_H_ */
