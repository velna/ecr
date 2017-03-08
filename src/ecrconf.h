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

const char * ecr_commit_sha();

#endif /* SRC_ECRCONF_H_ */
