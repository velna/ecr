/*
 * ecr_urlmatch.h
 *
 *  Created on: Aug 31, 2016
 *      Author: dev
 */

#ifndef SRC_ECR_ECR_URLMATCH_H_
#define SRC_ECR_ECR_URLMATCH_H_

#include "ecr_hashmap.h"

typedef ecr_hashmap_t ecr_urlmatch_t;

typedef struct ecr_urlmatch_node {
    int index;
    char * str;
    char all;
    ecr_str_t * prefix;
    ecr_str_t * suffix;
    struct ecr_urlmatch_node * next;
} ecr_urlmatch_node_t;

typedef struct {
    int size;
    char * str;
    ecr_urlmatch_node_t * next;
} ecr_urlmatch_url_t;

ecr_urlmatch_t * ecr_urlmatch_new();

void ecr_urlmatch_addpattern(ecr_urlmatch_t * in, char * pattern);

void ecr_urlmatch_print(ecr_urlmatch_t * in, FILE* out);

int ecr_urlmatch_match(ecr_urlmatch_t * in, char * url);

void ecr_urlmatch_destroy(ecr_urlmatch_t * in);

#endif /* SRC_ECR_ECR_URLMATCH_H_ */
