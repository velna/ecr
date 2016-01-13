/*
 * ecr_getopt.h
 *
 *  Created on: May 21, 2015
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_GETOPT_H_
#define SRC_ECR_ECR_GETOPT_H_

#include "ecrconf.h"

typedef struct {
    const char *name;
    int has_arg;
    int *flag;
    int val;
} ecr_option_t;

typedef struct {
    int optind;
    int opterr;
    int optopt;
    char *optarg;
    int initialized;
    char *nextchar;
    enum {
        REQUIRE_ORDER, PERMUTE, RETURN_IN_ORDER
    } ordering;
    int posixly_correct;
    int first_nonopt;
    int last_nonopt;
#if defined USE_NONOPTION_FLAGS
int nonoption_flags_max_len;
int nonoption_flags_len;
# endif
} ecr_getopt_data_t;

#define ECR_GETOPT_DATA_INITIALIZER        { 1, 0 }

int ecr_getopt(int argc, char * const *argv, const char *shortopts, ecr_getopt_data_t *data);

int ecr_getopt_long(int argc, char * const *_argv, const char *shortopts, const ecr_option_t *longopts, int *longind,
    ecr_getopt_data_t *data);

int ecr_getopt_long_only(int argc, char * const *_argv, const char *shortopts, const ecr_option_t *longopts,
    int *longind, ecr_getopt_data_t *data);

#endif /* SRC_ECR_ECR_GETOPT_H_ */
