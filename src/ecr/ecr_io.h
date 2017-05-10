/*
 * ecr_io.h
 *
 *  Created on: Jul 30, 2015
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_IO_H_
#define SRC_ECR_ECR_IO_H_

#include "ecrconf.h"
#include <stdio.h>

typedef FILE * (*ecr_io_chain_func)(FILE *file, const char *options);

typedef struct {
    const char *name;
    const char *rename_pattern;
    ecr_io_chain_func chain_func;
} ecr_io_reg_t;

extern ecr_io_reg_t ecr_io_default_regs[];

/**
 * options: mode=(r|w|a)[b][0-9][f|h|R|F][T],bufize=8192
 */
FILE * ecr_gzip_open(FILE *file, const char *options);

FILE * ecr_lzop_open(FILE *file, const char *options);

/**
 * mode=(r|w|a|r+|w+|a+),chown=user:group,chmod=0666,rtime=30T,rsize=100M
 */
FILE * ecr_rollingfile_open(const char *filestr, int id, ecr_io_reg_t *reg);
#endif /* SRC_ECR_ECR_IO_H_ */
