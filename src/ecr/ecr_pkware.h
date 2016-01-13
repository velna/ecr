/*
 * ecr_pkzip.h
 *
 *  Created on: Mar 9, 2015
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_PKWARE_H_
#define SRC_ECR_ECR_PKWARE_H_

#include "ecrconf.h"
#include <stdio.h>

FILE * ecr_pkware_fencrypt(FILE *file, const char *password);

FILE * ecr_pkware_fdecrypt(FILE *file, const char *password);

void ecr_pkware_encrypt(char *buf, size_t size, const char *password);

void ecr_pkware_decrypt(char *buf, size_t size, const char *password);

#endif /* SRC_ECR_ECR_PKWARE_H_ */
