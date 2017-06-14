/*
 * ecr_util_crypto.h
 *
 *  Created on: Jun 14, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_UTIL_CRYPTO_H_
#define SRC_ECR_ECR_UTIL_CRYPTO_H_

#include "ecrconf.h"

#define ECR_CRYPTO_XOR      1

typedef struct {
    char *ptr;
    int len;
    int pos;
} ecr_crypto_xor_key;

int ecr_util_encrypt(ecr_str_t *from, ecr_str_t *to, void *key, int algorithm);

#endif /* SRC_ECR_ECR_UTIL_CRYPTO_H_ */
