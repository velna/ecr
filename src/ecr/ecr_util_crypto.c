/*
 * ecr_util_crypto.c
 *
 *  Created on: Jun 14, 2017
 *      Author: velna
 */

#include "config.h"
#include "ecr_util_crypto.h"

static int ECR_INLINE encrypt_xor(ecr_str_t *from, ecr_str_t *to, ecr_crypto_xor_key *xor_key) {
    int keylen = xor_key->len;
    int pos = xor_key->pos % keylen;
    int i;
    if (to->len < from->len) {
        return -1;
    }
    for (i = 0; i < from->len; i++) {
        to->ptr[i] = from->ptr[i] ^ xor_key->ptr[pos++ % keylen];
    }
    return from->len;
}

int ecr_util_encrypt(ecr_str_t *from, ecr_str_t *to, void *key, int algorithm) {
    int rc;
    switch (algorithm) {
    case ECR_CRYPTO_XOR:
        rc = encrypt_xor(from, to, key);
        break;
    default:
        rc = -1;
        break;
    }
    return rc;
}
