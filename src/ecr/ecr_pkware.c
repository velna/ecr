/*
 * ecr_pkware.c
 *
 *  Created on: Mar 9, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_pkware.h"
#include "ecr_util.h"
#include <stdlib.h>
#include <string.h>

#define ECR_PKWARE_MAGIC        "VimCrypt~01!"
#define ECR_PKWARE_MAGIC_LEN    12

typedef struct {
    uint32_t keys[3];
    void *data;
} ecr_pkware_t;

static void ecr_pkware_update_keys(uint32_t *keys, char c) {
    keys[0] = ecr_crc32_ch(keys[0], c);
    keys[1] = keys[1] + (keys[0] & 0xff);
    keys[1] = keys[1] * 134775813 + 1;
    keys[2] = ecr_crc32_ch(keys[2], keys[1] >> 24);
}

static u_char ecr_pkware_decrypt_byte(uint32_t *keys) {
    uint16_t tmp;
    tmp = keys[2] | 2;
    return (tmp * (tmp ^ 1)) >> 8;
}

static char ecr_pkware_encrypt0(uint32_t *keys, char c) {
    char o;
    o = ecr_pkware_decrypt_byte(keys);
    ecr_pkware_update_keys(keys, c);
    return o ^ c;
}

static char ecr_pkware_decrypt0(uint32_t *keys, char c) {
    char o;
    o = c ^ ecr_pkware_decrypt_byte(keys);
    ecr_pkware_update_keys(keys, o);
    return o;
}

static ssize_t ecr_pkware_read(void *cookie, char *buf, size_t n) {
    ecr_pkware_t *pkware = (ecr_pkware_t*) cookie;
    FILE *file = (FILE*) pkware->data;
    int i;
    char c;

    for (i = 0; i < n; i++) {
        if (fread(&c, 1, 1, file) == 1) {
            buf[i] = ecr_pkware_decrypt0(pkware->keys, c);
        } else {
            break;
        }
    }
    return i;
}

static ssize_t ecr_pkware_write(void *cookie, const char *buf, size_t n) {
    ecr_pkware_t *pkware = (ecr_pkware_t*) cookie;
    FILE *file = (FILE*) pkware->data;
    ssize_t i;
    char c;

    for (i = 0; i < n; i++) {
        c = ecr_pkware_encrypt0(pkware->keys, buf[i]);
        if (fwrite(&c, 1, 1, file) != 1) {
            break;
        }
    }
    return i;
}

static int ecr_pkware_seek(void *cookie, off64_t *pos, int whence) {
    ecr_pkware_t *pkware = (ecr_pkware_t*) cookie;
    return fseek((FILE*) pkware->data, *pos, whence);
}

static int ecr_pkware_close(void *cookie) {
    ecr_pkware_t *pkware = (ecr_pkware_t*) cookie;
    int rc = fclose((FILE*) pkware->data);
    free(pkware);
    return rc;
}

static cookie_io_functions_t ecr_pkware_io_functions = { .read = ecr_pkware_read, .write = ecr_pkware_write, .seek =
        ecr_pkware_seek, .close = ecr_pkware_close };

static void ecr_pkware_init(ecr_pkware_t *pkware, const char *passwd, void *data) {
    int i;
    size_t len;

    pkware->keys[0] = 305419896;
    pkware->keys[1] = 591751049;
    pkware->keys[2] = 878082192;
    pkware->data = data;

    len = strlen(passwd);
    for (i = 0; i < len; i++) {
        ecr_pkware_update_keys(pkware->keys, passwd[i]);
    }
}

void ecr_pkware_encrypt(char *buf, size_t size, const char *password) {
    ecr_pkware_t pkware;
    ecr_pkware_init(&pkware, password, NULL);
    int i;
    for (i = 0; i < size; i++) {
        buf[i] = ecr_pkware_encrypt0(pkware.keys, buf[i]);
    }
}

void ecr_pkware_decrypt(char *buf, size_t size, const char *password) {
    ecr_pkware_t pkware;
    int i;
    ecr_pkware_init(&pkware, password, NULL);
    for (i = 0; i < size; i++) {
        buf[i] = ecr_pkware_decrypt0(pkware.keys, buf[i]);
    }
}

FILE * ecr_pkware_fencrypt(FILE *file, const char *password) {
    if (fwrite(ECR_PKWARE_MAGIC, ECR_PKWARE_MAGIC_LEN, 1, file) != 1) {
        return NULL;
    }
    ecr_pkware_t *pkware = calloc(1, sizeof(ecr_pkware_t));
    ecr_pkware_init(pkware, password, file);
    return fopencookie(pkware, "w", ecr_pkware_io_functions);
}

FILE * ecr_pkware_fdecrypt(FILE *file, const char *password) {
    char buf[12];
    if (fread(buf, ECR_PKWARE_MAGIC_LEN, 1, file) != 1 || memcmp(buf, ECR_PKWARE_MAGIC, ECR_PKWARE_MAGIC_LEN)) {
        return NULL;
    }
    ecr_pkware_t *pkware = calloc(1, sizeof(ecr_pkware_t));
    ecr_pkware_init(pkware, password, file);
    return fopencookie(pkware, "r", ecr_pkware_io_functions);
}
