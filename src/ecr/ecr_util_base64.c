/*
 * ecr_util_base64.c
 *
 *  Created on: Feb 15, 2016
 *      Author: velna
 */

#include "config.h"
#include "ecr_util.h"
#include <stdlib.h>
#include <string.h>

static const char * BASE64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

size_t ecr_base64_encode_s(char *to, const void *str, size_t len) {
    char *res;
    const unsigned char *cptr = str;
    int i, clen;
    clen = len / 3;

    for (res = to; clen--;) {
        *res++ = BASE64_TABLE[*cptr >> 2 & 0x3f]; /*取ptr高6位放入res低6位*/
        *res = *cptr++ << 4 & 0x30; /*移动ptr最低2位到高6位然后清0其 它位*/
        *res = BASE64_TABLE[(*cptr >> 4) | *res]; /*取ptr高4位给res低4位*/
        res++;
        *res = (*cptr++ & 0x0f) << 2; /*取ptr低4位移动到高6位*/
        *res = BASE64_TABLE[(*cptr >> 6) | *res]; /*取ptr高2位给res低2位*/
        res++;
        *res++ = BASE64_TABLE[*cptr++ & 0x3f];
    }

    if ((i = len % 3)) { /*处理多余字符只有两种情况多一个或者两个字符*/
        if (i == 1) { /*根据base64编码补=号*/
            *res++ = BASE64_TABLE[*cptr >> 2 & 0x3f];
            *res++ = BASE64_TABLE[*cptr << 4 & 0x30];
            *res++ = '=';
            *res++ = '=';
        } else {
            *res++ = BASE64_TABLE[*cptr >> 2 & 0x3f];
            *res = *cptr++ << 4 & 0x30;
            *res = BASE64_TABLE[(*cptr >> 4) | *res];
            res++;
            *res++ = BASE64_TABLE[(*cptr & 0x0f) << 2];
            *res++ = '=';
        }
    }
    *res = '\0';

    return res - to;
}

int ecr_base64_decode(const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen) {
    int i, j;
    unsigned char k;
    unsigned char temp[4];
    for (i = 0, j = 0; i < inlen; i += 4) {
        memset(temp, 0xFF, sizeof(temp));
        for (k = 0; k < 64; k++) {
            if (BASE64_TABLE[k] == in[i])
                temp[0] = k;
        }
        for (k = 0; k < 64; k++) {
            if (BASE64_TABLE[k] == in[i + 1])
                temp[1] = k;
        }
        for (k = 0; k < 64; k++) {
            if (BASE64_TABLE[k] == in[i + 2])
                temp[2] = k;
        }
        for (k = 0; k < 64; k++) {
            if (BASE64_TABLE[k] == in[i + 3])
                temp[3] = k;
        }

        out[j++] = ((unsigned char) (((unsigned char) (temp[0] << 2)) & 0xFC))
                | ((unsigned char) ((unsigned char) (temp[1] >> 4) & 0x03));
        if (in[i + 2] == '=')
            break;

        out[j++] = ((unsigned char) (((unsigned char) (temp[1] << 4)) & 0xF0))
                | ((unsigned char) ((unsigned char) (temp[2] >> 2) & 0x0F));
        if (in[i + 3] == '=')
            break;

        out[j++] = ((unsigned char) (((unsigned char) (temp[2] << 6)) & 0xF0)) | ((unsigned char) (temp[3] & 0x3F));
    }
    return j;
}
