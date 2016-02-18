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
static const unsigned char BASE64_MAP[256] = {
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        62,
        255,
        255,
        255,
        63,
        52,
        53,
        54,
        55,
        56,
        57,
        58,
        59,
        60,
        61,
        255,
        255,
        255,
        254,
        255,
        255,
        255,
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        21,
        22,
        23,
        24,
        25,
        255,
        255,
        255,
        255,
        255,
        255,
        26,
        27,
        28,
        29,
        30,
        31,
        32,
        33,
        34,
        35,
        36,
        37,
        38,
        39,
        40,
        41,
        42,
        43,
        44,
        45,
        46,
        47,
        48,
        49,
        50,
        51,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255 };

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
    size_t t, x, y, z;
    unsigned char c;
    int g;

    g = 3;
    for (x = y = z = t = 0; x < inlen; x++) {
        c = BASE64_MAP[in[x] & 0xFF];
        if (c == 255)
            continue;
        /* the final = symbols are read and used to trim the remaining bytes */
        if (c == 254) {
            c = 0;
            /* prevent g < 0 which would potentially allow an overflow later */
            if (--g < 0) {
                return -1;
            }
        } else if (g != 3) {
            /* we only allow = to be at the end */
            return -1;
        }
        t = (t << 6) | c;
        if (++y == 4) {
            if (z + g > *outlen) {
                return -1;
            }
            out[z++] = (unsigned char) ((t >> 16) & 255);
            if (g > 1)
                out[z++] = (unsigned char) ((t >> 8) & 255);
            if (g > 2)
                out[z++] = (unsigned char) (t & 255);
            y = t = 0;

        }

    }
    if (y != 0) {
        return -1;
    }
    *outlen = z;
    return 0;
}
