/*
 * ecr_util.h
 *
 *  Created on: Nov 15, 2012
 *      Author: velna
 */

#ifndef ECR_UTIL_H_
#define ECR_UTIL_H_

#include "ecrconf.h"
#include <stdio.h>
#include <ctype.h>
#include <netinet/in.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN

#define str1cmp(m, c0)                                                                      \
    (m[0] == c0)

#define str2cmp(m, c0, c1)                                                                  \
    (*(uint16_t *) m == ((c1 << 8) | c0))

#define str3cmp(m, c0, c1, c2)                                                              \
    (str2cmp(m, c0, c1) && (m[2] == c2))

#define str4cmp(m, c0, c1, c2, c3)                                                          \
    (*(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0))

#define str5cmp(m, c0, c1, c2, c3, c4)                                                      \
    (str4cmp(m, c0, c1, c2, c3) && (m[4] == c4))

#define str6cmp(m, c0, c1, c2, c3, c4, c5)                                                  \
    (str4cmp(m, c0, c1, c2, c3) &&                                                          \
        (((uint32_t *) m)[1] & 0xffff) == ((c5 << 8) | c4))

#define str7cmp(m, c0, c1, c2, c3, c4, c5, c6)                                              \
    (str6cmp(m, c0, c1, c2, c3, c4, c5) && (m[6] == c6))

#define str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                                          \
    (str4cmp(m, c0, c1, c2, c3) &&                                                          \
        (((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)))

#define str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                                      \
    (str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7) && m[8] == c8)

#define str10cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9)                                 \
    (str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7) &&                                          \
        (((uint32_t *) m)[2] & 0xffff) == ((c9 << 8) | c8))

#define str11cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10)                            \
    (str10cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) && (m[10] == c10))

#define str12cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11)                       \
    (str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7) &&                                          \
        (((uint32_t *) m)[2] == ((c11 << 24) | (c10 << 16) | (c9 << 8) | c8)))

#define str13cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12)                  \
    (str12cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) && m[12] == c12)

#define str14cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13)             \
    (str12cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) &&                       \
        (((uint32_t *) m)[3] & 0xffff) == ((c13 << 8) | c12))

#define str15cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14)        \
    (str14cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) && (m[14] == c14))

#define str16cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15)   \
    (str12cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) &&                       \
        (((uint32_t *) m)[3] == ((c15 << 24) | (c14 << 16) | (c13 << 8) | c12)))

#else

#define str1cmp(m, c0)                                                                      \
    (m[0] == c0)

#define str2cmp(m, c0, c1)                                                                  \
    (m[0] == c0 && m[1] == c1)

#define str3cmp(m, c0, c1, c2)                                                              \
    (m[0] == c0 && m[1] == c1 && m[2] == c2)

#define str4cmp(m, c0, c1, c2, c3)                                                          \
    (m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3)

#define str5cmp(m, c0, c1, c2, c3, c4)                                                      \
    (str4cmp(m, c0, c1, c2, c3) && (m[4] == c4))

#define str6cmp(m, c0, c1, c2, c3, c4, c5)                                                  \
    (str5cmp(m, c0, c1, c2, c3, c4) && m[5] == c5)

#define str7cmp(m, c0, c1, c2, c3, c4, c5, c6)                                              \
    (str6cmp(m, c0, c1, c2, c3, c4, c5) && m[6] == c6)

#define str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                                          \
    (str7cmp(m, c0, c1, c2, c3, c4, c5, c6) && m[7] == c7)

#define str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                                      \
    (str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7) && m[8] == c8)

#define str10cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9)                                 \
    (str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8) && m[9] == c9)

#define str11cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10)                            \
    (str10cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) && m[10] == c10)

#define str12cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11)                       \
    (str11cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) && m[11] == c11)

#define str13cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12)                  \
    (str12cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) && m[12] == c12)

#define str14cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13)             \
    (str13cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12) && m[13] == c13)

#define str15cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14)        \
    (str14cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13) &&             \
            m[14] == c14)

#define str16cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15)   \
    (str15cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14) &&        \
            m[15] == c15)

#endif

#define chricmp(m, c)                                                                       \
    (m == c || m == (c ^ 0x20))

#define str1icmp(m, c0)                                                                     \
    chricmp(m[0], c0)

#define str2icmp(m, c0, c1)                                                                 \
    (str1icmp(m, c0) && chricmp(m[1], c1))

#define str3icmp(m, c0, c1, c2)                                                             \
    (str2icmp(m, c0, c1) && chricmp(m[2], c2))

#define str4icmp(m, c0, c1, c2, c3)                                                         \
    (str3icmp(m, c0, c1, c2) && chricmp(m[3], c3))

#define str5icmp(m, c0, c1, c2, c3, c4)                                                     \
    (str4icmp(m, c0, c1, c2, c3) && chricmp(m[4], c4))

#define str6icmp(m, c0, c1, c2, c3, c4, c5)                                                 \
    (str5icmp(m, c0, c1, c2, c3, c4) && chricmp(m[5], c5))

#define str7icmp(m, c0, c1, c2, c3, c4, c5, c6)                                             \
    (str6icmp(m, c0, c1, c2, c3, c4, c5) && chricmp(m[6], c6))

#define str8icmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                                         \
    (str7icmp(m, c0, c1, c2, c3, c4, c5, c6) && chricmp(m[7], c7))

#define str9icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                                     \
    (str8icmp(m, c0, c1, c2, c3, c4, c5, c6, c7) && chricmp(m[8], c8))

#define str10icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9)                                \
    (str9icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8) && chricmp(m[9], c9))

#define str11icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10)                           \
    (str10icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) && chricmp(m[10], c10))

#define str12icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11)                      \
    (str11icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) && chricmp(m[11], c11))

#define str13icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12)                 \
    (str12icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) &&                      \
            chricmp(m[12], c12))

#define str14icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13)            \
    (str13icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12) &&                 \
            chricmp(m[13], c13))

#define str15icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14)       \
    (str14icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13) &&                                                                    \
            chricmp(m[14], c14))

#define str16icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15)  \
    (str15icmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14) &&                                                                    \
            chricmp(m[15], c15))

char * ecr_str_tok(ecr_str_t *str, const char *delims, ecr_str_t *out);
char * ecr_str_tok_replace(ecr_str_t *str, const char *delims, char replace_ch, ecr_str_t *out);

char *ecr_str_trim(char *s);

void ecr_string_trim(ecr_str_t *str, ecr_str_t *out);

char *ecr_str_tolower(char *s);

ecr_str_t* ecr_str_dup(ecr_str_t *to, ecr_str_t *from);

size_t ecr_str_rcspn(const char *s, size_t n, const char *stopset);

int ecr_str_cast(const char *str, ecr_type_t type, void *out);

size_t ecr_mem_cspn(const void *mem, size_t n, const char *stopset);

size_t ecr_mem_rcspn(const void *mem, size_t n, const char *stopset);

void ecr_binary_dump(FILE *out, const void *bin, size_t len);

void ecr_crc32_mix(const unsigned char *s, unsigned int len, void *out);

void ecr_crc32_hash_mix(const void *s, int len, uint32_t seed, void *out);

uint32_t ecr_crc32_ch(uint32_t crc_magic, char ch);

void ecr_murmur_hash3_x86_32(const void *key, int len, uint32_t seed, void *out);

uint64_t ecr_murmur_hash2_x64(const void *key, int len, uint32_t seed);

void ecr_murmur_hash3_x64_128(const void *key, const int len, const uint32_t seed, void *out);

void ecr_sha1_hex(const void *data, size_t size, char *to);

void ecr_hex_str(const char *binary, size_t size, char *to);

int ecr_hexstr2byte(const char *from, size_t size, char *to);

int ecr_echo_pid(pid_t pid, char *pid_file);

int ecr_time_diff(struct timeval *tv1, struct timeval *tv2);

u_int64_t ecr_current_time();

size_t ecr_format_time(u_int64_t timestamp, const char *fmt, char *buf, size_t size);

int ecr_init_change_proc_title(int argc, char **argv);

int ecr_change_proc_title(int argc, char **argv, const char *title);

int ecr_get_proc_title(pid_t pid, char *buf, size_t size);

int ecr_set_thread_name(const char *fmt, ...);

int ecr_get_thread_name(char *name);

int ecr_wildcard_match(char *src, char *pattern, int ignore_case);

/**
 * to must at least (len / 3 + 6 + len) bytes long
 */
size_t ecr_base64_encode_s(char *to, const void *cptr, size_t len);

int ecr_base64_decode(const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen);

char *ecr_mem_replace_char(char *str, size_t len, const char *finds, char replacement);

void * ecr_zmq_init(const char *endpoint, const char *options, void *zmq_ctx);

void ecr_random_init(uint32_t seed);

uint32_t ecr_random_next();

const char * ecr_inet_ntop(int af, const void *src, char *dst, size_t size);

int ecr_socket_bind(const char *endpoint);

int ecr_mkdirs(const char *path, mode_t mode);

#endif /* ECR_UTIL_H_ */
