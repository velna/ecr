/*
 * ecr_util.c
 *
 *  Created on: Nov 15, 2012
 *      Author: velna
 */

#include "config.h"
#include "ecr_util.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <openssl/sha.h>
#include <time.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <libgen.h>
#include <errno.h>

static char ecr_HEXS[] = "0123456789abcdef";

void ecr_sha1_hex(const void *data, size_t size, char *to) {
    unsigned char md[SHA_DIGEST_LENGTH];
    SHA_CTX sha_ctx;
    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, data, size);
    SHA1_Final(md, &sha_ctx);
    ecr_hex_str((char *) md, SHA_DIGEST_LENGTH, to);
}

void ecr_hex_str(const char * binary, size_t size, char * to) {
    int i;
    for (i = 0; i < size; i++) {
        to[i << 1] = ecr_HEXS[(binary[i] >> 4) & 0xf];
        to[(i << 1) + 1] = ecr_HEXS[binary[i] & 0xf];
    }
    to[size << 1] = '\0';
}

int ecr_hexstr2byte(const char * from, size_t size, char * to) {

    if (size % 2 != 0) {
        return -1;
    }

    int i;
    for (i = 0; i < size; i += 2) {
        char h = from[i];
        char l = from[i + 1];
        if (isalpha(h)) {
            h = h - (h >= 'a' ? 'a' : 'A') + 10;
        } else {
            h -= '0';
        }
        if (isalpha(l)) {
            l = l - (l >= 'a' ? 'a' : 'A') + 10;
        } else {
            l -= '0';
        }

        to[i / 2] = ((h << 4) & 0xf0) | (l & 0x0f);
    }
    to[size / 2] = '\0';
    return 0;
}

void ecr_binary_dump(FILE* out, const void* bin, size_t len) {
    int i, j, k;
    const u_char *s = bin;
    char c;
    for (i = 0; i < len; i++) {
        fprintf(out, " %02x", *(s + i));
        if (i % 16 == 15 || i == len - 1) {
            for (k = 0; k < 16 - (i % 16); k++) {
                fprintf(out, "   ");
            }
            fprintf(out, "\t");
            for (j = i - (i % 16); j <= i; j++) {
                c = *(s + j);
                if (isprint(c) && c != '\n' && c != '\r' && c != '\t') {
                    fprintf(out, "%c", c);
                } else {
                    fprintf(out, ".");
                }
            }
            fprintf(out, "\n");
        }
    }
    fprintf(out, "\n");
}

//char *ecr_str_rtok(char *s, const char *delimiters, char **save_ptr) {
//    char *ptr = *save_ptr;
//    char *ret = NULL;
//    int i;
//    if (!ptr) {
//        ptr = s + strlen(s) - 1;
//    }
//    while (ptr != s) {
//        for (i = 0; delimiters[i]; i++) {
//            if (*ptr == delimiters[i]) {
//                *ptr = '\0';
//                ret = ptr + 1;
//                *save_ptr = ptr - 1;
//                break;
//            }
//        }
//        ptr--;
//    }
//}

int ecr_echo_pid(pid_t pid, char * pid_file) {
    FILE* pid_file_fd;
    if (NULL != pid_file) {
        pid_file_fd = fopen(pid_file, "w");
        if (NULL != pid_file_fd) {
            fprintf(pid_file_fd, "%d\n", pid);
            fclose(pid_file_fd);
            return 0;
        } else {
            return -1;
        }
    }
    return -1;
}

int ecr_time_diff(struct timeval * tv1, struct timeval * tv2) {
    if (tv1->tv_sec == 0) {
        gettimeofday(tv1, NULL);
        return 0;
    }
    if (tv2->tv_sec == 0) {
        gettimeofday(tv2, NULL);
    } else {
        memcpy(tv1, tv2, sizeof(struct timeval));
        gettimeofday(tv2, NULL);
    }
    return (tv2->tv_sec * 1000 + tv2->tv_usec / 1000) - (tv1->tv_sec * 1000 + tv1->tv_usec / 1000);
}

u_int64_t ecr_current_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((u_int64_t) tv.tv_sec) * 1000 + tv.tv_usec / 1000;
}

size_t ecr_format_time(u_int64_t timestamp, const char *fmt, char *buf, size_t size) {
    time_t time = (time_t) timestamp / 1000;
    struct tm stm;
    localtime_r(&time, &stm);
    return strftime(buf, size, fmt, &stm);
}

extern char **environ;
static char *ecr_os_argv_last;

int ecr_change_proc_title(int argc, char ** argv, const char * title) {
    char *p;
    argv[1] = NULL;

    p = strncpy(argv[0], title, ecr_os_argv_last - argv[0]);

    if (ecr_os_argv_last - (char *) p) {
        memset(p, '\0', ecr_os_argv_last - (char *) p);
    }

    return 0;
}

int ecr_init_change_proc_title(int argc, char ** argv) {
    char *p;
    size_t size;
    int i;

    size = 0;

    for (i = 0; environ[i]; i++) {
        size += strlen(environ[i]) + 1;
    }

    p = malloc(size);
    if (p == NULL) {
        return -1;
    }

    ecr_os_argv_last = argv[0];

    for (i = 0; argv[i]; i++) {
        if (ecr_os_argv_last == argv[i]) {
            ecr_os_argv_last = argv[i] + strlen(argv[i]) + 1;
        }
    }

    for (i = 0; environ[i]; i++) {
        if (ecr_os_argv_last == environ[i]) {

            size = strlen(environ[i]) + 1;
            ecr_os_argv_last = environ[i] + size;

            strncpy(p, environ[i], size);
            environ[i] = p;
            p += size;
        }
    }

    ecr_os_argv_last--;

    return 0;
}

int ecr_get_proc_title(pid_t pid, char * buf, size_t size) {
    /* get file path */
    char proc_pid_cmdline_path[4096];
    sprintf(proc_pid_cmdline_path, "/proc/%d/cmdline", pid);

    /* get process title(name) */
    FILE * proc_pid_cmdline = fopen(proc_pid_cmdline_path, "r");
    fgets(buf, size - 1, proc_pid_cmdline);
    fclose(proc_pid_cmdline);

    return 0;
}

int ecr_set_thread_name(const char *fmt, ...) {
    char title[16] = { 0 };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(title, sizeof(title), fmt, ap);
    va_end(ap);
    return prctl(PR_SET_NAME, title);
}

int ecr_get_thread_name(char *name) {
    return prctl(PR_GET_NAME, name);
}

#define MATCH_CHAR(c1,c2,ignore_case)  ( (c1==c2) || ((ignore_case==1) &&(tolower(c1)==tolower(c2))) )

int ecr_wildcard_match(char *src, char *pattern, int ignore_case) {
    int result;

    while (*src) {
        if (*pattern == '*') {
            while ((*pattern == '*') || (*pattern == '?'))
                pattern++;

            if (!*pattern)
                return 1;

            while (*src && (!MATCH_CHAR(*src, *pattern, ignore_case)))
                src++;

            if (!*src)
                return 0;

            result = ecr_wildcard_match(src, pattern, ignore_case);
            while ((!result) && (*(src + 1)) && MATCH_CHAR(*(src + 1), *pattern, ignore_case))
                result = ecr_wildcard_match(++src, pattern, ignore_case);

            return result;

        } else {
            if (MATCH_CHAR(*src, *pattern, ignore_case) || ('?' == *pattern)) {
                return ecr_wildcard_match(++src, ++pattern, ignore_case);
            } else {
                return 0;
            }
        }
    }

    if (*pattern) {
        if ((*pattern == '*') && (*(pattern + 1) == 0))
            return 1;
        else
            return 0;
    } else
        return 1;
}

char *ecr_mem_replace_char(char *str, size_t len, const char *finds, char replacement) {
    const char *f = finds;
    size_t i = 0;
    while (i < len) {
        while (*f) {
            if (str[i] == *f) {
                str[i] = replacement;
                break;
            }
            f++;
        }
        i++;
    }
    return str;
}

static uint32_t ecr_radom_seed_ = 1;

void ecr_random_init(uint32_t seed) {
    ecr_radom_seed_ = seed;
    if (ecr_radom_seed_ == 0 || ecr_radom_seed_ == 2147483647L) {
        ecr_radom_seed_ = 1;
    }
}

uint32_t ecr_random_next() {
    static const uint32_t M = 2147483647L;   // 2^31-1
    static const uint64_t A = 16807;  // bits 14, 8, 7, 5, 2, 1, 0
    uint64_t product = ecr_radom_seed_ * A;
    ecr_radom_seed_ = (uint32_t) ((product >> 31) + (product & M));
    if (ecr_radom_seed_ > M) {
        ecr_radom_seed_ -= M;
    }
    return ecr_radom_seed_;
}

int ecr_mkdirs(const char *path, mode_t mode) {
    char *dir, *s;
    int rc;
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
//            printf("dir %s\n", path);
            rc = 0;
        } else {
            errno = ENOTDIR;
//            printf("not dir %s\n", path);
            rc = -1;
        }
    } else {
        rc = -1;
//        printf("stat %s: %s[%d]\n", path, strerror(errno), errno);
        switch (errno) {
        case ENOENT:
            s = strdup(path);
            dir = dirname(s);
            if (dir) {
                if (ecr_mkdirs(dir, mode) == 0) {
                    rc = mkdir(path, mode);
//                    printf("mkdir %s: %s[%d]\n", path, strerror(errno), errno);
                }
            }
            free(s);
            break;
        }
    }
    return rc;
}
