/*
 * ecr_logger.c
 *
 *  Created on: Nov 9, 2012
 *      Author: velna
 */

#include "config.h"
#include "ecr_logger.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/syscall.h>

ecr_rfile_t ECR_LOG_FILE[1] = { { .fd = 1 } };

static char* _LOG_LEVELS[8] = { "EMERG", "ALERT", "CRIT", "ERROR", "WARN", "NOTICE", "INFO", "DEBUG" };

ecr_rfile_t * ecr_logger_init(const char* log_file) {
    ecr_rfile_destroy(ECR_LOG_FILE);
    if (ecr_rfile_init(ECR_LOG_FILE, log_file, O_WRONLY | O_APPEND | O_CREAT, 0644, 0)) {
        perror(log_file);
    }
    return ECR_LOG_FILE;
}

ecr_rfile_t * ecr_logger_open(const char * log_file) {
    ecr_rfile_t * rf = malloc(sizeof(ecr_rfile_t));
    if (ecr_rfile_init(rf, log_file, O_WRONLY | O_APPEND | O_CREAT, 0644, 0)) {
        perror(log_file);
        free(rf);
        return NULL;
    }
    return rf;
}

void ecr_logger_close(ecr_rfile_t * rf) {
    ecr_rfile_destroy(rf);
    if (rf != ECR_LOG_FILE) {
        free(rf);
    }
}

void ecr_logger_print(ecr_rfile_t *rf, int level, const char* file, int line, const char* function, const char *data,
        size_t size) {
    struct timeval tv;
    struct tm stm;
    char message[LOG_MAX_LINE_SIZE], *p;
    int n, max = LOG_MAX_LINE_SIZE;
    p = message;

    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &stm);
    n = strftime(p, 32, "[%Y-%m-%d %H:%M:%S", &stm);
    max -= n;
    p += n;
    n = snprintf(p, max, ".%03d] [%6s] %d.%ld - at %s(%s:%d): ", (int) (tv.tv_usec / 1000), _LOG_LEVELS[level],
            getpid(), syscall(SYS_gettid), function, file, line);
    if (n > max) {
        n = max;
    }
    p += n;
    max -= n;
    memcpy(p, data, size);
    p += size;
    *p++ = '\n';
    ecr_rfile_write(rf, message, p - message);
}

void ecr_logger_printf(ecr_rfile_t *rf, const char* format, ...) {
    va_list args;
    char message[LOG_MAX_LINE_SIZE], *p;
    int n;
    p = message;

    va_start(args, format);
    n = vsnprintf(p, LOG_MAX_LINE_SIZE, format, args);
    if (n > LOG_MAX_LINE_SIZE) {
        n = LOG_MAX_LINE_SIZE;
    }
    p += n;
    va_end(args);
    ecr_rfile_write(rf, message, p - message);
}

void ecr_logger_vmessage(ecr_rfile_t *rf, int level, const char* file, int line, const char* function,
        const char* format, va_list va) {
    struct timeval tv;
    struct tm stm;
    char message[LOG_MAX_LINE_SIZE], *p;
    int n, max = LOG_MAX_LINE_SIZE;
    p = message;

    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &stm);
    n = strftime(p, LOG_MAX_LINE_SIZE, "[%Y-%m-%d %H:%M:%S", &stm);
    p += n;
    max -= n;
    n = snprintf(p, max, ".%03d] [%6s] %d.%ld - at %s(%s:%d): ", (int) (tv.tv_usec / 1000), _LOG_LEVELS[level],
            getpid(), syscall(SYS_gettid), function, file, line);
    if (n > max) {
        n = max;
    }
    p += n;
    max -= n;
    n = vsnprintf(p, max, format, va);
    if (n > max) {
        n = max;
    }
    p += n;
    *p++ = '\n';
    ecr_rfile_write(rf, message, p - message);
}

void ecr_logger_message(ecr_rfile_t *rf, int level, const char* file, int line, const char* function,
        const char* format, ...) {
    va_list args;
    va_start(args, format);
    ecr_logger_vmessage(rf, level, file, line, function, format, args);
    va_end(args);
}
