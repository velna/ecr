/*
 * ecr_rollingfile.c
 *
 *  Created on: May 28, 2013
 *      Author: velna
 */

#include "config.h"
#include "ecr_rollingfile.h"
#include "ecr_logger.h"
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

int ecr_rfile_init(ecr_rfile_t * rf, const char * filename_pattern, int flags, mode_t file_mode, int deflate) {
    time_t t = time(NULL);
    struct tm stm;

    memset(rf, 0, sizeof(ecr_rfile_t));
    if (filename_pattern) {
        localtime_r(&t, &stm);
        strftime(rf->filename, RFILE_MAX_FILENAME, filename_pattern, &stm);
        rf->last_time = stm;
        rf->flags = deflate ? (flags & ~O_APPEND) : flags;
        rf->file_mode = file_mode;
        rf->deflate = deflate;
        rf->pattern = strdup(filename_pattern);
        rf->fd = open(rf->filename, rf->flags, rf->file_mode);
        if (rf->fd < 0) {
            return -1;
        }
        fchmod(rf->fd, rf->file_mode);
    } else {
        rf->fd = STDOUT_FILENO;
    }
    if (rf->deflate) {
        rf->gz_file = gzdopen(rf->fd, "w");
        if (NULL == rf->gz_file) {
            return -1;
        }
        gzbuffer(rf->gz_file, RFILE_BUFSIZE);
        gzsetparams(rf->gz_file, rf->deflate, Z_DEFAULT_STRATEGY);
    } else {
        rf->file = fdopen(rf->fd, "w");
        if (NULL == rf->file) {
            return -1;
        }
        setbuffer(rf->file, rf->buf, RFILE_BUFSIZE);
    }
    return 0;
}

static inline void ecr_rolling_check(ecr_rfile_t * rf) {
    char filename[RFILE_MAX_FILENAME], *gzfilename;
    time_t t = time(NULL);
    int new_fd;
    struct tm stm;
    localtime_r(&t, &stm);
    if (rf->pattern && rf->last_time.tm_min != stm.tm_min) {
        rf->last_time = stm;
        strftime(filename, RFILE_MAX_FILENAME, rf->pattern, &stm);
        if (strcmp(filename, rf->filename) != 0) {
            new_fd = open(filename, rf->flags, rf->file_mode);
            if (new_fd < 0) {
                L_ERROR("can not open file %s: %s", filename, strerror(errno));
            } else {
                rf->fd = new_fd;
                fchmod(rf->fd, rf->file_mode);
                if (rf->deflate) {
                    //close old file
                    gzflush(rf->gz_file, Z_FINISH);
                    gzclose(rf->gz_file);

                    //rename to *.gz
                    asprintf(&gzfilename, "%s.gz", rf->filename);
                    if (!rf->gz_err && rename(rf->filename, gzfilename) == -1) {
                        L_ERROR("can not rename file %s to %s", rf->filename, gzfilename);
                    }
                    free(gzfilename);

                    //open new file
                    rf->gz_file = gzdopen(rf->fd, "w");
                    rf->gz_err = 0;
                    if (NULL == rf->gz_file) {
                        L_ERROR("can not open gzfile %s: %s", filename, strerror(errno));
                    } else {
                        gzbuffer(rf->gz_file, RFILE_BUFSIZE);
                        gzsetparams(rf->gz_file, rf->deflate, Z_DEFAULT_STRATEGY);
                    }
                } else {
                    fclose(rf->file);
                    rf->file = fdopen(rf->fd, "w");
                    if (NULL == rf->file) {
                        L_ERROR("can not open file %s: %s", filename, strerror(errno));
                    } else {
                        setbuffer(rf->file, rf->buf, RFILE_BUFSIZE);
                    }
                }
                strcpy(rf->filename, filename);
            }
        }
    }
}

int ecr_rfile_printf(ecr_rfile_t * rf, const char * fmt, ...) {
    int rc;
    ecr_str_t buf;
    ecr_rolling_check(rf);
    va_list arg;
    va_start(arg, fmt);
    if (rf->gz_file) {
        buf.len = vasprintf(&buf.ptr, fmt, arg);
        rc = gzwrite(rf->gz_file, buf.ptr, buf.len);
        if (rc == 0 && !rf->gz_err) {
            L_ERROR("error write gzip file %s: %s", rf->filename, strerror(errno));
            rf->gz_err = 1;
        }
        free(buf.ptr);
    } else {
        rc = vfprintf(rf->file, fmt, arg);
    }
    va_end(arg);
    return rc;
}

int ecr_rfile_write(ecr_rfile_t * rf, const void *data, size_t size) {
    int rc;
    ecr_rolling_check(rf);
    if (rf->gz_file) {
        rc = gzwrite(rf->gz_file, data, size);
        if (rc == 0 && !rf->gz_err) {
            L_ERROR("error write gzip file %s: %s", rf->filename, strerror(errno));
            rf->gz_err = 1;
        }
    } else {
        rc = write(rf->fd, data, size);
    }
    return rc;
}

void ecr_rfile_destroy(ecr_rfile_t* rf) {
    char *gzfilename;
    if (rf->pattern) {
        free(rf->pattern);
        rf->pattern = NULL;
    }
    if (rf->gz_file) {
        gzflush(rf->gz_file, Z_FINISH);
        gzclose(rf->gz_file);

        //rename to *.gz
        asprintf(&gzfilename, "%s.gz", rf->filename);
        if (!rf->gz_err && rename(rf->filename, gzfilename) == -1) {
            L_ERROR("can not rename file %s to %s", rf->filename, gzfilename);
        }
        free(gzfilename);

        rf->gz_file = NULL;
    }
    if (rf->file) {
        fclose(rf->file);
        rf->file = NULL;
    }
}
