/*
 * ecr_rollingfile.h
 *
 *  Created on: May 28, 2013
 *      Author: velna
 */

#ifndef ECR_ROLLINGFILE_H_
#define ECR_ROLLINGFILE_H_

#include "ecrconf.h"
#include <stdio.h>
#include <time.h>
#include <zlib.h>

#ifndef RFILE_MAX_FILENAME
#define RFILE_MAX_FILENAME	512
#endif

#ifndef RFILE_BUFSIZE
#define RFILE_BUFSIZE        (1024*1024)
#endif

typedef struct {
    char *pattern;
    char filename[RFILE_MAX_FILENAME];
    int fd;
    FILE *file;
    gzFile gz_file;
    int gz_err :1;
    char buf[RFILE_BUFSIZE];
    struct tm last_time;
    mode_t file_mode;
    int flags;
    int deflate;
} ecr_rfile_t;

int ecr_rfile_init(ecr_rfile_t * rf, const char * filename_pattern, int flags, mode_t file_mode, int deflate);

int ecr_rfile_printf(ecr_rfile_t * rf, const char * fmt, ...);

int ecr_rfile_write(ecr_rfile_t * rf, const void *data, size_t size);

void ecr_rfile_destroy(ecr_rfile_t* rf);

#endif /* ECR_ROLLINGFILE_H_ */
