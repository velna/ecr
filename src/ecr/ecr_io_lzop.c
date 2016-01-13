/*
 * ecr_io_lzop.c
 *
 *  Created on: Aug 12, 2015
 *      Author: yk
 */

#include "config.h"
#include "ecr_io.h"
#include "ecr_config.h"
#include "ecr_logger.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h>
#include <lzo/lzoutil.h>

#define LZOP_VERSION            0x1030
#define LZOP_COMPAT_VERSION     0x0940

#define SUFFIX_MAX      32
#define LZOPBUFSIZE 256 * 1024

#define F_OS_UNIX       0x03000000L
#define F_OS_MASK       0xff000000L

/* LZO may expand uncompressible data by a small amount */
#define MAX_COMPRESSED_SIZE(x)  ((x) + (x) / 16 + 64 + 3)

enum {
    M_LZO1X_1 = 1,
    M_LZO1X_1_15 = 2,
    M_LZO1X_999 = 3,
    M_NRV1A = 0x1a,
    M_NRV1B = 0x1b,
    M_NRV2A = 0x2a,
    M_NRV2B = 0x2b,
    M_NRV2D = 0x2d,
    M_ZLIB = 128,

    M_UNUSED
};

#define LZOP_NONE 0
#define LZOP_READ 7247
#define LZOP_WRITE 31153
#define LZOP_APPEND 1     /* mode set to LZOP_WRITE after the file is opened */

#define Z_DEFAULT_COMPRESSION_METHOD M_LZO1X_1
#define Z_DEFAULT_COMPRESSION_LEVEL 5
#define Z_DEFAULT_COMPRESSION_WOEK_LEN LZO1X_1_MEM_COMPRESS

#define ADLER32_INIT_VALUE  1
#define CRC32_INIT_VALUE    0

static const unsigned char LZOP_MAGIC[9] = { 0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a };

static const unsigned char LZOP_END[4] = { 0, 0, 0, 0 };

typedef struct {
    int mode;
    FILE *source;
    unsigned remain;
    unsigned buffer;
    lzo_bytep in;
    lzo_bytep out;
    int method;
    int level;
    int err;
    int work_len;
    lzo_bytep wrkmem;
    lzo_uint32 f_adler32;
    lzo_uint32 f_crc32;
    ecr_config_t config;
}ecr_lzop_file_t;

#define ecr_lzop_error(lzopfile, e, msg)  L_ERROR("lzop error[%d]: %s", (lzopfile->err = e), msg)

static void ecr_lzop_reset(ecr_lzop_file_t *lzopfile) {
    lzopfile->remain = lzopfile->buffer; /* no output data available */
    lzopfile->err = LZO_E_OK; /* clear error */
    lzopfile->f_adler32 = ADLER32_INIT_VALUE;
    lzopfile->f_crc32 = CRC32_INIT_VALUE;
}

static void xwrite(ecr_lzop_file_t *lzopfile, const lzo_voidp buf, lzo_uint len) {
    if (lzopfile->source != NULL && lzo_fwrite(lzopfile->source, buf, len) != len) {
        L_ERROR("lzop write error  (disk full ?)");
    }
}

static void xwrite32(ecr_lzop_file_t *lzopfile, lzo_uint32 v) {
    unsigned char b[4];
    b[3] = (unsigned char) (v >> 0);
    b[2] = (unsigned char) (v >> 8);
    b[1] = (unsigned char) (v >> 16);
    b[0] = (unsigned char) (v >> 24);
    xwrite(lzopfile, b, 4);
    lzopfile->f_adler32 = lzo_adler32(lzopfile->f_adler32, b, 4);
    lzopfile->f_crc32 = lzo_crc32(lzopfile->f_crc32, b, 4);
}
static void write32(ecr_lzop_file_t *lzopfile, lzo_uint32 v) {
    unsigned char b[4];
    b[3] = (unsigned char) (v >> 0);
    b[2] = (unsigned char) (v >> 8);
    b[1] = (unsigned char) (v >> 16);
    b[0] = (unsigned char) (v >> 24);
    xwrite(lzopfile, b, 4);
}

static void xwrite16(ecr_lzop_file_t *lzopfile, unsigned v) {
    unsigned char b[2];
    b[1] = (unsigned char) (v >> 0);
    b[0] = (unsigned char) (v >> 8);
    xwrite(lzopfile, b, 2);
    lzopfile->f_adler32 = lzo_adler32(lzopfile->f_adler32, b, 2);
    lzopfile->f_crc32 = lzo_crc32(lzopfile->f_crc32, b, 2);
}

static void xwrite8(ecr_lzop_file_t *lzopfile, int v) {
    unsigned char b = (unsigned char) v;
    xwrite(lzopfile, &b, 1);
    lzopfile->f_adler32 = lzo_adler32(lzopfile->f_adler32, &b, 1);
    lzopfile->f_crc32 = lzo_crc32(lzopfile->f_crc32, &b, 1);
}

static void write_header(ecr_lzop_file_t *lzopfile) {
    xwrite(lzopfile, LZOP_MAGIC, sizeof(LZOP_MAGIC));
    xwrite16(lzopfile, LZOP_VERSION & 0xffff);
    xwrite16(lzopfile, lzo_version() & 0xffff);
    xwrite16(lzopfile, LZOP_COMPAT_VERSION);
    xwrite8(lzopfile, (unsigned char) lzopfile->method);
    xwrite8(lzopfile, (unsigned char) lzopfile->level);
//    xwrite32(lzopfile, (unsigned int) 0); // all flags 0
    xwrite32(lzopfile, F_OS_UNIX & F_OS_MASK);
    xwrite32(lzopfile, (unsigned int) 0x81A4); // mode
    xwrite32(lzopfile, (unsigned int) time((time_t*) NULL)); // mtime
    xwrite32(lzopfile, (unsigned int) 0); // gmtdiff ignored
    xwrite8(lzopfile, (unsigned int) 0); // no filename
    write32(lzopfile, lzopfile->f_adler32);
}

static ssize_t ecr_lzop_read(void *cookie, char *buf, size_t len) {
    return 0;
}

static int ecr_lzop_init_write(ecr_lzop_file_t *lzopfile) {
    /* write lzop header */
    write_header(lzopfile);

    /* allocate input buffer */
    lzopfile->in = (unsigned char *) malloc(lzopfile->buffer);
    if (lzopfile->in == NULL) {
        ecr_lzop_error(lzopfile, LZO_E_OUT_OF_MEMORY, "out of memory");
        return -1;
    }

    lzopfile->remain = lzopfile->buffer;
    return 0;
}

static int ecr_lzop_comp(ecr_lzop_file_t *lzopfile) {
    int r = LZO_E_OK;
    lzo_uint src_len, dst_len = 0;

    if (lzopfile->in == NULL && ecr_lzop_init_write(lzopfile) == -1)
        return -1;

    if (lzopfile->out == NULL) {
        lzopfile->out = (unsigned char *) malloc(MAX_COMPRESSED_SIZE(lzopfile->buffer));
        if (lzopfile->out == NULL) {
            ecr_lzop_error(lzopfile, LZO_E_OUT_OF_MEMORY, "out of memory");
            return -1;
        }
    }
    if (lzopfile->wrkmem == NULL) {
        lzopfile->wrkmem = (unsigned char *) malloc(lzopfile->work_len);
        if (lzopfile->wrkmem == NULL) {
            ecr_lzop_error(lzopfile, LZO_E_OUT_OF_MEMORY, "out of memory");
            return -1;
        }
    }

    src_len = lzopfile->buffer - lzopfile->remain;

    /* write uncompressed block size */
    xwrite32(lzopfile, src_len);

    /* compress */
    if (lzopfile->method == M_LZO1X_1)
        r = lzo1x_1_compress(lzopfile->in, src_len, lzopfile->out, &dst_len, lzopfile->wrkmem);
    else if (lzopfile->method == M_LZO1X_1_15)
        r = lzo1x_1_15_compress(lzopfile->in, src_len, lzopfile->out, &dst_len, lzopfile->wrkmem);
    else if (lzopfile->method == M_LZO1X_999)
        r = lzo1x_999_compress_level(lzopfile->in, src_len, lzopfile->out, &dst_len, lzopfile->wrkmem,
        NULL, 0, 0, lzopfile->level);

    if (r != LZO_E_OK)
        ecr_lzop_error(lzopfile, LZO_E_INTERNAL_ERROR, "compress error");

    /* write compressed block size */
    if (dst_len < src_len) {
        xwrite32(lzopfile, dst_len);
        xwrite(lzopfile, lzopfile->out, dst_len);
    } else {
        xwrite32(lzopfile, src_len);
        xwrite(lzopfile, lzopfile->in, src_len);
    }

    lzopfile->remain = lzopfile->buffer;
    return 0;
}

static ssize_t ecr_lzop_write(void *cookie, const char *buf, size_t len) {
    ssize_t put = len;
    ecr_lzop_file_t *lzopfile = cookie;

    /* get internal structure */
    if (lzopfile == NULL)
        return 0;

    /* check that we're writing and that there's no error */
    if (lzopfile->mode != LZOP_WRITE || lzopfile->err != LZO_E_OK)
        return 0;

    /* since an int is returned, make sure len fits in one, otherwise return
     with an error (this avoids the flaw in the interface) */
    if ((int) len < 0) {
        ecr_lzop_error(lzopfile, LZO_E_INVALID_ARGUMENT, "requested length does not fit in int");
        return 0;
    }

    /* if len is zero, avoid unnecessary operations */
    if (len == 0)
        return 0;

    /* allocate memory if this is the first time through */
    if (lzopfile->in == NULL && ecr_lzop_init_write(lzopfile) == -1)
        return 0;

    /* check for seek request */
//        if (gzfile->seek) {
//            gzfile->seek = 0;
//            if (ecr_gzip_zero(gzfile, gzfile->skip) == -1)
//                return 0;
//        }
    do {
        unsigned copy;
        if (len > lzopfile->remain)
            copy = lzopfile->remain;
        else
            copy = len;

        memcpy(lzopfile->in + (lzopfile->buffer - lzopfile->remain), buf, copy);
        buf = (const char *) buf + copy;
        lzopfile->remain -= copy;
        len -= copy;

        if (lzopfile->remain == 0 && ecr_lzop_comp(lzopfile) == -1)
            return 0;
    } while (len);

    /* input was all buffered or compressed (put will fit in int) */
    return put;
}

static int ecr_lzop_seek(void *cookie, off64_t *off, int whence) {
    return 0;
}

static int ecr_lzop_close_r(ecr_lzop_file_t *lzopfile) {
    return 0;
}

static int ecr_lzop_close_w(ecr_lzop_file_t *lzopfile) {
    int ret = LZO_E_OK;

    /* get internal structure */
    if (lzopfile == NULL)
        return LZO_E_ERROR;

    /* check that we're writing */
    if (lzopfile->mode != LZOP_WRITE)
        return LZO_E_ERROR;

    /* check for seek request */
//        if (gzfile->seek) {
//            gzfile->seek = 0;
//            if (ecr_gzip_zero(gzfile, gzfile->skip) == -1)
//                ret = gzfile->err;
//        }
    /* flush, free memory, and close file */
    if (ecr_lzop_comp(lzopfile) == -1)
        ret = lzopfile->err;

    xwrite(lzopfile, LZOP_END, 4);

    if (fclose(lzopfile->source) == -1)
        ret = LZO_E_ERROR;

    if (lzopfile->in) {
        free(lzopfile->in);
    }
    if (lzopfile->out) {
        free(lzopfile->out);
    }
    if (lzopfile->wrkmem) {
        free(lzopfile->wrkmem);
    }
    ecr_config_destroy(&lzopfile->config);
    free(lzopfile);
    return ret;
}

static int ecr_lzop_close(void *cookie) {
    ecr_lzop_file_t *lzopfile = cookie;

    if (lzopfile == NULL)
        return LZO_E_ERROR;

    return lzopfile->mode == LZOP_READ ? ecr_lzop_close_r(lzopfile) : ecr_lzop_close_w(lzopfile);
}

static cookie_io_functions_t ecr_lzop_io_functions = { .read = ecr_lzop_read, .write = ecr_lzop_write, .seek =
        ecr_lzop_seek, .close = ecr_lzop_close };

FILE * ecr_lzop_open(FILE *file, const char *options) {
    FILE *ret;
    int buf_size;
    char *mode = NULL, *cookie_mode = NULL, *smode;
    ecr_config_line_t cfg_lines[] = {
//
            { "mode", &smode, ECR_CFG_STRING }, //
            { "bufsize", &buf_size, ECR_CFG_INT, .dv.i=LZOPBUFSIZE }, // fixed buffer size
            { 0 } };

    ecr_lzop_file_t *lzopfile = calloc(1, sizeof(ecr_lzop_file_t));
    if (ecr_config_init_str(&lzopfile->config, options) || ecr_config_load(&lzopfile->config, NULL, cfg_lines)
            || ecr_config_print_unused(&lzopfile->config)) {
        L_ERROR("invalid lzop options: %s", options);
        ecr_config_destroy(&lzopfile->config);
        free(lzopfile);
        return NULL;
    }

    lzopfile->remain = 0;
    lzopfile->buffer = buf_size;
    lzopfile->mode = LZOP_NONE;
    lzopfile->method = Z_DEFAULT_COMPRESSION_METHOD;
    lzopfile->level = Z_DEFAULT_COMPRESSION_LEVEL;
    lzopfile->source = file;
    lzopfile->work_len = Z_DEFAULT_COMPRESSION_WOEK_LEN;
    mode = smode;
    while (*mode) {
        if (*mode >= '1' && *mode <= '9')
            lzopfile->level = *mode - '0';
        else
            switch (*mode) {
            case 'r': // TODO
                free(lzopfile);
                return NULL;
            case 'w':
                lzopfile->mode = LZOP_WRITE;
                cookie_mode = "w";
                break;
            case 'a': // TODO
                ecr_config_destroy(&lzopfile->config);
                free(lzopfile);
                return NULL;
            case '+': /* can't read and write at the same time */
                ecr_config_destroy(&lzopfile->config);
                free(lzopfile);
                return NULL;
            case 'b': /* ignore -- will request binary anyway */
                break;
            case 'x':
                lzopfile->method = M_LZO1X_1;
                break;
            case 'y':
                lzopfile->method = M_LZO1X_1_15;
                break;
            case 'z':
                lzopfile->method = M_LZO1X_999;
                break;
            default: /* could consider as an error, but just ignore */
                ;
            }
        mode++;
    }

    if (lzopfile->method == M_LZO1X_1) {
        lzopfile->level = 5;
        lzopfile->work_len = LZO1X_1_MEM_COMPRESS;
    } else if (lzopfile->method == M_LZO1X_1_15) {
        lzopfile->level = 1;
        lzopfile->work_len = LZO1X_1_15_MEM_COMPRESS;
    } else if (lzopfile->method == M_LZO1X_999) {
        lzopfile->work_len = LZO1X_999_MEM_COMPRESS;
    }

    /* must provide an "r", "w", or "a" */
    if (lzopfile->mode == LZOP_NONE) {
        ecr_config_destroy(&lzopfile->config);
        free(lzopfile);
        L_ERROR("a");
        return NULL;
    }

    if (lzopfile->mode != LZOP_WRITE) {
        ecr_config_destroy(&lzopfile->config);
        free(lzopfile);
        L_ERROR("unsupported mode");
        return NULL;
    }

    /* initialize stream */
    ecr_lzop_reset(lzopfile);

    ret = fopencookie(lzopfile, cookie_mode, ecr_lzop_io_functions);
    if (!ret) {
        ecr_config_destroy(&lzopfile->config);
        free(lzopfile);
    }
    return ret;
}
