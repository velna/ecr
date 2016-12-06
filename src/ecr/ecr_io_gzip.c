/*
 * ecr_io_gzip.c
 *
 *  Created on: Jul 30, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_io.h"
#include "ecr_config.h"
#include "ecr_logger.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <zlib.h>

#define GZ_NONE 0
#define GZ_READ 7247
#define GZ_WRITE 31153
#define GZ_APPEND 1     /* mode set to GZ_WRITE after the file is opened */

/* values for ecr_gzip_file_t how */
#define LOOK 0      /* look for a gzip header */
#define COPY 1      /* copy input directly */
#define GZIP 2      /* decompress a gzip stream */

#define GZBUFSIZE 8192

#if MAX_MEM_LEVEL >= 8
#  define DEF_MEM_LEVEL 8
#else
#  define DEF_MEM_LEVEL  MAX_MEM_LEVEL
#endif

#define GT_OFF(x) (sizeof(int) == sizeof(size_t) && (x) > INT_MAX)

typedef struct {
    unsigned have;
    unsigned char *next;
    ssize_t pos;
    int mode;
    FILE *source;
    unsigned size;
    unsigned want;
    unsigned char *in;
    unsigned char *out;
    int direct;
    int how;
    ssize_t start;
    int eof;
    int past;
    int level;
    int strategy;
    ssize_t skip;
    int seek;
    int err;
    z_stream stream;
    ecr_config_t config;
} ecr_gzip_file_t;

#define ecr_gzip_error(gzfile, e, msg)  L_ERROR("gzip error[%d]: %s", (gzfile->err = e), msg)

static void ecr_gzip_reset(ecr_gzip_file_t *gzfile) {
    gzfile->have = 0; /* no output data available */
    if (gzfile->mode == GZ_READ) { /* for reading ... */
        gzfile->eof = 0; /* not at end of file */
        gzfile->past = 0; /* have not read past end yet */
        gzfile->how = LOOK; /* look for gzip header */
    }
    gzfile->seek = 0; /* no seek request pending */
    gzfile->err = Z_OK; /* clear error */
    gzfile->pos = 0; /* no uncompressed data yet */
    gzfile->stream.avail_in = 0; /* no input data yet */
}

/* -- see zlib.h -- */
static int ecr_gzip_rewind(ecr_gzip_file_t *gzfile) {
    /* get internal structure */
    if (gzfile == NULL)
        return -1;

    /* check that we're reading and that there's no error */
    if (gzfile->mode != GZ_READ || (gzfile->err != Z_OK && gzfile->err != Z_BUF_ERROR))
        return -1;

    /* back up and start over */
    if (fseek(gzfile->source, gzfile->start, SEEK_SET) == -1)
        return -1;
    ecr_gzip_reset(gzfile);
    return 0;
}

/* Use read() to load a buffer -- return -1 on error, otherwise 0.  Read from
 gzfile->fd, and update gzfile->eof, gzfile->err, and gzfile->msg as appropriate.
 This function needs to loop on read(), since read() is not guaranteed to
 read the number of bytes requested, depending on the type of descriptor. */
static int ecr_gzip_load(ecr_gzip_file_t *gzfile, unsigned char *buf, unsigned len, unsigned* have) {
    int ret;

    *have = 0;
    do {
        ret = fread(buf + *have, 1, len - *have, gzfile->source);
        if (ret <= 0)
            break;
        *have += ret;
    } while (*have < len);
    if (ret < 0) {
        ecr_gzip_error(gzfile, Z_ERRNO, strerror(errno));
        return -1;
    }
    if (ret == 0)
        gzfile->eof = 1;
    return 0;
}

/* Load up input buffer and set eof flag if last data loaded -- return -1 on
 error, 0 otherwise.  Note that the eof flag is set when the end of the input
 file is reached, even though there may be unused data in the buffer.  Once
 that data has been used, no more attempts will be made to read the file.
 If strm->avail_in != 0, then the current data is moved to the beginning of
 the input buffer, and then the remainder of the buffer is loaded with the
 available data from the input file. */
static int ecr_gzip_avail(ecr_gzip_file_t *gzfile) {
    unsigned got;
    z_streamp strm = &(gzfile->stream);

    if (gzfile->err != Z_OK && gzfile->err != Z_BUF_ERROR)
        return -1;
    if (gzfile->eof == 0) {
        if (strm->avail_in) { /* copy what's there to the start */
            unsigned char *p = gzfile->in;
            unsigned const char *q = strm->next_in;
            unsigned n = strm->avail_in;
            do {
                *p++ = *q++;
            } while (--n);
        }
        if (ecr_gzip_load(gzfile, gzfile->in + strm->avail_in, gzfile->size - strm->avail_in, &got) == -1)
            return -1;
        strm->avail_in += got;
        strm->next_in = gzfile->in;
    }
    return 0;
}

/* Look for gzip header, set up for inflate or copy.  gzfile->have must be 0.
 If this is the first time in, allocate required memory.  gzfile->how will be
 left unchanged if there is no more input data available, will be set to COPY
 if there is no gzip header and direct copying will be performed, or it will
 be set to GZIP for decompression.  If direct copying, then leftover input
 data from the input buffer will be copied to the output buffer.  In that
 case, all further file reads will be directly to either the output buffer or
 a user buffer.  If decompressing, the inflate gzfile will be initialized.
 ecr_gzip_look() will return 0 on success or -1 on failure. */
static int ecr_gzip_look(ecr_gzip_file_t *gzfile) {
    z_streamp strm = &(gzfile->stream);

    /* allocate read buffers and inflate memory */
    if (gzfile->size == 0) {
        /* allocate buffers */
        gzfile->in = (unsigned char *) malloc(gzfile->want);
        gzfile->out = (unsigned char *) malloc(gzfile->want << 1);
        if (gzfile->in == NULL || gzfile->out == NULL) {
            if (gzfile->out != NULL)
                free(gzfile->out);
            if (gzfile->in != NULL)
                free(gzfile->in);
            ecr_gzip_error(gzfile, Z_MEM_ERROR, "out of memory");
            return -1;
        }
        gzfile->size = gzfile->want;

        /* allocate inflate memory */
        gzfile->stream.zalloc = Z_NULL;
        gzfile->stream.zfree = Z_NULL;
        gzfile->stream.opaque = Z_NULL;
        gzfile->stream.avail_in = 0;
        gzfile->stream.next_in = Z_NULL;
        if (inflateInit2(&(gzfile->stream), 15 + 16) != Z_OK) { /* gunzip */
            free(gzfile->out);
            free(gzfile->in);
            gzfile->size = 0;
            ecr_gzip_error(gzfile, Z_MEM_ERROR, "out of memory");
            return -1;
        }
    }

    /* get at least the magic bytes in the input buffer */
    if (strm->avail_in < 2) {
        if (ecr_gzip_avail(gzfile) == -1)
            return -1;
        if (strm->avail_in == 0)
            return 0;
    }

    /* look for gzip magic bytes -- if there, do gzip decoding (note: there is
     a logical dilemma here when considering the case of a partially written
     gzip file, to wit, if a single 31 byte is written, then we cannot tell
     whether this is a single-byte file, or just a partially written gzip
     file -- for here we assume that if a gzip file is being written, then
     the header will be written in a single operation, so that reading a
     single byte is sufficient indication that it is not a gzip file) */
    if (strm->avail_in > 1 && strm->next_in[0] == 31 && strm->next_in[1] == 139) {
        inflateReset(strm);
        gzfile->how = GZIP;
        gzfile->direct = 0;
        return 0;
    }

    /* no gzip header -- if we were decoding gzip before, then this is trailing
     garbage.  Ignore the trailing garbage and finish. */
    if (gzfile->direct == 0) {
        strm->avail_in = 0;
        gzfile->eof = 1;
        gzfile->have = 0;
        return 0;
    }

    /* doing raw i/o, copy any leftover input to output -- this assumes that
     the output buffer is larger than the input buffer, which also assures
     space for gzungetc() */
    gzfile->next = gzfile->out;
    if (strm->avail_in) {
        memcpy(gzfile->next, strm->next_in, strm->avail_in);
        gzfile->have = strm->avail_in;
        strm->avail_in = 0;
    }
    gzfile->how = COPY;
    gzfile->direct = 1;
    return 0;
}

/* Decompress from input to the provided next_out and avail_out in the gzfile.
 On return, gzfile->have and gzfile->next point to the just decompressed
 data.  If the gzip stream completes, gzfile->how is reset to LOOK to look for
 the next gzip stream or raw data, once gzfile->have is depleted.  Returns 0
 on success, -1 on failure. */
static int ecr_gzip_decomp(ecr_gzip_file_t *gzfile) {
    int ret = Z_OK;
    unsigned had;
    z_streamp strm = &(gzfile->stream);

    /* fill output buffer up to end of deflate stream */
    had = strm->avail_out;
    do {
        /* get more input for inflate() */
        if (strm->avail_in == 0 && ecr_gzip_avail(gzfile) == -1)
            return -1;
        if (strm->avail_in == 0) {
            ecr_gzip_error(gzfile, Z_BUF_ERROR, "unexpected end of file");
            break;
        }

        /* decompress and handle errors */
        ret = inflate(strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_NEED_DICT) {
            ecr_gzip_error(gzfile, Z_STREAM_ERROR, "internal error: inflate stream corrupt");
            return -1;
        }
        if (ret == Z_MEM_ERROR) {
            ecr_gzip_error(gzfile, Z_MEM_ERROR, "out of memory");
            return -1;
        }
        if (ret == Z_DATA_ERROR) { /* deflate stream invalid */
            ecr_gzip_error(gzfile, Z_DATA_ERROR, strm->msg == NULL ? "compressed data error" : strm->msg);
            return -1;
        }
    } while (strm->avail_out && ret != Z_STREAM_END);

    /* update available output */
    gzfile->have = had - strm->avail_out;
    gzfile->next = strm->next_out - gzfile->have;

    /* if the gzip stream completed successfully, look for another */
    if (ret == Z_STREAM_END)
        gzfile->how = LOOK;

    /* good decompression */
    return 0;
}

/* Fetch data and put it in the output buffer.  Assumes gzfile->have is 0.
 Data is either copied from the input file or decompressed from the input
 file depending on gzfile->how.  If gzfile->how is LOOK, then a gzip header is
 looked for to determine whether to copy or decompress.  Returns -1 on error,
 otherwise 0.  ecr_gzip_fetch() will leave gzfile->how as COPY or GZIP unless the
 end of the input file has been reached and all data has been processed.  */
static int ecr_gzip_fetch(ecr_gzip_file_t *gzfile) {
    z_streamp strm = &(gzfile->stream);

    do {
        switch (gzfile->how) {
        case LOOK: /* -> LOOK, COPY (only if never GZIP), or GZIP */
            if (ecr_gzip_look(gzfile) == -1)
                return -1;
            if (gzfile->how == LOOK)
                return 0;
            break;
        case COPY: /* -> COPY */
            if (ecr_gzip_load(gzfile, gzfile->out, gzfile->size << 1, &(gzfile->have)) == -1)
                return -1;
            gzfile->next = gzfile->out;
            return 0;
        case GZIP: /* -> GZIP or LOOK (if end of gzip stream) */
            strm->avail_out = gzfile->size << 1;
            strm->next_out = gzfile->out;
            if (ecr_gzip_decomp(gzfile) == -1)
                return -1;
        }
    } while (gzfile->have == 0 && (!gzfile->eof || strm->avail_in));
    return 0;
}

/* Skip len uncompressed bytes of output.  Return -1 on error, 0 on success. */
static int ecr_gzip_skip(ecr_gzip_file_t *gzfile, size_t len) {
    unsigned n;

    /* skip over len bytes or reach end-of-file, whichever comes first */
    while (len)
        /* skip over whatever is in output buffer */
        if (gzfile->have) {
            n = GT_OFF(gzfile->have) || (size_t) gzfile->have > len ? (unsigned) len : gzfile->have;
            gzfile->have -= n;
            gzfile->next += n;
            gzfile->pos += n;
            len -= n;
        }

        /* output buffer empty -- return if we're at the end of the input */
        else if (gzfile->eof && gzfile->stream.avail_in == 0)
            break;

        /* need more data to skip -- load up output buffer */
        else {
            /* get more output, looking for header if required */
            if (ecr_gzip_fetch(gzfile) == -1)
                return -1;
        }
    return 0;
}

static ssize_t ecr_gzip_read(void *cookie, char *buf, size_t len) {
    unsigned got, n;
    ecr_gzip_file_t *gzfile = cookie;
    z_streamp strm;

    /* get internal structure */
    if (gzfile == NULL)
        return -1;
    strm = &(gzfile->stream);

    /* check that we're reading and that there's no (serious) error */
    if (gzfile->mode != GZ_READ || (gzfile->err != Z_OK && gzfile->err != Z_BUF_ERROR))
        return -1;

    /* since an int is returned, make sure len fits in one, otherwise return
     with an error (this avoids the flaw in the interface) */
    if ((int) len < 0) {
        ecr_gzip_error(gzfile, Z_DATA_ERROR, "requested length does not fit in int");
        return -1;
    }

    /* if len is zero, avoid unnecessary operations */
    if (len == 0)
        return 0;

    /* process a skip request */
    if (gzfile->seek) {
        gzfile->seek = 0;
        if (ecr_gzip_skip(gzfile, gzfile->skip) == -1)
            return -1;
    }

    /* get len bytes to buf, or less than len if at the end */
    got = 0;
    do {
        /* first just try copying data from the output buffer */
        if (gzfile->have) {
            n = gzfile->have > len ? len : gzfile->have;
            memcpy(buf, gzfile->next, n);
            gzfile->next += n;
            gzfile->have -= n;
        }

        /* output buffer empty -- return if we're at the end of the input */
        else if (gzfile->eof && strm->avail_in == 0) {
            gzfile->past = 1; /* tried to read past end */
            break;
        }

        /* need output data -- for small len or new stream load up our output
         buffer */
        else if (gzfile->how == LOOK || len < (gzfile->size << 1)) {
            /* get more output, looking for header if required */
            if (ecr_gzip_fetch(gzfile) == -1)
                return -1;
            continue; /* no progress yet -- go back to copy above */
            /* the copy above assures that we will leave with space in the
             output buffer, allowing at least one gzungetc() to succeed */
        }

        /* large len -- read directly into user buffer */
        else if (gzfile->how == COPY) { /* read directly */
            if (ecr_gzip_load(gzfile, (unsigned char *) buf, len, &n) == -1)
                return -1;
        }

        /* large len -- decompress directly into user buffer */
        else { /* gzfile->how == GZIP */
            strm->avail_out = len;
            strm->next_out = (unsigned char *) buf;
            if (ecr_gzip_decomp(gzfile) == -1)
                return -1;
            n = gzfile->have;
            gzfile->have = 0;
        }

        /* update progress */
        len -= n;
        buf = (char *) buf + n;
        got += n;
        gzfile->pos += n;
    } while (len);

    /* return number of bytes read into user buffer (will fit in int) */
    return (int) got;
}

static int ecr_gzip_init_write(ecr_gzip_file_t *gzfile) {
    int ret;
    z_streamp strm = &(gzfile->stream);

    /* allocate input buffer */
    gzfile->in = (unsigned char *) malloc(gzfile->want);
    if (gzfile->in == NULL) {
        ecr_gzip_error(gzfile, Z_MEM_ERROR, "out of memory");
        return -1;
    }

    /* only need output buffer and deflate gzfile if compressing */
    if (!gzfile->direct) {
        /* allocate output buffer */
        gzfile->out = (unsigned char *) malloc(gzfile->want);
        if (gzfile->out == NULL) {
            free(gzfile->in);
            ecr_gzip_error(gzfile, Z_MEM_ERROR, "out of memory");
            return -1;
        }

        /* allocate deflate memory, set up for gzip compression */
        strm->zalloc = Z_NULL;
        strm->zfree = Z_NULL;
        strm->opaque = Z_NULL;
        ret = deflateInit2(strm, gzfile->level, Z_DEFLATED, MAX_WBITS + 16, DEF_MEM_LEVEL, gzfile->strategy);
        if (ret != Z_OK) {
            free(gzfile->out);
            free(gzfile->in);
            ecr_gzip_error(gzfile, Z_MEM_ERROR, "out of memory");
            return -1;
        }
    }

    /* mark gzfile as initialized */
    gzfile->size = gzfile->want;

    /* initialize write buffer if compressing */
    if (!gzfile->direct) {
        strm->avail_out = gzfile->size;
        strm->next_out = gzfile->out;
        gzfile->next = strm->next_out;
    }
    return 0;
}

/* Compress whatever is at avail_in and next_in and write to the output file.
 Return -1 if there is an error writing to the output file, otherwise 0.
 flush is assumed to be a valid deflate() flush value.  If flush is Z_FINISH,
 then the deflate() gzfile is reset to start a new gzip stream.  If gz->direct
 is true, then simply write to the output file without compressing, and
 ignore flush. */
static int ecr_gzip_comp(ecr_gzip_file_t *gzfile, int flush) {
    int ret, got;
    unsigned have;
    z_streamp strm = &(gzfile->stream);

    /* allocate memory if this is the first time through */
    if (gzfile->size == 0 && ecr_gzip_init_write(gzfile) == -1)
        return -1;

    /* write directly if requested */
    if (gzfile->direct) {
        got = fwrite(strm->next_in, 1, strm->avail_in, gzfile->source);
        if (got < 0 || (unsigned) got != strm->avail_in) {
            ecr_gzip_error(gzfile, Z_ERRNO, strerror(errno));
            return -1;
        }
        strm->avail_in = 0;
        return 0;
    }

    /* run deflate() on provided input until it produces no more output */
    ret = Z_OK;
    do {
        /* write out current buffer contents if full, or if flushing, but if
         doing Z_FINISH then don't write until we get to Z_STREAM_END */
        if (strm->avail_out == 0 || (flush != Z_NO_FLUSH && (flush != Z_FINISH || ret == Z_STREAM_END))) {
            have = (unsigned) (strm->next_out - gzfile->next);
            if (have && ((got = fwrite(gzfile->next, 1, have, gzfile->source)) < 0 || (unsigned) got != have)) {
                ecr_gzip_error(gzfile, Z_ERRNO, strerror(errno));
                return -1;
            }
            if (strm->avail_out == 0) {
                strm->avail_out = gzfile->size;
                strm->next_out = gzfile->out;
            }
            gzfile->next = strm->next_out;
        }

        /* compress */
        have = strm->avail_out;
        ret = deflate(strm, flush);
        if (ret == Z_STREAM_ERROR) {
            ecr_gzip_error(gzfile, Z_STREAM_ERROR, "internal error: deflate stream corrupt");
            return -1;
        }
        have -= strm->avail_out;
    } while (have);

    /* if that completed a deflate stream, allow another to start */
    if (flush == Z_FINISH)
        deflateReset(strm);

    /* all done, no errors */
    return 0;
}

static int ecr_gzip_zero(ecr_gzip_file_t *gzfile, size_t len) {
    int first;
    unsigned n;
    z_streamp strm = &(gzfile->stream);

    /* consume whatever's left in the input buffer */
    if (strm->avail_in && ecr_gzip_comp(gzfile, Z_NO_FLUSH) == -1)
        return -1;

    /* compress len zeros (len guaranteed > 0) */
    first = 1;
    while (len) {
        n = GT_OFF(gzfile->size) || (size_t) gzfile->size > len ? (unsigned) len : gzfile->size;
        if (first) {
            memset(gzfile->in, 0, n);
            first = 0;
        }
        strm->avail_in = n;
        strm->next_in = gzfile->in;
        gzfile->pos += n;
        if (ecr_gzip_comp(gzfile, Z_NO_FLUSH) == -1)
            return -1;
        len -= n;
    }
    return 0;
}

static ssize_t ecr_gzip_write(void *cookie, const char *buf, size_t len) {
    ssize_t put = len;
    ecr_gzip_file_t *gzfile = cookie;
    z_streamp strm;

    /* get internal structure */
    if (gzfile == NULL)
        return 0;
    strm = &(gzfile->stream);

    /* check that we're writing and that there's no error */
    if (gzfile->mode != GZ_WRITE || gzfile->err != Z_OK)
        return 0;

    /* since an int is returned, make sure len fits in one, otherwise return
     with an error (this avoids the flaw in the interface) */
    if ((int) len < 0) {
        ecr_gzip_error(gzfile, Z_DATA_ERROR, "requested length does not fit in int");
        return 0;
    }

    /* if len is zero, avoid unnecessary operations */
    if (len == 0)
        return 0;

    /* allocate memory if this is the first time through */
    if (gzfile->size == 0 && ecr_gzip_init_write(gzfile) == -1)
        return 0;

    /* check for seek request */
    if (gzfile->seek) {
        gzfile->seek = 0;
        if (ecr_gzip_zero(gzfile, gzfile->skip) == -1)
            return 0;
    }

    /* for small len, copy to input buffer, otherwise compress directly */
    if (len < gzfile->size) {
        /* copy to input buffer, compress when full */
        do {
            unsigned have, copy;

            if (strm->avail_in == 0)
                strm->next_in = gzfile->in;
            have = (unsigned) ((strm->next_in + strm->avail_in) - gzfile->in);
            copy = gzfile->size - have;
            if (copy > len)
                copy = len;
            memcpy(gzfile->in + have, buf, copy);
            strm->avail_in += copy;
            gzfile->pos += copy;
            buf = (const char *) buf + copy;
            len -= copy;
            if (len && ecr_gzip_comp(gzfile, Z_NO_FLUSH) == -1)
                return 0;
        } while (len);
    } else {
        /* consume whatever's left in the input buffer */
        if (strm->avail_in && ecr_gzip_comp(gzfile, Z_NO_FLUSH) == -1)
            return 0;

        /* directly compress user buffer to file */
        strm->avail_in = len;
        strm->next_in = (z_const Bytef *) buf;
        gzfile->pos += len;
        if (ecr_gzip_comp(gzfile, Z_NO_FLUSH) == -1)
            return 0;
    }

    /* input was all buffered or compressed (put will fit in int) */
    return put;
}

static int ecr_gzip_seek(void *cookie, off64_t *off, int whence) {
    unsigned n;
    int ret;
    ecr_gzip_file_t *gzfile = cookie;
    off64_t offset = *off;

    /* get internal structure and check integrity */
    if (gzfile == NULL)
        return -1;
    if (gzfile->mode != GZ_READ && gzfile->mode != GZ_WRITE)
        return -1;

    /* check that there's no error */
    if (gzfile->err != Z_OK && gzfile->err != Z_BUF_ERROR)
        return -1;

    /* can only seek from start or relative to current position */
    if (whence != SEEK_SET && whence != SEEK_CUR)
        return -1;

    /* normalize offset to a SEEK_CUR specification */
    if (whence == SEEK_SET)
        offset -= gzfile->pos;
    else if (gzfile->seek)
        offset += gzfile->skip;
    gzfile->seek = 0;

    /* if within raw area while reading, just go there */
    if (gzfile->mode == GZ_READ && gzfile->how == COPY && gzfile->pos + offset >= 0) {
        ret = fseek(gzfile->source, offset - gzfile->have, SEEK_CUR);
        if (ret == -1)
            return -1;
        gzfile->have = 0;
        gzfile->eof = 0;
        gzfile->past = 0;
        gzfile->seek = 0;
        gzfile->err = Z_OK;
        gzfile->stream.avail_in = 0;
        *off = gzfile->pos += offset;
        return 0;
    }

    /* calculate skip amount, rewinding if needed for back seek when reading */
    if (offset < 0) {
        if (gzfile->mode != GZ_READ) /* writing -- can't go backwards */
            return -1;
        offset += gzfile->pos;
        if (offset < 0) /* before start of file! */
            return -1;
        if (ecr_gzip_rewind(gzfile) == -1) /* rewind, then skip to offset */
            return -1;
    }

    /* if reading, skip what's in output buffer (one less gzgetc() check) */
    if (gzfile->mode == GZ_READ) {
        n = GT_OFF(gzfile->have) || (int) gzfile->have > offset ? (unsigned) offset : gzfile->have;
        gzfile->have -= n;
        gzfile->next += n;
        gzfile->pos += n;
        offset -= n;
    }

    /* request skip (if not zero) */
    if (offset) {
        gzfile->seek = 1;
        gzfile->skip = offset;
    }
    *off = gzfile->pos + offset;
    return 0;
}

static int ecr_gzip_close_r(ecr_gzip_file_t *gzfile) {
    int ret, err;

    /* get internal structure */
    if (gzfile == NULL)
        return Z_STREAM_ERROR;

    /* check that we're reading */
    if (gzfile->mode != GZ_READ)
        return Z_STREAM_ERROR;

    /* free memory and close file */
    if (gzfile->size) {
        inflateEnd(&(gzfile->stream));
        free(gzfile->out);
        free(gzfile->in);
    }
    err = gzfile->err == Z_BUF_ERROR ? Z_BUF_ERROR : Z_OK;
    ret = fclose(gzfile->source);
    return ret ? Z_ERRNO : err;
}

static int ecr_gzip_close_w(ecr_gzip_file_t *gzfile) {
    int ret = Z_OK;

    /* get internal structure */
    if (gzfile == NULL)
        return Z_STREAM_ERROR;

    /* check that we're writing */
    if (gzfile->mode != GZ_WRITE) {
        return Z_STREAM_ERROR;
    }

    /* check for seek request */
    if (gzfile->seek) {
        gzfile->seek = 0;
        if (ecr_gzip_zero(gzfile, gzfile->skip) == -1)
            ret = gzfile->err;
    }

    /* flush, free memory, and close file */
    if (ecr_gzip_comp(gzfile, Z_FINISH) == -1)
        ret = gzfile->err;
    if (gzfile->size) {
        if (!gzfile->direct) {
            (void) deflateEnd(&(gzfile->stream));
            free(gzfile->out);
        }
        free(gzfile->in);
    }
    if (fclose(gzfile->source) == -1)
        ret = Z_ERRNO;
    return ret;
}

static int ecr_gzip_close(void *cookie) {
    ecr_gzip_file_t *gzfile = cookie;

    if (gzfile == NULL)
        return Z_STREAM_ERROR;

    int rc = (gzfile->mode == GZ_READ ? ecr_gzip_close_r(gzfile) : ecr_gzip_close_w(gzfile));
    ecr_config_destroy(&gzfile->config);
    free(gzfile);
    return rc;
}

static cookie_io_functions_t ecr_gzip_io_functions = { .read = ecr_gzip_read, .write = ecr_gzip_write, .seek =
        ecr_gzip_seek, .close = ecr_gzip_close };

FILE * ecr_gzip_open(FILE *file, const char *options) {
    FILE *ret;
    int buf_size = GZBUFSIZE;
    char *mode = NULL, *cookie_mode = NULL, *smode;
    ecr_config_line_t cfg_lines[] = {
    //
            { "mode", &smode, ECR_CFG_STRING }, //
            { "bufsize", &buf_size, ECR_CFG_INT, .dv.i = GZBUFSIZE }, //
            { 0 } };

    ecr_gzip_file_t *gzfile = calloc(1, sizeof(ecr_gzip_file_t));
    if (ecr_config_init_str(&gzfile->config, options) || ecr_config_load(&gzfile->config, NULL, cfg_lines)
            || ecr_config_print_unused(NULL, &gzfile->config)) {
        L_ERROR("invalid gzip options: %s", options);
        ecr_config_destroy(&gzfile->config);
        free(gzfile);
        return NULL;
    }
    gzfile->size = 0;
    gzfile->want = buf_size;
    gzfile->mode = GZ_NONE;
    gzfile->level = Z_DEFAULT_COMPRESSION;
    gzfile->strategy = Z_DEFAULT_STRATEGY;
    gzfile->direct = 0;
    gzfile->source = file;
    mode = smode;
    while (*mode) {
        if (*mode >= '0' && *mode <= '9')
            gzfile->level = *mode - '0';
        else
            switch (*mode) {
            case 'r':
                gzfile->mode = GZ_READ;
                cookie_mode = "r";
                break;
            case 'w':
                gzfile->mode = GZ_WRITE;
                cookie_mode = "w";
                break;
            case 'a':
                gzfile->mode = GZ_APPEND;
                cookie_mode = "a";
                break;
            case '+': /* can't read and write at the same time */
                free(gzfile);
                return NULL;
            case 'b': /* ignore -- will request binary anyway */
                break;
            case 'f':
                gzfile->strategy = Z_FILTERED;
                break;
            case 'h':
                gzfile->strategy = Z_HUFFMAN_ONLY;
                break;
            case 'R':
                gzfile->strategy = Z_RLE;
                break;
            case 'F':
                gzfile->strategy = Z_FIXED;
                break;
            case 'T':
                gzfile->direct = 1;
                break;
            default: /* could consider as an error, but just ignore */
                ;
            }
        mode++;
    }

    /* must provide an "r", "w", or "a" */
    if (gzfile->mode == GZ_NONE) {
        ecr_config_destroy(&gzfile->config);
        free(gzfile);
        L_ERROR("invalid mode.");
        return NULL;
    }

    /* can't force transparent read */
    if (gzfile->mode == GZ_READ) {
        if (gzfile->direct) {
            ecr_config_destroy(&gzfile->config);
            free(gzfile);
            L_ERROR("b");
            return NULL;
        }
        gzfile->direct = 1; /* for empty file */
    }

    if (gzfile->mode == GZ_APPEND)
        gzfile->mode = GZ_WRITE; /* simplify later checks */

    /* save the current position for rewinding (only if reading) */
    if (gzfile->mode == GZ_READ) {
        gzfile->start = fseek(gzfile->source, 0, SEEK_CUR);
        if (gzfile->start == -1)
            gzfile->start = 0;
    }

    /* initialize stream */
    ecr_gzip_reset(gzfile);

    ret = fopencookie(gzfile, cookie_mode, ecr_gzip_io_functions);
    if (!ret) {
        ecr_config_destroy(&gzfile->config);
        free(gzfile);
    }
    return ret;
}
