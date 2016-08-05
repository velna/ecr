/*
 * ecr_io_rollingfile.c
 *
 *  Created on: Jul 31, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_io.h"
#include "ecr_config.h"
#include "ecr_logger.h"
#include "ecr_list.h"
#include "ecr_util.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <libgen.h>

#define P_NONE  0
#define P_TIME  1
#define P_VAR   2

typedef struct {
    char hostname[256];
    int id;
    int batch;
} ecr_vars_t;

typedef struct {
    char *options;
    char *rename_pattern;
    ecr_io_chain_func chain_func;
} ecr_io_wrapper_t;

typedef struct {
    int id;
    char *pattern;
    char *filename; // if tmp > 0, its tmp name, otherwise its real name
    char *mode;
    mode_t chmod;
    int uid;
    int gid;
    int mkdirs;
    uint64_t rtime;
    int ctime;
    uint64_t rsize;
    struct tm last_check;
    uint64_t w_time;
    uint64_t w_size;
    FILE *source;
    ecr_list_t *wrappers;
    ecr_vars_t vars;
    char *tmp;
    int tmplen;
    int closed :1;
    pthread_mutex_t lock;
    ecr_config_t *config;
} ecr_rollingfile_t;

static pthread_once_t ecr_rf_cheker_oc = PTHREAD_ONCE_INIT;
static ecr_list_t ecr_rf_list;

static char * ecr_fmt_pattern(const char *pattern, const struct tm *t, ecr_vars_t *vars, const char *tmp) {
    const char *s = pattern;
    int f;
    char *ret, ch;
    size_t size = 0;
    FILE *stream = open_memstream(&ret, &size);
    f = P_NONE;
    while ((ch = *s)) {
        switch (f) {
        case P_TIME:
            switch (ch) {
            case '%':
                fputc(ch, stream);
                break;
            case 'Y':
                fprintf(stream, "%d", t->tm_year + 1900);
                break;
            case 'm':
                fprintf(stream, "%02d", t->tm_mon + 1);
                break;
            case 'd':
                fprintf(stream, "%02d", t->tm_mday);
                break;
            case 'H':
                fprintf(stream, "%02d", t->tm_hour);
                break;
            case 'M':
                fprintf(stream, "%02d", t->tm_min);
                break;
            case 'S':
                fprintf(stream, "%02d", t->tm_sec);
                break;
            case 'w':
                fprintf(stream, "%02d", t->tm_wday);
                break;
            case 'j':
                fprintf(stream, "%03d", t->tm_yday);
                break;
            default:
                L_ERROR("invalid conversion: %%%c", ch);
                fclose(stream);
                free(ret);
                return NULL;
            }
            f = P_NONE;
            break;
        case P_VAR:
            switch (ch) {
            case '$':
                fputc(ch, stream);
                break;
            case 'H':
                fprintf(stream, "%s", vars->hostname);
                break;
            case 'p':
                fprintf(stream, "%d", getpid());
                break;
            case 't':
                fprintf(stream, "%ld", syscall(SYS_gettid));
                break;
            case 'i':
                fprintf(stream, "%d", vars->id);
                break;
            case 'b':
                fprintf(stream, "%d", vars->batch);
                break;
            default:
                L_ERROR("invalid variable: $%c", ch);
                fclose(stream);
                free(ret);
                return NULL;
            }
            f = P_NONE;
            break;
        default:
            switch (ch) {
            case '%':
                f = P_TIME;
                break;
            case '$':
                f = P_VAR;
                break;
            default:
                fputc(ch, stream);
                break;
            }
            break;
        }
        s++;
    }
    if (tmp) {
        fprintf(stream, "%s", tmp);
    }
    fclose(stream);
    if (f != P_NONE) {
        free(ret);
        L_ERROR("incomplete conversion: %%");
        return NULL;
    }
    return ret;
}

static int ecr_rf_close0(ecr_rollingfile_t *rf) {
    char *fn, *rfn, *renamefile;
    int i, rc;
    ecr_io_wrapper_t *wrapper;

    rc = fclose(rf->source);
    fn = strdup(rf->filename);
    if (rf->tmp) {
        rfn = strndup(rf->filename, strlen(rf->filename) - rf->tmplen);
    } else {
        rfn = strdup(rf->filename);
    }

    for (i = 0; i < ecr_list_size(rf->wrappers); i++) {
        wrapper = ecr_list_get(rf->wrappers, i);
        if (wrapper->rename_pattern) {
            asprintf(&renamefile, wrapper->rename_pattern, rfn);
            if (rename(fn, renamefile)) {
                L_ERROR("error rename file %s to %s", fn, renamefile);
                free(renamefile);
                break;
            }
            if (rfn != fn) {
                free(rfn);
            }
            free(fn);
            rfn = fn = renamefile;
        }
    }

    if (rfn != fn) {
        free(rfn);
    }
    free(fn);
    return rc;
}

static int ecr_rf_maybe_open(ecr_rollingfile_t *rf, struct tm *stm, int batch) {
    int fd, i;
    FILE *file, *wrapped;
    char *filename, *path, *dir;
    time_t t;
    struct tm stm0;
    ecr_io_wrapper_t *wrapper;

    if (!stm) {
        t = time(NULL);
        localtime_r(&t, &stm0);
        stm = &stm0;
    }

    filename = ecr_fmt_pattern(rf->pattern, stm, &rf->vars, rf->tmp);
    if (!filename) {
        return -1;
    }
    if (rf->filename && strcmp(filename, rf->filename) == 0) {
        free(filename);
        if (batch) {
            rf->vars.batch++;
            filename = ecr_fmt_pattern(rf->pattern, stm, &rf->vars, rf->tmp);
            if (!filename) {
                return -1;
            }
            if (strcmp(filename, rf->filename) == 0) {
                free(filename);
                return 0;
            }
        } else {
            return 0;
        }
    } else {
        rf->vars.batch = 0;
    }

    if (rf->mkdirs) {
        path = strdup(filename);
        dir = dirname(path);
        if (dir && ecr_mkdirs(dir, rf->mkdirs)) {
            free(path);
            L_ERROR("error mkdir %s: %s", dir, strerror(errno));
            return -1;
        }
        free(path);
    }

    file = fopen(filename, rf->mode);
    if (!file) {
        L_ERROR("error open file %s: %s", filename, strerror(errno));
        free(filename);
        return -1;
    }
    fd = fileno(file);
    if (rf->uid >= 0 && rf->gid >= 0) {
        if (fchown(fd, rf->uid, rf->gid)) {
            L_WARN("error chown of file %s: %s", filename, strerror(errno));
        }
    }
    if (rf->chmod) {
        if (fchmod(fd, rf->chmod)) {
            L_WARN("error chmod of file %s: %s", filename, strerror(errno));
        }
    }
    for (i = 0; i < ecr_list_size(rf->wrappers); i++) {
        wrapper = ecr_list_get(rf->wrappers, i);
        wrapped = wrapper->chain_func(file, wrapper->options);
        if (!wrapped) {
            fclose(file);
            free(filename);
            return -1;
        }
        file = wrapped;
    }

    if (rf->source) {
        ecr_rf_close0(rf);
    }
    rf->source = file;
    free_to_null(rf->filename);
    rf->filename = filename;
    rf->last_check = *stm;
    rf->w_time = ecr_current_time();
    rf->w_size = 0;
    return 0;
}

static void * ecr_rf_check_routin(void *user) {
    int i;
    ecr_rollingfile_t *rf;
    struct timespec sleep_time = { 0, 200000000 };
    time_t t;
    struct tm stm;
    u_int64_t now;

    ecr_set_thread_name("rfckr");
    while (1) {
        for (i = 0; i < ecr_list_size(&ecr_rf_list); i++) {
            rf = ecr_list_get(&ecr_rf_list, i);
            if (rf->closed) {
                ecr_list_remove_at(&ecr_rf_list, i--);
                free(rf);
                continue;
            }
            if (!rf->w_size) {
                continue;
            }
            now = ecr_current_time();
            t = time(NULL);
            localtime_r(&t, &stm);
//            if (rf->ctime && t != mktime(&rf->last_check) && t % rf->ctime == 0) {
            if (rf->ctime && rf->last_check.tm_min != stm.tm_min && stm.tm_min % rf->ctime == 0) {
                pthread_mutex_lock(&rf->lock);
                ecr_rf_maybe_open(rf, &stm, 0);
                pthread_mutex_unlock(&rf->lock);
            } else if (rf->rtime && rf->w_time + rf->rtime <= now) {
                pthread_mutex_lock(&rf->lock);
                ecr_rf_maybe_open(rf, &stm, 1);
                pthread_mutex_unlock(&rf->lock);
            } else if (!rf->rsize) {
                if (rf->last_check.tm_min == stm.tm_min) {
                    continue;
                }
                rf->last_check = stm;
                pthread_mutex_lock(&rf->lock);
                ecr_rf_maybe_open(rf, &stm, 0);
                pthread_mutex_unlock(&rf->lock);
            }
        }
        nanosleep(&sleep_time, NULL);
    }
    return NULL;
}

static void ecr_rf_checker_init() {
    pthread_attr_t attr;
    pthread_t thread;

    ecr_list_init(&ecr_rf_list, 16);

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thread, &attr, ecr_rf_check_routin, NULL);
    pthread_attr_destroy(&attr);
}

static ssize_t ecr_rf_read(void *cookie, char *buf, size_t len) {
    L_ERROR("read on rolling file is not supported.");
    return -1;
}

static ssize_t ecr_rf_write(void *cookie, const char *buf, size_t len) {
    ecr_rollingfile_t *rf = cookie;
    int rc;
    if (!rf) {
        return -1;
    }
    if (rf->source) {
        pthread_mutex_lock(&rf->lock);
        rc = fwrite(buf, 1, len, rf->source);
        rf->w_size += rc;
        if (rf->rsize && rf->w_size >= rf->rsize) {
            ecr_rf_maybe_open(rf, NULL, 1);
        }
        pthread_mutex_unlock(&rf->lock);
    } else {
        rc = -1;
    }

    return rc;
}

static int ecr_rf_seek(void *cookie, off64_t *off, int whence) {
    L_ERROR("seek on rolling file is not supported.");
    errno = EBADF;
    return -1;
}

static void ecr_io_destroy_wrapper_handler(ecr_list_t *l, int i, void *value) {
    ecr_io_wrapper_t *wrapper = value;
    free(wrapper->options);
    free(wrapper->rename_pattern);
    free(wrapper);
}

static int ecr_rf_close(void *cookie) {
    ecr_rollingfile_t *rf = cookie;
    int rc;
    if (!rf) {
        return -1;
    }
    if (rf->source) {
        rc = ecr_rf_close0(rf);
        rf->source = NULL;
    } else {
        rc = -1;
    }
    free_to_null(rf->filename);
    free_to_null(rf->pattern);
    if (rf->wrappers) {
        ecr_list_destroy(rf->wrappers, ecr_io_destroy_wrapper_handler);
        rf->wrappers = NULL;
    }
    rf->closed = 1;
    if (rf->config) {
        ecr_config_destroy(rf->config);
        free_to_null(rf->config);
    }
    return rc;
}

static cookie_io_functions_t ecr_rf_io_functions = {
        .read = ecr_rf_read,
        .write = ecr_rf_write,
        .seek = ecr_rf_seek,
        .close = ecr_rf_close };

FILE * ecr_rollingfile_open(const char *filestr, int id, ecr_io_reg_t *regs) {
    FILE *ret;
    size_t bufsize;
    int rc, found;
    char *chown = NULL, *gid, *uid, *buf, *ss = NULL, *chain, *name, *options, *s, *rf_options = NULL;
    struct passwd pwd, *pwd_r;
    struct group grp, *grp_r;
    ecr_rollingfile_t *rf = calloc(1, sizeof(ecr_rollingfile_t));
    ecr_io_reg_t *reg;
    ecr_io_wrapper_t *wrapper;

    ecr_config_line_t cfg_lines[] = {
    //
            { "mode", &rf->mode, ECR_CFG_STRING, .dv.s = "w" }, //
            { "chown", &chown, ECR_CFG_STRING }, //
            { "chmod", &rf->chmod, ECR_CFG_INT }, //
            { "rtime", &rf->rtime, ECR_CFG_INT }, //
            { "ctime", &rf->ctime, ECR_CFG_INT }, //
            { "rsize", &rf->rsize, ECR_CFG_UINT64 }, //
            { "mkdir", &rf->mkdirs, ECR_CFG_INT }, //
            { "tmp", &rf->tmp, ECR_CFG_STRING }, //
            { 0 } };

    s = strdup(filestr);
    chain = strtok_r(s, "|", &ss);
    if (chain) {
        if ((rf_options = strchr(chain, ':'))) {
            *rf_options = '\0';
            rf_options++;
        }
        rf->pattern = strdup(chain);
    } else {
        ecr_rf_close(rf);
        free(s);
        return NULL;
    }
    rf->wrappers = ecr_list_new(16);
    chain = strtok_r(NULL, "|", &ss);
    while (chain) {
        name = chain;
        if ((options = strchr(chain, ':'))) {
            options[0] = '\0';
            options++;
        }
        reg = regs;
        found = 0;
        while (reg && reg->name) {
            if (strcmp(reg->name, name) == 0) {
                found = 1;
                wrapper = calloc(1, sizeof(ecr_io_wrapper_t));
                wrapper->options = strdup(options);
                wrapper->rename_pattern = strdup(reg->rename_pattern);
                wrapper->chain_func = reg->chain_func;
                ecr_list_add(rf->wrappers, wrapper);
            }
            reg++;
        }
        if (!found) {
            L_ERROR("invalid io name: %s", name);
            ecr_rf_close(rf);
            free(s);
            return NULL;
        }
        chain = strtok_r(NULL, "|", &ss);
    }
    rf->config = calloc(1, sizeof(ecr_config_t));
    if (ecr_config_init_str(rf->config, rf_options) || ecr_config_load(rf->config, NULL, cfg_lines)
            || ecr_config_print_unused(NULL, rf->config)) {
        L_ERROR("invalid rolling file options: %s", rf_options);
        ecr_rf_close(rf);
        free(rf);
        return NULL;
    }
    free(s);

    rf->rtime *= 1000;
    if (rf->ctime) {
        rf->ctime = rf->ctime / 60;
    }

    if (chown) {
        uid = chown;
        if ((gid = strchr(chown, ':'))) {
            gid[0] = '\0';
            gid++;
        } else {
            gid = uid;
        }
        bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize == -1) /* Value was indeterminate */
            bufsize = 16384; /* Should be more than enough */

        buf = malloc(bufsize);
        rc = getpwnam_r(uid, &pwd, buf, bufsize, &pwd_r);
        if (pwd_r == NULL) {
            if (rc == 0) {
                L_ERROR("user %s not found.", uid);
            } else {
                L_ERROR("getpwnam_r(): %s", strerror(errno));
            }
            ecr_rf_close(rf);
            free(buf);
            free(rf);
            return NULL;
        }
        rf->uid = pwd.pw_uid;
        free(buf);

        bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
        if (bufsize == -1) /* Value was indeterminate */
            bufsize = 16384; /* Should be more than enough */

        buf = malloc(bufsize);
        rc = getgrnam_r(uid, &grp, buf, bufsize, &grp_r);
        if (grp_r == NULL) {
            if (rc == 0) {
                L_ERROR("group %s not found.", uid);
            } else {
                L_ERROR("getgrnam_r(): %s", strerror(errno));
            }
            ecr_rf_close(rf);
            free(buf);
            free(rf);
            return NULL;
        }
        rf->gid = grp.gr_gid;
        free(buf);
    } else {
        rf->uid = -1;
        rf->gid = -1;
    }

    rf->id = rf->vars.id = id;
//    rf->rtime *= 1000;
    if (gethostname(rf->vars.hostname, 256)) {
        strcpy(rf->vars.hostname, "localhost");
    }
    if (rf->tmp) {
        rf->tmplen = strlen(rf->tmp);
    }
    if (ecr_rf_maybe_open(rf, NULL, 0)) {
        ecr_rf_close(rf);
        free(rf);
        return NULL;
    }

    pthread_once(&ecr_rf_cheker_oc, ecr_rf_checker_init);
    ecr_list_add(&ecr_rf_list, rf);
    pthread_mutex_init(&rf->lock, NULL);

    ret = fopencookie(rf, rf->mode, ecr_rf_io_functions);
    if (!ret) {
        ecr_rf_close(rf);
        free(rf);
    } else {
        setvbuf(ret, NULL, _IONBF, 0);
    }
    return ret;
}
