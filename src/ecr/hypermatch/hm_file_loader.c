/*
 * hm_file_loader.c
 *
 *  Created on: Aug 3, 2017
 *      Author: velna
 */

#include "hm_loader.h"
#include "ecr_logger.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>

#define HM_FILE_ATTR_MTIME  "FILE_MTIME"

static int ecr_hm_file_load(ecr_hm_source_t *source, int force_reload, ecr_hm_source_data_t *source_data, void *user) {
    struct stat st, *last_stat;
    FILE *stream;
    int rc;
//    ecr_uri_t uri, *base_uri = user;
    char *uri_path = source->uri.path;

//    if (!source->uri.absolute_path) {
//        uri_path = strdup(source->uri.path);
//        ecr_uri_destroy(&source->uri);
//        if (ecr_uri_resolve(base_uri, uri_path, &source->uri)) {
//            ecr_hm_error(source->hm, "error resolve uri '%s'.", source->uri.path);
//            free(uri_path);
//            return -1;
//        }
//        free(uri_path);
//    }
//    uri_path = strdup(source->uri.path);
    L_INFO("load from file: %s", uri_path);

    last_stat = ecr_hashmap_get(&source->attrs, HM_FILE_ATTR_MTIME, strlen(HM_FILE_ATTR_MTIME));

    if (stat(uri_path, &st) == 0 && !force_reload && last_stat && st.st_mtim.tv_sec == last_stat->st_mtim.tv_sec) {
//        free(uri_path);
        return 0;
    }

    stream = fopen(uri_path, "r");
    if (NULL == stream) {
        ecr_hm_error(source->hm, "can not open %s for read: %s", uri_path, strerror(errno));
//        free(uri_path);
        return -1;
    }

    rc = ecr_hm_load_from_stream(source, stream, source_data, user);
    if (rc != -1) {
        if (!last_stat) {
            last_stat = malloc(sizeof(struct stat));
            ecr_hashmap_put(&source->attrs, HM_FILE_ATTR_MTIME, strlen(HM_FILE_ATTR_MTIME), last_stat);
        }
        memcpy(last_stat, &st, sizeof(struct stat));
        L_INFO("load %d items from file %s", rc, uri_path);
    }
    fclose(stream);
//    free(uri_path);
    return rc;
}

static int ecr_hm_file_load_values(ecr_hm_source_t *source, ecr_uri_t *uri, ecr_list_t *values, void *user) {
    L_INFO("load values from file: %s", uri->path);

    FILE *stream = fopen(source->uri.path, "r");
    int rc = ecr_hm_load_values_from_stream(source, stream, values, user);
    fclose(stream);
    return rc;
}

ecr_hm_loader_t ecr_hm_file_loader = {
//
        .scheme = "file",
        .load = ecr_hm_file_load,
        .load_values = ecr_hm_file_load_values
//
        };

//ecr_hm_loader_t * ecr_hm_file_loader_new(const char *base_dir) {
//    ecr_uri_t base_uri, root_uri, *uri = NULL;
//    int rc;
//    const char *bdir;
//    ecr_hm_loader_t *loader = NULL;
//
//    bdir = base_dir ? base_dir : getcwd(NULL, 0);
//    if (ecr_uri_init(&base_uri, bdir)) {
//        goto end;
//    }
//    uri = calloc(1, sizeof(ecr_uri_t));
//    if (!base_uri.absolute_path) {
//        ecr_uri_init(&root_uri, "file:///");
//        rc = ecr_uri_resolve(&root_uri, bdir, uri);
//        ecr_uri_destroy(&root_uri);
//        ecr_uri_destroy(&base_uri);
//        if (rc) {
//            free(uri);
//            goto end;
//        }
//    } else {
//        ecr_uri_destroy(&base_uri);
//        ecr_uri_init(uri, bdir);
//    }
//    loader = calloc(1, sizeof(ecr_hm_loader_t));
//    loader->load = ecr_hm_file_load;
//    loader->load_values = ecr_hm_file_load_values;
//    loader->scheme = "file";
//    loader->user = uri;
//    end: {
//        if (bdir != base_dir) {
//            free_to_null(bdir);
//        }
//        return loader;
//    }
//}
