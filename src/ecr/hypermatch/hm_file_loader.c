/*
 * hm_file_loader.c
 *
 *  Created on: Aug 3, 2017
 *      Author: velna
 */

#include "hm_loader.h"
#include "ecr_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>

#define HM_FILE_ATTR_MTIME  "FILE_MTIME"

static int ecr_hm_file_load(ecr_hm_source_t *source, int force_reload, ecr_hm_source_data_t *source_data) {
    time_t m_time;
    struct stat st;
    FILE *stream;
    int rc;

    L_INFO("load from file: %s", source->uri.path);

    m_time = (time_t) (ecr_hashmap_get(&source->attrs, HM_FILE_ATTR_MTIME, strlen(HM_FILE_ATTR_MTIME)) - NULL);

    if (stat(source->uri.path, &st) == 0 && !force_reload && st.st_mtim.tv_sec == m_time) {
        return 0;
    }

    stream = fopen(source->uri.path, "r");
    if (NULL == stream) {
        ecr_hm_error(source->hm, "can not open %s for read: %s", source->uri.path, strerror(errno));
        return -1;
    }

    rc = ecr_hm_load_from_stream(source, stream, source_data);
    if (rc != -1) {
        ecr_hashmap_put(&source->attrs, HM_FILE_ATTR_MTIME, strlen(HM_FILE_ATTR_MTIME), st.st_mtim.tv_sec + NULL);
        L_INFO("load %d items from file %s", rc, source->uri.path);
    }
    fclose(stream);
    return rc;
}

static int ecr_hm_file_load_values(ecr_hm_source_t *source, ecr_uri_t *uri, ecr_list_t *values) {
    L_INFO("load values from file: %s", uri->path);

    FILE *stream = fopen(source->uri.path, "r");
    int rc = ecr_hm_load_values_from_stream(source, stream, values);
    fclose(stream);
    return rc;
}

ecr_hm_loader_t ecr_hm_file_loader = {
//
        .scheme = "file",
        .load = ecr_hm_file_load,
        .load_values = ecr_hm_file_load_values };
