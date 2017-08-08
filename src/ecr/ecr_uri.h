/*
 * ecr_uri.h
 *
 *  Created on: Aug 7, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_URI_H_
#define SRC_ECR_ECR_URI_H_

#include "ecrconf.h"
#include <uriparser/Uri.h>

typedef struct {
    char *string;
    bool absolute_path;
    bool absolute;
    char *scheme;
    char *fragment;
    char *user_info;
    char *host;
    int port;
    char *path;
    char *query;

    //private fields
    UriUriA _uri;
} ecr_uri_t;

int ecr_uri_init(ecr_uri_t *uri, const char *str);

int ecr_uri_resolve(ecr_uri_t *uri, const char *relative_uri, ecr_uri_t *uri_out);

void ecr_uri_destroy(ecr_uri_t *uri);

#endif /* SRC_ECR_ECR_URI_H_ */
