/*
 * ecr_uri.c
 *
 *  Created on: Aug 7, 2017
 *      Author: velna
 */

#include "config.h"
#include "ecr_uri.h"

static char * uri_get_string(UriTextRangeA *range) {
    if (!range->first) {
        return NULL;
    }
    if (range->afterLast) {
        return strndup(range->first, range->afterLast - range->first);
    } else {
        return strdup(range->first);
    }
}

static char * uri_get_path(ecr_uri_t *uri) {
    char *buf = NULL;
    size_t len = 0;
    FILE *stream;
    UriPathSegmentA *p;

    if (!uri->_uri.pathHead && !uri->_uri.absolutePath) {
        return NULL;
    }

    stream = open_memstream(&buf, &len);
    if (uri->absolute_path) {
        fputc('/', stream);
    }
    for (p = uri->_uri.pathHead; p; p = p->next) {
        if (p != uri->_uri.pathHead) {
            fputc('/', stream);
        }
        if (p->text.first) {
            if (p->text.afterLast) {
                fwrite(p->text.first, p->text.afterLast - p->text.first, 1, stream);
            } else {
                fputs(p->text.first, stream);
            }
        }
    }
    fclose(stream);
    return buf;
}

static int ecr_uri_set_fields(ecr_uri_t *uri) {
    char *s;
    int n;

    uriNormalizeSyntaxA(&uri->_uri);
    uri->scheme = uri_get_string(&uri->_uri.scheme);
    uri->fragment = uri_get_string(&uri->_uri.fragment);
    uri->query = uri_get_string(&uri->_uri.query);
    uri->user_info = uri_get_string(&uri->_uri.userInfo);
    uri->host = uri_get_string(&uri->_uri.hostText);
    if ((s = uri_get_string(&uri->_uri.portText))) {
        uri->port = atoi(s);
        free(s);
    }

    uri->absolute_path = uri->_uri.absolutePath == URI_TRUE || uri->host != NULL || uri->scheme != NULL;
    uri->absolute = uri->scheme != NULL;

    if (!uri->_uri.pathHead && !uri->_uri.absolutePath) {
        uri->path = NULL;
    } else {
        uri->path = uri_get_path(uri);
    }

    if (uriToStringCharsRequiredA(&uri->_uri, &n) != URI_SUCCESS) {
        return -1;
    }
    n++;
    uri->string = malloc(n * sizeof(char));
    if (uriToStringA(uri->string, &uri->_uri, n, NULL) != URI_SUCCESS) {
        free_to_null(uri->string);
        return -1;
    }
    return 0;
}

int ecr_uri_init(ecr_uri_t *uri, const char *str) {
    UriParserStateA state;

    memset(uri, 0, sizeof(ecr_uri_t));
    state.uri = &uri->_uri;
    if (uriParseUriA(&state, str) != URI_SUCCESS) {
        uriFreeUriMembersA(&uri->_uri);
        return -1;
    }

    if (ecr_uri_set_fields(uri)) {
        ecr_uri_destroy(uri);
        return -1;
    } else {
        return 0;
    }
}

int ecr_uri_resolve(ecr_uri_t *uri, const char *relative_uri, ecr_uri_t *uri_out) {
    UriParserStateA state;
    UriUriA relative;

    state.uri = &relative;
    if (uriParseUriA(&state, relative_uri) != URI_SUCCESS) {
        uriFreeUriMembersA(&relative);
        return -1;
    }

    memset(uri_out, 0, sizeof(ecr_uri_t));
    if (uriAddBaseUriA(&uri_out->_uri, &relative, &uri->_uri) != URI_SUCCESS) {
        uriFreeUriMembersA(&uri_out->_uri);
        return -1;
    }
    if (ecr_uri_set_fields(uri_out)) {
        ecr_uri_destroy(uri_out);
        return -1;
    } else {
        return 0;
    }
}

void ecr_uri_destroy(ecr_uri_t *uri) {
    free_to_null(uri->string);
    free_to_null(uri->fragment);
    free_to_null(uri->host);
    free_to_null(uri->path);
    free_to_null(uri->user_info);
    free_to_null(uri->query);
    free_to_null(uri->scheme);
    uriFreeUriMembersA(&uri->_uri);
}

