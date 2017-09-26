/*
 * ecr_util_mongoc.c
 *
 *  Created on: Sep 11, 2017
 *      Author: velna
 */

#include "config.h"
#include "ecr_util_mongoc.h"

bool ecr_mongoc_collection_find_one(mongoc_collection_t *collection, const bson_t *filter,
        const mongoc_read_prefs_t *read_prefs, bson_t **doc_out, bson_error_t *err) {
    bool rc;
    bson_t *opts = BCON_NEW("limit", BCON_INT64(2), "batchSize", BCON_INT64(2));
    const bson_t *doc;
    mongoc_cursor_t *cursor = mongoc_collection_find_with_opts(collection, filter, opts, read_prefs);
    if (mongoc_cursor_next(cursor, &doc)) {
        *doc_out = bson_copy(doc);
        rc = !mongoc_cursor_next(cursor, &doc);
    } else {
        *doc_out = NULL;
        rc = true;
    }
    if (!mongoc_cursor_error(cursor, err)) {
        err->code = 0;
        err->domain = 0;
        err->message[0] = '\0';
    }
    mongoc_cursor_destroy(cursor);
    bson_destroy(opts);
    return rc;
}

bson_t * ecr_mongoc_collection_find_by_id(mongoc_collection_t *collection, const char *id,
        const mongoc_read_prefs_t *read_prefs, bson_error_t *err) {
    bson_oid_t oid;
    const bson_t *doc = NULL;
    bson_oid_init_from_string(&oid, id);
    bson_t *filter = BCON_NEW("_id", BCON_OID(&oid));
    mongoc_cursor_t *cursor = mongoc_collection_find_with_opts(collection, filter, NULL, read_prefs);
    mongoc_cursor_next(cursor, &doc);
    if (!mongoc_cursor_error(cursor, err)) {
        err->code = 0;
        err->domain = 0;
        err->message[0] = '\0';
    }
    mongoc_cursor_destroy(cursor);
    bson_destroy(filter);
    return bson_copy(doc);
}
