/*
 * ecr_util_mongoc.h
 *
 *  Created on: Sep 11, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_UTIL_MONGOC_H_
#define SRC_ECR_ECR_UTIL_MONGOC_H_

#include "ecrconf.h"
#include <mongoc.h>

/**
 * find first record of query, return true if result is only one.
 * update doc_out to the first record found, set to NULL if result is empty.
 */
bool ecr_mongoc_collection_find_one(mongoc_collection_t *collection, const bson_t *filter,
        const mongoc_read_prefs_t *read_prefs, bson_t **doc_out, bson_error_t *err);

bson_t * ecr_mongoc_collection_find_by_id(mongoc_collection_t *collection, const char *id,
        const mongoc_read_prefs_t *read_prefs, bson_error_t *err);

#endif /* SRC_ECR_ECR_UTIL_MONGOC_H_ */
