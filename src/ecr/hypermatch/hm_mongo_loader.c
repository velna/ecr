/*
 * hm_mongo_loader.c
 *
 *  Created on: Sep 6, 2017
 *      Author: velna
 */

#include "config.h"
#include "hm_loader.h"
#include "ecr_util_mongoc.h"
#include <mongoc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MONGO_COLLECTION_HM         "hm"
#define MONGO_COLLECTION_LOGIC      "hm_logic"
#define MONGO_COLLECTION_ITEM       "hm_item"
#define MONGO_COLLECTION_FIELD      "hm_field"

#define MONGO_OID_STRLEN            25

#define bson_find_utf8(hm, iter, row, field, name) \
        if (!bson_iter_init_find(&iter, row, name) || bson_iter_type(&iter) != BSON_TYPE_UTF8) { \
            ecr_hm_error(hm, "can not find field '" name "' of type string"); \
            rc = -1; \
            goto end; \
        } \
        field = bson_iter_utf8(&iter, NULL);

#define bson_find_oid(hm, iter, row, field) \
        if (!bson_iter_init_find(&iter, row, "_id") || bson_iter_type(&iter) != BSON_TYPE_OID) { \
            ecr_hm_error(hm, "can not find field '_id' of type ObjectID"); \
            rc = -1; \
            goto end; \
        } \
        oid = bson_iter_oid(&iter); \
        bson_oid_to_string(oid, field);

typedef struct {
    mongoc_client_pool_t *pool;
} ecr_hm_mongo_loader_t;

static int ecr_hm_mongo_load_fields(ecr_hm_t *hm, ecr_hashmap_t *fields, mongoc_client_t *client, const char *dbname,
        mongoc_read_prefs_t *read_prefs) {
    int rc = 0;
    bson_t filter = BSON_INITIALIZER;
    const bson_t *row;
    bson_iter_t iter;
    bson_error_t err;
    const char *name;
    char id[MONGO_OID_STRLEN];
    const bson_oid_t *oid;
    mongoc_collection_t *collection_field = mongoc_client_get_collection(client, dbname, MONGO_COLLECTION_FIELD);
    mongoc_cursor_t *cursor = mongoc_collection_find_with_opts(collection_field, &filter, NULL, read_prefs);
    while (mongoc_cursor_next(cursor, &row)) {
        bson_find_oid(hm, iter, row, id)
        bson_find_utf8(hm, iter, row, name, "name")
        ecr_hashmap_put(fields, id, MONGO_OID_STRLEN, strdup(name));
    }
    if (mongoc_cursor_error(cursor, &err)) {
        ecr_hm_error(hm, "error execute find on collection [%s.%s]: %s", dbname, MONGO_COLLECTION_FIELD, err.message);
        rc = -1;
        goto end;
    }

    end: {
        mongoc_cursor_destroy(cursor);
        return rc;
    }
}

static int ecr_hm_mongo_load_items(ecr_hm_source_t *source, ecr_hm_source_data_t *source_data, const char *logic_id,
        mongoc_client_t *client, const char *dbname, mongoc_read_prefs_t *read_prefs) {
    int rc = 0;
    const bson_t *row;
    bson_t *filter = BCON_NEW("logic_id", BCON_UTF8(logic_id));
    const char *item;
    char *var_name;
    bson_error_t err;
    bson_iter_t iter;
    mongoc_collection_t *collection_item = mongoc_client_get_collection(client, dbname, MONGO_COLLECTION_ITEM);
    mongoc_cursor_t *cursor = mongoc_collection_find_with_opts(collection_item, filter, NULL, read_prefs);

    asprintf(&var_name, "$%s", logic_id);
    while (mongoc_cursor_next(cursor, &row)) {
        bson_find_utf8(source->hm, iter, row, item, "item")
        ecr_hm_source_data_add_value(source_data, var_name, item);
    }
    if (mongoc_cursor_error(cursor, &err)) {
        ecr_hm_error(source->hm, "error execute find on collection [%s.%s]: %s", dbname, MONGO_COLLECTION_ITEM,
                err.message);
        rc = -1;
        goto end;
    }

    end: {
        free(var_name);
        bson_destroy(filter);
        mongoc_cursor_destroy(cursor);
        return rc;
    }
}

static int ecr_hm_mongo_load(ecr_hm_source_t *source, int force_reload, ecr_hm_source_data_t *source_data, void *user) {
    ecr_hm_mongo_loader_t *loader = user;
    mongoc_client_t *client;
    mongoc_collection_t *collection_hm, *collection_logic;
    bson_t query;
    bson_iter_t iter;
    bson_error_t err;
    mongoc_read_prefs_t *read_prefs;
    bson_t *hm_row = NULL, *logic_row = NULL;
    mongoc_cursor_t *cursor = NULL;
    ecr_hashmap_t fields;
    char *expression = NULL, *field;
    const char *field_id, *match_type, *hm_expression;
    char logic_id[MONGO_OID_STRLEN];
    const bson_oid_t *oid;
    ecr_str_t expr = { NULL, 0 };
    FILE *expr_stream = NULL;

    if (!source->uri.query) {
        ecr_hm_error(source->hm, "no query specified on mongo uri: %s", source->uri.string);
        return -1;
    }

    char *path = strdup(source->uri.path), *s, *dbname;

    dbname = strtok_r(path, "/.", &s);
    if (!dbname) {
        ecr_hm_error(source->hm, "no db name specified on mongo uri: %s", source->uri.string);
        free(path);
        return -1;
    }

    if (!bson_init_from_json(&query, source->uri.query, -1, &err)) {
        ecr_hm_error(source->hm, "error init query of [%s]: %s", source->uri.query, err.message);
        free(path);
        return -1;
    }
    int rc;
    ecr_hashmap_init(&fields, 16, 0);
    read_prefs = mongoc_read_prefs_new(MONGOC_READ_PRIMARY_PREFERRED);
    client = mongoc_client_pool_pop(loader->pool);
    if (ecr_hm_mongo_load_fields(source->hm, &fields, client, dbname, read_prefs)) {
        rc = -1;
        goto end;
    }
    collection_hm = mongoc_client_get_collection(client, dbname, MONGO_COLLECTION_HM);

    if (!ecr_mongoc_collection_find_one(collection_hm, &query, read_prefs, &hm_row, &err)) {
        ecr_hm_error(source->hm, "more than 1 record find for query: [%s]", source->uri.query);
        rc = -1;
        goto end;
    }
    if (!hm_row) {
        ecr_hm_error(source->hm, "no record find for query: [%s]", source->uri.query);
        rc = -1;
        goto end;
    }
    if (err.code) {
        ecr_hm_error(source->hm, "error execute count [%s]: %s", source->uri.query, err.message);
        rc = -1;
        goto end;
    }

    bson_find_utf8(source->hm, iter, hm_row, hm_expression, "expression")
    expression = strdup(hm_expression);
    char *token = strtok_r(expression, " ", &s);
    expr_stream = open_memstream(&expr.ptr, &expr.len);
    collection_logic = mongoc_client_get_collection(client, dbname, MONGO_COLLECTION_LOGIC);
    while (token) {
        if (!strcasecmp(token, "and") || !strcasecmp(token, "or") || !strcasecmp(token, "not") || !strcmp(token, "&&")
                || !strcmp(token, "||") || !strcmp(token, "!") || !strcmp(token, "(") || !strcmp(token, ")")) {
            fprintf(expr_stream, " %s ", token);
        } else {
            logic_row = ecr_mongoc_collection_find_by_id(collection_logic, token, read_prefs, &err);
            if (err.code) {
                ecr_hm_error(source->hm, "error find " MONGO_COLLECTION_LOGIC " of id [%s]: %s", token, err.message);
                rc = -1;
                goto end;
            }
            bson_find_oid(source->hm, iter, hm_row, logic_id)
            bson_find_utf8(source->hm, iter, hm_row, field_id, "field_id")
            bson_find_utf8(source->hm, iter, hm_row, match_type, "match_type")
            field = ecr_hashmap_get(&fields, field_id, strlen(field_id));
            if (!field) {
                ecr_hm_error(source->hm, "can not find " MONGO_COLLECTION_FIELD " of id [%s]", field_id);
                rc = -1;
                goto end;
            }
            fprintf(expr_stream, " %s %s $%s ", field, match_type, logic_id);
            if (ecr_hm_mongo_load_items(source, source_data, logic_id, client, dbname, read_prefs)) {
                rc = -1;
                goto end;
            }
        }
        token = strtok_r(NULL, " ", &s);
    }
    fflush(expr_stream);
    ecr_hm_source_data_add_expr(source_data, expr.ptr);
    end: {
        if (cursor) {
            mongoc_cursor_destroy(cursor);
        }
        if (hm_row) {
            bson_destroy(hm_row);
        }
        if (expr_stream) {
            fclose(expr_stream);
        }
        free_to_null(expr.ptr);
        ecr_hashmap_destroy(&fields, ecr_hashmap_free_value_handler);
        free_to_null(expression);
        free(path);
        bson_destroy(&query);
        mongoc_read_prefs_destroy(read_prefs);
        mongoc_client_pool_push(loader->pool, client);
        return rc;
    }
}

static int ecr_hm_mongo_load_values(ecr_hm_source_t *source, ecr_uri_t *uri, ecr_list_t *values, void *user) {

    return 0;
}

static void ecr_hm_mongo_destroy(ecr_hm_loader_t *loader) {
    free(loader->user);
    free(loader);
}

ecr_hm_loader_t * ecr_hm_mongo_loader_new(mongoc_client_pool_t *pool) {
    ecr_hm_loader_t *loader = calloc(1, sizeof(ecr_hm_loader_t));
    ecr_hm_mongo_loader_t *mongo_loader = calloc(1, sizeof(ecr_hm_mongo_loader_t));
    mongo_loader->pool = pool;
    loader->scheme = "mongodb";
    loader->user = mongo_loader;
    loader->load = ecr_hm_mongo_load;
    loader->load_values = ecr_hm_mongo_load_values;
    loader->destroy_cb = ecr_hm_mongo_destroy;
    return loader;
}
