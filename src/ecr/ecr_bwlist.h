/*
 * ecr_bwlist2.h
 *
 *  Created on: Dec 4, 2015
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_BWLIST_H_
#define SRC_ECR_ECR_BWLIST_H_

#include "ecrconf.h"
#include "ecr_hashmap.h"
#include "ecr_fixedhashmap.h"
#include "ecr_wumanber.h"
#include "ecr_list.h"
#include "ecr_skiplist.h"
#include <stdio.h>
#include <mongoc.h>

#define ECR_BWL_NAME_EQUALS             "equals"
#define ECR_BWL_NAME_WUMANBER           "wumanber"
#define ECR_BWL_NAME_EXISTS             "exists"
#define ECR_BWL_NAME_REGEX              "regex"

#define ECR_BWL_SOURCE_STRING            "string:"
#define ECR_BWL_SOURCE_FILE              "file:"
#define ECR_BWL_SOURCE_CFILE             "cfile:"
#define ECR_BWL_SOURCE_MONGODB           "mongodb:"

typedef enum {
    BWL_FILE = 1, BWL_CFILE, BWL_MONGO, BWL_STRING
} ecr_bwl_source_type_t;

typedef enum {
    BWL_EQUALS = 1, BWL_WUMANBER, BWL_EXISTS, BWL_REGEX
} ecr_bwl_type_t;

typedef enum {
    BWL_NONE = 0, BWL_AND, BWL_OR, BWL_NOT
} ecr_bwl_logic_t;

typedef struct ecr_bwl_s ecr_bwl_t;

typedef void (*ecr_bwl_log_handler)(ecr_bwl_t *list, int level, const char *message);

typedef struct {
    int expr_id;
    char *tag;
    void *user;
} ecr_bwl_user_t;

typedef struct ecr_bwl_expr_s {
    ecr_bwl_logic_t logic;
    union {
        int id;
        struct {
            struct ecr_bwl_expr_s *left;
            struct ecr_bwl_expr_s *right;
        };
    };
} ecr_bwl_expr_t;

typedef struct {
    mongoc_client_pool_t *mongo_pool;
    char *basepath;
    ecr_fixedhash_ctx_t *fixedhash_ctx;
    char *cfile_pwd;
    ecr_bwl_log_handler log_handler;
} ecr_bwl_opt_t;

typedef struct ecr_bwl_group_s {
    ecr_str_t name;
    ecr_fixedhash_key_t name_key;
    ecr_bwl_type_t type;
    union {
        ecr_hashmap_t equals;
        ecr_wm_t wumanber;
        ecr_list_t exists;
        ecr_hashmap_t regex;
    } items;
    struct ecr_bwl_group_s *next;
} ecr_bwl_group_t;

typedef struct {
    int id;
    void *user;
    union {
        struct timespec file_m_date;
        struct {
            int64_t m_date;
            int64_t doc_count;
        } mongo;
        int string_ok;
    } status;
    char *source;
    ecr_bwl_source_type_t source_type;
    ecr_bwl_logic_t logic;
} ecr_bwl_source_t;

typedef struct ecr_bwl_source_data_s {
    int id;
    void *user;
    ecr_bwl_source_t *source;
    ecr_hashmap_t item_groups;
    ecr_hashmap_t expr_map;
    ecr_bwl_expr_t *expr;
    struct ecr_bwl_source_data_s *next;
} ecr_bwl_source_data_t;

typedef struct {
    int next_sid;
    ecr_list_t source_list;
    ecr_bwl_t *bwl;
    ecr_bwl_group_t *groups;
    int next_expr_id;
    ecr_bwl_source_data_t *source_data;
    ecr_hashmap_t user_map;
} ecr_bwl_data_t;

struct ecr_bwl_s {
    unsigned int version;
    pthread_mutex_t lock;
    ecr_bwl_opt_t opts;
    ecr_bwl_data_t *data;
    ecr_bwl_data_t *tmp_data;
    ecr_bwl_data_t *next_data;
};

typedef struct {
    unsigned int version;
    void **users;
    size_t users_size;
    ecr_str_t sources;
    ecr_str_t exprs;
    ecr_str_t **expr_items;
} ecr_bwl_result_t;

int ecr_bwl_init(ecr_bwl_t *list, ecr_bwl_opt_t *opt);

void ecr_bwl_destroy(ecr_bwl_t *list);

/**
 * return -1 for error, 0 for ok, and id_out will be the id of the bwlist if id_out is not null.
 * if *id_out > 0, the new source will replace the old one which id is *id_out, and id_out is left un-modified.
 */
int ecr_bwl_add(ecr_bwl_t *list, const char *source, ecr_bwl_logic_t logic, void *user, int *id_out);

int ecr_bwl_remove(ecr_bwl_t *list, int id);

int ecr_bwl_compile(ecr_bwl_t *list);

int ecr_bwl_reload(ecr_bwl_t *list);

int ecr_bwl_check(ecr_bwl_t *list);

#define ecr_bwl_result_memsize(list) (sizeof(ecr_bwl_result_t) + ((list)->data->next_expr_id + (list)->data->next_sid) * (1 + sizeof(void*)))

ecr_bwl_result_t * ecr_bwl_result_init_mem(ecr_bwl_t *list, void *mem);

ecr_bwl_result_t * ecr_bwl_result_init(ecr_bwl_t *list);

#define ecr_bwl_contains(result, id) ((result)->sources.ptr[id])

void ecr_bwl_result_clear(ecr_bwl_result_t *result);

void ecr_bwl_result_destroy(ecr_bwl_result_t *result);

int ecr_bwl_matches_fixed(ecr_bwl_t *list, ecr_fixedhash_t *hash, ecr_bwl_result_t *results);

void ecr_bwl_dump(ecr_bwl_t *list, FILE *stream);

#endif /* SRC_ECR_ECR_BWLIST_H_ */
