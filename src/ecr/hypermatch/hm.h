/*
 * hm.h
 *
 *  Created on: Aug 1, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_HYPERMATCH_HM_H_
#define SRC_ECR_HYPERMATCH_HM_H_

#include "ecrconf.h"
#include "ecr_hashmap.h"
#include "ecr_uri.h"
#include "ecr_fixedhashmap.h"

#define ECR_HM_ERRBUF_SIZE      256

typedef struct ecr_hm_s ecr_hm_t;
typedef struct ecr_hm_match_context_s ecr_hm_match_context_t;

typedef enum {
    HM_OK, HM_ERROR, HM_UNMODIFIED
} ecr_hm_status_t;

typedef enum {
    HM_AND, HM_OR, HM_NOT
} ecr_hm_logic_t;

typedef enum {
    HM_LEAF, HM_COMPOSITE
} ecr_hm_expr_type_t;

typedef struct {
    const char *name;
    bool has_values;
    void* (*init)(const char *name);
    void (*destroy)(void *data);
    int (*add_values)(void *data, ecr_list_t *values, int expr_id);
    void (*matches)(void *data, ecr_hm_match_context_t *match_ctx);
    void (*compile)(void *data);
    size_t (*size)(void *data);
} ecr_hm_matcher_reg_t;

typedef struct {
    void *data;
    ecr_hm_matcher_reg_t *reg;
} ecr_hm_matcher_t;

typedef struct {
    char *str;
    ecr_fixedhash_key_t key;
} ecr_hm_field_t;

typedef struct ecr_hm_expr_s {
    ecr_hm_expr_type_t type;
    union {
        struct {
            int id;
            ecr_hm_field_t field;
            ecr_hm_matcher_t *matcher;
        } leaf;
        struct {
            ecr_hm_logic_t logic;
            struct ecr_hm_expr_s *left;
            struct ecr_hm_expr_s *right;
        } composite;
    };
} ecr_hm_expr_t;

typedef struct {
    int id;
    ecr_uri_t uri;
    ecr_hm_t *hm;
    ecr_hashmap_t attrs;
    ecr_hm_expr_t *expr;
} ecr_hm_source_t;

typedef struct {
    ecr_hm_source_t *source;
    ecr_hm_logic_t logic;
    ecr_hashmap_t values; //<var:char*, ecr_list_t<value:char*>>
    ecr_hashmap_t expr_set; //<expr:char*, NULL>
} ecr_hm_source_data_t;

typedef struct {
    const char *scheme;
    /**
     * return -1 for error, 0 for unmodified, >0 for num of values actually loads.
     */
    int (*load)(ecr_hm_source_t *source, int force_reload, ecr_hm_source_data_t *source_data);
    int (*load_values)(ecr_hm_source_t *source, ecr_uri_t *uri, ecr_list_t *values);
} ecr_hm_loader_t;

typedef struct {
    ecr_hm_t *hm;
    int next_sid; //自增长的source data id
    int next_expr_id; //自增长的expression id
    bool compiled;
    ecr_hashmap_t source_map; // <sid:int, source_info:ecr_hm_source_info_t>
    ecr_hashmap_t expr_id_map; //<"$sid:$field $match_tpe $group", expr_id:int>
    ecr_hashmap_t matcher_map; //<"$field $matcher_name", matcher:ecr_hm_matcher_t>
} ecr_hm_data_t;

typedef enum {
    HM_UNDEF = 0, HM_NOT_MATCH, HM_MATCH
} ecr_hm_match_status_t;

typedef struct {
    ecr_hm_match_status_t status;
    ecr_hm_field_t *field;
    ecr_str_t *target;
} ecr_hm_result_kv_t;

typedef struct {
    unsigned int version;
    ecr_str_t source_match_list;
    size_t expr_match_list_size;
    ecr_hm_result_kv_t* expr_match_list;
} ecr_hm_result_t;

struct ecr_hm_match_context_s {
    ecr_hm_result_t *result;
    ecr_hm_expr_t *expr;
    ecr_str_t *target;
};

struct ecr_hm_s {
    volatile unsigned int version; //每编译一次，version值加1。如果和ecr_hm_result_t的version不一致，则匹配返回－1
    pthread_mutex_t lock;
    ecr_fixedhash_ctx_t *fixedhash_ctx;
    ecr_hashmap_t matcher_registry;
    ecr_hashmap_t loader_registry;
    ecr_hm_data_t *data; //存放正在使用的数据
    ecr_hm_data_t *tmp_data; //临时数据
    ecr_hm_data_t *next_data; //正在编译的数据
    char errbuf[ECR_HM_ERRBUF_SIZE];
};

extern ecr_hm_matcher_reg_t ecr_hm_equals_matcher_reg;
extern ecr_hm_matcher_reg_t ecr_hm_exists_matcher_reg;
extern ecr_hm_matcher_reg_t ecr_hm_wumanber_matcher_reg;
extern ecr_hm_matcher_reg_t ecr_hm_urlmatch_matcher_reg;

extern ecr_hm_loader_t ecr_hm_file_loader;

int ecr_hm_init(ecr_hm_t *hm, ecr_fixedhash_ctx_t *fixedhash_ctx);

void ecr_hm_destroy(ecr_hm_t *hm);

#define ecr_hm_error(hm, fmt, ...) snprintf((hm)->errbuf, ECR_HM_ERRBUF_SIZE, fmt, ##__VA_ARGS__)

int ecr_hm_reg_matcher(ecr_hm_t *hm, ecr_hm_matcher_reg_t *matcher_reg);

ecr_hm_matcher_reg_t* ecr_hm_get_matcher_reg(ecr_hm_t *hm, const char *name);

int ecr_hm_reg_loader(ecr_hm_t *hm, ecr_hm_loader_t *loader);

ecr_hm_loader_t* ecr_hm_find_loader(ecr_hm_t *hm, const char *scheme);

ecr_hm_source_t* ecr_hm_add(ecr_hm_t *hm, const char *uri);

int ecr_hm_remove(ecr_hm_t *hm, int source_id);

ecr_hm_status_t ecr_hm_compile(ecr_hm_t *hm);

ecr_hm_status_t ecr_hm_check(ecr_hm_t *hm, bool force_reload);

bool ecr_hm_matches(ecr_hm_t *hm, ecr_fixedhash_t *targets, ecr_hm_result_t* result);

void ecr_hm_matches_add(ecr_hm_match_context_t *match_ctx, int expr_id);

ecr_hm_result_t * ecr_hm_result_init_mem(ecr_hm_t *hm, void *mem, size_t mem_size);

ecr_hm_result_t * ecr_hm_result_new(ecr_hm_t *hm);

#define ecr_hm_result_contains(result, sid) ((result)->sources.ptr[sid])

void ecr_hm_result_clear(ecr_hm_result_t *hm);

#endif /* SRC_ECR_HYPERMATCH_HM_H_ */
