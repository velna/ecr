/*
 * ecr_app.h
 *
 *  Created on: Dec 26, 2014
 *      Author: velna
 */

#ifndef ECR_APP_H_
#define ECR_APP_H_

#include "ecrconf.h"
#include "ecr_config.h"
#include "ecr_rollingfile.h"
#include "ecr_cmd.h"
#include "ecr_list.h"
#include "ecr_counter.h"
#include <signal.h>
#include <mongoc.h>
#include <librdkafka/rdkafka.h>

typedef struct ecr_app_module_s ecr_app_module_t;

typedef struct {
    char *home;
    int main_loop_interval;
    char *log_file;
    char *stat_log_file;
    char *pid_file;
    int fork_process;
    char *cmd_zmq_bind;
    int zmq_io_thread_count;
    char *mongo_uri;
    char *kafka_brokers;
} ecr_app_config_t;

typedef struct {
    pid_t pid;
    int num_cores;
    char hostname[256];
    time_t startup_time;
    char startup_time_str[32];
    int running :1;
    ecr_app_config_t config;
    ecr_config_t config_props;
    ecr_rfile_t *log_file;
    ecr_rfile_t *stat_log_file;
    void * zmq_ctx;
    const char *config_file;
    int argc;
    char **argv;
    ecr_cmd_ctx_t cmd_ctx;
    ecr_counter_ctx_t counter_ctx;
    sigset_t sigset;
    mongoc_client_pool_t *mongo_pool;
    rd_kafka_t *kafka;
} ecr_app_t;

typedef struct {
    int idx;
    ecr_app_t *app;
    ecr_list_t *modules;
    ecr_app_module_t *module;
} ecr_app_module_stack_t;

struct ecr_app_module_s {
    char *name;
    int (*init_handler)(ecr_app_module_stack_t *stack);
    int (*loop_handler)(ecr_app_module_stack_t *stack, FILE *stream);
    int (*destroy_handler)(ecr_app_module_stack_t *stack);
};

int ecr_app_init(ecr_app_t *app, int argc, char **argv);

//int ecr_app_add_module(ecr_app_t *app, ecr_app_module_t *module);

int ecr_app_startup(ecr_app_t *app, ecr_list_t *modules);

int ecr_app_init_next(ecr_app_module_stack_t *stack);

int ecr_app_loop_next(ecr_app_module_stack_t *stack, FILE *stream);

int ecr_app_destroy_next(ecr_app_module_stack_t *stack);

void ecr_app_shutdown(ecr_app_t *app);

#endif /* ECR_APP_H_ */
