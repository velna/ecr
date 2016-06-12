/*
 * ecr_server.h
 *
 *  Created on: Dec 23, 2015
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_SERVER_H_
#define SRC_ECR_ECR_SERVER_H_

#include "ecrconf.h"
#include "ecr_list.h"
#include <uv.h>
#include <pthread.h>

typedef struct ecr_server_s ecr_server_t;

typedef struct mecap_cmd_s {
    int code;
    void *data;
    struct mecap_cmd_s *next;
    struct mecap_cmd_s *prev;
} ecr_server_cmd_t;

typedef struct {
    ecr_server_cmd_t *head;
    ecr_server_cmd_t *tail;
    pthread_mutex_t mutex;
} ecr_server_cmd_chain_t;

typedef struct {
    ecr_server_cmd_chain_t cmd_chain;
    uv_async_t *async;
} ecr_server_cmd_ctx_t;

typedef struct {
    int id;
    pthread_t thread;
    uv_loop_t loop;
    uv_pipe_t *pipe;
    ecr_server_cmd_ctx_t cmd_ctx;
    ecr_server_t *server;
} ecr_server_worker_t;

typedef void (*ecr_server_accept_cb)(ecr_server_worker_t *worker, uv_tcp_t *tcp);
typedef void (*ecr_server_error_cb)(ecr_server_worker_t *worker, int err, void *data);

typedef struct {
    char *name;
    char *pipe_file_path;
    int num_workers;
    int thread_pool_size;
    ecr_server_accept_cb accept_cb;
    ecr_server_error_cb error_cb;
    uv_shutdown_cb shutdown_cb;
    int tcp_nodelay;
    int tcp_keepalive;
    int tcp_keepalive_timeout;
} ecr_server_config_t;

struct ecr_server_s {
    ecr_server_config_t config;
    uv_tcp_t *master_socket;
    ecr_server_worker_t master;
    ecr_server_worker_t *workers;
    ecr_list_t worker_pipes;
};

int ecr_server_init(ecr_server_t *server, ecr_server_config_t *config);

int ecr_server_bind(ecr_server_t *server, const char *address);

int ecr_server_listen(ecr_server_t *server, int backlog);

void ecr_server_close(ecr_server_t *server);

void ecr_server_close_cb(uv_handle_t *handle);

void ecr_server_destroy(ecr_server_t *server);

#endif /* SRC_ECR_ECR_SERVER_H_ */
