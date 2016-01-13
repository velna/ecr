/*
 * ecr_cmd.h
 *
 *  Created on: Feb 17, 2014
 *      Author: velna
 */

#ifndef ECR_CMD_H_
#define ECR_CMD_H_

#include "ecrconf.h"
#include "ecr_hashmap.h"
#include <stdio.h>

typedef struct {
    ecr_hashmap_t cmd_map;
    void *zmq_context;
    void *zmq_socket;
    pthread_mutex_t zmq_mutex;
    char alive;
    pthread_t cmd_thread;
} ecr_cmd_ctx_t;

typedef void (*ecr_cmd_handler)(ecr_cmd_ctx_t *ctx, int argc, char **argv, FILE *stream);

typedef struct {
    char *cmd;
    char *description;
    ecr_cmd_handler handler;
} ecr_cmd_t;

int ecr_cmd_ctx_init(ecr_cmd_ctx_t *ctx, void *zmq_ctx, const char *cmd_zmq_bind);

int ecr_cmd_register(ecr_cmd_ctx_t *ctx, char *cmd, ecr_cmd_handler handler, const char *description);

void ecr_cmd_unregister(ecr_cmd_ctx_t *ctx, char *cmd);

void ecr_cmd_response(ecr_cmd_ctx_t *ctx, const void *message, size_t size, int hasmore);

void ecr_cmd_ctx_destroy(ecr_cmd_ctx_t *ctx);

#endif /* ECR_CMD_H_ */
