/*
 * ecr_cmd.c
 *
 *  Created on: Feb 17, 2014
 *      Author: velna
 */

#include "config.h"
#include "ecr_cmd.h"
#include "ecr_util.h"
#include "ecr_buf.h"
#include "ecr_logger.h"
#include "ecr_list.h"
#include "ecr_util.h"
#include <stdlib.h>
#include <string.h>
#include <zmq.h>

static int ecr_cmd_zmq_send(void* socket, const void* msg, size_t len, int flags) {
    int rc;
    zmq_msg_t message;
    zmq_msg_init_size(&message, len);
    memcpy(zmq_msg_data(&message), msg, len);
    rc = zmq_msg_send(&message, socket, flags);
    zmq_msg_close(&message);
    return rc;
}

void ecr_cmd_response(ecr_cmd_ctx_t *ctx, const void *message, size_t size, int hasmore) {
    pthread_mutex_lock(&ctx->zmq_mutex);
    size_t s = size > 0 ? size : strlen((const char*) message);
    ecr_cmd_zmq_send(ctx->zmq_socket, message, s, hasmore ? ZMQ_SNDMORE : 0);
    pthread_mutex_unlock(&ctx->zmq_mutex);
}

static int ecr_cmd_parse_v2(char *str, size_t size, int *argc_out, char ***argv_out) {
    char *cmd, *cmd_s = NULL, *arg, **argv;
    int i, argc, rc;

    ecr_list_t list;
    ecr_list_init(&list, 16);
    cmd = strndup(str, size);
    arg = strtok_r(cmd, " \t", &cmd_s);
    while (arg) {
        ecr_list_add(&list, arg);
        arg = strtok_r(NULL, " \t", &cmd_s);
    }
    argc = ecr_list_size(&list);
    if (argc > 0) {
        argv = calloc(argc, sizeof(char*));
        for (i = 0; i < argc; i++) {
            argv[i] = strdup((char *) ecr_list_get(&list, i));
        }
        *argc_out = argc;
        *argv_out = argv;
        rc = 0;
    } else {
        rc = -1;
    }
    ecr_list_destroy(&list, NULL);
    free(cmd);
    return rc;
}

static int ecr_cmd_parse_v1(char *cmd, size_t size, int *argc_out, char ***argv_out) {
    int argc, i = 0;
    char **argv, *cp = cmd, *end = cmd + size;
    if (size <= sizeof(int)) {
        return -1;
    }
    memcpy(&argc, cp, sizeof(int));
    argv = calloc(argc, sizeof(char*));
    cp += sizeof(int);
    argv[i++] = cp;
    while (i < argc && cp < end) {
        if (*cp == '\0') {
            argv[i++] = cp + 1;
        }
        cp++;
    }
    if (i != argc || cp >= end) {
        free(argv);
        return -1;
    }
    for (i = 0; i < argc; i++) {
        argv[i] = strdup(argv[i]);
    }
    *argc_out = argc;
    *argv_out = argv;
    return 0;
}

static void * ecr_cmd_routine(void *user) {
    ecr_cmd_ctx_t *ctx = user;
    zmq_msg_t message;
    char **argv, *data;
    ecr_str_t cmd_line = { 0 }, response = { 0 };
    size_t data_size;
    int argc, rc, i;
    ecr_cmd_t* cmd;
    FILE *cmd_line_stream, *response_stream;

    ecr_set_thread_name("cmd");
    L_INFO("cmd dispatch thread started.");
    cmd_line_stream = open_memstream(&cmd_line.ptr, &cmd_line.len);
    response_stream = open_memstream(&response.ptr, &response.len);
    while (ctx->alive) {
        zmq_msg_init(&message);
        if (zmq_msg_recv(&message, ctx->zmq_socket, 0) != -1) {
            data = zmq_msg_data(&message);
            data_size = zmq_msg_size(&message);
            if (memchr(data, '\0', data_size - 1)) {
                rc = ecr_cmd_parse_v1(data, data_size, &argc, &argv);
            } else {
                rc = ecr_cmd_parse_v2(data, data_size, &argc, &argv);
            }
            if (rc == 0) {
                rewind(cmd_line_stream);
                for (i = 0; i < argc - 1; i++) {
                    fprintf(cmd_line_stream, "%s ", argv[i]);
                }
                fprintf(cmd_line_stream, "%s", argv[i]);
                fflush(cmd_line_stream);
                L_INFO("process cmd: %s", cmd_line.ptr);
                if ((cmd = ecr_hashmap_get(&ctx->cmd_map, argv[0], strlen(argv[0]))) != NULL) {
                    rewind(response_stream);
                    cmd->handler(ctx, argc, argv, response_stream);
                    fflush(response_stream);
                    ecr_cmd_response(ctx, response.ptr, response.len, 0);
                } else {
                    ecr_cmd_response(ctx, "(unknown command)", 0, 0);
                }
                for (i = 0; i < argc; i++) {
                    free(argv[i]);
                }
                free(argv);
            } else {
                ecr_cmd_response(ctx, "(invalid command format)", 0, 0);
            }
        } else {
            if (zmq_errno() == ETERM) {
                zmq_close(ctx->zmq_socket);
                ctx->zmq_socket = NULL;
                break;
            } else if (zmq_errno() != EAGAIN) {
                L_ERROR("recv error:%s", zmq_strerror(zmq_errno()));
            }
        }
        zmq_msg_close(&message);
    }
    fclose(cmd_line_stream);
    free(cmd_line.ptr);
    fclose(response_stream);
    free(response.ptr);
    L_INFO("cmd dispatch thread finished.");
    return (void*) 0;
}

static void ecr_cmd_help_handler(ecr_cmd_ctx_t *ctx, int argc, char** argv, FILE* stream) {
    ecr_cmd_t * cmd;
    ecr_hashmap_iter_t i;
    ecr_hashmap_iter_init(&i, &ctx->cmd_map);

    while (ecr_hashmap_iter_next(&i, NULL, NULL, (void**) &cmd) == 0) {
        fprintf(stream, "%s\t%s\n", cmd->cmd, cmd->description);
    }
}

int ecr_cmd_register(ecr_cmd_ctx_t *ctx, char * s_cmd, ecr_cmd_handler handler, const char * description) {
    if (ctx->alive != 1) {
        return -1;
    }
    ecr_cmd_t* cmd = calloc(1, sizeof(ecr_cmd_t));

    cmd->cmd = calloc(strlen(s_cmd) + 1, sizeof(char));
    memcpy(cmd->cmd, s_cmd, strlen(s_cmd));

    cmd->description = calloc(strlen(description) + 1, sizeof(char));
    memcpy(cmd->description, description, strlen(description));

    cmd->handler = handler;

    ecr_hashmap_put(&ctx->cmd_map, s_cmd, strlen(s_cmd), cmd);
    return 0;
}

void ecr_cmd_unregister(ecr_cmd_ctx_t *ctx, char *s_cmd) {
    ecr_cmd_t* cmd = ecr_hashmap_remove(&ctx->cmd_map, s_cmd, strlen(s_cmd));
    if (NULL != cmd) {
        free(cmd->description);
        free(cmd->cmd);
        free(cmd);
    }
}

int ecr_cmd_ctx_init(ecr_cmd_ctx_t *ctx, void * zmq_ctx, const char* cmd_zmq_bind) {
    int rc;
    int zmq_opt;
    memset(ctx, 0, sizeof(ecr_cmd_ctx_t));
    ecr_hashmap_init(&ctx->cmd_map, 16, 0);
    ctx->alive = 1;
    ctx->zmq_context = zmq_ctx;
    ctx->zmq_socket = zmq_socket(ctx->zmq_context, ZMQ_REP);
    zmq_opt = 500;
    zmq_setsockopt(ctx->zmq_socket, ZMQ_LINGER, &zmq_opt, sizeof(int));
    zmq_opt = 500;
    zmq_setsockopt(ctx->zmq_socket, ZMQ_RCVTIMEO, &zmq_opt, sizeof(int));
    rc = zmq_bind(ctx->zmq_socket, cmd_zmq_bind);
    if (rc == 0) {
        L_INFO("cmd zmq bind at %s", cmd_zmq_bind);
        ecr_cmd_register(ctx, "help", ecr_cmd_help_handler, "print this help message");
        pthread_mutex_init(&ctx->zmq_mutex, NULL);
        pthread_create(&ctx->cmd_thread, NULL, ecr_cmd_routine, ctx);
        return 0;
    } else {
        L_ERROR("cmd zmq bind error at %s: %s", cmd_zmq_bind, zmq_strerror(zmq_errno()));
        return -1;
    }
}

static void ecr_cmd_cmdmap_free_handler(ecr_hashmap_t *map, void * key, size_t key_size, void * value) {
    ecr_cmd_t* cmd = (ecr_cmd_t*) value;
    if (NULL != cmd) {
        free(cmd->description);
        free(cmd->cmd);
        free(cmd);
    }
}

void ecr_cmd_ctx_destroy(ecr_cmd_ctx_t *ctx) {
    ctx->alive = 0;
    if (ctx->cmd_thread != 0) {
        pthread_join(ctx->cmd_thread, NULL);
        ctx->cmd_thread = 0;
    }
    if (NULL != ctx->zmq_socket) {
        zmq_close(ctx->zmq_socket);
        ctx->zmq_socket = NULL;
    }
    ecr_hashmap_destroy(&ctx->cmd_map, ecr_cmd_cmdmap_free_handler);
    pthread_mutex_destroy(&ctx->zmq_mutex);
}
