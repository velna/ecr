/*
 * ecr_server.c
 *
 *  Created on: Dec 23, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_server.h"
#include "ecr_logger.h"
#include "ecr_util.h"
#include <string.h>
#include <stdlib.h>

#define CMD_CODE_SHUTDOWN           1

#define ecr_uv_close(handle, cb) \
    switch ((handle)->type) { \
    case UV_NAMED_PIPE: \
        L_DEBUG("close named pipe: %d", ((uv_pipe_t*)handle)->io_watcher.fd); \
        break; \
    case UV_TCP: \
        L_DEBUG("close tcp: %d", ((uv_tcp_t*)handle)->io_watcher.fd); \
        break; \
    case UV_STREAM: \
        L_DEBUG("clse stream: %d", ((uv_stream_t*)handle)->io_watcher.fd); \
        break; \
    default: \
        L_DEBUG("close handle of type %d", (handle)->type); \
        break; \
    } \
    uv_close((handle), cb); \


void ecr_server_close_cb(uv_handle_t *handle) {
    switch (handle->type) {
    case UV_NAMED_PIPE:
        L_DEBUG("named pipe closed: %d", ((uv_pipe_t*)handle)->io_watcher.fd);
        break;
    case UV_TCP:
        L_DEBUG("tcp closed: %d", ((uv_tcp_t*)handle)->io_watcher.fd);
        break;
    case UV_STREAM:
        L_DEBUG("stream closed: %d", ((uv_stream_t*)handle)->io_watcher.fd);
        break;
    default:
        L_DEBUG("handle of type %d is closed", handle->type);
        break;
    }
    free(handle);
}

static void ecr_server_close_walk_cb(uv_handle_t *handle, void *arg) {
    ecr_server_worker_t *worker = arg;
    if (uv_is_closing(handle)) {
        L_DEBUG("handle %d is closing", handle->u.fd);
        return;
    }
    if (handle == (uv_handle_t*) worker->server->master_socket) {
        ecr_uv_close(handle, ecr_server_close_cb);
    } else {
        if (handle->type == UV_TCP) {
            uv_shutdown_t* sreq = malloc(sizeof(uv_shutdown_t));
            L_DEBUG("shutdown handle %d", ((uv_stream_t*)handle)->io_watcher.fd);
            uv_shutdown(sreq, (uv_stream_t*) handle, worker->server->config.shutdown_cb);
        } else {
            ecr_uv_close(handle, ecr_server_close_cb);
        }
    }
}

static void ecr_server_cmd_send(ecr_server_worker_t *worker, int cmd_code, void *data) {
    ecr_server_cmd_t *cmd = malloc(sizeof(ecr_server_cmd_t));
    ecr_server_cmd_chain_t *cmd_chain = &worker->cmd_ctx.cmd_chain;
    cmd->code = cmd_code;
    cmd->data = data;
    pthread_mutex_lock(&cmd_chain->mutex);
    linked_list_push(cmd_chain, cmd)
    ;
    pthread_mutex_unlock(&cmd_chain->mutex);
    uv_async_send(worker->cmd_ctx.async);
}

static void ecr_server_cmd_cb(uv_async_t *handle) {
    ecr_server_worker_t *worker = handle->data;
    ecr_server_cmd_chain_t *cmd_chain = &worker->cmd_ctx.cmd_chain;
    ecr_server_cmd_chain_t polled_chain[1];
    ecr_server_cmd_t *cmd;

    pthread_mutex_lock(&cmd_chain->mutex);
    polled_chain->head = cmd_chain->head;
    polled_chain->tail = cmd_chain->tail;
    cmd_chain->head = NULL;
    cmd_chain->tail = NULL;
    pthread_mutex_unlock(&cmd_chain->mutex);

    linked_list_pop(polled_chain, cmd);
    while (cmd) {
        switch (cmd->code) {
        case CMD_CODE_SHUTDOWN:
            uv_stop(&worker->loop);
            break;
        default:
            L_ERROR("unknown cmd code: %d", cmd->code);
            break;
        }
        free(cmd);
        linked_list_pop(polled_chain, cmd);
    }
}

static void ecr_server_worker_init(ecr_server_t *server, ecr_server_worker_t *worker, int id) {
    worker->id = id;
    worker->server = server;
    uv_loop_init(&worker->loop);
    pthread_mutex_init(&worker->cmd_ctx.cmd_chain.mutex, NULL);
    worker->cmd_ctx.async = malloc(sizeof(uv_async_t));
    worker->cmd_ctx.async->data = worker;
    uv_async_init(&worker->loop, worker->cmd_ctx.async, ecr_server_cmd_cb);
    worker->pipe = malloc(sizeof(uv_pipe_t));
    uv_pipe_init(&worker->loop, worker->pipe, 1);
    worker->pipe->data = worker;
}

int ecr_server_init(ecr_server_t *server, ecr_server_config_t *config) {
    char *pool_size;
    memset(server, 0, sizeof(ecr_server_t));
    server->config = *config;
    server->config.pipe_file_path = strdup(config->pipe_file_path);
    server->config.name = strdup(config->name);

    if (config->thread_pool_size) {
        asprintf(&pool_size, "%d", config->thread_pool_size);
        setenv("UV_THREADPOOL_SIZE", pool_size, 1);
        free(pool_size);
    }

    ecr_server_worker_init(server, &server->master, -1);
    server->master_socket = malloc(sizeof(uv_tcp_t));
    uv_tcp_init(&server->master.loop, server->master_socket);
    uv_tcp_nodelay(server->master_socket, server->config.tcp_nodelay);
    uv_tcp_keepalive(server->master_socket, server->config.tcp_keepalive, server->config.tcp_keepalive_timeout);
    server->master_socket->data = server;

    ecr_list_init(&server->worker_pipes, config->num_workers);

    return 0;
}

int ecr_server_bind(ecr_server_t *server, const char *address) {
    char *addr, *host, *sport, *s = NULL;

    addr = strdup(address);
    host = strtok_r(addr, ":", &s);
    if (!host) {
        L_ERROR("invalid address: %s", address);
        free(addr);
        return -1;
    }
    sport = strtok_r(NULL, ":", &s);
    if (!sport) {
        L_ERROR("invalid address: %s", address);
        free(addr);
        return -1;
    }

    L_INFO("bind at %s:%s", host, sport);
    struct sockaddr_in sock_addr;
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons((uint16_t) atoi(sport));
    sock_addr.sin_addr.s_addr = inet_addr(host);
    uv_tcp_bind(server->master_socket, (struct sockaddr *) &sock_addr, 0);

    free(addr);
    return 0;
}

static void * ecr_server_master_routine(void *user) {
    ecr_server_t *server = user;

    ecr_set_thread_name("%s-master", server->config.name);

    L_INFO("[%s] master thread started.", server->config.name);

    uv_run(&server->master.loop, UV_RUN_DEFAULT);

    L_INFO("[%s] master thread finished.", server->config.name);
    return NULL;
}

static void ecr_server_pipe_write_cb(uv_write_t* req, int status) {
    if (status) {
        L_ERROR("pipe write error: %s[%d]", uv_strerror(status), status);
    }
    ecr_uv_close((uv_handle_t* ) req->data, ecr_server_close_cb);
    free(req);
}

static void ecr_server_master_connection_cb(uv_stream_t *stream, int status) {
    static uv_buf_t buf = { ".", 1 };
    static int worker_id = 0;
    if (status) {
        return;
    }
    ecr_server_t *server = stream->data;
    uv_pipe_t *worker_pipe = ecr_list_get(&server->worker_pipes, worker_id);

    uv_tcp_t *client = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
    uv_tcp_init(stream->loop, client);
    if (uv_accept(stream, (uv_stream_t*) client) == 0) {
        L_DEBUG("accept connection: %d", client->io_watcher.fd);
        uv_stream_set_blocking((uv_stream_t*) client, 0);
        uv_write_t *write = malloc(sizeof(uv_write_t));
        write->data = client;
        L_DEBUG("write connection fd %d to pipe %d of worker %d", client->io_watcher.fd, worker_pipe->io_watcher.fd, worker_id);
        uv_write2(write, (uv_stream_t*) worker_pipe, &buf, 1, (uv_stream_t*) client, ecr_server_pipe_write_cb);
        worker_id = (worker_id + 1) % server->config.num_workers;
    } else {
        ecr_uv_close((uv_handle_t* ) client, ecr_server_close_cb);
    }
}

static void ecr_server_master_pipe_connection_cb(uv_stream_t *stream, int status) {
    if (status) {
        return;
    }
    ecr_server_worker_t *worker = stream->data;
    uv_pipe_t *client = (uv_pipe_t*) malloc(sizeof(uv_pipe_t));
    uv_pipe_init(stream->loop, client, 1);
    if (uv_accept(stream, (uv_stream_t*) client) == 0) {
        L_DEBUG("Worker %d - accept new pipe: %d", worker->id, client->io_watcher.fd);
        uv_stream_set_blocking((uv_stream_t*) client, 0);
        ecr_list_add(&worker->server->worker_pipes, client);
    } else {
        ecr_uv_close((uv_handle_t* ) client, ecr_server_close_cb);
    }
}

static void ecr_server_worker_pipe_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    if (nread < 0) {
        ecr_uv_close((uv_handle_t* ) stream, ecr_server_close_cb);
        if (buf->base) {
            free(buf->base);
        }
        return;
    }
    ecr_server_worker_t *worker = stream->data;
    uv_pipe_t *pipe = (uv_pipe_t*) stream;
    if (uv_pipe_pending_count(pipe)) {
        uv_tcp_t *client = malloc(sizeof(uv_tcp_t));
        client->data = worker;
        uv_tcp_init(pipe->loop, client);
        if (uv_accept(stream, (uv_stream_t*) client) == 0) {
            L_DEBUG("accept tcp %d from pipe %d", client->io_watcher.fd, stream->io_watcher.fd);
            uv_stream_set_blocking((uv_stream_t*) client, 0);
            worker->server->config.accept_cb(worker, client);
        } else {
            ecr_uv_close((uv_handle_t* ) client, ecr_server_close_cb);
        }
    }
    if (buf->base) {
        free(buf->base);
    }
}

static void ecr_server_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = malloc(buf->len = suggested_size);
}

static void ecr_server_worker_pipe_connect_cb(uv_connect_t *req, int status) {
    if (status) {
        L_ERROR("pipe connect error: %s[%d]", uv_strerror(status), status);
    } else {
        uv_read_start(req->handle, ecr_server_alloc_cb, ecr_server_worker_pipe_read_cb);
    }
}

static void * ecr_server_worker_routine(void *user) {
    ecr_server_worker_t *worker = user;

    ecr_set_thread_name("%s-worker-%d", worker->server->config.name, worker->id);
    L_INFO("[%s] worker thread %d started.", worker->server->config.name, worker->id);

    uv_connect_t pipe_connect;

    pipe_connect.data = worker;
    uv_pipe_connect(&pipe_connect, worker->pipe, worker->server->config.pipe_file_path,
            ecr_server_worker_pipe_connect_cb);
    L_DEBUG("pipe connected at %s[%d]", worker->server->config.pipe_file_path, pipe_connect.handle->io_watcher.fd);

    uv_run(&worker->loop, UV_RUN_DEFAULT);
    uv_walk(&worker->loop, ecr_server_close_walk_cb, worker);
    while (uv_run(&worker->loop, UV_RUN_ONCE))
        ;
    L_INFO("[%s] worker thread %d finished.", worker->server->config.name, worker->id);
    return NULL;
}

int ecr_server_listen(ecr_server_t *server, int backlog) {
    int i;
    cpu_set_t mask;

    unlink(server->config.pipe_file_path);
    uv_pipe_bind(server->master.pipe, server->config.pipe_file_path);
    uv_listen((uv_stream_t*) server->master.pipe, 128, ecr_server_master_pipe_connection_cb);
    uv_stream_set_blocking((uv_stream_t*) server->master.pipe, 0);
    L_DEBUG("listen pipe at %s[%d]", server->config.pipe_file_path, server->master.pipe->io_watcher.fd);

    server->workers = calloc(server->config.num_workers, sizeof(ecr_server_worker_t));
    for (i = 0; i < server->config.num_workers; i++) {
        ecr_server_worker_init(server, &server->workers[i], i);
        pthread_create(&server->workers[i].thread, NULL, ecr_server_worker_routine, &server->workers[i]);
        CPU_ZERO(&mask);
        CPU_SET(i + 4, &mask);
        if (pthread_setaffinity_np(server->workers[i].thread, sizeof(cpu_set_t), &mask) == -1) {
            L_ERROR("pthread_setaffinity_np() failed: %s, cpu_num: %d", strerror(errno), i + 4);
        }
    }

    uv_listen((uv_stream_t*) server->master_socket, backlog, ecr_server_master_connection_cb);
    uv_stream_set_blocking((uv_stream_t*) server->master_socket, 0);

    pthread_create(&server->master.thread, NULL, ecr_server_master_routine, server);

    return 0;
}

void ecr_server_close(ecr_server_t *server) {
    int i;
    ecr_server_cmd_send(&server->master, CMD_CODE_SHUTDOWN, NULL);
    for (i = 0; i < server->config.num_workers; i++) {
        ecr_server_cmd_send(&server->workers[i], CMD_CODE_SHUTDOWN, NULL);
    }
}

static void ecr_server_worker_destroy(ecr_server_worker_t *worker) {
    ecr_server_cmd_t *cmd;

    pthread_join(worker->thread, NULL);
    pthread_mutex_destroy(&worker->cmd_ctx.cmd_chain.mutex);
    linked_list_pop(&worker->cmd_ctx.cmd_chain, cmd);
    while (cmd) {
        free(cmd);
        linked_list_pop(&worker->cmd_ctx.cmd_chain, cmd);
    }
    uv_loop_close(&worker->loop);
}

void ecr_server_destroy(ecr_server_t *server) {
    int i;
    ecr_server_worker_destroy(&server->master);
    for (i = 0; i < server->config.num_workers; i++) {
        ecr_server_worker_destroy(&server->workers[i]);
    }
    free_to_null(server->workers);
    ecr_list_destroy(&server->worker_pipes, NULL);
    free_to_null(server->config.name);
    free_to_null(server->config.pipe_file_path);
}
