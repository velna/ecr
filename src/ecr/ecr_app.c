/*
 * ecr_app.c
 *
 *  Created on: Dec 26, 2014
 *      Author: velna
 */

#include "config.h"
#include "ecr_app.h"
#include "ecr_logger.h"
#include "ecr_util.h"
#include "ecr_getopt.h"
#include "ecr_kafka.h"
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <zmq.h>

static ecr_option_t ecr_sys_cmd_options[] = {
//
        { "heartbeat", 0, NULL, 'b' }, //
        { "shutdown", 0, NULL, 'd' }, //
        { "help", 0, NULL, 'h' }, //
        { 0, 0, 0, 0 } }; //

static void ecr_sys_cmd_handler(ecr_cmd_ctx_t *ctx, int argc, char **argv, FILE *stream) {
    char opt;

    ecr_getopt_data_t getopt_data = ECR_GETOPT_DATA_INITIALIZER;
    while ((opt = ecr_getopt_long(argc, argv, "", ecr_sys_cmd_options, NULL, &getopt_data)) != EOF) {
        switch (opt) {
        case 'b':
            fprintf(stream, "ok");
            break;
        case 'd':
//            app_ctx.running = 0;
            fprintf(stream, "ok, shutdown.");
            break;
        case 'h':
            fprintf(stream, "not implemented.");
            break;
        default:
            fprintf(stream, "unknow command\n");
            break;
        }
    }
}

static void * ecr_app_signal_routine(void *user) {
    ecr_app_t *app = user;
    int sig;

    ecr_set_thread_name("sig");
    sigwait(&app->sigset, &sig);
    L_INFO("signaled with %s", strsignal(sig));
    ecr_app_shutdown(app);

    return NULL;
}

static void ecr_app_mongo_log_handler(mongoc_log_level_t log_level, const char *log_domain, const char *message,
        void *user_data) {
    L_INFO("%s: %s", log_domain, message);
}

int ecr_app_init(ecr_app_t *app, int argc, char **argv) {
    int opt;
    struct tm stm;
    pthread_attr_t attr;
    pthread_t thread;
    char thread_name[255];

    ecr_config_line_t app_config_lines[] = {
    //
            { "home", &app->config.home, ECR_CFG_STRING }, //
            { "umask", &app->config.umask, ECR_CFG_INT, .dv.i = 022 }, //
            { "main_loop_interval", &app->config.main_loop_interval, ECR_CFG_INT, .dv.i = 2 }, //
            { "fork_process", &app->config.fork_process, ECR_CFG_INT, .dv.i = 0 }, //
            { "log_file", &app->config.log_file, ECR_CFG_STRING }, //
            { "stat_log_file", &app->config.stat_log_file, ECR_CFG_STRING }, //
            { "cmd_zmq_bind", &app->config.cmd_zmq_bind, ECR_CFG_STRING }, //
            { "pid_file", &app->config.pid_file, ECR_CFG_STRING }, //
            { "zmq_io_thread_count", &app->config.zmq_io_thread_count, ECR_CFG_INT, .dv.i = 1 }, //
            { "mongo_uri", &app->config.mongo_uri, ECR_CFG_STRING }, //
            { "kafka_brokers", &app->config.kafka_brokers, ECR_CFG_STRING }, //
            { 0 } };

    assert(app && argc >= 0 && argv);
    memset(app, 0, sizeof(ecr_app_t));
    app->argc = argc;
    app->argv = argv;

    ecr_get_thread_name(thread_name);

    ecr_getopt_data_t getopt_data = ECR_GETOPT_DATA_INITIALIZER;
    while ((opt = ecr_getopt(argc, argv, "c:", &getopt_data)) != -1) {
        switch (opt) {
        case 'c':
            app->config_file = getopt_data.optarg;
            break;
        }
    }
    if (!app->config_file) {
        L_ERROR("no config file configured.");
        return -1;
    }
    if (ecr_config_init(&app->config_props, app->config_file)) {
        ecr_config_destroy(&app->config_props);
        return -1;
    }
    ecr_config_load(&app->config_props, "app", app_config_lines);

    if (!app->config.home) {
        L_ERROR("home not configured.");
        return -1;
    }
    if (chdir(app->config.home)) {
        L_ERROR("can not change work dir to %s.", app->config.home);
        return -1;
    }
    umask(app->config.umask);

    if (app->config.fork_process) {
        app->pid = fork();
        if (app->pid < 0) {
            L_ERROR("error fork process!");
            return -1;
        } else if (app->pid > 0) {
            L_INFO("forked process: %d", app->pid);
            ecr_echo_pid(app->pid, app->config.pid_file);
            ecr_config_destroy(&app->config_props);
            return 1;
        } else {
            app->pid = getpid();
        }
    } else {
        app->pid = getpid();
        ecr_echo_pid(app->pid, app->config.pid_file);
    }

    sigemptyset(&app->sigset);
    sigaddset(&app->sigset, SIGINT);
    pthread_sigmask(SIG_BLOCK, &app->sigset, NULL);

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thread, &attr, ecr_app_signal_routine, app);
    pthread_attr_destroy(&attr);

    if (app->config.log_file != NULL) {
        app->log_file = ecr_logger_init(app->config.log_file);
    }

    if (app->config.stat_log_file != NULL) {
        app->stat_log_file = ecr_logger_open(app->config.stat_log_file);
    } else {
        app->stat_log_file = ECR_LOG_FILE;
    }

    L_INFO("system init...");

    time(&app->startup_time);
    localtime_r(&app->startup_time, &stm);
    strftime(app->startup_time_str, 32, "%Y-%m-%d %H:%M:%S", &stm);

    app->num_cores = (int) sysconf(_SC_NPROCESSORS_ONLN);
    if (gethostname(app->hostname, 256)) {
        L_ERROR("can not get hostname.");
        return -1;
    } else {
        L_INFO("host name: %s", app->hostname);
    }

    ecr_counter_ctx_init(&app->counter_ctx);

    // init cmd
    ecr_set_thread_name("zmq");
    app->zmq_ctx = zmq_ctx_new();
    zmq_ctx_set(app->zmq_ctx, ZMQ_IO_THREADS, app->config.zmq_io_thread_count);
    if (app->config.cmd_zmq_bind) {
        if (ecr_cmd_ctx_init(&app->cmd_ctx, app->zmq_ctx, app->config.cmd_zmq_bind) == 0) {
            ecr_cmd_register(&app->cmd_ctx, "sys", ecr_sys_cmd_handler, "system control commands.");
        } else {
            ecr_set_thread_name(thread_name);
            L_ERROR("cmd zmq init error, bind at: %s.", app->config.cmd_zmq_bind);
            return -1;
        }
    } else {
        L_WARN("cmd zmq is not configured.");
    }
    ecr_set_thread_name(thread_name);

    // init mongo
    if (app->config.mongo_uri) {
        ecr_set_thread_name("mongo");
        mongoc_init();
        mongoc_log_set_handler(ecr_app_mongo_log_handler, NULL);
        mongoc_uri_t *uri = mongoc_uri_new(app->config.mongo_uri);
        app->mongo_pool = mongoc_client_pool_new(uri);
        mongoc_uri_destroy(uri);
        ecr_set_thread_name(thread_name);
        if (!app->mongo_pool) {
            L_ERROR("mongo connect field at %s", app->config.mongo_uri);
            return -1;
        }
        L_INFO("mongo connected at %s", app->config.mongo_uri);
    }

    // init kafka
    if (app->config.kafka_brokers) {
        app->kafka = ecr_kafka_new_producer(app->config.kafka_brokers, "app.kafka", &app->config_props);
        if (!app->kafka) {
            L_ERROR("error init kafka.");
            return -1;
        }
        L_INFO("kafka brokers connected at %s", app->config.kafka_brokers);
    }

    return 0;
}

int ecr_app_init_next(ecr_app_module_stack_t *stack) {
    do {
        if (stack->idx < ecr_list_size(stack->modules)) {
            stack->module = ecr_list_get(stack->modules, stack->idx++);
            L_INFO("init app module %s ...", stack->module->name);
        } else {
            return 0;
        }
    } while (!stack->module->init_handler);

    return stack->module->init_handler(stack);
}

int ecr_app_loop_next(ecr_app_module_stack_t *stack, FILE *stream) {
    do {
        if (stack->idx < ecr_list_size(stack->modules)) {
            stack->module = ecr_list_get(stack->modules, stack->idx++);
        } else {
            return 0;
        }
    } while (!stack->module->loop_handler);

    return stack->module->loop_handler(stack, stream);
}

int ecr_app_destroy_next(ecr_app_module_stack_t *stack) {
    do {
        if (stack->idx >= 0) {
            stack->module = ecr_list_get(stack->modules, stack->idx--);
            L_INFO("destroy app module %s ...", stack->module->name);
        } else {
            return 0;
        }
    } while (!stack->module->destroy_handler);

    return stack->module->destroy_handler(stack);
}

int ecr_app_startup(ecr_app_t *app, ecr_list_t *modules) {
    char * stat_string;
    size_t size;
    FILE* stream;
    ecr_app_module_stack_t stack;
    int rc = 0;

    assert(app);
    L_INFO("system startup...");

    stack.app = app;
    stack.modules = modules;
    app->running = 1;

    stack.idx = 0;
    if (ecr_app_init_next(&stack)) {
        ecr_app_shutdown(app);
        stack.idx--;
        ecr_app_destroy_next(&stack);
        rc = -1;
        goto end;
    }
    L_INFO("system initialized, enter main loop.");
    stat_string = NULL;
    size = 0;
    stream = open_memstream(&stat_string, &size);
    while (app->running) {
        sleep(app->config.main_loop_interval);
        stack.idx = 0;
        fprintf(stream, "%s\t%s\t%s\t%s\n", "column", "total", "pps(avg)", "pss(stat_interval)");
        fprintf(stream, "startup_time:\t%s\n", app->startup_time_str);
        fprintf(stream, "timestamp:\t%lu\n", ecr_current_time());
        ecr_app_loop_next(&stack, stream);
        ecr_counter_snapshot(&app->counter_ctx);
        ecr_counter_print(&app->counter_ctx, stream);
        fflush(stream);
        if (size) {
            L_MSG(app->stat_log_file, stat_string);
        }
        fseek(stream, 0, SEEK_SET);
    }

    stack.idx = ecr_list_size(modules) - 1;
    ecr_app_destroy_next(&stack);

    ecr_counter_print_all(&app->counter_ctx, stream);
    fflush(stream);
    if (size) {
        L_INFO("\n%s", stat_string);
    }
    fclose(stream);
    free(stat_string);

    end: {
        ecr_cmd_ctx_destroy(&app->cmd_ctx);
        ecr_config_destroy(&app->config_props);
        ecr_counter_ctx_destroy(&app->counter_ctx);

        if (app->stat_log_file != NULL) {
            ecr_logger_close(app->stat_log_file);
        }

        zmq_ctx_term(app->zmq_ctx);

        if (app->mongo_pool) {
            mongoc_client_pool_destroy(app->mongo_pool);
            mongoc_cleanup();
            app->mongo_pool = NULL;
            L_INFO("mongo pool destroied.");
        }

        if (app->kafka) {
            rd_kafka_destroy(app->kafka);
            rd_kafka_wait_destroyed(1000);
            app->kafka = NULL;
        }

        L_INFO("goodbye.");

        if (app->log_file != NULL) {
            ecr_logger_close(app->log_file);
        }
    }
    return rc;
}

void ecr_app_shutdown(ecr_app_t *app) {
    assert(app);
    if (app->running) {
        L_INFO("system shutdown...");
        app->running = 0;
    }
}
