/*
 * ecr_pub.c
 *
 *  Created on: Jan 15, 2016
 *      Author: velna
 */

#include "config.h"
#include "ecr_pub.h"
#include "ecr_util.h"
#include "ecr_logger.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <zmq.h>

int ecr_pub_init(ecr_pub_t *pub, const char *id, ecr_pub_config_t *config) {
    int i;

    memset(pub, 0, sizeof(ecr_pub_t));
    pub->id = strdup(id);
    pub->config = *config;
    pub->buf_array = calloc(config->num_threads, sizeof(ecr_str_t));
    pub->stream_array = calloc(config->num_threads, sizeof(FILE *));
    for (i = 0; i < config->num_threads; i++) {
        pub->stream_array[i] = open_memstream(&pub->buf_array[i].ptr, &pub->buf_array[i].len);
    }
    return 0;
}

int ecr_pub_output_config(ecr_pub_t *pub, ecr_config_t *config) {
    int ok = 0, error = 0;
    ecr_pub_output_config_t stat_config = { .type = ECR_PUB_STAT };
    ecr_pub_output_config_t file_config = { .type = ECR_PUB_FILE };
    ecr_pub_output_config_t zmq_config = { .type = ECR_PUB_ZMQ };
    ecr_pub_output_config_t kafka_config = { .type = ECR_PUB_KAFKA };
    ecr_config_line_t config_lines[] = {
    //
            { "file_format", &file_config.format, ECR_CFG_STRING }, //
            { "file_name", &file_config.file.name, ECR_CFG_STRING }, //
            { "file_split", &file_config.file.split, ECR_CFG_INT }, //
            { "zmq_format", &zmq_config.format, ECR_CFG_STRING }, //
            { "zmq_endpoint", &zmq_config.zmq.endpoint, ECR_CFG_STRING }, //
            { "zmq_options", &zmq_config.zmq.options, ECR_CFG_STRING }, //
            { "kafka_format", &kafka_config.format, ECR_CFG_STRING }, //
            { "kafka_brokers", &kafka_config.kafka.brokers, ECR_CFG_STRING }, //
            { "kafka_topic", &kafka_config.kafka.topic, ECR_CFG_STRING }, //
            { 0 } };

    ecr_config_load(config, pub->id, config_lines);
    if (file_config.format && file_config.file.name) {
        if (ecr_pub_output_add(pub, &file_config)) {
            error = 1;
        } else {
            ok = 1;
        }
    }
    if (zmq_config.format && zmq_config.zmq.endpoint) {
        if (ecr_pub_output_add(pub, &zmq_config)) {
            error = 1;
        } else {
            ok = 1;
        }
    }
    if (kafka_config.format && kafka_config.kafka.topic) {
        if (ecr_pub_output_add(pub, &kafka_config)) {
            error = 1;
        } else {
            ok = 1;
        }
    }
    if (!ok) {
        if (ecr_pub_output_add(pub, &stat_config)) {
            error = 1;
        }
    }
    return error ? -1 : 0;
}

static void ecr_pub_kafka_logger(const rd_kafka_t *rk, int level, const char *fac, const char *buf) {
    L_LOG(level, "%s: %s", rd_kafka_name(rk), buf);
}

int ecr_pub_output_add(ecr_pub_t *pub, ecr_pub_output_config_t *config) {
    ecr_pub_output_t *output = calloc(1, sizeof(ecr_pub_output_t));
    int i, j;
    char *fp, *s, errstr[512];
    FILE *file;

    switch (config->type) {
    case ECR_PUB_STAT:
        output->total = ecr_counter_create(pub->config.cctx, pub->id, "stat_ok", 0);
        output->total_bytes = ecr_counter_create(pub->config.cctx, pub->id, "stat_bytes", 0);
        L_INFO("%s: add stat only output.", pub->id);
        break;
    case ECR_PUB_ZMQ:
        if (!pub->config.zmq_ctx) {
            L_ERROR("%s: no zmq context configurred.", pub->id);
            free(output);
            return -1;
        }
        output->zmq.skt = ecr_zmq_init(config->zmq.endpoint, config->zmq.options, pub->config.zmq_ctx);
        if (!output->zmq.skt) {
            L_ERROR("%s: error init zmq file %s[%s]", pub->id, config->zmq.endpoint, config->zmq.options);
            free(output);
            return -1;
        }
        pthread_mutex_init(&output->zmq.lock, NULL);
        output->total = ecr_counter_create(pub->config.cctx, pub->id, "zmq_ok", 0);
        output->total_bytes = ecr_counter_create(pub->config.cctx, pub->id, "zmq_bytes", 0);
        L_INFO("%s: add zmq output: %s[%s].", pub->id, config->zmq.endpoint, config->zmq.options);
        break;
    case ECR_PUB_FILE:
        output->file.split = config->file.split <= 0 ? 1 : config->file.split;
        output->file.idx_array = calloc(pub->config.num_threads, sizeof(int));
        output->file.array = calloc(pub->config.num_threads * output->file.split, sizeof(FILE *));
        for (i = 0; i < pub->config.num_threads; i++) {
            for (j = 0; j < output->file.split; j++) {
                fp = strdup(config->file.name);
                s = fp;
                while (*s) {
                    if (*s == '#') {
                        *s = '0' + j;
                    }
                    s++;
                }
                file = output->file.array[i * output->file.split + j] = ecr_rollingfile_open(fp, i,
                        pub->config.io_regs);
                free(fp);
                if (!file) {
                    L_ERROR("%s: error init rolling file %s", pub->id, config->file.name);
                    for (i = 0; i < pub->config.num_threads; i++) {
                        for (j = 0; j < output->file.split; j++) {
                            if ((file = output->file.array[i * output->file.split + j])) {
                                fclose(file);
                            }
                        }
                    }
                    free(output->file.array);
                    free(output);
                    return -1;
                }
            }
        }
        output->total = ecr_counter_create(pub->config.cctx, pub->id, "file_ok", 0);
        output->total_bytes = ecr_counter_create(pub->config.cctx, pub->id, "file_bytes", 0);
        L_INFO("%s: add file output: %s[%d].", pub->id, config->file.name, config->file.split);
        break;
    case ECR_PUB_KAFKA:
        if (config->kafka.brokers) {
            output->kafka.new = 1;
            output->kafka.conf = rd_kafka_conf_new();
            output->kafka.kafka = rd_kafka_new(RD_KAFKA_PRODUCER, output->kafka.conf, errstr, sizeof(errstr));
            if (!output->kafka.kafka) {
                L_ERROR("%s: error init kafka file %s@%s, %s", pub->id, config->kafka.topic, config->kafka.brokers,
                        errstr);
                free(output);
                return -1;
            }
            rd_kafka_set_logger(output->kafka.kafka, ecr_pub_kafka_logger);
            rd_kafka_set_log_level(output->kafka.kafka, LOG_INFO);

            if (rd_kafka_brokers_add(output->kafka.kafka, config->kafka.brokers) == 0) {
                L_ERROR("%s: error init kafka file %s@%s", pub->id, config->kafka.topic, config->kafka.brokers);
                free(output);
                return -1;
            }
        } else {
            output->kafka.kafka = pub->config.kafka;
            if (!output->kafka.kafka) {
                L_ERROR(
                        "%s: error init kafka file %s@%s, no broker configured and no system default kafka is configured.",
                        pub->id, config->kafka.topic, config->kafka.brokers);
                free(output);
                return -1;
            }
        }

        output->kafka.topic_conf = rd_kafka_topic_conf_new();
        output->kafka.topic = rd_kafka_topic_new(output->kafka.kafka, config->kafka.topic, output->kafka.topic_conf);
        if (!output->kafka.topic) {
            L_ERROR("%s: error init kafka file %s@%s, Failed to create new topic: %s", pub->id, config->kafka.topic,
                    config->kafka.brokers, rd_kafka_err2str(rd_kafka_errno2err(errno)));
            free(output);
            return -1;
        }
        output->total = ecr_counter_create(pub->config.cctx, pub->id, "kafka_ok", 0);
        output->total_bytes = ecr_counter_create(pub->config.cctx, pub->id, "kafka_bytes", 0);
        L_INFO("%s: add kafka output: %s@%s.", pub->id, config->kafka.topic, config->kafka.brokers);
        break;
    default:
        L_ERROR("%s: unknown pub type: %d", pub->id, config->type);
        free(output);
        return -1;
    }
    output->type = config->type;
    output->codec = ECR_PUB_CODEC_NONE;
    if (config->format) {
        size_t off = strspn(config->format, "abcdefghijklmnopqrstuvwxyz0123456789");
        if (off && config->format[off] == ':') {
            char *codec_name = strndup(config->format, off);
            i = 0;
            while (pub->config.codecs[i].name) {
                if (strcmp(codec_name, pub->config.codecs[i].name) == 0) {
                    output->codec = pub->config.codecs[i].codec;
                    output->format = strdup(config->format + off + 1);
                    break;
                }
                i++;
            }
            free(codec_name);
        }
        if (!output->format) {
            output->format = strdup(config->format);
        }
    }
    if (pub->config.output_init_cb) {
        pub->config.output_init_cb(pub, output);
    }
    output->next = pub->outputs;
    pub->outputs = output;
    return 0;
}

void ecr_pub(ecr_pub_t *pub, void *data, int tid) {
    ecr_pub_output_t *output = pub->outputs;
    ecr_str_t *buf = &pub->buf_array[tid];
    FILE *stream = pub->stream_array[tid];

    while (output) {
        ecr_counter_incr(output->total);
        if (output->type != ECR_PUB_STAT) {
            rewind(stream);
            pub->config.write_cb(pub, output, stream, data, tid);
            fflush(stream);
            switch (output->type) {
            case ECR_PUB_ZMQ:
                pthread_mutex_lock(&output->zmq.lock);
                zmq_send(output->zmq.skt, buf->ptr, buf->len, ZMQ_DONTWAIT);
                pthread_mutex_unlock(&output->zmq.lock);
                break;
            case ECR_PUB_FILE:
                fwrite(buf->ptr, buf->len, 1,
                        output->file.array[tid * output->file.split + output->file.idx_array[tid]]);
                if (++output->file.idx_array[tid] == output->file.split) {
                    output->file.idx_array[tid] = 0;
                }
                break;
            case ECR_PUB_KAFKA:
                rd_kafka_produce(output->kafka.topic, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, buf->ptr, buf->len,
                        (NULL), 0, (NULL));
                rd_kafka_poll(output->kafka.kafka, 0);
                break;
            default:
                break;
            }
            ecr_counter_add(output->total_bytes, buf->len);
        }
        output = output->next;
    }
}

void ecr_pub_destroy(ecr_pub_t *pub) {
    ecr_pub_output_t *output = pub->outputs, *next;
    int i, j;
    FILE *file;

    L_INFO("destroy pub %s", pub->id);
    while (output) {
        if (pub->config.output_destroy_cb) {
            pub->config.output_destroy_cb(pub, output);
        }
        switch (output->type) {
        case ECR_PUB_STAT:
            // do nothing
            break;
        case ECR_PUB_ZMQ:
            zmq_close(output->zmq.skt);
            pthread_mutex_destroy(&output->zmq.lock);
            break;
        case ECR_PUB_FILE:
            for (i = 0; i < pub->config.num_threads; i++) {
                for (j = 0; j < output->file.split; j++) {
                    if ((file = output->file.array[i * output->file.split + j])) {
                        fclose(file);
                    }
                }
            }
            free(output->file.array);
            free(output->file.idx_array);
            break;
        case ECR_PUB_KAFKA:
            rd_kafka_poll(output->kafka.kafka, 0);
            rd_kafka_topic_destroy(output->kafka.topic);
            if (output->kafka.new) {
                rd_kafka_destroy(output->kafka.kafka);
                rd_kafka_wait_destroyed(1000);
            }
            break;
        }
        free_to_null(output->format);
        next = output->next;
        free(output);
        output = next;
    }
    pub->outputs = NULL;
    if (pub->stream_array) {
        for (i = 0; i < pub->config.num_threads; i++) {
            fclose(pub->stream_array[i]);
            free_to_null(pub->buf_array[i].ptr);
        }
        free_to_null(pub->stream_array);
        free_to_null(pub->buf_array);
    }
    free_to_null(pub->id);
}
