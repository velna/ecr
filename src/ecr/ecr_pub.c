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
#include "ecr_kafka.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <zmq.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

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
    ecr_pub_output_config_t packet_config = { .type = ECR_PUB_PACKET };
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
            { "packet_device", &kafka_config.packet.device, ECR_CFG_STRING }, //
            { 0 } };

    ecr_config_load(config, pub->id, config_lines);
    if (file_config.format && file_config.file.name) {
        if (ecr_pub_output_add(pub, &file_config, config)) {
            error++;
        } else {
            ok++;
        }
    }
    if (zmq_config.format && zmq_config.zmq.endpoint) {
        if (ecr_pub_output_add(pub, &zmq_config, config)) {
            error++;
        } else {
            ok++;
        }
    }
    if (kafka_config.format && kafka_config.kafka.topic) {
        if (ecr_pub_output_add(pub, &kafka_config, config)) {
            error++;
        } else {
            ok++;
        }
    }
    if (packet_config.format && packet_config.packet.device) {
        if (ecr_pub_output_add(pub, &packet_config, config)) {
            error++;
        } else {
            ok++;
        }
    }
    if (!ok) {
        if (ecr_pub_output_add(pub, &stat_config, config)) {
            error++;
        }
    }
    return error ? -1 : 0;
}

int ecr_pub_output_add(ecr_pub_t *pub, ecr_pub_output_config_t *output_config, ecr_config_t *config) {
    ecr_pub_output_t *output = calloc(1, sizeof(ecr_pub_output_t));
    int i, j;
    char *fp, *s, errstr[512], *id;
    FILE *file;
    char errbuf[PCAP_ERRBUF_SIZE];

    switch (output_config->type) {
    case ECR_PUB_STAT:
        output->ok = ecr_counter_create(pub->config.cctx, pub->id, "stat_ok", 0);
        output->error = ecr_counter_create(pub->config.cctx, pub->id, "stat_error", 0);
        output->bytes_ok = ecr_counter_create(pub->config.cctx, pub->id, "stat_bytes_ok", 0);
        output->bytes_error = ecr_counter_create(pub->config.cctx, pub->id, "stat_bytes_error", 0);
        L_INFO("%s: add stat only output.", pub->id);
        break;
    case ECR_PUB_ZMQ:
        if (!pub->config.zmq_ctx) {
            L_ERROR("%s: no zmq context configurred.", pub->id);
            free(output);
            return -1;
        }
        output->zmq.skt = ecr_zmq_init(output_config->zmq.endpoint, output_config->zmq.options, pub->config.zmq_ctx);
        if (!output->zmq.skt) {
            L_ERROR("%s: error init zmq file %s[%s]", pub->id, output_config->zmq.endpoint, output_config->zmq.options);
            free(output);
            return -1;
        }
        pthread_mutex_init(&output->zmq.lock, NULL);
        output->ok = ecr_counter_create(pub->config.cctx, pub->id, "zmq_ok", 0);
        output->error = ecr_counter_create(pub->config.cctx, pub->id, "zmq_error", 0);
        output->bytes_ok = ecr_counter_create(pub->config.cctx, pub->id, "zmq_bytes_ok", 0);
        output->bytes_error = ecr_counter_create(pub->config.cctx, pub->id, "zmq_bytes_error", 0);
        L_INFO("%s: add zmq output: %s[%s].", pub->id, output_config->zmq.endpoint, output_config->zmq.options);
        break;
    case ECR_PUB_FILE:
        output->file.split = output_config->file.split <= 0 ? 1 : output_config->file.split;
        output->file.idx_array = calloc(pub->config.num_threads, sizeof(int));
        output->file.array = calloc(pub->config.num_threads * output->file.split, sizeof(FILE *));
        for (i = 0; i < pub->config.num_threads; i++) {
            for (j = 0; j < output->file.split; j++) {
                fp = strdup(output_config->file.name);
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
                    L_ERROR("%s: error init rolling file %s", pub->id, output_config->file.name);
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
        output->ok = ecr_counter_create(pub->config.cctx, pub->id, "file_ok", 0);
        output->error = ecr_counter_create(pub->config.cctx, pub->id, "file_error", 0);
        output->bytes_ok = ecr_counter_create(pub->config.cctx, pub->id, "file_bytes_ok", 0);
        output->bytes_error = ecr_counter_create(pub->config.cctx, pub->id, "file_bytes_error", 0);
        L_INFO("%s: add file output: %s[%d].", pub->id, output_config->file.name, output_config->file.split);
        break;
    case ECR_PUB_KAFKA:
        asprintf(&id, "%s.kafka", pub->id);
        if (output_config->kafka.brokers) {
            output->kafka.new = 1;
            output->kafka.kafka = ecr_kafka_new_producer(output_config->kafka.brokers, id, config);
            if (!output->kafka.kafka) {
                L_ERROR("%s: error init kafka file %s@%s, %s", pub->id, output_config->kafka.topic,
                        output_config->kafka.brokers, errstr);
                free(output);
                free(id);
                return -1;
            }
        } else {
            output->kafka.kafka = pub->config.kafka;
            if (!output->kafka.kafka) {
                L_ERROR(
                        "%s: error init kafka file %s@%s, no broker configured and no system default kafka is configured.",
                        pub->id, output_config->kafka.topic, output_config->kafka.brokers);
                free(output);
                free(id);
                return -1;
            }
        }

        output->kafka.topic = ecr_kafka_new_topic(output->kafka.kafka, id, output_config->kafka.topic, config);
        if (!output->kafka.topic) {
            L_ERROR("%s: error init kafka file %s@%s, Failed to create new topic: %s", pub->id,
                    output_config->kafka.topic, output_config->kafka.brokers,
                    rd_kafka_err2str(rd_kafka_errno2err(errno)));
            free(output);
            free(id);
            return -1;
        }
        output->ok = ecr_counter_create(pub->config.cctx, pub->id, "kafka_ok", 0);
        output->error = ecr_counter_create(pub->config.cctx, pub->id, "kafka_error", 0);
        output->bytes_ok = ecr_counter_create(pub->config.cctx, pub->id, "kafka_bytes_ok", 0);
        output->bytes_error = ecr_counter_create(pub->config.cctx, pub->id, "kafka_bytes_error", 0);
        L_INFO("%s: add kafka output: %s@%s.", pub->id, output_config->kafka.topic, output_config->kafka.brokers);
        free(id);
        break;
    case ECR_PUB_PACKET:
        output->packet.pcap = pcap_create(output_config->packet.device, errbuf);
        if (!output->packet.pcap) {
            L_ERROR("error open device %s for output: %s", output_config->packet.device, errbuf);
        }
        if (pcap_activate(output->packet.pcap) != 0) {
            L_ERROR("pcap_activate() error: %s", pcap_geterr(output->packet.pcap));
            free(output);
            return -1;
        }
        break;
    default:
        L_ERROR("%s: unknown pub type: %d", pub->id, output_config->type);
        free(output);
        return -1;
    }
    output->type = output_config->type;
    output->codec = ECR_PUB_CODEC_NONE;
    if (output_config->format) {
        if (pub->config.codecs) {
            size_t off = strspn(output_config->format, "abcdefghijklmnopqrstuvwxyz0123456789");
            if (off && output_config->format[off] == ':') {
                char *codec_name = strndup(output_config->format, off);
                i = 0;
                while (pub->config.codecs[i].name) {
                    if (strcmp(codec_name, pub->config.codecs[i].name) == 0) {
                        output->codec = pub->config.codecs[i].codec;
                        output->format = strdup(output_config->format + off + 1);
                        break;
                    }
                    i++;
                }
                free(codec_name);
            }
        }
        if (!output->format) {
            output->format = strdup(output_config->format);
        }
    }
    if (pub->config.output_init_cb) {
        pub->config.output_init_cb(pub, output);
    }
    output->next = pub->outputs;
    pub->outputs = output;
    return 0;
}

void ecr_pub_key(ecr_pub_t *pub, void *data, void *key, size_t key_len, int tid) {
    ecr_pub_output_t *output = pub->outputs;
    ecr_str_t *buf = &pub->buf_array[tid];
    FILE *stream = pub->stream_array[tid];
    int ok;

    while (output) {
        ok = 1;
        if (output->type != ECR_PUB_STAT) {
            rewind(stream);
            pub->config.write_cb(pub, output, stream, data, tid);
            fflush(stream);
            switch (output->type) {
            case ECR_PUB_ZMQ:
                pthread_mutex_lock(&output->zmq.lock);
                if (zmq_send(output->zmq.skt, buf->ptr, buf->len, ZMQ_DONTWAIT) == -1) {
                    ok = 0;
                }
                pthread_mutex_unlock(&output->zmq.lock);
                break;
            case ECR_PUB_FILE:
                if (fwrite(buf->ptr, buf->len, 1,
                        output->file.array[tid * output->file.split + output->file.idx_array[tid]]) != 1) {
                    ok = 0;
                }
                if (++output->file.idx_array[tid] == output->file.split) {
                    output->file.idx_array[tid] = 0;
                }
                break;
            case ECR_PUB_KAFKA:
                if (rd_kafka_produce(output->kafka.topic, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, buf->ptr,
                        buf->len, key, key_len, (NULL))) {
                    ok = 0;
                }
                rd_kafka_poll(output->kafka.kafka, 0);
                break;
            case ECR_PUB_PACKET:
                if (pcap_sendpacket(output->packet.pcap, (u_char*) buf->ptr, (int) buf->len)) {
                    ok = 0;
                }
                break;
            default:
                break;
            }
            ecr_counter_add(ok ? output->bytes_ok : output->bytes_error, buf->len);
        }
        ecr_counter_incr(ok ? output->ok : output->error);
        output = output->next;
    }
}

void ecr_pub_destroy(ecr_pub_t *pub) {
    ecr_pub_output_t *output = pub->outputs, *next;
    int i, j;
    FILE *file;

    if (!pub->id) {
        return;
    }
    L_INFO("destroy pub %s", pub->id);
    while (output) {
        if (pub->config.output_destroy_cb) {
            pub->config.output_destroy_cb(pub, output);
        }
        switch (output->type) {
        case ECR_PUB_STAT:
            ecr_counter_delete(pub->config.cctx, pub->id, "stat_ok");
            ecr_counter_delete(pub->config.cctx, pub->id, "stat_bytes");
            break;
        case ECR_PUB_ZMQ:
            zmq_close(output->zmq.skt);
            pthread_mutex_destroy(&output->zmq.lock);
            ecr_counter_delete(pub->config.cctx, pub->id, "zmq_ok");
            ecr_counter_delete(pub->config.cctx, pub->id, "zmq_bytes");
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
            ecr_counter_delete(pub->config.cctx, pub->id, "file_ok");
            ecr_counter_delete(pub->config.cctx, pub->id, "file_bytes");
            break;
        case ECR_PUB_KAFKA:
            rd_kafka_poll(output->kafka.kafka, 0);
            rd_kafka_topic_destroy(output->kafka.topic);
            if (output->kafka.new) {
                rd_kafka_destroy(output->kafka.kafka);
                rd_kafka_wait_destroyed(1000);
            }
            ecr_counter_delete(pub->config.cctx, pub->id, "kafka_ok");
            ecr_counter_delete(pub->config.cctx, pub->id, "kafka_bytes");
            break;
        case ECR_PUB_PACKET:
            if (output->packet.pcap) {
                pcap_close(output->packet.pcap);
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
