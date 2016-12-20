/*
 * ecr_pub.h
 *
 *  Created on: Jan 15, 2016
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_PUB_H_
#define SRC_ECR_ECR_PUB_H_

#include "ecrconf.h"
#include "ecr_config.h"
#include "ecr_io.h"
#include "ecr_counter.h"
#include <pcap.h>
#include <pthread.h>
#include <librdkafka/rdkafka.h>

#define ECR_PUB_CODEC_NONE  -1

typedef enum {
    ECR_PUB_STAT, ECR_PUB_ZMQ, ECR_PUB_FILE, ECR_PUB_KAFKA, ECR_PUB_PACKET
} ecr_pub_type_t;

typedef struct {
    ecr_pub_type_t type;
    union {
        struct {
            const char *endpoint;
            const char *options;
        } zmq;
        struct {
            const char *name;
            int split;
        } file;
        struct {
            const char *brokers;
            const char *topic;
        } kafka;
        struct {
            const char *device;
        } packet;
    };
    const char *format;
    ecr_config_t *config;
} ecr_pub_output_config_t;

typedef struct ecr_pub_output_s {
    ecr_pub_type_t type;
    int codec;
    char *format;
    void *user;
    ecr_counter_t *ok;
    ecr_counter_t *error;
    ecr_counter_t *bytes_ok;
    ecr_counter_t *bytes_error;
    union {
        struct {
            void *skt;
            pthread_mutex_t lock;
        } zmq;
        struct {
            FILE **array;
            int split;
            int *idx_array;
        } file;
        struct {
            int new;
            rd_kafka_t *kafka;
            rd_kafka_topic_t *topic;
        } kafka;
        struct {
            pcap_t *pcap;
        } packet;
    };
    struct ecr_pub_output_s *next;
} ecr_pub_output_t;

typedef struct {
    const char *name;
    int codec;
} ecr_pub_codec_t;

typedef struct ecr_pub_s ecr_pub_t;

typedef void (*ecr_pub_write_cb)(ecr_pub_t *pub, ecr_pub_output_t *output, FILE *stream, void *data, int tid);

typedef void (*ecr_pub_output_cb)(ecr_pub_t *pub, ecr_pub_output_t *output);

typedef struct {
    int num_threads;
    ecr_counter_ctx_t *cctx;
    void *zmq_ctx;
    rd_kafka_t *kafka;
    ecr_io_reg_t *io_regs;
    ecr_pub_codec_t *codecs;
    ecr_pub_write_cb write_cb;
    ecr_pub_output_cb output_init_cb;
    ecr_pub_output_cb output_destroy_cb;
} ecr_pub_config_t;

struct ecr_pub_s {
    char *id;
    ecr_pub_config_t config;
    ecr_str_t *buf_array;
    FILE **stream_array;
    ecr_pub_output_t *outputs;
};

int ecr_pub_init(ecr_pub_t *pub, const char *id, ecr_pub_config_t *config);

int ecr_pub_output_config(ecr_pub_t *pub, ecr_config_t *config);

int ecr_pub_output_add(ecr_pub_t *pub, ecr_pub_output_config_t *output_config, ecr_config_t *config);

void ecr_pub_key(ecr_pub_t *pub, void *data, void *key, size_t key_len, int tid);

#define ecr_pub(pub, data, tid) ecr_pub_key(pub, data, NULL, 0, tid)

void ecr_pub_destroy(ecr_pub_t *pub);

#endif /* SRC_ECR_ECR_PUB_H_ */
