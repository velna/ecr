/*
 * ecr_io_kafka.c
 *
 *  Created on: Sep 17, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_kafka.h"
#include "ecr_config.h"
#include "ecr_logger.h"
#include "ecr_util.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

static void ecr_kafka_logger(const rd_kafka_t *rk, int level, const char *fac, const char *buf) {
    L_LOG(level, "%s: %s", rd_kafka_name(rk), buf);
}

int ecr_kafka_init(ecr_kafka_t *iokafka, const char *brokers, const char *topic, const char *options) {
    char errstr[512];
    rd_kafka_conf_t *conf;
    rd_kafka_topic_conf_t *topic_conf;

    memset(iokafka, 0, sizeof(ecr_kafka_t));
    conf = rd_kafka_conf_new();
    iokafka->rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    rd_kafka_conf_destroy(conf);
    if (!iokafka->rk) {
        L_ERROR("Failed to create new producer: %s", errstr);
        return -1;
    }
    rd_kafka_set_logger(iokafka->rk, ecr_kafka_logger);
    rd_kafka_set_log_level(iokafka->rk, LOG_INFO);

    if (rd_kafka_brokers_add(iokafka->rk, brokers) == 0) {
        L_ERROR("No valid brokers specified.");
        return -1;
    }

    topic_conf = rd_kafka_topic_conf_new();
    iokafka->rkt = rd_kafka_topic_new(iokafka->rk, topic, topic_conf);
    rd_kafka_topic_conf_destroy(topic_conf);
    if (!iokafka->rkt) {
        L_ERROR("Failed to create new topic: %s", rd_kafka_err2str(rd_kafka_errno2err(errno)));
        return -1;
    }

    return 0;
}

int ecr_kafka_produce(ecr_kafka_t *iokafka, const char *buf, size_t len) {
    int rc = rd_kafka_produce(iokafka->rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, (void*) buf, len, NULL, 0,
            (NULL));

    rd_kafka_poll(iokafka->rk, 0);

    return rc;
}

int ecr_kafka_destroy(ecr_kafka_t *iokafka) {
    rd_kafka_poll(iokafka->rk, 0);
    rd_kafka_topic_destroy(iokafka->rkt);
    rd_kafka_destroy(iokafka->rk);
    rd_kafka_wait_destroyed(1000);

    return 0;
}
