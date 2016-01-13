/*
 * ecr_kafka.h
 *
 *  Created on: Nov 13, 2015
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_KAFKA_H_
#define SRC_ECR_ECR_KAFKA_H_

#include "ecrconf.h"
#include <librdkafka/rdkafka.h>

typedef struct {
    rd_kafka_t *rk;
    rd_kafka_topic_t *rkt;
} ecr_kafka_t;

int ecr_kafka_init(ecr_kafka_t *iokafka, const char *brokers, const char *topic, const char *options);

int ecr_kafka_produce(ecr_kafka_t *iokafka, const char *buf, size_t len);

int ecr_kafka_destroy(ecr_kafka_t *iokafka);

#endif /* SRC_ECR_ECR_KAFKA_H_ */
