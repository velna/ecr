/*
 * ecr_kafka.h
 *
 *  Created on: Nov 13, 2015
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_KAFKA_H_
#define SRC_ECR_ECR_KAFKA_H_

#include "ecrconf.h"
#include "ecr_config.h"
#include <librdkafka/rdkafka.h>

rd_kafka_t * ecr_kafka_new_producer(const char *brokers, const char *id, ecr_config_t *config);

rd_kafka_t * ecr_kafka_new_consumer(const char *brokers, const char *id, ecr_config_t *config);

rd_kafka_topic_t * ecr_kafka_new_topic(rd_kafka_t *kafka, const char *id, const char *topic_name, ecr_config_t *config);

#endif /* SRC_ECR_ECR_KAFKA_H_ */
