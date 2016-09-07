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

static int ecr_kafka_conf_set(rd_kafka_conf_t *conf, const char *name, const char *id, ecr_config_t *config) {
    int rc = 0;
    char *value, errstr[512];
    if (ecr_config_get(config, id, name, ECR_CFG_STRING, &value) == 0) {
        if (rd_kafka_conf_set(conf, name, value, errstr, 512) != RD_KAFKA_CONF_OK) {
            L_ERROR("error set kafka conf: name=[%s], value=[%s], errstr=[%s].", name, value, errstr);
            rc = -1;
        }
    }
    return rc;
}

static int ecr_kafka_topic_conf_set(rd_kafka_topic_conf_t *conf, const char *name, const char *id, ecr_config_t *config) {
    int rc = 0;
    char *value, errstr[512];
    if (ecr_config_get(config, id, name, ECR_CFG_STRING, &value) == 0) {
        if (rd_kafka_topic_conf_set(conf, name, value, errstr, 512) != RD_KAFKA_CONF_OK) {
            L_ERROR("error set kafka topic conf: name=[%s], value=[%s], errstr=[%s].", name, value, errstr);
            rc = -1;
        }
    }
    return rc;
}

static void ecr_kafka_logger(const rd_kafka_t *rk, int level, const char *fac, const char *buf) {
    L_LOG(level, "%s: %s", rd_kafka_name(rk), buf);
}

static rd_kafka_t* ecr_kafka_new(rd_kafka_type_t type, const char *brokers, const char *id, ecr_config_t *config) {
    rd_kafka_conf_t *conf = rd_kafka_conf_new();
    rd_kafka_t *kafka;
    char errstr[512];

#define CONF_SET(name) \
    if (ecr_kafka_conf_set(conf, name, id, config)) { \
        goto error; \
    }

    CONF_SET("client.id")
    CONF_SET("metadata.broker.list")
    CONF_SET("bootstrap.servers")
    CONF_SET("message.max.bytes")
    CONF_SET("receive.message.max.bytes")
    CONF_SET("max.in.flight.requests.per.connection")
    CONF_SET("metadata.request.timeout.ms")
    CONF_SET("topic.metadata.refresh.interval.ms")
    CONF_SET("topic.metadata.refresh.fast.cnt")
    CONF_SET("topic.metadata.refresh.fast.interval.ms")
    CONF_SET("topic.metadata.refresh.sparse")
    CONF_SET("topic.blacklist")
    CONF_SET("debug")
    CONF_SET("socket.timeout.ms")
    CONF_SET("socket.blocking.max.ms")
    CONF_SET("socket.send.buffer.bytes")
    CONF_SET("socket.receive.buffer.bytes")
    CONF_SET("socket.keepalive.enable")
    CONF_SET("socket.max.fails")
    CONF_SET("broker.address.ttl")
    CONF_SET("broker.address.family")
    CONF_SET("reconnect.backoff.jitter.ms")
    CONF_SET("statistics.interval.ms")
    CONF_SET("enabled_events")
    CONF_SET("log_level")
    CONF_SET("log.thread.name")
    CONF_SET("log.connection.close")
    CONF_SET("internal.termination.signal")
    CONF_SET("api.version.request")
    CONF_SET("api.version.fallback.ms")
    CONF_SET("broker.version.fallback")
    CONF_SET("security.protocol")
    CONF_SET("ssl.cipher.suites")
    CONF_SET("ssl.key.location")
    CONF_SET("ssl.key.password")
    CONF_SET("ssl.certificate.location")
    CONF_SET("ssl.ca.location")
    CONF_SET("ssl.crl.location")
    CONF_SET("sasl.mechanisms")
    CONF_SET("sasl.kerberos.service.name")
    CONF_SET("sasl.kerberos.principal")
    CONF_SET("sasl.kerberos.kinit.cmd")
    CONF_SET("sasl.kerberos.keytab")
    CONF_SET("sasl.kerberos.min.time.before.relogin")
    CONF_SET("sasl.username")
    CONF_SET("sasl.password")
    CONF_SET("group.id")
    CONF_SET("partition.assignment.strategy")
    CONF_SET("session.timeout.ms")
    CONF_SET("heartbeat.interval.ms")
    CONF_SET("group.protocol.type")
    CONF_SET("coordinator.query.interval.ms")
    CONF_SET("enable.auto.commit")
    CONF_SET("auto.commit.interval.ms")
    CONF_SET("enable.auto.offset.store")
    CONF_SET("queued.min.messages")
    CONF_SET("queued.max.messages.kbytes")
    CONF_SET("fetch.wait.max.ms")
    CONF_SET("fetch.message.max.bytes")
    CONF_SET("max.partition.fetch.bytes")
    CONF_SET("fetch.min.bytes")
    CONF_SET("fetch.error.backoff.ms")
    CONF_SET("offset.store.method")
    CONF_SET("enable.partition.eof")
    CONF_SET("queue.buffering.max.messages")
    CONF_SET("queue.buffering.max.kbytes")
    CONF_SET("queue.buffering.max.ms")
    CONF_SET("message.send.max.retries")
    CONF_SET("retries")
    CONF_SET("retry.backoff.ms")
    CONF_SET("compression.codec")
    CONF_SET("batch.num.messages")
    CONF_SET("delivery.report.only.error")
#undef CONF_SET
    rd_kafka_conf_set_log_cb(conf, ecr_kafka_logger);
    kafka = rd_kafka_new(type, conf, errstr, sizeof(errstr));
    if (!kafka) {
        L_ERROR("error create producer: %s", errstr);
        goto error;
    }
    rd_kafka_set_log_level(kafka, LOG_INFO);
    if (brokers && rd_kafka_brokers_add(kafka, brokers) == 0) {
        L_ERROR("invalid brokers[%s]: %s", brokers, rd_kafka_err2str(rd_kafka_last_error()));
        goto error;
    }
    return kafka;

    error: {
        rd_kafka_conf_destroy(conf);
        return NULL;
    }
}

rd_kafka_t* ecr_kafka_new_producer(const char *brokers, const char *id, ecr_config_t *config) {
    return ecr_kafka_new(RD_KAFKA_PRODUCER, brokers, id, config);
}

rd_kafka_t* ecr_kafka_new_consumer(const char *brokers, const char *id, ecr_config_t *config) {
    return ecr_kafka_new(RD_KAFKA_CONSUMER, brokers, id, config);
}

rd_kafka_topic_t * ecr_kafka_new_topic(rd_kafka_t *kafka, const char *id, const char *topic_name, ecr_config_t *config) {
    rd_kafka_topic_conf_t *topic_conf;
    rd_kafka_topic_t * topic;
    char *topic_id;

    topic_conf = rd_kafka_topic_conf_new();
    asprintf(&topic_id, "%s.%s", id, topic_name);
#define CONF_SET(name) \
    if (ecr_kafka_topic_conf_set(topic_conf, name, topic_id, config)) { \
        goto error; \
    }
    CONF_SET("request.required.acks")
    CONF_SET("acks")
    CONF_SET("request.timeout.ms")
    CONF_SET("message.timeout.ms")
    CONF_SET("produce.offset.report")
    CONF_SET("compression.codec")
    CONF_SET("auto.commit.enable")
    CONF_SET("enable.auto.commit")
    CONF_SET("auto.commit.interval.ms")
    CONF_SET("auto.offset.reset")
    CONF_SET("offset.store.path")
    CONF_SET("offset.store.sync.interval.ms")
    CONF_SET("offset.store.method")
    CONF_SET("consume.callback.max.messages")
#undef CONF_SET

    free(topic_id);
    topic = rd_kafka_topic_new(kafka, topic_name, topic_conf);
    if (!topic) {
        L_ERROR("error create topic [%s]: %s", topic_name, rd_kafka_err2str(rd_kafka_last_error()));
        goto error;
    }
    return topic;

    error: {
        rd_kafka_topic_conf_destroy(topic_conf);
        return NULL;
    }
}
