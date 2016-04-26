/*
 * ecr_zmq.c
 *
 *  Created on: Nov 13, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_config.h"
#include "ecr_logger.h"
#include "ecr_util.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <zmq.h>

#define ZMQ_TCP     1
#define ZMQ_IPC     2
#define ZMQ_INPROC  3
#define ZMQ_PGM     4
#define ZMQ_EPGM    5

void * ecr_zmq_init(const char *endpoint, const char *options, void *zmq_ctx) {
    char *type, *mode;
    uint8_t key[32];
    int rc;
    void *skt;
    int sockettype;
    int transport;
    int listening;
    ecr_config_t config;

    //zmq skt options
    int sndhwm;
    int rcvhwm;
    uint64_t affinity;
    char *subscribe;
    char *unsubscribe;
    char *identity;
    int rate;
    int recovery_ivl;
    int sndbuf;
    int rcvbuf;
    int linger;
    int reconnect_ivl;
    int reconnect_ivl_max;
    int backlog;
    int64_t maxmsgsize;
    int multicast_hops;
    int rcvtimeo;
    int sndtimeo;
    int ipv6;
    int ipv4only;
    int immediate;
    int router_mandatory;
    int router_raw;
    int probe_router;
    int xpub_verbose;
    int req_correlate;
    int req_relaxed;
    int tcp_keepalive;
    int tcp_keepalive_idle;
    int tcp_keepalive_cnt;
    int tcp_keepalive_intvl;
    char *tcp_accept_filter;
    int plain_server;
    char *plain_username;
    char *plain_password;
    int curve_server;
    char *curve_publickey;
    char *curve_secretkey;
    char *curve_serverkey;
    char *zap_domain;
    int conflate;

    ecr_config_line_t cfg_lines[] = {
    //
            { "type", &type, ECR_CFG_STRING }, //
            { "mode", &mode, ECR_CFG_STRING }, //
            { "sndhwm", &sndhwm, ECR_CFG_INT, .dv.i = 1000 }, //
            { "rcvhwm", &rcvhwm, ECR_CFG_INT, .dv.i = 1000 }, //
            { "affinity", &affinity, ECR_CFG_UINT64, .dv.u64 = 0 }, //
            { "subscribe", &subscribe, ECR_CFG_STRING }, //
            { "unsubscribe", &unsubscribe, ECR_CFG_STRING }, //
            { "identity", &identity, ECR_CFG_STRING }, //
            { "rate", &rate, ECR_CFG_INT, .dv.i = 100 }, //
            { "recovery_ivl", &recovery_ivl, ECR_CFG_INT, .dv.i = 10000 }, //
            { "sndbuf", &sndbuf, ECR_CFG_INT, .dv.i = 0 }, //
            { "rcvbuf", &rcvbuf, ECR_CFG_INT, .dv.i = 0 }, //
            { "linger", &linger, ECR_CFG_INT, .dv.i = -1 }, //
            { "reconnect_ivl", &reconnect_ivl, ECR_CFG_INT, .dv.i = 100 }, //
            { "reconnect_ivl_max", &reconnect_ivl_max, ECR_CFG_INT, .dv.i = 0 }, //
            { "backlog", &backlog, ECR_CFG_INT, .dv.i = 100 }, //
            { "maxmsgsize", &maxmsgsize, ECR_CFG_INT64, .dv.i64 = -1 }, //
            { "multicast_hops", &multicast_hops, ECR_CFG_INT, .dv.i = 1 }, //
            { "rcvtimeo", &rcvtimeo, ECR_CFG_INT, .dv.i = -1 }, //
            { "sndtimeo", &sndtimeo, ECR_CFG_INT, .dv.i = -1 }, //
            { "ipv6", &ipv6, ECR_CFG_INT, .dv.i = 0 }, //
            { "ipv4only", &ipv4only, ECR_CFG_INT, .dv.i = 1 }, //
            { "immediate", &immediate, ECR_CFG_INT, .dv.i = 0 }, //
            { "router_mandatory", &router_mandatory, ECR_CFG_INT, .dv.i = 0 }, //
            { "router_raw", &router_raw, ECR_CFG_INT, .dv.i = 0 }, //
            { "probe_router", &probe_router, ECR_CFG_INT, .dv.i = 0 }, //
            { "xpub_verbose", &xpub_verbose, ECR_CFG_INT, .dv.i = 0 }, //
            { "req_correlate", &req_correlate, ECR_CFG_INT, .dv.i = 0 }, //
            { "req_relaxed", &req_relaxed, ECR_CFG_INT, .dv.i = 0 }, //
            { "tcp_keepalive", &tcp_keepalive, ECR_CFG_INT, .dv.i = -1 }, //
            { "tcp_keepalive_idle", &tcp_keepalive_idle, ECR_CFG_INT, .dv.i = -1 }, //
            { "tcp_keepalive_cnt", &tcp_keepalive_cnt, ECR_CFG_INT, .dv.i = -1 }, //
            { "tcp_keepalive_intvl", &tcp_keepalive_intvl, ECR_CFG_INT, .dv.i = -1 }, //
            { "tcp_accept_filter", &tcp_accept_filter, ECR_CFG_STRING }, //
            { "plain_server", &plain_server, ECR_CFG_INT, .dv.i = 0 }, //
            { "plain_username", &plain_username, ECR_CFG_STRING }, //
            { "plain_password", &plain_password, ECR_CFG_STRING }, //
            { "curve_server", &curve_server, ECR_CFG_INT, .dv.i = 0 }, //
            { "curve_publickey", &curve_publickey, ECR_CFG_STRING }, //
            { "curve_secretkey", &curve_secretkey, ECR_CFG_STRING }, //
            { "curve_serverkey", &curve_serverkey, ECR_CFG_STRING }, //
            { "zap_domain", &zap_domain, ECR_CFG_STRING }, //
            { "conflate", &conflate, ECR_CFG_INT, .dv.i = 0 }, //
            { 0 } };

    if (!endpoint || !options || !zmq_ctx) {
        L_ERROR("invalid zmq config");
        return NULL;
    }

    if (ecr_config_init_str(&config, options) || ecr_config_load(&config, NULL, cfg_lines)
            || ecr_config_print_unused(NULL, &config)) {
        L_ERROR("invalid zmq file options: %s", options);
        ecr_config_destroy(&config);
        return NULL;
    }
    if (!type) {
        L_ERROR("type must be configured.");
        ecr_config_destroy(&config);
        return NULL;
    }

    type = ecr_str_tolower(type);
    if (strcmp(type, "req") == 0) {
        sockettype = ZMQ_REQ;
    } else if (strcmp(type, "rep") == 0) {
        sockettype = ZMQ_REP;
    } else if (strcmp(type, "dealer") == 0) {
        sockettype = ZMQ_DEALER;
    } else if (strcmp(type, "router") == 0) {
        sockettype = ZMQ_ROUTER;
    } else if (strcmp(type, "pub") == 0) {
        sockettype = ZMQ_PUB;
    } else if (strcmp(type, "sub") == 0) {
        sockettype = ZMQ_SUB;
    } else if (strcmp(type, "xpub") == 0) {
        sockettype = ZMQ_XPUB;
    } else if (strcmp(type, "xsub") == 0) {
        sockettype = ZMQ_XSUB;
    } else if (strcmp(type, "push") == 0) {
        sockettype = ZMQ_PUSH;
    } else if (strcmp(type, "pull") == 0) {
        sockettype = ZMQ_PULL;
    } else if (strcmp(type, "pair") == 0) {
        sockettype = ZMQ_PAIR;
    } else if (strcmp(type, "stream") == 0) {
        sockettype = ZMQ_STREAM;
    } else {
        L_ERROR("invalid skt type: %s", type);
        ecr_config_destroy(&config);
        return NULL;
    }

    if (strncmp(endpoint, "tcp", 3) == 0) {
        transport = ZMQ_TCP;
    } else if (strncmp(endpoint, "ipc", 3) == 0) {
        transport = ZMQ_IPC;
    } else if (strncmp(endpoint, "inproc", 6) == 0) {
        transport = ZMQ_INPROC;
    } else if (strncmp(endpoint, "pgm", 3) == 0) {
        transport = ZMQ_PGM;
    } else if (strncmp(endpoint, "epgm", 4) == 0) {
        transport = ZMQ_EPGM;
    } else {
        L_ERROR("invalid endpoint: %s", endpoint);
        ecr_config_destroy(&config);
        return NULL;
    }

    if (strcmp(mode, "bind") == 0) {
        listening = 1;
    } else if (strcmp(mode, "connect") == 0) {
        listening = 0;
    } else {
        L_ERROR("invalid mode: %s", mode);
        ecr_config_destroy(&config);
        return NULL;
    }

    // tcp ipc inproc pgm epgm

    skt = zmq_socket(zmq_ctx, sockettype);
    zmq_setsockopt(skt, ZMQ_SNDHWM, &sndhwm, sizeof(int));
    zmq_setsockopt(skt, ZMQ_RCVHWM, &rcvhwm, sizeof(int));
    if (affinity) {
        zmq_setsockopt(skt, ZMQ_AFFINITY, &affinity, sizeof(uint64_t));
    }

    if (sockettype == ZMQ_SUB) {
        if (subscribe) {
            zmq_setsockopt(skt, ZMQ_SUBSCRIBE, subscribe, strlen(subscribe));
        }
        if (unsubscribe) {
            zmq_setsockopt(skt, ZMQ_UNSUBSCRIBE, unsubscribe, strlen(unsubscribe));
        }
    }

    if (identity
            && (sockettype == ZMQ_REQ || sockettype == ZMQ_REP || sockettype == ZMQ_ROUTER || sockettype == ZMQ_DEALER)) {
        zmq_setsockopt(skt, ZMQ_IDENTITY, identity, strlen(identity));
    }

    if (transport == ZMQ_PGM || transport == ZMQ_EPGM) {
        zmq_setsockopt(skt, ZMQ_RATE, &rate, sizeof(int));
        zmq_setsockopt(skt, ZMQ_RECOVERY_IVL, &recovery_ivl, sizeof(int));
        zmq_setsockopt(skt, ZMQ_MULTICAST_HOPS, &multicast_hops, sizeof(int));
    }
    zmq_setsockopt(skt, ZMQ_SNDBUF, &sndbuf, sizeof(int));
    zmq_setsockopt(skt, ZMQ_RCVBUF, &rcvbuf, sizeof(int));
    zmq_setsockopt(skt, ZMQ_LINGER, &linger, sizeof(int));

    if (transport == ZMQ_TCP || transport == ZMQ_IPC || transport == ZMQ_INPROC) {
        zmq_setsockopt(skt, ZMQ_RECONNECT_IVL, &reconnect_ivl, sizeof(int));
        zmq_setsockopt(skt, ZMQ_RECONNECT_IVL_MAX, &reconnect_ivl_max, sizeof(int));
        zmq_setsockopt(skt, ZMQ_BACKLOG, &backlog, sizeof(int));
        zmq_setsockopt(skt, ZMQ_IMMEDIATE, &immediate, sizeof(int));
    }
    zmq_setsockopt(skt, ZMQ_MAXMSGSIZE, &maxmsgsize, sizeof(int64_t));
    zmq_setsockopt(skt, ZMQ_RCVTIMEO, &rcvtimeo, sizeof(int));
    zmq_setsockopt(skt, ZMQ_SNDTIMEO, &sndtimeo, sizeof(int));

    if (transport == ZMQ_TCP) {
        zmq_setsockopt(skt, ZMQ_IPV6, &ipv6, sizeof(int));
        zmq_setsockopt(skt, ZMQ_IPV4ONLY, &ipv4only, sizeof(int));
        zmq_setsockopt(skt, ZMQ_TCP_KEEPALIVE, &tcp_keepalive, sizeof(int));
        zmq_setsockopt(skt, ZMQ_TCP_KEEPALIVE_IDLE, &tcp_keepalive_idle, sizeof(int));
        zmq_setsockopt(skt, ZMQ_TCP_KEEPALIVE_CNT, &tcp_keepalive_cnt, sizeof(int));
        zmq_setsockopt(skt, ZMQ_TCP_KEEPALIVE_INTVL, &tcp_keepalive_intvl, sizeof(int));
        if (tcp_accept_filter && listening) {
            zmq_setsockopt(skt, ZMQ_TCP_ACCEPT_FILTER, tcp_accept_filter, strlen(tcp_accept_filter));
        }
        zmq_setsockopt(skt, ZMQ_PLAIN_SERVER, &plain_server, sizeof(int));
        if (plain_username) {
            zmq_setsockopt(skt, ZMQ_PLAIN_USERNAME, plain_username, strlen(plain_username));
        }
        if (plain_password) {
            zmq_setsockopt(skt, ZMQ_PLAIN_PASSWORD, plain_password, strlen(plain_password));
        }
        zmq_setsockopt(skt, ZMQ_CURVE_SERVER, &curve_server, sizeof(int));
        if (curve_publickey && strlen(curve_publickey) == 40) {
            zmq_setsockopt(skt, ZMQ_CURVE_PUBLICKEY, zmq_z85_decode(key, curve_publickey), 32);
        }
        if (curve_secretkey && strlen(curve_secretkey) == 40) {
            zmq_setsockopt(skt, ZMQ_CURVE_SECRETKEY, zmq_z85_decode(key, curve_secretkey), 32);
        }
        if (curve_serverkey && strlen(curve_serverkey) == 40) {
            zmq_setsockopt(skt, ZMQ_CURVE_SERVERKEY, zmq_z85_decode(key, curve_serverkey), 32);
        }
        if (zap_domain) {
            zmq_setsockopt(skt, ZMQ_ZAP_DOMAIN, zap_domain, strlen(zap_domain));
        }
    }

    if (sockettype == ZMQ_ROUTER) {
        zmq_setsockopt(skt, ZMQ_ROUTER_MANDATORY, &router_mandatory, sizeof(int));
        zmq_setsockopt(skt, ZMQ_ROUTER_RAW, &router_raw, sizeof(int));
    }

    if (sockettype == ZMQ_ROUTER || sockettype == ZMQ_DEALER || sockettype == ZMQ_REQ) {
        zmq_setsockopt(skt, ZMQ_PROBE_ROUTER, &probe_router, sizeof(int));
    }

    if (sockettype == ZMQ_XPUB) {
        zmq_setsockopt(skt, ZMQ_XPUB_VERBOSE, &xpub_verbose, sizeof(int));
    }

    if (sockettype == ZMQ_REQ) {
        zmq_setsockopt(skt, ZMQ_REQ_CORRELATE, &req_correlate, sizeof(int));
        zmq_setsockopt(skt, ZMQ_REQ_RELAXED, &req_relaxed, sizeof(int));
    }

    if (sockettype == ZMQ_PULL || sockettype == ZMQ_PUSH || sockettype == ZMQ_SUB || sockettype == ZMQ_PUB
            || sockettype == ZMQ_DEALER) {
        zmq_setsockopt(skt, ZMQ_CONFLATE, &conflate, sizeof(int));
    }

    if (listening) {
        rc = zmq_bind(skt, endpoint);
    } else {
        rc = zmq_connect(skt, endpoint);
    }
    if (rc) {
        L_ERROR("error init zmq skt: %s", zmq_strerror(zmq_errno()));
        zmq_close(skt);
        ecr_config_destroy(&config);
        return NULL;
    }
    ecr_config_destroy(&config);
    return skt;
}

