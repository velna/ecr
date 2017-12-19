/*
 * ecr_xcmd_main.c
 *
 *  Created on: Dec 15, 2016
 *      Author: velna
 */

#include <stdlib.h>
#include <string.h>
#include <zmq.h>

#define EXIT_CODE_OK                        0
#define EXIT_CODE_CMD_LINE_ERROR            1
#define EXIT_CODE_ZMQ_CONNECT_ERROR         2
#define EXIT_CODE_ZMQ_SEND_ERROR            3
#define EXIT_CODE_ZMQ_RECEIVE_TIMEOUT       4
#define EXIT_CODE_ZMQ_RECEIVE_ERROR         5

static void usage() {
    printf("xcmd zmqendpoint cmd [option]...\n");
    printf("for example: xcmd tcp://127.0.0.1:1258 help\n");
}

int main(int argc, const char** argv) {
    void* cmd_zmq_context;
    void* cmd_zmq_socket;
    int msg_len = 0, i;
    int more;
    size_t more_size = sizeof(int);
    zmq_msg_t message;
    char * cp;

    if (argc < 3) {
        usage();
        return EXIT_CODE_CMD_LINE_ERROR;
    }

    cmd_zmq_context = zmq_init(1);
    cmd_zmq_socket = zmq_socket(cmd_zmq_context, ZMQ_REQ);
    if (zmq_connect(cmd_zmq_socket, argv[1]) != 0) {
        printf("can not connect to %s: %d\n", argv[1], zmq_errno());
        return EXIT_CODE_ZMQ_CONNECT_ERROR;
    }

    msg_len += sizeof(int);
    for (i = 2; i < argc; i++) {
        msg_len += strlen(argv[i]) + 1;
    }

    zmq_msg_init_size(&message, msg_len);
    cp = zmq_msg_data(&message);
    i = argc - 2;
    memcpy(cp, &i, sizeof(int));
    cp += sizeof(int);
    for (i = 2; i < argc; i++) {
        memcpy(cp, argv[i], strlen(argv[i]) + 1);
        cp += strlen(argv[i]) + 1;
    }
    if (zmq_msg_send(&message, cmd_zmq_socket, 0) == -1) {
        printf("cmd send error: %s\n", zmq_strerror(zmq_errno()));
        return EXIT_CODE_ZMQ_SEND_ERROR;
    }
    zmq_msg_close(&message);

    zmq_pollitem_t items[] = { { cmd_zmq_socket, 0, ZMQ_POLLIN, 0 } };
    zmq_poll(items, 1, 3 * 1000);
    if (!(items[0].revents & ZMQ_POLLIN)) {
        printf("cmd receive timeout\n");
        return EXIT_CODE_ZMQ_RECEIVE_TIMEOUT;
    }

    do {
        zmq_msg_init(&message);
        if (zmq_msg_recv(&message, cmd_zmq_socket, 0) == -1) {
            printf("cmd receive error\n");
            zmq_msg_close(&message);
            zmq_term(cmd_zmq_context);
            return EXIT_CODE_ZMQ_RECEIVE_ERROR;
        }
        cp = strndup(zmq_msg_data(&message), zmq_msg_size(&message));
        printf("%s", cp);
        free(cp);
        if (zmq_getsockopt(cmd_zmq_socket, ZMQ_RCVMORE, &more, &more_size) == -1) {
            printf("cmd getsockopt error: %s", zmq_strerror(zmq_errno()));
            break;
        }
    } while (more);
    printf("\n");

    zmq_close(cmd_zmq_socket);
    zmq_term(cmd_zmq_context);
    return EXIT_CODE_OK;
}
