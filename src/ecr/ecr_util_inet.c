/*
 * ecr_util_inet.c
 *
 *  Created on: Jan 12, 2016
 *      Author: velna
 */

#include "config.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

static const char * ecr_inet_ntop_v4(const void *src, char *dst, size_t size) {
    const char digits[] = "0123456789";
    int i;
    struct in_addr *addr = (struct in_addr *) src;
    u_long a = ntohl(addr->s_addr);
    const char *orig_dst = dst;

    if (size < INET_ADDRSTRLEN) {
        errno = ENOSPC;
        return NULL;
    }
    for (i = 0; i < 4; ++i) {
        int n = (a >> (24 - i * 8)) & 0xFF;
        int non_zerop = 0;

        if (non_zerop || n / 100 > 0) {
            *dst++ = digits[n / 100];
            n %= 100;
            non_zerop = 1;
        }
        if (non_zerop || n / 10 > 0) {
            *dst++ = digits[n / 10];
            n %= 10;
            non_zerop = 1;
        }
        *dst++ = digits[n];
        if (i != 3)
            *dst++ = '.';
    }
    *dst++ = '\0';
    return orig_dst;
}

static const char * ecr_inet_ntop_v6(const void *src, char *dst, size_t size) {
    const char xdigits[] = "0123456789abcdef";
    int i;
    const struct in6_addr *addr = (struct in6_addr *) src;
    const u_char *ptr = addr->s6_addr;
    const char *orig_dst = dst;
    int compressed = 0;

    if (size < INET6_ADDRSTRLEN) {
        errno = ENOSPC;
        return NULL;
    }
    for (i = 0; i < 8; ++i) {
        int non_zerop = 0;

        if (compressed == 0 && ptr[0] == 0 && ptr[1] == 0 && i <= 5 && ptr[2] == 0 && ptr[3] == 0 && ptr[4] == 0
                && ptr[5] == 0) {

            compressed = 1;

            if (i == 0)
                *dst++ = ':';
            *dst++ = ':';

            for (ptr += 6, i += 3; i < 8 && ptr[0] == 0 && ptr[1] == 0; ++i, ptr += 2)
                ;

            if (i >= 8)
                break;
        }

        if (non_zerop || (ptr[0] >> 4)) {
            *dst++ = xdigits[ptr[0] >> 4];
            non_zerop = 1;
        }
        if (non_zerop || (ptr[0] & 0x0F)) {
            *dst++ = xdigits[ptr[0] & 0x0F];
            non_zerop = 1;
        }
        if (non_zerop || (ptr[1] >> 4)) {
            *dst++ = xdigits[ptr[1] >> 4];
            non_zerop = 1;
        }
        *dst++ = xdigits[ptr[1] & 0x0F];
        if (i != 7)
            *dst++ = ':';
        ptr += 2;
    }
    *dst++ = '\0';
    return orig_dst;
}

const char * ecr_inet_ntop(int af, const void *src, char *dst, size_t size) {
    switch (af) {
    case AF_INET:
        return ecr_inet_ntop_v4(src, dst, size);
    case AF_INET6:
        return ecr_inet_ntop_v6(src, dst, size);
    default:
        errno = EAFNOSUPPORT;
        return NULL;
    }
}

int ecr_socket_bind(const char *endpoint) {
    char *s, *proto, *host, *sport;
    int port, sock = -1, tcp;
    struct sockaddr_in dest_addr;

    s = strstr(endpoint, "://");
    if (!s) {
        return -1;
    }
    proto = strndup(endpoint, s - endpoint);
    s += 3;
    sport = strchr(s, ':');
    if (!sport) {
        free(proto);
        return -1;
    }
    host = strndup(s, sport - s);
    sport++;
    port = atoi(sport);
    if (port <= 0) {
        goto end;
    }
    tcp = 0;
    if (strcmp("tcp", proto) == 0) {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        tcp = 1;
    } else if (strcmp("udp", proto) == 0) {
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    } else {
        goto end;
    }
    if (sock < 0) {
        goto end;
    }
    memset(&dest_addr, 0, sizeof(struct sockaddr_in));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = host[0] == '*' ? INADDR_ANY : inet_addr(host);
    if (bind(sock, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr))) {
        close(sock);
        sock = -1;
        goto end;
    }
    if (tcp) {
        if (listen(sock, 128)) {
            close(sock);
            sock = -1;
            goto end;
        }
    }
    end: {
        free(proto);
        free(host);
        return sock;
    }
}
