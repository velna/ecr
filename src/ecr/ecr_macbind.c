/*
 * ecr_macbind.c
 *
 *  Created on: Apr 17, 2014
 *      Author: dev
 */

#include "config.h"
#include "ecr_macbind.h"
#include "ecr_hashmap.h"
#include "ecr_util.h"
#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>

static ecr_hashmap_t ecr_device_macs;

int ecr_macbind_init(char * prefix, char * suffix) {
    struct ifaddrs *ifap, *ifaptr;
    unsigned char *ptr;

    if (prefix == NULL) {
        prefix = "";
    }
    if (suffix == NULL) {
        suffix = "";
    }

    char * data = calloc(strlen(prefix) + strlen(suffix) + 32, sizeof(char));

    ecr_hashmap_init(&ecr_device_macs, 16, 0);
    if (getifaddrs(&ifap) == 0) {
        for (ifaptr = ifap; ifaptr != NULL; ifaptr = (ifaptr)->ifa_next) {
            if (((ifaptr)->ifa_addr)->sa_family == AF_PACKET) {
                ptr = (unsigned char *) ifaptr->ifa_addr;
                ptr += 12;

                int data_len = sprintf(data, "%s%02X:%02X:%02X:%02X:%02X:%02X%s", prefix, *ptr, *(ptr + 1), *(ptr + 2),
                                       *(ptr + 3), *(ptr + 4), *(ptr + 5), suffix);

                MD5_CTX md5ctx;
                char md5[MD5_DIGEST_LENGTH], md5_hex[MD5_DIGEST_LENGTH * 2 + 1];
                MD5_Init(&md5ctx);
                MD5_Update(&md5ctx, data, data_len);
                MD5_Final((unsigned char *) md5, &md5ctx);
                ecr_hex_str(md5, MD5_DIGEST_LENGTH, md5_hex);

                ecr_hashmap_put(&ecr_device_macs, ifaptr->ifa_name, strlen(ifaptr->ifa_name), strdup(md5_hex));
            }
        }
        freeifaddrs(ifap);
    }

    free(data);

    return 0;
}

int ecr_macbind_matches(const char * device, const char * binds) {
    if (binds == NULL) {
        return 0;
    }

    char * mac = NULL;
    if ((mac = ecr_hashmap_get(&ecr_device_macs, device, strlen(device))) != NULL) {
        if (strcasestr(binds, mac)) {
            return 0;
        }
    }
    return -1;
}

static void ecr_macbind_free_handler(ecr_hashmap_t *map, void * key, size_t key_size, void * value) {
    if (value != NULL) {
        free(value);
    }
}

void ecr_macbind_destroy() {
    ecr_hashmap_destroy(&ecr_device_macs, ecr_macbind_free_handler);
}
