/*
 * ecr_ipdb.c
 *
 *  Created on: Apr 11, 2017
 *      Author: velna
 */

#include "ecr_ipdb.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include <arpa/inet.h>

static int ecr_ipdb_region_compare_func(const void *a, const void *b) {
    ecr_ipdb_region_t *ra = *((ecr_ipdb_region_t **) a), *rb = *((ecr_ipdb_region_t **) b);
    if (ra->start_ip > rb->end_ip) {
        return 1;
    }
    if (rb->start_ip > ra->end_ip) {
        return -1;
    }
    return 0;
}

int ecr_ipdb_init(ecr_ipdb_t *ipdb, const char *ipdbfile) {
    FILE *file;
    char *start_ip = NULL, *end_ip = NULL, *line = NULL, *s, *token;
    size_t n = 0;
    uint32_t province, city, county;
    ecr_ipdb_region_t *region;

    memset(ipdb, 0, sizeof(ecr_ipdb_t));

    file = fopen(ipdbfile, "r");
    if (!file) {
        return -1;
    }

    ipdb->regions = malloc(sizeof(ecr_list_t));
    ecr_list_init(ipdb->regions, 16);
    while (getline(&line, &n, file) != -1) {
        if (n == 0 || line[0] == '\n' || line[0] == '\r' || line[0] == '#') {
            continue;
        }
        token = strtok_r(line, "\t", &s);
        if (!token) {
            continue;
        }
        start_ip = token;

        token = strtok_r(NULL, "\t", &s);
        if (!token) {
            continue;
        }
        end_ip = token;

        token = strtok_r(NULL, "\t", &s);
        if (!token) {
            continue;
        }
        //continent

        token = strtok_r(NULL, "\t", &s);
        if (!token) {
            continue;
        }
        //country

        token = strtok_r(NULL, "\t", &s);
        if (!token) {
            continue;
        }
        province = (uint32_t) atoi(token);

        token = strtok_r(NULL, "\t", &s);
        if (!token) {
            continue;
        }
        city = (uint32_t) atoi(token);

        token = strtok_r(NULL, "\t", &s);
        if (!token) {
            continue;
        }
        county = (uint32_t) atoi(token);

        region = malloc(sizeof(ecr_ipdb_region_t));
        inet_pton(AF_INET, start_ip, &region->start_ip);
        region->start_ip = ntohl(region->start_ip);
        inet_pton(AF_INET, end_ip, &region->end_ip);
        region->end_ip = ntohl(region->end_ip);
        region->province = province;
        region->city = city;
        region->county = county;
        ecr_list_add(ipdb->regions, region);
    }
    fclose(file);
    ecr_list_sort(ipdb->regions, ecr_ipdb_region_compare_func);
    free_to_null(line);

    return 0;
}

int ecr_ipdb_query(ecr_ipdb_t *ipdb, uint32_t ipv4, ecr_ipdb_region_t *region_out) {
    ecr_ipdb_region_t region[1], **find, *key;
    uint32_t ipraw = ntohl(ipv4);
    region->start_ip = region->end_ip = ipraw;
    key = region;
    find = bsearch(&key, ipdb->regions->data, ipdb->regions->size, sizeof(void*), ecr_ipdb_region_compare_func);
    if (find) {
        *region_out = **find;
        return 0;
    }
    return -1;
}

void ecr_ipdb_destroy(ecr_ipdb_t *ipdb) {
    if (ipdb->regions) {
        ecr_list_destroy(ipdb->regions, ecr_list_free_value_handler);
        free(ipdb->regions);
        ipdb->regions = NULL;
    }
}
