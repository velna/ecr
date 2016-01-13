/*
 * ecr_radius.c
 *
 *  Created on: Mar 12, 2013
 *      Author: velna
 */

#include "config.h"
#include "ecr_radius.h"
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#define RADIUS_HDR_LEN  20
#define RADIUS_MAX_LEN  4096

static ecr_radius_attr_t * ecr_parse_attr(u_char* p, size_t size, int vendor) {
    if (size < 2 || size > RADIUS_MAX_LEN || p[1] <= 0 || p[1] > size) {
        return NULL;
    }
    ecr_radius_attr_t * attr = calloc(1, sizeof(ecr_radius_attr_t));
    attr->type = p[0];
    attr->value_len = p[1] - 2;
    attr->value = size == 2 ? NULL : p + 2;
    if (!vendor && attr->type == RADIUS_ATTR_VENDOR_SPECIFIC && attr->value_len > 4) {
        attr->vendor_attr = ecr_parse_attr(attr->value + 4, attr->value_len - 4, 1);
    }
    if (size - p[1] > 0) {
        attr->next = ecr_parse_attr(p + p[1], size - p[1], vendor);
    }
    return attr;
}

ecr_radius_t * ecr_radius_parse(u_char* p, size_t size) {
    if (size < RADIUS_HDR_LEN || size > RADIUS_MAX_LEN) {
        return NULL;
    }
    ecr_radius_t * rds = calloc(1, sizeof(ecr_radius_t));
    memcpy(rds, p, RADIUS_HDR_LEN);
    u_short len = ntohs(rds->len);
    if (size < len || len > RADIUS_MAX_LEN || len < RADIUS_HDR_LEN) {
        free(rds);
        return NULL;
    }
    if (rds->code > 13 || (rds->code > 5 && rds->code < 11)) {
        free(rds);
        return NULL;
    }
    rds->attrs = ecr_parse_attr(p + RADIUS_HDR_LEN, len - RADIUS_HDR_LEN, 0);
    return rds;
}

void ecr_radius_destroy(ecr_radius_t * rds) {
    if (NULL == rds) {
        return;
    }
    ecr_radius_attr_t * attr = rds->attrs, *next, *vendor_attr, *vendor_attr_next;
    while (NULL != attr) {
        next = attr->next;
        vendor_attr = attr->vendor_attr;
        while (vendor_attr) {
            vendor_attr_next = vendor_attr->next;
            free(vendor_attr);
            vendor_attr = vendor_attr_next;
        }
        free(attr);
        attr = next;
    }
    free(rds);
}
