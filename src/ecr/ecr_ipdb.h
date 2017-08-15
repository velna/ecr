/*
 * ecr_ipdb.h
 *
 *  Created on: Apr 11, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_ECR_IPDB_H_
#define SRC_ECR_ECR_IPDB_H_

#include "ecrconf.h"
#include "ecr_list.h"

typedef struct {
    uint32_t start_ip;
    uint32_t end_ip;
    uint32_t province;
    uint32_t city;
    uint32_t county;
} ecr_ipdb_region_t;

typedef struct {
    ecr_list_t *regions;
} ecr_ipdb_t;

int ecr_ipdb_init(ecr_ipdb_t *ipdb, const char *ipdbfile);

int ecr_ipdb_query(ecr_ipdb_t *ipdb, uint32_t ipv4, ecr_ipdb_region_t *region_out);

void ecr_ipdb_destroy(ecr_ipdb_t *ipdb);

#endif /* SRC_ECR_ECR_IPDB_H_ */
