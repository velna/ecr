/*
 * hm_mongo_loaders.h
 *
 *  Created on: Sep 8, 2017
 *      Author: velna
 */

#ifndef SRC_ECR_HYPERMATCH_HM_MONGO_LOADER_H_
#define SRC_ECR_HYPERMATCH_HM_MONGO_LOADER_H_

#include "hm.h"
#include <mongoc.h>

ecr_hm_loader_t * ecr_hm_mongo_loader_new(mongoc_client_pool_t *pool);

#endif /* SRC_ECR_HYPERMATCH_HM_MONGO_LOADER_H_ */
