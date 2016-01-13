/*
 * ecr_macbind.h
 *
 *  Created on: Apr 17, 2014
 *      Author: dev
 */

#ifndef ECR_MACBIND_H_
#define ECR_MACBIND_H_

#include "ecrconf.h"

int ecr_macbind_init(char * prefix, char * suffix);

int ecr_macbind_matches(const char * device, const char * binds);

void ecr_macbind_destroy();

#endif /* ECR_MACBIND_H_ */
