/*
 * ecr_version.c
 *
 *  Created on: Jan 17, 2016
 *      Author: velna
 */

#include "ecrconf.h"
#include "commit_sha.h"

const char * ecr_commit_sha() {
#ifdef COMMIT_SHA
    return COMMIT_SHA;
#else
    return NULL;
#endif
}
