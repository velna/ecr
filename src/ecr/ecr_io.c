/*
 * ecr_io.c
 *
 *  Created on: May 10, 2017
 *      Author: velna
 */

#include "config.h"
#include "ecr_io.h"

ecr_io_reg_t ecr_io_default_regs[] = { {
//
        .name = "gzip",
        .rename_pattern = "%s.gz",
        .chain_func = ecr_gzip_open }, {
//
        .name = "lzo",
        .rename_pattern = "%s.lzo",
        .chain_func = ecr_lzop_open }, {
//
        0 } };
