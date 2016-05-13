/*
 * run_test.c
 *
 *  Created on: May 24, 2016
 *      Author: velna
 */

#include <stdio.h>
#include <stdlib.h>
#include "CUnit/CUnit.h"
#include "CUnit/Basic.h"

extern CU_SuiteInfo http_decoder_suites[];

static void add_tests() {
    CU_register_suites(http_decoder_suites);
}

int main(int argc, char **argv) {
    if (CU_initialize_registry()) {
        fprintf(stderr, " Initialization of Test Registry failed. ");
        exit(EXIT_FAILURE);
    } else {
        add_tests();
        CU_basic_run_tests();
        //CU_set_output_filename("TestMax");
        //CU_list_tests_to_file();
        //CU_automated_run_tests();
        CU_cleanup_registry();
    }
    return 0;
}
