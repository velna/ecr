/*
 * stoi.c
 *
 *  Created on: May 9, 2017
 *      Author: velna
 */

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 1) {
        return -1;
    }
    if (strlen(argv[1]) < 4) {
        return -1;
    }
    printf("0x%x\n", *((int*) argv[1]));
    return 0;
}
