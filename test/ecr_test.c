/*
 ============================================================================
 Name        : c678.c
 Author      : velna
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ecr.h>
#include <assert.h>
#include <errno.h>

void ecr_test_rollingfile() {
    static ecr_io_reg_t ecr_io_regs[] = {
    //
            { .name = "gzip", .rename_pattern = "%s.gz", .chain_func = ecr_gzip_open },
            { .name = "lzop", .rename_pattern = "%s.lzo", .chain_func = ecr_lzop_open },
            { 0 } };

//    FILE *file = ecr_rollingfile_open("rf_test_%Y%m%d_p$pt$ti$i_$H_$b.txt:mode=w,rsize=1|gzip:mode=w", 0, ecr_io_regs);
//    if (!file) {
//        L_ERROR("err open rolling file.");
//        return;
//    }
//    fprintf(file, "%s\n", "haha");
//    fprintf(file, "%s\n", "lala");
//    fclose(file);

    int i;
    for (i = 0; i < 10; i++) {
        FILE *file = ecr_rollingfile_open(
                "rf_test_%Y%m%d%H%M%S_p$pt$ti$i_$H_$b.txt:mode=w,rsize=1,rtime=30T,tmp=.tmp|lzop:mode=wz9", i,
                ecr_io_regs);
        if (!file) {
            L_ERROR("err open rolling file.");
            return;
        }
        fprintf(file, "%s\n", "haha");
        fprintf(file, "%s\n", "lala");
        fclose(file);
    }
}

void ecr_test_gzip() {
    FILE *gzfile = ecr_gzip_open(fopen("gzip_test.gz", "w"), "mode=w");
    if (!gzfile) {
        L_ERROR("error open file: %s", strerror(errno));
        return;
    }
    L_INFO("%d, %d", gzfile->_fileno, fileno(gzfile));
    int i;
    for (i = 0; i < 10000; i++) {
        fprintf(gzfile, "%d\t%s\n", i, "som text values");
    }
    fclose(gzfile);
    gzfile = ecr_gzip_open(fopen("gzip_test.gz", "r"), "mode=r");
    if (!gzfile) {
        L_ERROR("error open file: %s", strerror(errno));
        return;
    }
    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, gzfile) >= 0) {
        //printf("%s", line);
    }
    fclose(gzfile);
}

void ecr_test_tlv() {
    ecr_tlv_t tlv;
    ecr_buf_t buf;
    char data[4096];
    int i = 0x12345678;
    char c = 'b';
    short s = 0x1234;
    long l = 0x1234567812345678;
    char *str = "hi, my name is velna.";

    ecr_tlv_t tlv2;
    size_t type, len;
    int *pi;
    char *pc;
    short *ps;
    long *pl;
    char *pstr;

    ecr_buf_init(&buf, data, 4096);

    ecr_tlv_init(&tlv, 1, 1, &buf);
    ecr_tlv_append(&tlv, 1, &i, sizeof(int));
    ecr_tlv_append(&tlv, 2, &c, sizeof(char));
    ecr_tlv_append(&tlv, 3, &s, sizeof(short));
    ecr_tlv_append(&tlv, 4, &l, sizeof(long));
    ecr_tlv_append(&tlv, 5, str, strlen(str) + 1);
    ecr_buf_flip(&buf);

    ecr_binary_dump(stdout, ecr_buf_data(&buf), ecr_buf_size(&buf));

    ecr_tlv_init(&tlv2, 1, 1, &buf);

    pi = ecr_tlv_get(&tlv2, &type, &len);
    printf("%Zd, %Zd, %x\n", type, len, *pi);
    pc = ecr_tlv_get(&tlv2, &type, &len);
    printf("%Zd, %Zd, %c\n", type, len, *pc);
    ps = ecr_tlv_get(&tlv2, &type, &len);
    printf("%Zd, %Zd, %hx\n", type, len, *ps);
    pl = ecr_tlv_get(&tlv2, &type, &len);
    printf("%Zd, %Zd, %lx\n", type, len, *pl);
    pstr = ecr_tlv_get(&tlv2, &type, &len);
    printf("%Zd, %Zd, %s\n", type, len, pstr);

}

void ecr_test_pkware() {
    const char *password = "abcd";
    const char *filename = "/home/velna/test.txt";
    FILE *file = fopen(filename, "w");
    file = ecr_pkware_fencrypt(file, password);
    fprintf(file, "%s", "abcdefg");
    fclose(file);

    file = fopen(filename, "r");
    file = ecr_pkware_fdecrypt(file, password);
    char *line;
    size_t len;
    getline(&line, &len, file);
    printf("%s\n", line);
}

void ecr_test_buf(int n) {
    int k = n + 1;
    char buf[k];
    int i;
    memset(buf, 'a', k);
    for (i = 0; i < k; i++) {
        printf("%c", buf[i]);
    }
    printf("\n");
}

void test_bwlist(const char *bwlist_file) {
    ecr_bwl_t bwlist;
    ecr_bwl_opt_t bwopt;
    int id, i;
    ecr_fixedhash_ctx_t ctx;
    ecr_fixedhash_t *hash;
    char mem[4096];
    ecr_str_t host, uri;
    ecr_bwl_result_t *result;

    ecr_fixedhash_ctx_init_string(&ctx, "host,uri");
    hash = ecr_fixedhash_init(&ctx, mem, 4096);
    host.ptr = "www.sabc.com";
    host.len = strlen(host.ptr);
    ecr_fixedhash_put_original(hash, "host", 4, &host);
    uri.ptr = "/abdc.html";
    uri.len = strlen(uri.ptr);
    ecr_fixedhash_put_original(hash, "uri", 3, &uri);

    bwopt.basepath = NULL;
    bwopt.fixedhash_ctx = &ctx;
    bwopt.mongo_pool = NULL;
    ecr_bwl_init(&bwlist, &bwopt);
    ecr_bwl_add(&bwlist, bwlist_file, BWL_OR, (void*) 123, &id);
    ecr_bwl_compile(&bwlist);

    ecr_bwl_dump(&bwlist, stdout);

    result = ecr_bwl_result_init(&bwlist);
    ecr_bwl_matches_fixed(&bwlist, hash, result);
    printf("result: %d\n", ecr_bwl_contains(result, id));
    printf("%p\n", result->users[id]);
    for (i = 1; i < bwlist.data->next_expr_id; i++) {
        printf("%d=%hhd\n", i, result->exprs.ptr[i]);
    }

    ecr_bwl_reload(&bwlist);

    ecr_bwl_matches_fixed(&bwlist, hash, result);
    printf("result: %d\n", ecr_bwl_contains(result, id));
    printf("%p\n", result->users[id]);
    for (i = 1; i < bwlist.data->next_expr_id; i++) {
        printf("%d=%hhd\n", i, result->exprs.ptr[i]);
    }

    ecr_bwl_result_destroy(result);
    ecr_fixedhash_ctx_destroy(&ctx);
    ecr_bwl_destroy(&bwlist);
}

struct test_s {
    size_t s;
    size_t c;
};

void test_inet_ntop() {
    int ip = 0x34565634;
    int i;
    char ip_str[INET6_ADDRSTRLEN];
    uint64_t now = ecr_current_time();
    for (i = 0; i < 1; i++) {
        ecr_inet_ntop(AF_INET, &ip, ip_str, INET6_ADDRSTRLEN);
        printf("%s\n", ip_str);
        inet_ntop(AF_INET, &ip, ip_str, INET6_ADDRSTRLEN);
        printf("%s\n", ip_str);
    }
    printf("%lu\n", ecr_current_time() - now);
}

void base64_test() {
    char buf[4096] = { 0 }, str[20];
    memset(str, 0xff, sizeof(str));
    size_t n = ecr_base64_encode_s(buf, str, 20);
    ecr_binary_dump(stdout, buf, n);
    printf("%zd, [%s]\n", n, buf);
}

int main(int argc, char **argv) {
    base64_test();
    return EXIT_SUCCESS;
}
