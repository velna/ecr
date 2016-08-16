/*
 ============================================================================
 Name        : c678.c
 Author      : velna
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ecr.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>

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
    printf("%lu, %lu, %x\n", type, len, *pi);
    pc = ecr_tlv_get(&tlv2, &type, &len);
    printf("%lu, %lu, %c\n", type, len, *pc);
    ps = ecr_tlv_get(&tlv2, &type, &len);
    printf("%lu, %lu, %hx\n", type, len, *ps);
    pl = ecr_tlv_get(&tlv2, &type, &len);
    printf("%lu, %lu, %lx\n", type, len, *pl);
    pstr = ecr_tlv_get(&tlv2, &type, &len);
    printf("%lu, %lu, %s\n", type, len, pstr);

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
    ecr_bwl_opt_t bwopt = { 0 };
    int id = 0, i;
    ecr_fixedhash_ctx_t ctx;
    ecr_fixedhash_t *hash;
    char mem[4096];
    ecr_str_t host, uri;
    ecr_bwl_result_t *result;

    ecr_fixedhash_ctx_init(&ctx);
    ecr_fixedhash_ctx_add_keys(&ctx, "host,uri");
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
        if (result->expr_items[i]) {
            printf("%d=%hhd, %s\n", i, result->exprs.ptr[i], result->expr_items[i]->ptr);
        } else {
            printf("%d=%hhd\n", i, result->exprs.ptr[i]);
        }
    }

    ecr_bwl_reload(&bwlist);

    ecr_bwl_matches_fixed(&bwlist, hash, result);
    printf("result: %d\n", ecr_bwl_contains(result, id));
    printf("%p\n", result->users[id]);
    for (i = 1; i < bwlist.data->next_expr_id; i++) {
        if (result->expr_items[i]) {
            printf("%d=%hhd, %s\n", i, result->exprs.ptr[i], result->expr_items[i]->ptr);
        } else {
            printf("%d=%hhd\n", i, result->exprs.ptr[i]);
        }
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
    printf("%lu, [%s]\n", n, buf);
}

void ecr_version_test() {
    printf("%s\n", ecr_commit_sha());
}

void test_http_deocder() {
    ecr_http_message_t *message;
    ecr_fixedhash_ctx_t hash_ctx;
    ecr_http_decoder_t decoder;
    ecr_fixedhash_ctx_init(&hash_ctx);
    ecr_fixedhash_ctx_add_keys(&hash_ctx, HTTP_HASH_FIELDS);

    ecr_http_decoder_init(&decoder, &hash_ctx, 16);

    char *requests[] = { //
            //
                    "POST /abc.html HTTP/1.1\r\n"
                            "Host: www.baidu.com\r\n"
                            "Transfer-Encoding: chunked\r\n"
                            "\r\n"
                            "a\r\n"
                            "0123456789\r\n"
                            "14",
                    "\r\n"
                            "12345678901",
                    "234567890\r\n"
                            "0\r\n"
                            "\r\n",
                    NULL
            //
            };
    char *req;
    int i = 0, rc;
    message = ecr_http_new_request(&decoder);
    while ((req = requests[i])) {
        rc = ecr_http_decode(message, req, strlen(req));
        printf("rc:%d, errno: %d, chunk_left:%lu, content_legnth:%lu\n", rc, message->error_no, message->_chunk_left,
                message->_content_length);
        i++;
    }
    ecr_http_message_dump(message, stdout);
    ecr_http_message_destroy(message);
}

#define THREAD_LOCAL_THREADS    10
pthread_key_t thread_local_key;

void * thread_local_test_thread(void *user) {
    char *data = NULL, *s;
    int i, c = 0;
    u_int64_t start = ecr_current_time();
    for (i = 0; i < 10000000; i++) {
        asprintf(&s, "%d", i);
        free(s);
//        data = pthread_getspecific(thread_local_key);
//        if (!data) {
//            data = user;
//            pthread_setspecific(thread_local_key, data);
//        }
    }
    printf("%p: %lu, %d\n", data, ecr_current_time() - start, c);
    return NULL;
}

void test_thread_local() {
    size_t i;
    pthread_t threads[THREAD_LOCAL_THREADS];
    pthread_key_create(&thread_local_key, NULL);
    for (i = 0; i < THREAD_LOCAL_THREADS; i++) {
        pthread_create(&threads[i], NULL, thread_local_test_thread, (void*) i + 1);
    }
    for (i = 0; i < THREAD_LOCAL_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
}

typedef struct {
    uint32_t val;
} sl_test_t;

int sl_compare(const void *a, const void *b) {
    const sl_test_t *va = a, *vb = b;
    return va->val - vb->val;
}

void sl_free_handler(ecr_skiplist_t *sl, void *value, void *user) {
    free(value);
}

void test_skip_list() {
    ecr_skiplist_t sl;
    ecr_skiplist_iter_t iter;
    ecr_skiplist_init(&sl, sl_compare);

    int i, j, f = 0, r = 0, val;
    sl_test_t *v, *old;
    srandom(time(NULL));
    for (i = 0; i < 10000; i++) {
        for (j = 0; j < 10; j++) {
            v = malloc(sizeof(sl_test_t));
            v->val = random() % 1000;
            old = ecr_skiplist_set(&sl, v);
            if (old) {
                assert(old->val == v->val);
                free(old);
                f++;
            }
        }
        ecr_skiplist_iter_init(&iter, &sl);
        val = v->val;
        for (j = 0; j < val % 5 && (v = ecr_skiplist_iter_next(&iter)); j++) {
            val = v->val;
            old = ecr_skiplist_remove(&sl, v);
            assert(old == v);
            free(old);
            r++;
        }
    }
    printf("size: %lu, free: %d, remove: %d\n", ecr_skiplist_size(&sl), f, r);
    ecr_skiplist_iter_init(&iter, &sl);
    old = NULL;
    while ((v = ecr_skiplist_iter_next(&iter))) {
        if (old) {
            assert(old->val <= v->val);
        }
        old = v;
    }
    ecr_skiplist_destroy(&sl, sl_free_handler, NULL);
}

void test_uint(int argc, char **argv) {
    uint8_t a, b;
    int8_t v;
    a = (uint8_t) atoi(argv[1]);
    b = (uint8_t) atoi(argv[2]);
    v = a - b;
    printf("a: %hhu, b: %hhu, a-b: %hhd\n", a, b, v);
}

int main(int argc, char **argv) {
    test_uint(argc, argv);
    return EXIT_SUCCESS;
}
