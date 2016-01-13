/*
 * ecr_bloomfilter.c
 *
 *  Created on: Jun 14, 2014
 *      Author: velna
 */

#include "config.h"
#include "ecr_bloomfilter.h"
#include "ecr_util.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define MIX_UINT64(v)       ((uint32_t)((v>>32)^(v)))
#define SETBIT(f, n)        (f->map->filter[n>>3] |= (1 << (n % 8)))
#define DELBIT(f, n)        (f->map->filter[n>>3] &= ~(1 << (n % 8)))
#define GETBIT(f, n)        (f->map->filter[n>>3] & (1 << (n % 8)))

static inline void ecr_bf_calc_param(size_t n, double p, size_t *pm, uint32_t *pk) {
    /**
     *  n - Number of items in the filter
     *  p - Probability of false positives, float between 0 and 1 or a number indicating 1-in-p
     *  m - Number of bits in the filter
     *  k - Number of hash functions
     *
     *  f = ln(2) × ln(1/2) × m / n = (0.6185) ^ (m/n)
     *  m = -1 * ln(p) × n / 0.6185
     *  k = ln(2) × m / n = 0.6931 * m / n
     **/

    size_t m;
    uint32_t k;

    // 计算指定假阳概率下需要的比特数
    m = (size_t) ceil(-1 * log(p) * n / 0.6185);
    m = (m - m % 64) + 64; // 8字节对齐

    // 计算哈希函数个数
    k = (uint32_t) (0.6931 * m / n);
    k++;

    *pm = m;
    *pk = k;
    return;
}

inline void ecr_bf_hash(ecr_bf_t *bf, const void * key, int len, size_t *hash_pos) {
    int i;
    size_t filter_bits = bf->map->filter_bits;
    uint64_t hash1 = ecr_murmur_hash2_x64(key, len, bf->map->seed);
    uint64_t hash2 = ecr_murmur_hash2_x64(key, len, MIX_UINT64(hash1));

    for (i = 0; i < (int) bf->map->hash_funcs; i++) {
        hash_pos[i] = (hash1 + i * hash2) % filter_bits;
    }
}

int ecr_bf_init(ecr_bf_t *bf, uint32_t seed, size_t max_items, double prob_false, const char *mmap_file, char *errbuf) {
    uint64_t filter_bits, filter_size, file_size;
    uint32_t hash_funcs;
    int fd, file_exists;
    struct stat st;
    ecr_bf_mmap_t *map;

    if ((prob_false <= 0) || (prob_false >= 1)) {
        return -1;
    }
    ecr_bf_calc_param(max_items, prob_false, &filter_bits, &hash_funcs);
    if (hash_funcs > BF_MAX_HASH_FUNC) {
        return -1;
    }
    filter_size = filter_bits >> 3;
    file_size = sizeof(ecr_bf_mmap_t) + filter_size - 1;

    file_exists = !stat(mmap_file, &st);
    if (file_exists && st.st_size != file_size) {
        snprintf(errbuf, BF_ERRBUF_SIZE, "invalid bloom filter file: %s.", mmap_file);
        return -1;
    }
    fd = open(mmap_file, O_RDWR | O_CREAT);
    if (file_exists) {
        map = mmap64(NULL, st.st_size, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_NORESERVE, fd, 0);
        if (map == MAP_FAILED) {
            snprintf(errbuf, BF_ERRBUF_SIZE, "can not map bloom filter file '%s', %s", mmap_file, strerror(errno));
            close(fd);
            return -1;
        }
        if (map->magic_code != BF_MGAIC_CODE || map->seed != seed || map->max_items != max_items
                || map->prob_false != prob_false || map->filter_bits != filter_bits || map->hash_funcs != hash_funcs) {
            snprintf(errbuf, BF_ERRBUF_SIZE, "bloom filter param not match: %s", mmap_file);
            munmap(map, st.st_size);
            close(fd);
            return -1;
        }
    } else {
        lseek(fd, file_size - 1, SEEK_SET);
        write(fd, "", 1);
        map = mmap64(NULL, file_size, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_NORESERVE, fd, 0);
        if (map == MAP_FAILED) {
            snprintf(errbuf, BF_ERRBUF_SIZE, "can not map bloom filter file '%s', %s", mmap_file, strerror(errno));
            close(fd);
            return -1;
        }
        map->filter_bits = filter_bits;
        map->filter_size = filter_size;
        map->hash_funcs = hash_funcs;
        map->magic_code = BF_MGAIC_CODE;
        map->max_items = max_items;
        map->prob_false = prob_false;
        map->seed = seed;
        memset(map->filter, 0, map->filter_size);
    }
    memset(bf, 0, sizeof(ecr_bf_t));
    bf->map = map;
    bf->fd = fd;
    return 0;
}

void ecr_bf_destroy(ecr_bf_t *bf) {
    if (bf->map) {
        munmap(bf->map, bf->map->filter_size + sizeof(ecr_bf_mmap_t) - 1);
        bf->map = NULL;
    }
    if (bf->fd) {
        close(bf->fd);
        bf->fd = 0;
    }
}

inline int ecr_bf_add(ecr_bf_t *bf, size_t *hp) {
    int i, f = -1;

    for (i = 0; i < (int) bf->map->hash_funcs; i++) {
        if (f && GETBIT(bf, hp[i]) == 0) {
            f = 0;
        }
        SETBIT(bf, hp[i]);
    }

    // 增加count数
    if (!f) {
        AO_fetch_and_add1(&bf->map->count);
    }
    return f;
}

inline int ecr_bf_del(ecr_bf_t *bf, size_t *hp) {
    int i, f = 0;

    for (i = 0; i < (int) bf->map->hash_funcs; i++) {
        if (GETBIT(bf, hp[i]) == 0) {
            f = -1;
            break;
        }
    }
    if (!f) {
        for (i = 0; i < (int) bf->map->hash_funcs; i++) {
            DELBIT(bf, hp[i]);
        }
        AO_fetch_and_add1(&bf->map->deletes);
    }
    return f;
}

inline int ecr_bf_check(ecr_bf_t *bf, size_t *hp) {
    int i;

    for (i = 0; i < (int) bf->map->hash_funcs; i++) {
        // 如果有任意bit不为1，说明key不在bloomfilter中
        // 注意: GETBIT()返回不是0|1，高位可能出现128之类的情况
        if (GETBIT(bf, hp[i]) == 0)
            return -1;
    }
    return 0;
}
