/*
 * ecr_bloomfilter.h
 *
 *  Created on: Jun 13, 2014
 *      Author: velna
 */

#ifndef ECR_BLOOMFILTER_H_
#define ECR_BLOOMFILTER_H_

#include "ecrconf.h"
#include <atomic_ops.h>

#define BF_MGAIC_CODE      (0x01464C42)
#define BF_MAX_HASH_FUNC   32
#define BF_ERRBUF_SIZE     512

#pragma pack (push, 1)
typedef struct {
    uint32_t magic_code;                // 文件头部标识，填充 __MGAIC_CODE__
    uint32_t seed;                      // MurmurHash的种子偏移量
    uint64_t max_items;                 // n - BloomFilter中最大元素个数 (输入量)
    double prob_false;                  // p - 假阳概率 (输入量，比如万分之一：0.00001)
    uint64_t filter_bits;               // m = ceil((n * log(p)) / log(1.0 / (pow(2.0, log(2.0))))); - BloomFilter的比特数
    volatile AO_t count;                // Add()的计数，超过MAX_BF_N则返回失败
    uint64_t filter_size;               // filter_bits / BYTE_BITS
    uint32_t hash_funcs;                // k = round(log(2.0) * m / n); - 哈希函数个数
    volatile AO_t deletes;
    char _reserved[196];
    unsigned char filter[1];            // BloomFilter存储指针，使用malloc分配
} ecr_bf_mmap_t;
#pragma pack (pop)

typedef struct {
    int fd;
    ecr_bf_mmap_t *map;
} ecr_bf_t;

int ecr_bf_init(ecr_bf_t *bf, uint32_t seed, size_t max_items, double prob_false, const char *mmap_file, char *errbuf);

void ecr_bf_destroy(ecr_bf_t *bf);

void ecr_bf_hash(ecr_bf_t *bf, const void * key, int len, size_t *hash_pos);

int ecr_bf_add(ecr_bf_t *bf, size_t *hash_pos);

int ecr_bf_del(ecr_bf_t *bf, size_t *hash_pos);

int ecr_bf_check(ecr_bf_t *bf, size_t *hash_pos);

#endif /* ECR_BLOOMFILTER_H_ */
