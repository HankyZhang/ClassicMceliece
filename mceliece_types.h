#ifndef MCELIECE_TYPES_H
#define MCELIECE_TYPES_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// 参数集定义 - 以mceliece6688128为例
#define MCELIECE_M 13          // log2(q)
#define MCELIECE_N 6688        // 码长
#define MCELIECE_T 128         // 纠错能力
#define MCELIECE_K (MCELIECE_N - MCELIECE_M * MCELIECE_T)  // 码维 = 6688 - 13*128 = 5024
#define MCELIECE_Q (1 << MCELIECE_M)  // 2^13 = 8192

// 对称密码参数
#define MCELIECE_L 256         // Hash输出长度(比特)
#define MCELIECE_SIGMA1 16     // >= m
#define MCELIECE_SIGMA2 32     // >= 2m
#define MCELIECE_MU 0          // 半系统参数μ
#define MCELIECE_NU 0          // 半系统参数ν

// 计算所需的字节长度
#define MCELIECE_L_BYTES (MCELIECE_L / 8)                    // 32字节
#define MCELIECE_N_BYTES ((MCELIECE_N + 7) / 8)              // 836字节
#define MCELIECE_MT_BYTES ((MCELIECE_M * MCELIECE_T + 7) / 8) // 208字节
#define MCELIECE_K_BYTES ((MCELIECE_K + 7) / 8)              // 628字节

// 密钥长度
#define MCELIECE_PUBLICKEY_BYTES (MCELIECE_MT_BYTES * MCELIECE_K_BYTES)  // 公钥长度
#define MCELIECE_PRIVATEKEY_BYTES (MCELIECE_L_BYTES + 8 + MCELIECE_T * ((MCELIECE_M + 7) / 8) + ((2*MCELIECE_M - 1) * (1 << (MCELIECE_M - 4)) + 7) / 8 + MCELIECE_N_BYTES)

// 密文长度
#define MCELIECE_CIPHERTEXT_BYTES MCELIECE_MT_BYTES          // 非pc参数集

// 有限域元素类型
typedef uint16_t gf_elem_t;  // GF(2^13)元素，用16位存储
typedef struct {
    int rows;
    int cols;
    gf_elem_t *data;
} matrix_fq_t;

// 多项式结构
typedef struct {
    gf_elem_t *coeffs;  // 系数数组
    int degree;         // 次数
    int max_degree;     // 最大次数（分配的空间）
} polynomial_t;

// 矩阵结构
typedef struct {
    uint8_t *data;      // 数据存储
    int rows;           // 行数
    int cols;           // 列数
    int cols_bytes;     // 每行占用的字节数
} matrix_t;

// 密钥结构
// mceliece_types.h
typedef struct {
    uint8_t delta[MCELIECE_L_BYTES];
    uint64_t c;
    polynomial_t g;
    gf_elem_t *alpha;
    uint8_t s[MCELIECE_N_BYTES];
    int *p; // <--- 添加这个成员来存储置换向量
} private_key_t;

typedef struct {
    matrix_t T;  // 公钥矩阵T
} public_key_t;

// 错误码定义
typedef enum {
    MCELIECE_SUCCESS = 0,
    MCELIECE_ERROR_INVALID_PARAM = -1,
    MCELIECE_ERROR_MEMORY = -2,
    MCELIECE_ERROR_DECODE_FAIL = -3,
    MCELIECE_ERROR_KEYGEN_FAIL = -4
} mceliece_error_t;


#endif // MCELIECE_TYPES_H