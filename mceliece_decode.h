#ifndef MCELIECE_DECODE_H
#define MCELIECE_DECODE_H


#include <stdint.h>
#include "mceliece_types.h"
#include "mceliece_matrix_ops.h"
#include "mceliece_gf.h"
#include "mceliece_vector.h"

#ifdef __cplusplus
extern "C" {
#endif
    // syndrome 计算
    void compute_syndrome(const uint8_t *received, const polynomial_t *g,
                      const gf_elem_t *alpha, gf_elem_t *syndrome);

    // Berlekamp-Massey算法：求解线性反馈移位寄存器
    mceliece_error_t berlekamp_massey(const gf_elem_t *syndrome,
                                     polynomial_t *sigma, polynomial_t *omega);


    // Chien搜索：寻找错误定位多项式的根
    mceliece_error_t chien_search(const polynomial_t *sigma, const gf_elem_t *alpha,
                                 int *error_positions, int *num_errors);

    // caculate e
    mceliece_error_t decode_goppa(const uint8_t *received, const polynomial_t *g,
                                 const gf_elem_t *alpha, uint8_t *error_vector,
                                 int *decode_success);
    // 完整的解码算法
    mceliece_error_t decode_ciphertext(const uint8_t *ciphertext, const private_key_t *sk,
                                   uint8_t *error_vector, int *success);

#ifdef __cplusplus
}
#endif

#endif // MCELIECE_DECODE_H
