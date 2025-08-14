#ifndef MCELIECE_GF_H
#define MCELIECE_GF_H
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include "mceliece_types.h"  // 假设里面定义了 gf_elem_t 和 polynomial_t 等类型

#ifdef __cplusplus
extern "C" {
#endif
    extern gf_elem_t *gf_log;
    extern gf_elem_t *gf_antilog;

    //init
    void gf_init(void);
    // static gf_mul_for_init

    // GF(2^13)加法（异或）
    gf_elem_t gf_add(gf_elem_t a, gf_elem_t b);

    // GF(2^13)乘法
    gf_elem_t gf_mul(gf_elem_t a, gf_elem_t b);

    // GF(2^13)求逆
    gf_elem_t gf_inv(gf_elem_t a);

    // GF(2^13)除法
    gf_elem_t gf_div(gf_elem_t a, gf_elem_t b);

    // GF(2^13)幂运算
    gf_elem_t gf_pow(gf_elem_t base, int exp);

    // 从比特向量表示转换为GF元素
    gf_elem_t bits_to_gf(const uint8_t *bits, int start_bit);

    // 从GF元素转换为比特向量表示
    void gf_to_bits(gf_elem_t elem, uint8_t *bits, int start_bit);


#ifdef __cplusplus
}
#endif

#endif // GF_H
