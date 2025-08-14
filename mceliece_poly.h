#ifndef CLASSICMCELIECE_MCELIECE_POLY_H
#define CLASSICMCELIECE_MCELIECE_POLY_H
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include "mceliece_types.h"



polynomial_t* polynomial_create(int max_degree);
void polynomial_free(polynomial_t *poly);

// 多项式在GF中的求值
gf_elem_t polynomial_eval(const polynomial_t *poly, gf_elem_t x);

// 设置多项式系数并更新次数
void polynomial_set_coeff(polynomial_t *poly, int degree, gf_elem_t coeff);

// 多项式复制
void polynomial_copy(polynomial_t *dst, const polynomial_t *src);

// 检查多项式是否为零
int polynomial_is_zero(const polynomial_t *poly);

// 多项式加法（GF上就是异或）
void polynomial_add(polynomial_t *result, const polynomial_t *a, const polynomial_t *b);
// 多项式乘法: result(x) = a(x) * b(x)
void polynomial_mul(polynomial_t *result, const polynomial_t *a, const polynomial_t *b);

// 多项式除法: q(x) = a(x) / b(x), r(x) = a(x) mod b(x)
void polynomial_div(polynomial_t *q, polynomial_t *r, const polynomial_t *a, const polynomial_t *b);

#endif //CLASSICMCELIECE_MCELIECE_POLY_H
