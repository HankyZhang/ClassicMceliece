//

//

#ifndef CLASSICMCELIECE_MCELIECE_MATRIX_OPS_H
#define CLASSICMCELIECE_MCELIECE_MATRIX_OPS_H



#include <stdint.h>
#include "mceliece_types.h"
#include "gf.h"


// 矩阵创建与释放
matrix_t* matrix_create(int rows, int cols);
void matrix_free(matrix_t *mat);

// 设置与读取矩阵元素（按bit操作）
void matrix_set_bit(matrix_t *mat, int row, int col, int value);
int matrix_get_bit(const matrix_t *mat, int row, int col);

// 行列基本操作
void matrix_swap_rows(matrix_t *mat, int row1, int row2);
void matrix_swap_cols(matrix_t *mat, int col1, int col2);
void matrix_xor_rows(matrix_t *mat, int row_dst, int row_src);

// 高斯消元与系统形式检查
int matrix_is_systematic(const matrix_t *mat);
int reduce_to_systematic_form(matrix_t *H);

// 向量操作
void matrix_vector_multiply(const matrix_t *mat, const uint8_t *vec, uint8_t *result);

// MatGen 与编码
mceliece_error_t mat_gen(const polynomial_t *g, const gf_elem_t *alpha,
                         matrix_t *T_out);
void encode_vector(const uint8_t *error_vector, const matrix_t *T, uint8_t *ciphertext);

// syndrome 计算
void compute_syndrome(const uint8_t *received, const polynomial_t *g,
                      const gf_elem_t *alpha, gf_elem_t *syndrome);


#endif //CLASSICMCELIECE_MCELIECE_MATRIX_OPS_H
