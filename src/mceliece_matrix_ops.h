#ifndef CLASSICMCELIECE_MCELIECE_MATRIX_OPS_H
#define CLASSICMCELIECE_MCELIECE_MATRIX_OPS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> // For malloc and free
#include <string.h> // For memset
#include <stddef.h>
#include "mceliece_types.h"
#include "mceliece_gf.h"
#include "mceliece_vector.h"

#ifdef __cplusplus
extern "C" {
#endif

// Matrix creation and destruction
matrix_t* matrix_create(int rows, int cols);
void matrix_free(matrix_t *mat);

// Matrix element access (bit-level operations)
void matrix_set_bit(matrix_t *mat, int row, int col, int value);
int matrix_get_bit(const matrix_t *mat, int row, int col);

// Basic row and column operations
void matrix_swap_rows(matrix_t *mat, int row1, int row2);
void matrix_swap_cols(matrix_t *mat, int col1, int col2);
void matrix_xor_rows(matrix_t *mat, int row_dst, int row_src);

// Gaussian elimination and systematic form operations
int matrix_is_systematic(const matrix_t *mat);
int reduce_to_systematic_form(matrix_t *H);
// Variant that records row ops (U) and column permutation (perm)
int reduce_to_systematic_form_record(matrix_t *H, matrix_t *U_out, int *perm_out);

// Reference-style matrix operations (matching NIST implementation)
int build_parity_check_matrix_reference_style(matrix_t *H, const polynomial_t *g, const gf_elem_t *support);
int reduce_to_systematic_form_reference_style(matrix_t *H);

// Export the right block (columns >= left_cols) of H using reference byte packing.
// Packs bits MSB-first within each byte for groups of 8 columns: for columns j..j+7,
// output byte b where bit7 corresponds to column j and bit0 to column j+7.
// out must have size rows * out_row_bytes, where out_row_bytes == (cols-left_cols)/8.
int matrix_export_right_block_reference_packing(const matrix_t *H, int left_cols, unsigned char *out, int out_row_bytes);

// Matrix-vector operations
void matrix_vector_multiply(const matrix_t *mat, const uint8_t *vec, uint8_t *result);
// Invert a square binary matrix (GF(2)); returns 0 on success
int matrix_invert(const matrix_t *A, matrix_t *A_inv);

// Additional utility functions for matrices over finite fields
matrix_fq_t* matrix_fq_create(int rows, int cols);
void matrix_fq_free(matrix_fq_t *mat);
void matrix_fq_set(matrix_fq_t *mat, int row, int col, gf_elem_t value);
gf_elem_t matrix_fq_get(const matrix_fq_t *mat, int row, int col);

#ifdef __cplusplus
}
#endif

#endif //CLASSICMCELIECE_MCELIECE_MATRIX_OPS_H
