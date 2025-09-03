
#include "mceliece_matrix_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mceliece_poly.h"
// Build H using our GF operations only. Reference GF is used only in tracer.



// No direct reference GF/API usage here; we call our gf_* which may bridge internally

// 矩阵创建
matrix_t* matrix_create(int rows, int cols) {
    matrix_t *mat = malloc(sizeof(matrix_t));
    if (!mat) return NULL;

    mat->rows = rows;
    mat->cols = cols;
    mat->cols_bytes = (cols + 7) / 8;  // 按字节对齐

    mat->data = calloc(rows * mat->cols_bytes, sizeof(uint8_t));
    if (!mat->data) {
        free(mat);
        return NULL;
    }

    return mat;
}

// 矩阵释放
void matrix_free(matrix_t *mat) {
    if (mat) {
        if (mat->data) free(mat->data);
        free(mat);
    }
}



// 矩阵位获取
int matrix_get_bit(const matrix_t *mat, int row, int col) {
    if (!mat || row < 0 || row >= mat->rows || col < 0 || col >= mat->cols) {
        printf("ERROR: matrix_get_bit bounds check failed: mat=%p, row=%d/%d, col=%d/%d\n",
               mat, row, mat ? mat->rows : -1, col, mat ? mat->cols : -1);
        return 0; // Return 0 instead of crashing
    }
    const uint8_t *p = &mat->data[row * mat->cols_bytes + (col >> 3)];
    return (int)((p[0] >> (col & 7)) & 1);
}

void matrix_set_bit(matrix_t *mat, int row, int col, int bit) {
    if (!mat || row < 0 || row >= mat->rows || col < 0 || col >= mat->cols) {
        printf("ERROR: matrix_set_bit bounds check failed: mat=%p, row=%d/%d, col=%d/%d\n",
               mat, row, mat ? mat->rows : -1, col, mat ? mat->cols : -1);
        return; // Don't crash, just return
    }
    int byte_idx = row * mat->cols_bytes + (col / 8);
    int bit_idx = col % 8;

    if (bit) {
        mat->data[byte_idx] |= (1 << bit_idx);
    } else {
        mat->data[byte_idx] &= ~(1 << bit_idx);
    }
}


// 矩阵行交换
void matrix_swap_rows(matrix_t *mat, int row1, int row2) {
    if (row1 == row2 || row1 >= mat->rows || row2 >= mat->rows) return;
    
    for (int col = 0; col < mat->cols_bytes; col++) {
        uint8_t temp = mat->data[row1 * mat->cols_bytes + col];
        mat->data[row1 * mat->cols_bytes + col] = mat->data[row2 * mat->cols_bytes + col];
        mat->data[row2 * mat->cols_bytes + col] = temp;
    }
}

// 矩阵列交换
void matrix_swap_cols(matrix_t *mat, int col1, int col2) {
    if (col1 == col2 || col1 >= mat->cols || col2 >= mat->cols) return;

    for (int row = 0; row < mat->rows; row++) {
        int bit1 = matrix_get_bit(mat, row, col1);
        int bit2 = matrix_get_bit(mat, row, col2);
        matrix_set_bit(mat, row, col1, bit2);
        matrix_set_bit(mat, row, col2, bit1);
    }
}

// 矩阵行异或（row_dst = row_dst XOR row_src）
void matrix_xor_rows(matrix_t *mat, int row_dst, int row_src) {
    if (row_dst >= mat->rows || row_src >= mat->rows) return;
    uint8_t *dst = &mat->data[row_dst * mat->cols_bytes];
    const uint8_t *src = &mat->data[row_src * mat->cols_bytes];
    int cb = mat->cols_bytes;
    // 64-bit chunks
    int off = 0;
    for (; off + 8 <= cb; off += 8) {
        *(uint64_t *)(dst + off) ^= *(const uint64_t *)(src + off);
    }
    // tail
    for (; off < cb; off++) dst[off] ^= src[off];
}

// 检查矩阵是否为系统形式
int matrix_is_systematic(const matrix_t *mat) {
    if (mat->rows > mat->cols) return 0;

    // 检查前mat->rows列是否构成单位矩阵
    for (int i = 0; i < mat->rows; i++) {
        for (int j = 0; j < mat->rows; j++) {
            int expected = (i == j) ? 1 : 0;
            if (matrix_get_bit(mat, i, j) != expected) {
                return 0;
            }
        }
    }

    return 1;
}

int reduce_to_systematic_form(matrix_t *H) {
    // Systematic path must NOT swap columns. Use row-only reduction.
    return reduce_to_systematic_form_reference_style(H);
}

// Build H using the same bit-sliced packing and column grouping convention
// as the reference path: rows are grouped by bit position (k in 0..GFBITS-1)
// within each power i in 0..T-1; columns are packed 8-at-a-time into bytes.
int build_parity_check_matrix_reference_style(matrix_t *H, const polynomial_t *g, const gf_elem_t *support) {
    
    if (!H || !g || !support) return -1;
    const int t = MCELIECE_T;
    const int m = MCELIECE_M;
    const int n = MCELIECE_N;
    if (H->rows != t * m || H->cols != n) return -1;

    // inv[j] = 1 / g(support[j])
    gf_elem_t *inv = (gf_elem_t*)malloc((size_t)n * sizeof(gf_elem_t));
    if (!inv) return -1;

    // Evaluate monic polynomial g at support using our gf_* (internally bridged to ref GF)
    for (int j = 0; j < n; j++) {
        gf_elem_t a = (gf_elem_t)(support[j] & ((1u << m) - 1u));
        // Evaluate monic polynomial: start at 1 (implicit leading coeff)
        gf_elem_t val = 1;
        for (int d = t - 1; d >= 0; d--) {
            val = gf_mul(val, a);
            val ^= (gf_elem_t)g->coeffs[d];
        }
        if (val == 0) { free(inv); return -1; }
        inv[j] = gf_inv(val);
    }

    // Clear matrix
    memset(H->data, 0, (size_t)H->rows * (size_t)H->cols_bytes);

    // Fill rows: for each i (power), for each 8-column block, for each bit k
    for (int i = 0; i < t; i++) {
        for (int j = 0; j < n; j += 8) {
            int block_len = (j + 8 <= n) ? 8 : (n - j);
            for (int k = 0; k < m; k++) {
                unsigned char b = 0;
                // Reference mapping: MSB=col j+7 ... LSB=col j (for partial block, highest index first)
                for (int tbit = block_len - 1; tbit >= 0; tbit--) {
                    b <<= 1;
                    b |= (unsigned char)((inv[j + tbit] >> k) & 1);
                }
                int row = i * m + k;
                H->data[row * H->cols_bytes + (size_t)j/8] = b;
            }
        }
        // inv[j] *= support[j] for next power
        for (int j = 0; j < n; j++) {
            gf_elem_t a = (gf_elem_t)(support[j] & ((1u << m) - 1u));
            inv[j] = gf_mul(inv[j], a);
        }
    }

    free(inv);
    
    return 0;
}

// Perform the byte/bit-ordered elimination that assumes a fixed pivot walk
// through the left mt x mt identity block without column swaps.
int reduce_to_systematic_form_reference_style(matrix_t *H) {
    
    if (!H) return -1;
    const int mt = H->rows;
    const int left_bytes = (mt + 7) / 8;

    for (int byte_idx = 0; byte_idx < left_bytes; byte_idx++) {
        for (int bit_in_byte = 0; bit_in_byte < 8; bit_in_byte++) {
            int row = byte_idx * 8 + bit_in_byte;
            if (row >= mt) break;

            // Forward: make pivot bit unique by xoring rows below when needed
            for (int r = row + 1; r < mt; r++) {
                unsigned char x = (unsigned char)(H->data[row * H->cols_bytes + byte_idx] ^
                                                  H->data[r   * H->cols_bytes + byte_idx]);
                unsigned char m = (unsigned char)((x >> bit_in_byte) & 1u);
                m = (unsigned char)(-(signed char)m);
                for (int c = 0; c < H->cols_bytes; c++) {
                    H->data[row * H->cols_bytes + c] ^= (unsigned char)(H->data[r * H->cols_bytes + c] & m);
                }
            }

            // Require pivot = 1
            if (((H->data[row * H->cols_bytes + byte_idx] >> bit_in_byte) & 1u) == 0u) {
                return -1;
            }

            // Backward: clear pivot bit from all other rows
            for (int r = 0; r < mt; r++) {
                if (r == row) continue;
                unsigned char m = (unsigned char)((H->data[r * H->cols_bytes + byte_idx] >> bit_in_byte) & 1u);
                m = (unsigned char)(-(signed char)m);
                for (int c = 0; c < H->cols_bytes; c++) {
                    H->data[r * H->cols_bytes + c] ^= (unsigned char)(H->data[row * H->cols_bytes + c] & m);
                }
            }
        }
    }
    
    return 0;
}

// Export the right block of a matrix in the same byte/bit packing as the
// reference implementation uses for the public key rows. Bits are packed
// MSB-first within each byte for groups of 8 columns.
int matrix_export_right_block_reference_packing(const matrix_t *H, int left_cols, unsigned char *out, int out_row_bytes) {
    if (!H || !out) return -1;
    if (left_cols < 0 || left_cols > H->cols) return -1;
    int right_cols = H->cols - left_cols;
    if (right_cols % 8 != 0) return -1; // reference pk expects whole bytes
    if (out_row_bytes != right_cols / 8) return -1;

    for (int r = 0; r < H->rows; r++) {
        unsigned char *dst = out + r * out_row_bytes;
        for (int j = 0; j < right_cols; j += 8) {
            unsigned char b = 0;
            // Match reference bit ordering: col j+7 -> bit7, col j+0 -> bit0
            for (int t = 7; t >= 0; t--) {
                int bit = matrix_get_bit(H, r, left_cols + j + t) & 1;
                b <<= 1;
                b |= (unsigned char)bit;
            }
            dst[j / 8] = b;
        }
    }
    return 0;
}

// Same as reduce_to_systematic_form but also records the row operations in U_out (mt x mt)
// and the column permutation in perm_out (length n). U_out will satisfy: U_out * H_original * P = [I | T].
int reduce_to_systematic_form_record(matrix_t *H, matrix_t *U_out, int *perm_out) {
    int mt = H->rows;
    int n = H->cols;
    int i, j;

    // Initialize U_out as identity if provided
    if (U_out) {
        for (int r = 0; r < mt; r++) {
            for (int c = 0; c < mt; c++) {
                matrix_set_bit(U_out, r, c, r == c);
            }
        }
    }

    // Initialize column permutation
    int *col_perm = malloc(n * sizeof(int));
    if (!col_perm) return -1;
    for (i = 0; i < n; i++) col_perm[i] = i;

    // Forward elimination
    for (i = 0; i < mt; i++) {
        int pivot_row = -1;
        int pivot_col = -1;
        for (int col = i; col < n; col++) {
            for (int row = i; row < mt; row++) {
                if (matrix_get_bit(H, row, col) == 1) {
                    pivot_row = row;
                    pivot_col = col;
                    break;
                }
            }
            if (pivot_row != -1) break;
        }
        if (pivot_row == -1) { free(col_perm); return -1; }

        if (pivot_row != i) {
            matrix_swap_rows(H, i, pivot_row);
            if (U_out) matrix_swap_rows(U_out, i, pivot_row);
        }
        if (pivot_col != i) {
            matrix_swap_cols(H, i, pivot_col);
            int temp = col_perm[i]; col_perm[i] = col_perm[pivot_col]; col_perm[pivot_col] = temp;
        }
        for (j = i + 1; j < mt; j++) {
            if (matrix_get_bit(H, j, i) == 1) {
                matrix_xor_rows(H, j, i);
                if (U_out) matrix_xor_rows(U_out, j, i);
            }
        }
    }

    // Back elimination
    for (i = mt - 1; i >= 0; i--) {
        for (j = 0; j < i; j++) {
            if (matrix_get_bit(H, j, i) == 1) {
                matrix_xor_rows(H, j, i);
                if (U_out) matrix_xor_rows(U_out, j, i);
            }
        }
    }

    // Export permutation as mapping original_index -> systematic_index
    // After elimination, col_perm[i] = original_index now at column i
    // We want perm_out[original] = i
    if (perm_out) {
        for (i = 0; i < n; i++) perm_out[i] = 0;
        for (i = 0; i < n; i++) {
            int original = col_perm[i];
            perm_out[original] = i;
        }
    }

    free(col_perm);
    return 0;
}



// 矩阵向量乘法：result = mat * vec
void matrix_vector_multiply(const matrix_t *mat, const uint8_t *vec, uint8_t *result) {
    if (!mat || !vec || !result) return;

    int result_bytes = (mat->rows + 7) / 8;
    memset(result, 0, result_bytes);

    for (int row = 0; row < mat->rows; row++) {
        int sum = 0;

        for (int col = 0; col < mat->cols; col++) {
            int mat_bit = matrix_get_bit(mat, row, col);
            int vec_bit = vector_get_bit(vec, col);
            sum ^= (mat_bit & vec_bit);
        }

        // 去掉 if 语句，直接用 sum 作为 value 参数
        vector_set_bit(result, row, sum);
    }
}

// Invert a square binary matrix A (rows==cols) over GF(2). Returns 0 on success.
int matrix_invert(const matrix_t *A, matrix_t *A_inv) {
    if (!A || !A_inv || A->rows != A->cols || A_inv->rows != A->rows || A_inv->cols != A->cols) return -1;
    int n = A->rows;
    matrix_t *W = matrix_create(n, 2 * n);
    if (!W) return -1;
    // Build [A | I]
    for (int r = 0; r < n; r++) {
        for (int c = 0; c < n; c++) {
            matrix_set_bit(W, r, c, matrix_get_bit(A, r, c));
            matrix_set_bit(W, r, n + c, (r == c));
        }
    }
    // Gauss-Jordan to [I | A^-1]
    // Forward
    for (int i = 0; i < n; i++) {
        int piv = -1;
        for (int r = i; r < n; r++) {
            if (matrix_get_bit(W, r, i)) { piv = r; break; }
        }
        if (piv == -1) { matrix_free(W); return -1; }
        if (piv != i) matrix_swap_rows(W, i, piv);
        for (int r = 0; r < n; r++) {
            if (r != i && matrix_get_bit(W, r, i)) {
                matrix_xor_rows(W, r, i);
            }
        }
    }
    // Extract right half
    for (int r = 0; r < n; r++) {
        for (int c = 0; c < n; c++) {
            matrix_set_bit(A_inv, r, c, matrix_get_bit(W, r, n + c));
        }
    }
    matrix_free(W);
    return 0;
}


















