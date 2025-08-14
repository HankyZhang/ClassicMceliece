
#include "mceliece_matrix_ops.h"



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
    int byte_idx = row * mat->cols_bytes + (col / 8);
    int bit_idx = col % 8;

    return (mat->data[byte_idx] >> bit_idx) & 1;
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

    for (int col = 0; col < mat->cols_bytes; col++) {
        mat->data[row_dst * mat->cols_bytes + col] ^=
                mat->data[row_src * mat->cols_bytes + col];
    }
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
    int mt = H->rows;
    int n = H->cols;
    int i, j;

    // Create column permutation array
    int *col_perm = malloc(n * sizeof(int));
    if (!col_perm) return -1;
    
    // Initialize column permutation
    for (i = 0; i < n; i++) {
        col_perm[i] = i;
    }

    // --- Forward elimination to form upper triangular matrix ---
    for (i = 0; i < mt; i++) {
        // 1. Find pivot (starting from column i, starting from row i)
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

        if (pivot_row == -1) {
            // No pivot found, matrix is singular
            free(col_perm);
            return -1;
        }

        // 2. Swap pivot row to current row i
        if (pivot_row != i) {
            matrix_swap_rows(H, i, pivot_row);
        }

        // 3. Swap pivot column to current column i
        if (pivot_col != i) {
            matrix_swap_cols(H, i, pivot_col);
            // Update column permutation
            int temp = col_perm[i];
            col_perm[i] = col_perm[pivot_col];
            col_perm[pivot_col] = temp;
        }

        // 4. Eliminate all elements below the pivot in column i
        for (j = i + 1; j < mt; j++) {
            if (matrix_get_bit(H, j, i) == 1) {
                matrix_xor_rows(H, j, i);
            }
        }
    }

    // --- Back elimination to form identity matrix ---
    for (i = mt - 1; i >= 0; i--) {
        for (j = 0; j < i; j++) {
            if (matrix_get_bit(H, j, i) == 1) {
                matrix_xor_rows(H, j, i);
            }
        }
    }

    free(col_perm);
    return 0; // Success
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


















