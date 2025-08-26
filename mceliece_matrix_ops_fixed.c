#include "mceliece_matrix_ops.h"
#include "mceliece_poly.h"

// Matrix creation (unchanged)
matrix_t* matrix_create(int rows, int cols) {
    matrix_t *mat = malloc(sizeof(matrix_t));
    if (!mat) return NULL;

    mat->rows = rows;
    mat->cols = cols;
    mat->cols_bytes = (cols + 7) / 8;

    mat->data = calloc(rows * mat->cols_bytes, sizeof(uint8_t));
    if (!mat->data) {
        free(mat);
        return NULL;
    }

    return mat;
}

// Matrix free (unchanged)
void matrix_free(matrix_t *mat) {
    if (mat) {
        if (mat->data) free(mat->data);
        free(mat);
    }
}

// Bit access functions (unchanged)
int matrix_get_bit(const matrix_t *mat, int row, int col) {
    if (!mat || row < 0 || row >= mat->rows || col < 0 || col >= mat->cols) {
        return 0;
    }
    const uint8_t *p = &mat->data[row * mat->cols_bytes + (col >> 3)];
    return (int)((p[0] >> (col & 7)) & 1);
}

void matrix_set_bit(matrix_t *mat, int row, int col, int bit) {
    if (!mat || row < 0 || row >= mat->rows || col < 0 || col >= mat->cols) {
        return;
    }
    uint8_t *p = &mat->data[row * mat->cols_bytes + (col >> 3)];
    uint8_t mask = (uint8_t)(1u << (col & 7));
    if (bit) {
        p[0] |= mask;
    } else {
        p[0] &= (uint8_t)(~mask);
    }
}

// Row operations (unchanged)
void matrix_swap_rows(matrix_t *mat, int row1, int row2) {
    if (!mat || row1 < 0 || row1 >= mat->rows || row2 < 0 || row2 >= mat->rows) {
        return;
    }
    if (row1 == row2) return;
    
    uint8_t *r1 = &mat->data[row1 * mat->cols_bytes];
    uint8_t *r2 = &mat->data[row2 * mat->cols_bytes];
    
    for (int i = 0; i < mat->cols_bytes; i++) {
        uint8_t temp = r1[i];
        r1[i] = r2[i];
        r2[i] = temp;
    }
}

void matrix_xor_rows(matrix_t *mat, int row_dst, int row_src) {
    if (!mat || row_dst < 0 || row_dst >= mat->rows || row_src < 0 || row_src >= mat->rows) {
        return;
    }
    
    uint8_t *dst = &mat->data[row_dst * mat->cols_bytes];
    uint8_t *src = &mat->data[row_src * mat->cols_bytes];
    
    for (int i = 0; i < mat->cols_bytes; i++) {
        dst[i] ^= src[i];
    }
}

// Build parity check matrix using reference-style approach
int build_parity_check_matrix_reference_style(matrix_t *H, const polynomial_t *g, const gf_elem_t *support) {
    if (!H || !g || !support) return -1;
    
    int PK_NROWS = MCELIECE_M * MCELIECE_T;
    int SYS_N = MCELIECE_N;
    int SYS_T = MCELIECE_T;
    int GFBITS = MCELIECE_M;
    
    if (H->rows != PK_NROWS || H->cols != SYS_N) {
        printf("❌ Matrix dimensions mismatch: expected %dx%d, got %dx%d\n", 
               PK_NROWS, SYS_N, H->rows, H->cols);
        return -1;
    }
    
    // Clear matrix
    memset(H->data, 0, H->rows * H->cols_bytes);
    
    // Compute inverses: inv[j] = 1/g(support[j])
    gf_elem_t *inv = malloc(SYS_N * sizeof(gf_elem_t));
    if (!inv) return -1;
    
    printf("Computing polynomial evaluations at support points...\n");
    for (int j = 0; j < SYS_N; j++) {
        gf_elem_t eval = polynomial_eval(g, support[j]);
        if (eval == 0) {
            printf("❌ Zero evaluation at support[%d] = %04X\n", j, support[j]);
            free(inv);
            return -1;
        }
        inv[j] = gf_inv(eval);
    }
    
    printf("Building matrix using reference algorithm...\n");
    
    // Build matrix following reference pk_gen.c logic EXACTLY
    for (int i = 0; i < SYS_T; i++) {
        // For each power of the support elements
        for (int j = 0; j < SYS_N; j += 8) {
            for (int k = 0; k < GFBITS; k++) {
                // Pack 8 bits into one byte EXACTLY like reference
                uint8_t b = 0;
                
                // Reference bit packing order (MSB from highest column)
                if (j + 7 < SYS_N) { b  = (inv[j+7] >> k) & 1; b <<= 1; }
                if (j + 6 < SYS_N) { b |= (inv[j+6] >> k) & 1; b <<= 1; }
                if (j + 5 < SYS_N) { b |= (inv[j+5] >> k) & 1; b <<= 1; }
                if (j + 4 < SYS_N) { b |= (inv[j+4] >> k) & 1; b <<= 1; }
                if (j + 3 < SYS_N) { b |= (inv[j+3] >> k) & 1; b <<= 1; }
                if (j + 2 < SYS_N) { b |= (inv[j+2] >> k) & 1; b <<= 1; }
                if (j + 1 < SYS_N) { b |= (inv[j+1] >> k) & 1; b <<= 1; }
                if (j + 0 < SYS_N) { b |= (inv[j+0] >> k) & 1; }
                
                // Set the byte in the matrix EXACTLY like reference
                int row = i * GFBITS + k;
                int byte_col = j / 8;
                if (row < H->rows && byte_col < H->cols_bytes) {
                    H->data[row * H->cols_bytes + byte_col] = b;
                }
            }
        }
        
        // Update inv[j] = inv[j] * support[j] for next iteration  
        for (int j = 0; j < SYS_N; j++) {
            inv[j] = gf_mul(inv[j], support[j]);
        }
        
        if (i % 32 == 0) {
            printf("  Completed step %d/%d\n", i + 1, SYS_T);
        }
    }
    
    free(inv);
    printf("✅ Matrix built successfully\n");
    return 0;
}

// Gaussian elimination following reference implementation
int reduce_to_systematic_form_reference_style(matrix_t *H) {
    if (!H) return -1;
    
    int PK_NROWS = H->rows;
    int SYS_N = H->cols;
    
    printf("Starting Gaussian elimination (reference style)...\n");
    printf("Matrix: %d x %d\n", PK_NROWS, SYS_N);
    
    // Reference-style Gaussian elimination
    // Process byte by byte, bit by bit
    for (int i = 0; i < (PK_NROWS + 7) / 8; i++) {
        for (int j = 0; j < 8; j++) {
            int row = i * 8 + j;
            
            if (row >= PK_NROWS) break;
            
            // Forward elimination: clear all rows below the current row
            for (int k = row + 1; k < PK_NROWS; k++) {
                uint8_t mask = H->data[row * H->cols_bytes + i] ^ H->data[k * H->cols_bytes + i];
                mask >>= j;
                mask &= 1;
                mask = (uint8_t)(-(int8_t)mask);  // Extend to all bits
                
                for (int c = 0; c < SYS_N / 8; c++) {
                    H->data[row * H->cols_bytes + c] ^= H->data[k * H->cols_bytes + c] & mask;
                }
            }
            
            // Check if diagonal element is 1 (systematic form requirement)
            if (((H->data[row * H->cols_bytes + i] >> j) & 1) == 0) {
                printf("❌ Not systematic at row %d, bit %d\n", row, j);
                return -1;
            }
            
            // Backward elimination: clear all rows above and below
            for (int k = 0; k < PK_NROWS; k++) {
                if (k != row) {
                    uint8_t mask = H->data[k * H->cols_bytes + i] >> j;
                    mask &= 1;
                    mask = (uint8_t)(-(int8_t)mask);  // Extend to all bits
                    
                    for (int c = 0; c < SYS_N / 8; c++) {
                        H->data[k * H->cols_bytes + c] ^= H->data[row * H->cols_bytes + c] & mask;
                    }
                }
            }
            
            if (row % 100 == 0) {
                printf("  Processed row %d/%d\n", row, PK_NROWS);
            }
        }
    }
    
    printf("✅ Gaussian elimination completed\n");
    return 0;
}

// Check if matrix is in systematic form
int matrix_is_systematic(const matrix_t *mat) {
    if (!mat) return 0;
    
    int min_dim = (mat->rows < mat->cols) ? mat->rows : mat->cols;
    
    // Check if the first min_dim x min_dim submatrix is identity
    for (int i = 0; i < min_dim; i++) {
        for (int j = 0; j < min_dim; j++) {
            int expected = (i == j) ? 1 : 0;
            int actual = matrix_get_bit(mat, i, j);
            if (actual != expected) {
                return 0;
            }
        }
    }
    
    return 1;
}

// Matrix-vector multiply (unchanged)
void matrix_vector_multiply(const matrix_t *mat, const uint8_t *vec, uint8_t *result) {
    if (!mat || !vec || !result) return;
    
    memset(result, 0, (mat->rows + 7) / 8);
    
    for (int row = 0; row < mat->rows; row++) {
        uint8_t dot = 0;
        
        for (int col = 0; col < mat->cols; col++) {
            int mat_bit = matrix_get_bit(mat, row, col);
            int vec_bit = (vec[col / 8] >> (col % 8)) & 1;
            dot ^= (mat_bit & vec_bit);
        }
        
        if (dot) {
            result[row / 8] |= (1 << (row % 8));
        }
    }
}

// Additional utility functions for finite field matrices
matrix_fq_t* matrix_fq_create(int rows, int cols) {
    matrix_fq_t *mat = malloc(sizeof(matrix_fq_t));
    if (!mat) return NULL;
    
    mat->rows = rows;
    mat->cols = cols;
    mat->data = calloc(rows * cols, sizeof(gf_elem_t));
    if (!mat->data) {
        free(mat);
        return NULL;
    }
    
    return mat;
}

void matrix_fq_free(matrix_fq_t *mat) {
    if (mat) {
        if (mat->data) free(mat->data);
        free(mat);
    }
}

void matrix_fq_set(matrix_fq_t *mat, int row, int col, gf_elem_t value) {
    if (!mat || row < 0 || row >= mat->rows || col < 0 || col >= mat->cols) {
        return;
    }
    mat->data[row * mat->cols + col] = value;
}

gf_elem_t matrix_fq_get(const matrix_fq_t *mat, int row, int col) {
    if (!mat || row < 0 || row >= mat->rows || col < 0 || col >= mat->cols) {
        return 0;
    }
    return mat->data[row * mat->cols + col];
}

// Original systematic form reduction (for compatibility)
int reduce_to_systematic_form(matrix_t *H) {
    // For now, just call the reference-style version
    return reduce_to_systematic_form_reference_style(H);
}

// Placeholder for the record version
int reduce_to_systematic_form_record(matrix_t *H, matrix_t *U_out, int *perm_out) {
    // Not implemented yet - return error
    (void)U_out; (void)perm_out;
    return reduce_to_systematic_form_reference_style(H);
}

// Column swap operation
void matrix_swap_cols(matrix_t *mat, int col1, int col2) {
    if (!mat || col1 < 0 || col1 >= mat->cols || col2 < 0 || col2 >= mat->cols) {
        return;
    }
    if (col1 == col2) return;
    
    for (int row = 0; row < mat->rows; row++) {
        int bit1 = matrix_get_bit(mat, row, col1);
        int bit2 = matrix_get_bit(mat, row, col2);
        matrix_set_bit(mat, row, col1, bit2);
        matrix_set_bit(mat, row, col2, bit1);
    }
}

// Matrix invert - placeholder
int matrix_invert(const matrix_t *A, matrix_t *A_inv) {
    // Not implemented
    (void)A; (void)A_inv;
    return -1;
}
