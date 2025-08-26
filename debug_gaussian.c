#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mceliece_types.h"
#include "mceliece_keygen.h"
#include "mceliece_shake.h"
#include "mceliece_matrix_ops.h"

// Function declarations for perfect implementation
int build_parity_check_matrix_perfect(matrix_t *H, const polynomial_t *g, const gf_elem_t *support);

void debug_gaussian_elimination_step_by_step(matrix_t *H) {
    if (!H) return;
    
    int PK_NROWS = H->rows;
    int SYS_N = H->cols;
    
    printf("DEBUGGING GAUSSIAN ELIMINATION STEP BY STEP\n");
    printf("Matrix: %d x %d\n", PK_NROWS, SYS_N);
    printf("Expected diagonal positions: 0,0 to %d,%d\n", PK_NROWS-1, PK_NROWS-1);
    
    // Check initial matrix properties
    printf("\nInitial matrix analysis:\n");
    printf("Checking first 10 diagonal elements:\n");
    for (int i = 0; i < 10 && i < PK_NROWS; i++) {
        int bit = matrix_get_bit(H, i, i);
        printf("  H[%d,%d] = %d\n", i, i, bit);
    }
    
    printf("\nChecking last 10 diagonal elements:\n");
    for (int i = PK_NROWS - 10; i < PK_NROWS; i++) {
        if (i >= 0 && i < SYS_N) {
            int bit = matrix_get_bit(H, i, i);
            printf("  H[%d,%d] = %d\n", i, i, bit);
        }
    }
    
    // Start Gaussian elimination with detailed logging
    printf("\nStarting Gaussian elimination with debug info...\n");
    
    for (int i = 0; i < (PK_NROWS + 7) / 8; i++) {
        for (int j = 0; j < 8; j++) {
            int row = i * 8 + j;
            
            if (row >= PK_NROWS) break;
            
            // Log every 100th row and the last few rows
            if (row % 100 == 0 || row >= PK_NROWS - 10) {
                printf("\nProcessing row %d (byte %d, bit %d):\n", row, i, j);
                
                // Check current diagonal element before elimination
                if (row < SYS_N) {
                    uint8_t diag_byte = H->data[row * H->cols_bytes + i];
                    int diag_bit = (diag_byte >> j) & 1;
                    printf("  Current diagonal H[%d,%d] = %d (byte=0x%02X, bit=%d)\n", 
                           row, row, diag_bit, diag_byte, j);
                }
            }
            
            // Forward elimination step
            for (int k = row + 1; k < PK_NROWS; k++) {
                uint8_t mask = H->data[row * H->cols_bytes + i] ^ H->data[k * H->cols_bytes + i];
                mask >>= j;
                mask &= 1;
                mask = (uint8_t)(-(int8_t)mask);
                
                for (int c = 0; c < SYS_N / 8; c++) {
                    H->data[row * H->cols_bytes + c] ^= H->data[k * H->cols_bytes + c] & mask;
                }
            }
            
            // Check if diagonal element is 1
            uint8_t diag_byte = H->data[row * H->cols_bytes + i];
            int diag_bit = (diag_byte >> j) & 1;
            
            if (row % 100 == 0 || row >= PK_NROWS - 10 || diag_bit == 0) {
                printf("  After forward elimination: H[%d,%d] = %d (byte=0x%02X)\n", 
                       row, row, diag_bit, diag_byte);
            }
            
            if (diag_bit == 0) {
                printf("❌ FAILED at row %d: diagonal element is 0\n", row);
                printf("  Byte index: %d, bit index: %d\n", i, j);
                printf("  Expected position: H[%d,%d]\n", row, row);
                printf("  Actual byte content: 0x%02X\n", diag_byte);
                
                // Show some context around this position
                printf("  Context - row %d bytes around position %d:\n", row, i);
                for (int ctx = i - 2; ctx <= i + 2; ctx++) {
                    if (ctx >= 0 && ctx < H->cols_bytes) {
                        printf("    byte[%d] = 0x%02X", ctx, H->data[row * H->cols_bytes + ctx]);
                        if (ctx == i) printf(" <- DIAGONAL");
                        printf("\n");
                    }
                }
                
                // Check if we're at the edge case
                printf("  Edge case analysis:\n");
                printf("    PK_NROWS = %d\n", PK_NROWS);
                printf("    SYS_N = %d\n", SYS_N);
                printf("    row = %d\n", row);
                printf("    Expected diagonal at column %d\n", row);
                printf("    Matrix columns available: 0 to %d\n", SYS_N - 1);
                
                if (row >= SYS_N) {
                    printf("    🔍 ISSUE: Trying to access diagonal beyond matrix width!\n");
                    printf("    This suggests a dimension mismatch.\n");
                }
                
                return;  // Stop at first failure
            }
            
            // Backward elimination step
            for (int k = 0; k < PK_NROWS; k++) {
                if (k != row) {
                    uint8_t mask = H->data[k * H->cols_bytes + i] >> j;
                    mask &= 1;
                    mask = (uint8_t)(-(int8_t)mask);
                    
                    for (int c = 0; c < SYS_N / 8; c++) {
                        H->data[k * H->cols_bytes + c] ^= H->data[row * H->cols_bytes + c] & mask;
                    }
                }
            }
            
            if (row % 100 == 0 || row >= PK_NROWS - 10) {
                printf("  After backward elimination: H[%d,%d] = %d\n", 
                       row, row, matrix_get_bit(H, row, row));
            }
        }
    }
    
    printf("✅ Gaussian elimination completed without errors\n");
}

void analyze_matrix_dimensions() {
    printf("MATRIX DIMENSION ANALYSIS\n");
    printf("=========================\n");
    
    printf("McEliece-6688128 parameters:\n");
    printf("  MCELIECE_M = %d\n", MCELIECE_M);
    printf("  MCELIECE_T = %d\n", MCELIECE_T);
    printf("  MCELIECE_N = %d\n", MCELIECE_N);
    printf("  MCELIECE_Q = %d\n", MCELIECE_Q);
    
    int PK_NROWS = MCELIECE_M * MCELIECE_T;
    int SYS_N = MCELIECE_N;
    
    printf("\nMatrix dimensions:\n");
    printf("  PK_NROWS = M * T = %d * %d = %d\n", MCELIECE_M, MCELIECE_T, PK_NROWS);
    printf("  SYS_N = N = %d\n", SYS_N);
    printf("  Matrix size: %d x %d\n", PK_NROWS, SYS_N);
    
    printf("\nFor systematic form:\n");
    printf("  We need a %d x %d identity matrix in the left part\n", PK_NROWS, PK_NROWS);
    printf("  Diagonal elements: H[0,0] to H[%d,%d]\n", PK_NROWS-1, PK_NROWS-1);
    
    if (PK_NROWS > SYS_N) {
        printf("  ❌ PROBLEM: PK_NROWS (%d) > SYS_N (%d)\n", PK_NROWS, SYS_N);
        printf("  This means the matrix is taller than it is wide!\n");
        printf("  Cannot have identity matrix of size %d x %d in a matrix with only %d columns\n", 
               PK_NROWS, PK_NROWS, SYS_N);
    } else {
        printf("  ✅ GOOD: PK_NROWS (%d) <= SYS_N (%d)\n", PK_NROWS, SYS_N);
        printf("  Identity matrix %d x %d will fit in left part\n", PK_NROWS, PK_NROWS);
        printf("  Public key will be the remaining %d x %d right part\n", 
               PK_NROWS, SYS_N - PK_NROWS);
    }
    
    printf("\nByte indexing for last row:\n");
    int last_row = PK_NROWS - 1;
    int last_diag_col = last_row;
    int byte_idx = last_diag_col / 8;
    int bit_idx = last_diag_col % 8;
    
    printf("  Last diagonal: H[%d,%d]\n", last_row, last_diag_col);
    printf("  Byte index: %d, Bit index: %d\n", byte_idx, bit_idx);
    printf("  Expected in Gaussian loop: i=%d, j=%d, row=%d\n", byte_idx, bit_idx, last_row);
    
    // Check if our loop covers this
    int max_i = (PK_NROWS + 7) / 8;
    printf("  Gaussian loop covers: i=0 to i=%d\n", max_i - 1);
    printf("  That's byte indices 0 to %d\n", max_i - 1);
    
    if (byte_idx < max_i) {
        printf("  ✅ Last diagonal position IS covered by loop\n");
    } else {
        printf("  ❌ Last diagonal position NOT covered by loop\n");
    }
}

int main() {
    printf("GAUSSIAN ELIMINATION DEBUG\n");
    printf("==========================\n");
    
    // Analyze dimensions first
    analyze_matrix_dimensions();
    
    // Initialize and build matrix
    gf_init();
    
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }

    size_t prg_len = 40000;
    uint8_t *prg_output = malloc(prg_len);
    mceliece_prg(seed, prg_output, prg_len);
    
    size_t s_len = (MCELIECE_N + 7) / 8;
    size_t field_len = (32 * MCELIECE_Q + 7) / 8;
    const uint8_t *field_section = prg_output + s_len;
    const uint8_t *poly_section = prg_output + s_len + field_len;
    
    gf_elem_t *alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
    polynomial_t *g = polynomial_create(MCELIECE_T);
    
    generate_field_ordering(alpha, field_section);
    generate_irreducible_poly_final(g, poly_section);
    
    int PK_NROWS = MCELIECE_M * MCELIECE_T;
    int SYS_N = MCELIECE_N;
    
    matrix_t *H = matrix_create(PK_NROWS, SYS_N);
    printf("\nBuilding test matrix...\n");
    build_parity_check_matrix_perfect(H, g, alpha);
    
    printf("\n");
    for(int i = 0; i < 60; i++) printf("=");
    printf("\nSTEP-BY-STEP GAUSSIAN ELIMINATION DEBUG\n");
    for(int i = 0; i < 60; i++) printf("=");
    printf("\n");
    
    debug_gaussian_elimination_step_by_step(H);
    
    // Cleanup
    matrix_free(H);
    polynomial_free(g);
    free(alpha);
    free(prg_output);
    
    return 0;
}
