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

void test_gaussian_with_small_example() {
    printf("TESTING GAUSSIAN ELIMINATION LOGIC WITH SMALL EXAMPLE\n");
    printf("=====================================================\n");
    
    // Create a small test matrix to understand the reference logic
    printf("Creating 8x16 test matrix to debug the elimination logic...\n");
    
    matrix_t *test_H = matrix_create(8, 16);
    if (!test_H) return;
    
    // Fill with a pattern that should be reducible
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 16; j++) {
            int val = ((i + j) % 2) ^ ((i * j) % 2);  // Some pattern
            matrix_set_bit(test_H, i, j, val);
        }
        // Ensure diagonal is 1 initially
        matrix_set_bit(test_H, i, i, 1);
    }
    
    printf("Initial test matrix (8x16):\n");
    for (int i = 0; i < 8; i++) {
        printf("Row %d: ", i);
        for (int j = 0; j < 16; j++) {
            printf("%d", matrix_get_bit(test_H, i, j));
        }
        printf("\n");
    }
    
    printf("\nApplying reference-style Gaussian elimination step by step...\n");
    
    // Apply the exact reference algorithm
    int PK_NROWS = 8;
    int SYS_N = 16;
    
    for (int i = 0; i < (PK_NROWS + 7) / 8; i++) {
        for (int j = 0; j < 8; j++) {
            int row = i * 8 + j;
            
            if (row >= PK_NROWS) break;
            
            printf("\n--- Processing row %d (byte %d, bit %d) ---\n", row, i, j);
            
            // Show current state before elimination
            printf("Before forward elimination:\n");
            printf("  Row %d: ", row);
            for (int col = 0; col < 16; col++) {
                printf("%d", matrix_get_bit(test_H, row, col));
            }
            printf(" (diagonal bit = %d)\n", matrix_get_bit(test_H, row, row));
            
            // Forward elimination step (exact reference logic)
            for (int k = row + 1; k < PK_NROWS; k++) {
                printf("  Forward: comparing row %d with row %d\n", row, k);
                
                // Show rows being compared
                printf("    Row %d: ", row);
                for (int col = 0; col < 16; col++) {
                    printf("%d", matrix_get_bit(test_H, row, col));
                }
                printf("\n");
                printf("    Row %d: ", k);
                for (int col = 0; col < 16; col++) {
                    printf("%d", matrix_get_bit(test_H, k, col));
                }
                printf("\n");
                
                // Extract mask calculation
                uint8_t byte_row = test_H->data[row * test_H->cols_bytes + i];
                uint8_t byte_k = test_H->data[k * test_H->cols_bytes + i];
                uint8_t mask = byte_row ^ byte_k;
                printf("    Bytes: row_byte=0x%02X, k_byte=0x%02X, xor=0x%02X\n", 
                       byte_row, byte_k, mask);
                
                mask >>= j;
                mask &= 1;
                printf("    After shift>>%d and &1: mask=%d\n", j, mask);
                
                mask = (uint8_t)(-(int8_t)mask);  // Sign extend
                printf("    After sign extend: mask=0x%02X\n", mask);
                
                if (mask != 0) {
                    printf("    Applying XOR to row %d...\n", row);
                    
                    // Apply mask to entire rows (reference logic)
                    for (int c = 0; c < SYS_N / 8; c++) {
                        uint8_t old_val = test_H->data[row * test_H->cols_bytes + c];
                        test_H->data[row * test_H->cols_bytes + c] ^= test_H->data[k * test_H->cols_bytes + c] & mask;
                        uint8_t new_val = test_H->data[row * test_H->cols_bytes + c];
                        if (old_val != new_val) {
                            printf("      Byte[%d]: 0x%02X -> 0x%02X\n", c, old_val, new_val);
                        }
                    }
                    
                    printf("    Row %d after: ", row);
                    for (int col = 0; col < 16; col++) {
                        printf("%d", matrix_get_bit(test_H, row, col));
                    }
                    printf("\n");
                } else {
                    printf("    No change needed (mask=0)\n");
                }
            }
            
            // Check diagonal element
            int diag_bit = matrix_get_bit(test_H, row, row);
            printf("  Diagonal check: H[%d,%d] = %d\n", row, row, diag_bit);
            
            if (diag_bit == 0) {
                printf("  ❌ FAILED: diagonal is 0, would return -1\n");
                matrix_free(test_H);
                return;
            }
            
            // Backward elimination step
            printf("  Backward elimination:\n");
            for (int k = 0; k < PK_NROWS; k++) {
                if (k != row) {
                    uint8_t mask = test_H->data[k * test_H->cols_bytes + i] >> j;
                    mask &= 1;
                    
                    if (mask != 0) {
                        printf("    Eliminating row %d (bit=%d)\n", k, mask);
                        mask = (uint8_t)(-(int8_t)mask);
                        
                        for (int c = 0; c < SYS_N / 8; c++) {
                            test_H->data[k * test_H->cols_bytes + c] ^= test_H->data[row * test_H->cols_bytes + c] & mask;
                        }
                    }
                }
            }
            
            printf("  Final state after processing row %d:\n", row);
            for (int r = 0; r < 8; r++) {
                printf("    Row %d: ", r);
                for (int col = 0; col < 16; col++) {
                    printf("%d", matrix_get_bit(test_H, r, col));
                }
                printf(" (diag=%d)\n", matrix_get_bit(test_H, r, r));
            }
        }
    }
    
    printf("\n✅ Test completed - check if systematic form was achieved\n");
    
    // Check final systematic form
    int is_systematic = 1;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            int expected = (i == j) ? 1 : 0;
            int actual = matrix_get_bit(test_H, i, j);
            if (actual != expected) {
                printf("❌ Not systematic at [%d,%d]: expected %d, got %d\n", i, j, expected, actual);
                is_systematic = 0;
            }
        }
    }
    
    if (is_systematic) {
        printf("✅ Perfect systematic form achieved!\n");
    } else {
        printf("❌ Systematic form not achieved\n");
    }
    
    matrix_free(test_H);
}

int main() {
    printf("DETAILED GAUSSIAN ELIMINATION DEBUG\n");
    printf("===================================\n");
    
    gf_init();
    
    // Test with small example first
    test_gaussian_with_small_example();
    
    return 0;
}
