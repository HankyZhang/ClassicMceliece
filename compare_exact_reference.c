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

// Exact reference Gaussian elimination (copied line by line)
int reference_gaussian_elimination(matrix_t *H) {
    int PK_NROWS = H->rows;
    int SYS_N = H->cols;
    
    printf("Reference-style Gaussian elimination...\n");
    
    // gaussian elimination (EXACT COPY of reference)
    for (int i = 0; i < (PK_NROWS + 7) / 8; i++) {
        for (int j = 0; j < 8; j++) {
            int row = i * 8 + j;
            
            if (row >= PK_NROWS) break;
            
            // Forward elimination: lines 116-125
            for (int k = row + 1; k < PK_NROWS; k++) {
                uint8_t mask = H->data[row * H->cols_bytes + i] ^ H->data[k * H->cols_bytes + i];
                mask >>= j;
                mask &= 1;
                mask = (uint8_t)(-(int8_t)mask);  // This is -mask in reference
                
                for (int c = 0; c < SYS_N / 8; c++) {
                    H->data[row * H->cols_bytes + c] ^= H->data[k * H->cols_bytes + c] & mask;
                }
            }
            
            // Check diagonal: lines 127-130
            if (((H->data[row * H->cols_bytes + i] >> j) & 1) == 0) {
                printf("❌ Reference would fail at row %d, diagonal not 1\n", row);
                return -1;
            }
            
            // Backward elimination: lines 132-143
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
            
            if ((row + 1) % 200 == 0) {
                printf("  Reference processed row %d/%d\n", row + 1, PK_NROWS);
            }
        }
    }
    
    printf("✅ Reference Gaussian elimination completed\n");
    return 0;
}

int test_reference_attempt_rate() {
    printf("TESTING REFERENCE SUCCESS RATE\n");
    printf("===============================\n");
    printf("Using exact reference algorithm to see attempt rate\n\n");
    
    gf_init();
    
    int successful = 0;
    int total_attempts = 20;  // Test 20 different seeds
    
    for (int attempt = 0; attempt < total_attempts; attempt++) {
        printf("=== Attempt %d/%d ===\n", attempt + 1, total_attempts);
        
        // Generate random seed
        uint8_t seed[32];
        for (int i = 0; i < 32; i++) {
            seed[i] = (uint8_t)(rand() & 0xFF);
        }
        
        printf("Seed: ");
        for (int i = 0; i < 4; i++) printf("%02X", seed[i]);
        printf("...\n");
        
        // Generate components
        size_t prg_len = 40000;
        uint8_t *prg_output = malloc(prg_len);
        mceliece_prg(seed, prg_output, prg_len);
        
        size_t s_len = (MCELIECE_N + 7) / 8;
        size_t field_len = (32 * MCELIECE_Q + 7) / 8;
        const uint8_t *field_section = prg_output + s_len;
        const uint8_t *poly_section = prg_output + s_len + field_len;
        
        gf_elem_t *alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
        polynomial_t *g = polynomial_create(MCELIECE_T);
        
        int field_result = generate_field_ordering(alpha, field_section);
        int poly_result = generate_irreducible_poly_final(g, poly_section);
        
        if (field_result != 0 || poly_result != 0) {
            printf("  ❌ Core generation failed\n");
            polynomial_free(g);
            free(alpha);
            free(prg_output);
            continue;
        }
        
        // Build matrix
        int PK_NROWS = MCELIECE_M * MCELIECE_T;
        int SYS_N = MCELIECE_N;
        
        matrix_t *H = matrix_create(PK_NROWS, SYS_N);
        int build_result = build_parity_check_matrix_perfect(H, g, alpha);
        
        if (build_result != 0) {
            printf("  ❌ Matrix building failed\n");
            matrix_free(H);
            polynomial_free(g);
            free(alpha);
            free(prg_output);
            continue;
        }
        
        // Test with exact reference Gaussian elimination
        int gauss_result = reference_gaussian_elimination(H);
        
        if (gauss_result == 0) {
            printf("  ✅ SUCCESS with reference algorithm!\n");
            successful++;
        } else {
            printf("  ❌ Failed with reference algorithm\n");
        }
        
        // Cleanup
        matrix_free(H);
        polynomial_free(g);
        free(alpha);
        free(prg_output);
        
        printf("\n");
    }
    
    printf("=====================================\n");
    printf("REFERENCE SUCCESS RATE RESULTS:\n");
    printf("=====================================\n");
    printf("Successful: %d/%d (%.1f%%)\n", successful, total_attempts, 
           (100.0 * successful) / total_attempts);
    
    if (successful >= total_attempts * 0.8) {  // Expect >80% success
        printf("✅ Reference algorithm shows high success rate\n");
        printf("Our implementation should match this rate!\n");
    } else if (successful >= total_attempts * 0.3) {  // 30-80% success
        printf("📊 Moderate success rate - this might be normal\n");
    } else {
        printf("❌ Low success rate - something may be wrong\n");
    }
    
    printf("\nExpected behavior:\n");
    printf("• Reference typically succeeds in 1-3 attempts\n");
    printf("• Very low failure rates indicate good matrix structure\n");
    printf("• If our rate is much lower, there's likely a bug\n");
    
    return 0;
}

int main() {
    srand(12345);  // Fixed seed for reproducible testing
    return test_reference_attempt_rate();
}
