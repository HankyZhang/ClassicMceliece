#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mceliece_types.h"
#include "mceliece_keygen.h"
#include "mceliece_shake.h"
#include "mceliece_poly.h"
#include "reference_shake.h"

void debug_matrix_element_by_element(const gf_elem_t *support, const polynomial_t *g, int max_debug) {
    printf("=== DETAILED MATRIX ELEMENT ANALYSIS ===\n");
    
    // Test first few elements to understand the discrepancy
    printf("Testing first %d support elements:\n", max_debug);
    
    for (int j = 0; j < max_debug; j++) {
        gf_elem_t alpha_j = support[j];
        gf_elem_t g_eval = polynomial_eval(g, alpha_j);
        gf_elem_t inv_eval = gf_inv(g_eval);
        
        printf("j=%d: alpha[%d]=%04X, g(alpha)=%04X, inv=%04X\n", 
               j, j, alpha_j, g_eval, inv_eval);
        
        // Show how this gets packed into the matrix
        printf("  Bit representation of inv: ");
        for (int bit = MCELIECE_M - 1; bit >= 0; bit--) {
            printf("%d", (inv_eval >> bit) & 1);
        }
        printf(" (MSB first)\n");
        
        // Show how bits get distributed in first T iterations
        gf_elem_t current_inv = inv_eval;
        for (int i = 0; i < 4 && i < MCELIECE_T; i++) {  // Just first 4 iterations
            printf("  Iteration %d: current_inv=%04X, bits=", i, current_inv);
            for (int bit = MCELIECE_M - 1; bit >= 0; bit--) {
                printf("%d", (current_inv >> bit) & 1);
            }
            printf("\n");
            
            // Update for next iteration
            current_inv = gf_mul(current_inv, alpha_j);
        }
        printf("\n");
    }
}

void analyze_reference_bit_packing() {
    printf("=== REFERENCE BIT PACKING ANALYSIS ===\n");
    
    // Simulate reference bit packing for columns 0-15
    printf("Reference bit packing pattern for first 16 columns:\n");
    
    // Create test inv values
    gf_elem_t test_inv[16];
    for (int i = 0; i < 16; i++) {
        test_inv[i] = i + 1;  // Simple test pattern
    }
    
    // Show how reference packs bits (j=0 to j=7 first)
    printf("Columns 0-7 bit packing:\n");
    for (int k = 0; k < MCELIECE_M; k++) {
        printf("  Row %d (bit %d): ", k, k);
        
        // Reference packing: b = (inv[j+7] >> k) & 1; b <<= 1; etc.
        uint8_t b = 0;
        if (7 < 8)  { b  = (test_inv[7] >> k) & 1; b <<= 1; }
        if (6 < 8)  { b |= (test_inv[6] >> k) & 1; b <<= 1; }
        if (5 < 8)  { b |= (test_inv[5] >> k) & 1; b <<= 1; }
        if (4 < 8)  { b |= (test_inv[4] >> k) & 1; b <<= 1; }
        if (3 < 8)  { b |= (test_inv[3] >> k) & 1; b <<= 1; }
        if (2 < 8)  { b |= (test_inv[2] >> k) & 1; b <<= 1; }
        if (1 < 8)  { b |= (test_inv[1] >> k) & 1; b <<= 1; }
        if (0 < 8)  { b |= (test_inv[0] >> k) & 1; }
        
        printf("byte=%02X = ", b);
        for (int bit = 7; bit >= 0; bit--) {
            printf("%d", (b >> bit) & 1);
        }
        printf(" (bit 7=col7, bit 0=col0)\n");
    }
    
    printf("\nColumns 8-15 bit packing:\n");
    for (int k = 0; k < MCELIECE_M; k++) {
        printf("  Row %d (bit %d): ", k, k);
        
        uint8_t b = 0;
        if (15 < 16) { b  = (test_inv[15] >> k) & 1; b <<= 1; }
        if (14 < 16) { b |= (test_inv[14] >> k) & 1; b <<= 1; }
        if (13 < 16) { b |= (test_inv[13] >> k) & 1; b <<= 1; }
        if (12 < 16) { b |= (test_inv[12] >> k) & 1; b <<= 1; }
        if (11 < 16) { b |= (test_inv[11] >> k) & 1; b <<= 1; }
        if (10 < 16) { b |= (test_inv[10] >> k) & 1; b <<= 1; }
        if (9 < 16)  { b |= (test_inv[9] >> k) & 1; b <<= 1; }
        if (8 < 16)  { b |= (test_inv[8] >> k) & 1; }
        
        printf("byte=%02X = ", b);
        for (int bit = 7; bit >= 0; bit--) {
            printf("%d", (b >> bit) & 1);
        }
        printf(" (bit 7=col15, bit 0=col8)\n");
    }
}

int main() {
    printf("MATRIX BIT-PACKING DEBUG\n");
    printf("========================\n");
    
    gf_init();
    
    // Generate test components
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
    
    printf("Using verified components:\n");
    printf("Alpha[0-7]: ");
    for (int i = 0; i < 8; i++) printf("%04X ", alpha[i]);
    printf("\n");
    
    // Debug matrix elements
    debug_matrix_element_by_element(alpha, g, 8);
    
    // Analyze reference packing
    analyze_reference_bit_packing();
    
    // Test actual matrix bit access
    printf("\n=== MATRIX ACCESS PATTERN TEST ===\n");
    
    // Create matrices using both methods
    int PK_NROWS = MCELIECE_M * MCELIECE_T;
    int SYS_N = MCELIECE_N;
    
    // Method 1: Our bit-by-bit approach
    printf("Building matrix with bit-by-bit method...\n");
    matrix_t *H_bits = matrix_create(PK_NROWS, SYS_N);
    memset(H_bits->data, 0, H_bits->rows * H_bits->cols_bytes);
    
    for (int j = 0; j < 32; j++) {  // Just first 32 columns for debug
        gf_elem_t eval = polynomial_eval(g, alpha[j]);
        gf_elem_t inv_val = gf_inv(eval);
        
        gf_elem_t current_inv = inv_val;
        for (int i = 0; i < MCELIECE_T; i++) {
            for (int bit = 0; bit < MCELIECE_M; bit++) {
                int matrix_bit = (current_inv >> bit) & 1;
                matrix_set_bit(H_bits, i * MCELIECE_M + bit, j, matrix_bit);
            }
            current_inv = gf_mul(current_inv, alpha[j]);
        }
    }
    
    // Method 2: Reference byte-packing approach  
    printf("Building matrix with reference byte-packing...\n");
    matrix_t *H_bytes = matrix_create(PK_NROWS, SYS_N);
    memset(H_bytes->data, 0, H_bytes->rows * H_bytes->cols_bytes);
    
    // Compute inv array like reference
    gf_elem_t *inv = malloc(SYS_N * sizeof(gf_elem_t));
    for (int j = 0; j < SYS_N; j++) {
        gf_elem_t eval = polynomial_eval(g, alpha[j]);
        inv[j] = gf_inv(eval);
    }
    
    // Reference matrix building (first few iterations only for debug)
    for (int i = 0; i < 4; i++) {  // Just first 4 iterations
        for (int j = 0; j < 32; j += 8) {  // Just first 32 columns
            for (int k = 0; k < MCELIECE_M; k++) {
                uint8_t b = 0;
                
                // Exact reference bit packing
                if (j + 7 < SYS_N && j + 7 < 32) { b  = (inv[j+7] >> k) & 1; b <<= 1; }
                if (j + 6 < SYS_N && j + 6 < 32) { b |= (inv[j+6] >> k) & 1; b <<= 1; }
                if (j + 5 < SYS_N && j + 5 < 32) { b |= (inv[j+5] >> k) & 1; b <<= 1; }
                if (j + 4 < SYS_N && j + 4 < 32) { b |= (inv[j+4] >> k) & 1; b <<= 1; }
                if (j + 3 < SYS_N && j + 3 < 32) { b |= (inv[j+3] >> k) & 1; b <<= 1; }
                if (j + 2 < SYS_N && j + 2 < 32) { b |= (inv[j+2] >> k) & 1; b <<= 1; }
                if (j + 1 < SYS_N && j + 1 < 32) { b |= (inv[j+1] >> k) & 1; b <<= 1; }
                if (j + 0 < SYS_N && j + 0 < 32) { b |= (inv[j+0] >> k) & 1; }
                
                int row = i * MCELIECE_M + k;
                int byte_col = j / 8;
                if (row < H_bytes->rows && byte_col < H_bytes->cols_bytes) {
                    H_bytes->data[row * H_bytes->cols_bytes + byte_col] = b;
                }
            }
        }
        
        // Update inv for next iteration
        for (int j = 0; j < SYS_N; j++) {
            inv[j] = gf_mul(inv[j], alpha[j]);
        }
    }
    
    // Compare the two matrices
    printf("\nComparing matrices (first 4 rows, first 32 columns):\n");
    int differences = 0;
    for (int i = 0; i < 4 * MCELIECE_M && i < H_bits->rows; i++) {
        for (int j = 0; j < 32 && j < H_bits->cols; j++) {
            int bit1 = matrix_get_bit(H_bits, i, j);
            int bit2 = matrix_get_bit(H_bytes, i, j);
            if (bit1 != bit2) {
                printf("  Difference at (%d,%d): bits=%d, bytes=%d\n", i, j, bit1, bit2);
                differences++;
                if (differences >= 20) {
                    printf("  ... (stopping after 20 differences)\n");
                    break;
                }
            }
        }
        if (differences >= 20) break;
    }
    
    if (differences == 0) {
        printf("✅ Matrices match perfectly!\n");
    } else {
        printf("❌ Found %d differences\n", differences);
        
        // Show first row in detail
        printf("\nFirst row comparison:\n");
        printf("Bits method: ");
        for (int j = 0; j < 32; j++) {
            printf("%d", matrix_get_bit(H_bits, 0, j));
        }
        printf("\nByte method: ");
        for (int j = 0; j < 32; j++) {
            printf("%d", matrix_get_bit(H_bytes, 0, j));
        }
        printf("\n");
    }
    
    // Cleanup
    free(inv);
    matrix_free(H_bytes);
    matrix_free(H_bits);
    polynomial_free(g);
    free(alpha);
    free(prg_output);
    
    return 0;
}
