#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mceliece_types.h"
#include "mceliece_keygen.h"
#include "mceliece_shake.h"
#include "mceliece_matrix_ops.h"

// Include reference functions
#define CRYPTO_NAMESPACE(x) ref_##x
#include "mceliece6688128/gf.h"
#include "mceliece6688128/root.h"
#include "mceliece6688128/params.h"

// Function declarations for perfect implementation
int build_parity_check_matrix_perfect(matrix_t *H, const polynomial_t *g, const gf_elem_t *support);

// Reference matrix building (exact copy from pk_gen.c)
void reference_matrix_build(uint8_t mat[PK_NROWS][SYS_N/8], gf *f, gf *L) {
    int i, j, k;
    gf inv[SYS_N];
    unsigned char b;
    
    printf("Reference matrix building...\n");
    
    // Clear matrix
    for (i = 0; i < PK_NROWS; i++)
        for (j = 0; j < SYS_N/8; j++)
            mat[i][j] = 0;
    
    // Evaluate polynomial at all support points
    ref_root(inv, f, L);
    
    // Invert all evaluations
    for (i = 0; i < SYS_N; i++)
        inv[i] = ref_gf_inv(inv[i]);
        
    printf("First few inv values: ");
    for (i = 0; i < 8; i++) printf("%04X ", inv[i]);
    printf("\n");
    
    // Build matrix
    for (i = 0; i < SYS_T; i++) {
        for (j = 0; j < SYS_N; j += 8) {
            for (k = 0; k < GFBITS; k++) {
                b  = (inv[j+7] >> k) & 1; b <<= 1;
                b |= (inv[j+6] >> k) & 1; b <<= 1;
                b |= (inv[j+5] >> k) & 1; b <<= 1;
                b |= (inv[j+4] >> k) & 1; b <<= 1;
                b |= (inv[j+3] >> k) & 1; b <<= 1;
                b |= (inv[j+2] >> k) & 1; b <<= 1;
                b |= (inv[j+1] >> k) & 1; b <<= 1;
                b |= (inv[j+0] >> k) & 1;
                
                mat[i * GFBITS + k][j/8] = b;
            }
        }
        
        // Update inv for next iteration
        for (j = 0; j < SYS_N; j++)
            inv[j] = ref_gf_mul(inv[j], L[j]);
            
        if ((i + 1) % 32 == 0) {
            printf("  Reference completed iteration %d/%d\n", i + 1, SYS_T);
        }
    }
    
    printf("✅ Reference matrix building completed\n");
}

void compare_matrix_building() {
    printf("COMPARING MATRIX BUILDING: OUR vs REFERENCE\n");
    printf("===========================================\n");
    
    gf_init();
    ref_gf_init();
    
    // Use a known working seed
    const char* seed_hex = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    printf("Using seed: ");
    for (int i = 0; i < 8; i++) printf("%02X", seed[i]);
    printf("...\n");
    
    // Generate components
    size_t prg_len = 40000;
    uint8_t *prg_output = malloc(prg_len);
    mceliece_prg(seed, prg_output, prg_len);
    
    size_t s_len = (MCELIECE_N + 7) / 8;
    size_t field_len = (32 * MCELIECE_Q + 7) / 8;
    const uint8_t *field_section = prg_output + s_len;
    const uint8_t *poly_section = prg_output + s_len + field_len;
    
    // Generate our components
    gf_elem_t *alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
    polynomial_t *g = polynomial_create(MCELIECE_T);
    
    generate_field_ordering(alpha, field_section);
    generate_irreducible_poly_final(g, poly_section);
    
    printf("Our components ready:\n");
    printf("  Alpha[0-7]: ");
    for (int i = 0; i < 8; i++) printf("%04X ", alpha[i]);
    printf("\n");
    printf("  g[0-7]: ");
    for (int i = 0; i < 8; i++) printf("%04X ", g->coeffs[i]);
    printf("\n");
    
    // Convert to reference format
    gf ref_L[SYS_N];
    gf ref_f[SYS_T + 1];
    
    // Copy field elements
    for (int i = 0; i < SYS_N; i++) {
        ref_L[i] = (gf)alpha[i];
    }
    
    // Copy polynomial (note: reference expects degree SYS_T, with leading coefficient)
    for (int i = 0; i < SYS_T; i++) {
        ref_f[i] = (gf)g->coeffs[i];
    }
    ref_f[SYS_T] = 1;  // Leading coefficient for monic polynomial
    
    printf("Reference components:\n");
    printf("  L[0-7]: ");
    for (int i = 0; i < 8; i++) printf("%04X ", ref_L[i]);
    printf("\n");
    printf("  f[0-7]: ");
    for (int i = 0; i < 8; i++) printf("%04X ", ref_f[i]);
    printf("\n");
    
    // Build matrix with our method
    printf("\n=== BUILDING WITH OUR METHOD ===\n");
    matrix_t *H_ours = matrix_create(PK_NROWS, SYS_N);
    int our_result = build_parity_check_matrix_perfect(H_ours, g, alpha);
    
    if (our_result != 0) {
        printf("❌ Our matrix building failed\n");
        matrix_free(H_ours);
        polynomial_free(g);
        free(alpha);
        free(prg_output);
        return;
    }
    
    // Build matrix with reference method
    printf("\n=== BUILDING WITH REFERENCE METHOD ===\n");
    uint8_t (*ref_mat)[SYS_N/8] = malloc(PK_NROWS * sizeof(*ref_mat));
    reference_matrix_build(ref_mat, ref_f, ref_L);
    
    // Compare matrices
    printf("\n=== COMPARING MATRICES ===\n");
    int differences = 0;
    int max_show = 20;
    
    for (int i = 0; i < PK_NROWS && differences < max_show; i++) {
        for (int j = 0; j < SYS_N && differences < max_show; j++) {
            int our_bit = matrix_get_bit(H_ours, i, j);
            
            // Extract bit from reference matrix
            int byte_idx = j / 8;
            int bit_idx = j % 8;
            int ref_bit = (ref_mat[i][byte_idx] >> bit_idx) & 1;
            
            if (our_bit != ref_bit) {
                printf("  Difference at [%d,%d]: ours=%d, ref=%d\n", i, j, our_bit, ref_bit);
                differences++;
            }
        }
    }
    
    if (differences == 0) {
        printf("✅ Matrices are IDENTICAL!\n");
        printf("Matrix building is correct - the issue must be elsewhere.\n");
    } else {
        printf("❌ Found %d differences (showing max %d)\n", differences, max_show);
        
        // Show first few rows for debugging
        printf("\nFirst 8 bits of first 8 rows:\n");
        printf("Ours: ");
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                printf("%d", matrix_get_bit(H_ours, i, j));
            }
            printf(" ");
        }
        printf("\nRef:  ");
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                int byte_idx = j / 8;
                int bit_idx = j % 8;
                int ref_bit = (ref_mat[i][byte_idx] >> bit_idx) & 1;
                printf("%d", ref_bit);
            }
            printf(" ");
        }
        printf("\n");
    }
    
    // Cleanup
    matrix_free(H_ours);
    free(ref_mat);
    polynomial_free(g);
    free(alpha);
    free(prg_output);
}

int main() {
    compare_matrix_building();
    return 0;
}
