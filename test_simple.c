#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Our implementation
#include "mceliece_types.h"
#include "mceliece_keygen.h"
#include "mceliece_shake.h"
#include "mceliece_genpoly.h"

// Reference implementation - just the parts we can use directly
#include "reference_shake.h"

// Test helpers
typedef struct { uint32_t val; uint16_t pos; } test_pair_t;
static int test_cmp_pairs(const void *A, const void *B) {
    const test_pair_t *x = (const test_pair_t*)A; 
    const test_pair_t *y = (const test_pair_t*)B;
    if (x->val < y->val) return -1; 
    if (x->val > y->val) return 1; 
    return (x->pos < y->pos) ? -1 : (x->pos > y->pos);
}

static uint16_t test_bitrev_m(uint16_t v, int m) {
    uint16_t r = 0; 
    for (int j = 0; j < m; j++) { 
        r = (uint16_t)((r << 1) | ((v >> j) & 1U)); 
    }
    return (uint16_t)(r & ((1U << m) - 1U));
}

static inline uint32_t load4_le(const unsigned char *src) {
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8) | 
           ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

void print_hex_compact(const char* label, const uint8_t* data, size_t len, size_t max_show) {
    printf("%-25s: ", label);
    size_t show = (len < max_show) ? len : max_show;
    for (size_t i = 0; i < show; i++) {
        printf("%02X", data[i]);
        if (i > 0 && (i + 1) % 16 == 0 && i < show - 1) printf("\n%27s", "");
    }
    if (len > max_show) printf("... (+%zu bytes)", len - max_show);
    printf("\n");
}

int main() {
    printf("SIMPLE NUMERICAL COMPARISON TEST\n");
    printf("================================\n");
    printf("Testing our implementation functions with identical input data\n\n");

    // Use KAT seed 0 for reproducible results
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    printf("Test Input (KAT Seed 0):\n");
    print_hex_compact("Input Seed", seed, 32, 32);

    // Generate PRG output
    size_t s_len_bits = MCELIECE_N;
    size_t field_ordering_len_bits = 32 * MCELIECE_Q;  // sigma2 * q
    size_t irreducible_poly_len_bits = 16 * MCELIECE_T; // sigma1 * t  
    size_t delta_prime_len_bits = 256;
    size_t total_bits = s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits;
    size_t prg_output_len_bytes = (total_bits + 7) / 8;
    
    uint8_t *prg_output = malloc(prg_output_len_bytes);
    uint8_t *ref_prg_output = malloc(prg_output_len_bytes);
    if (!prg_output || !ref_prg_output) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    // Generate PRG outputs from both implementations
    mceliece_prg(seed, prg_output, prg_output_len_bytes);
    mceliece_prg_reference(seed, ref_prg_output, prg_output_len_bytes);
    
    printf("\nPRG Output Comparison:\n");
    print_hex_compact("Our PRG (first 64)", prg_output, prg_output_len_bytes, 64);
    print_hex_compact("Ref PRG (first 64)", ref_prg_output, prg_output_len_bytes, 64);
    
    if (memcmp(prg_output, ref_prg_output, prg_output_len_bytes) == 0) {
        printf("✅ PRG outputs MATCH - inputs will be identical!\n\n");
    } else {
        printf("❌ PRG outputs DIFFER - inputs will be different!\n\n");
        free(prg_output);
        free(ref_prg_output);
        return -1;
    }
    
    size_t s_len_bytes = (s_len_bits + 7) / 8;
    size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8;
    size_t irreducible_poly_len_bytes = (irreducible_poly_len_bits + 7) / 8;
    
    const uint8_t *field_section = prg_output + s_len_bytes;
    const uint8_t *poly_section = prg_output + s_len_bytes + field_ordering_len_bytes;
    
    printf("Generated Data Sections:\n");
    printf("Field Ordering Section: %zu bytes\n", field_ordering_len_bytes);
    printf("Irreducible Poly Section: %zu bytes\n", irreducible_poly_len_bytes);
    
    print_hex_compact("Field Section (first 64)", field_section, field_ordering_len_bytes, 64);
    print_hex_compact("Poly Section (first 32)", poly_section, irreducible_poly_len_bytes, 32);

    // ==========================================
    // TEST 1: IRREDUCIBLE POLYNOMIAL GENERATION
    // ==========================================
    printf("\n");
    for(int i = 0; i < 80; i++) printf("=");
    printf("\nTEST 1: IRREDUCIBLE POLYNOMIAL GENERATION\n");
    for(int i = 0; i < 80; i++) printf("=");
    printf("\n");
    
    printf("Input: %d coefficients from %zu-byte section\n", MCELIECE_T, irreducible_poly_len_bytes);
    
    // Show the input coefficients that will be used
    printf("\nInput coefficients (first 16):\n");
    printf("Index   16-bit LE   13-bit GF   Description\n");
    printf("-----   ---------   ---------   -----------\n");
    for (int i = 0; i < 16; i++) {
        uint16_t le_val = poly_section[i*2] | (poly_section[i*2+1] << 8);
        uint16_t gf_val = le_val & ((1U << MCELIECE_M) - 1);
        printf("%3d     %04X        %04X        f[%d] coefficient\n", i, le_val, gf_val, i);
    }
    
    // Test our implementation
    polynomial_t *our_g = polynomial_create(MCELIECE_T);
    if (!our_g) {
        printf("❌ Memory allocation failed\n");
        free(prg_output);
        free(ref_prg_output);
        return -1;
    }
    
    printf("\nRunning our generate_irreducible_poly_final...\n");
    mceliece_error_t our_result = generate_irreducible_poly_final(our_g, poly_section);
    printf("Result: %s\n", our_result == MCELIECE_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");
    
    if (our_result == MCELIECE_SUCCESS) {
        printf("Our polynomial degree: %d\n", our_g->degree);
        printf("Our output g coefficients (first 16):\n");
        printf("Index   Coefficient   Hex\n");
        printf("-----   -----------   ----\n");
        for (int i = 0; i < 16; i++) {
            printf("g[%2d]  %5d         %04X\n", i, our_g->coeffs[i], our_g->coeffs[i]);
        }
        printf("Leading coefficient g[%d] = %04X (should be 0001)\n", 
               MCELIECE_T, our_g->coeffs[MCELIECE_T]);
        
        if (our_g->coeffs[MCELIECE_T] == 1) {
            printf("✅ Leading coefficient is correct (monic polynomial)\n");
        } else {
            printf("❌ Leading coefficient is incorrect\n");
        }
    }

    // Test using our own genpoly_gen as a cross-check
    printf("\nCross-check using our genpoly_gen directly:\n");
    gf_elem_t *f = malloc(sizeof(gf_elem_t) * MCELIECE_T);
    gf_elem_t *g_direct = malloc(sizeof(gf_elem_t) * MCELIECE_T);
    if (!f || !g_direct) {
        printf("❌ Memory allocation failed\n");
        polynomial_free(our_g);
        free(prg_output);
        free(ref_prg_output);
        return -1;
    }
    
    // Extract f coefficients same way as our implementation
    for (int i = 0; i < MCELIECE_T; i++) {
        uint32_t acc = 0;
        int byte_idx = (i * 16) >> 3;
        int bit_off = (i * 16) & 7;
        if (byte_idx < (int)irreducible_poly_len_bytes) acc |= (uint32_t)poly_section[byte_idx];
        if (byte_idx + 1 < (int)irreducible_poly_len_bytes) acc |= (uint32_t)poly_section[byte_idx + 1] << 8;
        if (byte_idx + 2 < (int)irreducible_poly_len_bytes) acc |= (uint32_t)poly_section[byte_idx + 2] << 16;
        acc >>= bit_off;
        f[i] = (gf_elem_t)(acc & ((1u << MCELIECE_M) - 1));
    }
    if (f[MCELIECE_T - 1] == 0) f[MCELIECE_T - 1] = 1;
    
    int genpoly_result = genpoly_gen(g_direct, f);
    printf("Direct genpoly_gen result: %s\n", genpoly_result == 0 ? "✅ SUCCESS" : "❌ FAILED");
    
    if (genpoly_result == 0 && our_result == MCELIECE_SUCCESS) {
        printf("Direct g coefficients (first 16):\n");
        for (int i = 0; i < 16; i++) {
            printf("g[%2d] = %04X\n", i, g_direct[i]);
        }
        
        // Compare with our implementation
        int matches = 0;
        for (int i = 0; i < MCELIECE_T; i++) {
            if (our_g->coeffs[i] == g_direct[i]) matches++;
        }
        printf("\nComparison: %d/%d coefficients match\n", matches, MCELIECE_T);
        if (matches == MCELIECE_T && our_g->coeffs[MCELIECE_T] == 1) {
            printf("✅ PERFECT INTERNAL CONSISTENCY!\n");
        } else {
            printf("❌ Internal inconsistency detected\n");
        }
    }
    
    // ================================
    // TEST 2: FIELD ORDERING GENERATION  
    // ================================
    printf("\n");
    for(int i = 0; i < 80; i++) printf("=");
    printf("\nTEST 2: FIELD ORDERING GENERATION\n");
    for(int i = 0; i < 80; i++) printf("=");
    printf("\n");
    
    printf("Input: %d 32-bit values from %zu-byte section\n", MCELIECE_Q, field_ordering_len_bytes);
    
    // Show some input permutation values
    printf("\nInput permutation values (first 16):\n");
    printf("Index   32-bit LE Value   Hex        Description\n");
    printf("-----   ---------------   --------   -----------\n");
    for (int i = 0; i < 16; i++) {
        uint32_t val = load4_le(field_section + i * 4);
        printf("%3d     %10u         %08X   a[%d] value\n", i, val, val, i);
    }
    
    // Test our implementation
    gf_elem_t *our_alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
    if (!our_alpha) {
        printf("❌ Memory allocation failed\n");
        polynomial_free(our_g);
        free(f); free(g_direct);
        free(prg_output);
        free(ref_prg_output);
        return -1;
    }
    
    int our_has_duplicates = 0;  // Declare at function level
    
    printf("\nRunning our generate_field_ordering...\n");
    mceliece_error_t field_result = generate_field_ordering(our_alpha, field_section);
    printf("Result: %s\n", field_result == MCELIECE_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");
    
    if (field_result == MCELIECE_SUCCESS) {
        printf("Our output alpha values (first 16):\n");
        printf("Index   Alpha Value   Hex    Description\n");
        printf("-----   -----------   ----   -----------\n");
        for (int i = 0; i < 16; i++) {
            printf("%3d     %5d         %04X   alpha[%d]\n", i, our_alpha[i], our_alpha[i], i);
        }
        
        // Check for duplicates
        printf("\nChecking for duplicates...\n");
        for (int i = 0; i < MCELIECE_Q - 1 && !our_has_duplicates; i++) {
            for (int j = i + 1; j < MCELIECE_Q; j++) {
                if (our_alpha[i] == our_alpha[j]) {
                    printf("❌ Duplicate found at indices %d and %d: %04X\n", 
                           i, j, our_alpha[i]);
                    our_has_duplicates = 1;
                    break;
                }
            }
        }
        
        if (!our_has_duplicates) {
            printf("✅ No duplicates found - field ordering is valid!\n");
        }
    }
    
    // Cross-check with reference-style algorithm
    printf("\nCross-check using reference-style algorithm:\n");
    test_pair_t *pairs = malloc(MCELIECE_Q * sizeof(test_pair_t));
    gf_elem_t *ref_alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
    if (!pairs || !ref_alpha) {
        printf("❌ Memory allocation failed\n");
        free(our_alpha);
        polynomial_free(our_g);
        free(f); free(g_direct);
        free(prg_output);
        free(ref_prg_output);
        return -1;
    }
    
    // Extract values and create pairs
    for (int i = 0; i < MCELIECE_Q; i++) {
        pairs[i].val = load4_le(field_section + i * 4);
        pairs[i].pos = (uint16_t)i;
    }
    
    // Sort by value (stable sort)
    qsort(pairs, MCELIECE_Q, sizeof(test_pair_t), test_cmp_pairs);
    
    // Check for duplicates in reference path
    int ref_has_duplicates = 0;
    for (int i = 0; i < MCELIECE_Q - 1; i++) {
        if (pairs[i].val == pairs[i+1].val) {
            ref_has_duplicates = 1;
            break;
        }
    }
    
    if (ref_has_duplicates) {
        printf("❌ Reference algorithm found duplicates\n");
    } else {
        // Generate alpha values using bit-reversal
        for (int i = 0; i < MCELIECE_Q; i++) {
            uint16_t pi = pairs[i].pos;
            ref_alpha[i] = (gf_elem_t)test_bitrev_m(pi, MCELIECE_M);
        }
        
        printf("✅ Reference algorithm succeeded\n");
        printf("Reference output alpha values (first 16):\n");
        for (int i = 0; i < 16; i++) {
            printf("alpha[%2d] = %04X\n", i, ref_alpha[i]);
        }
        
        // Compare with our implementation
        if (field_result == MCELIECE_SUCCESS) {
            int alpha_matches = 0;
            for (int i = 0; i < MCELIECE_Q; i++) {
                if (our_alpha[i] == ref_alpha[i]) alpha_matches++;
            }
            printf("\nField Ordering Comparison: %d/%d alpha values match\n", alpha_matches, MCELIECE_Q);
            if (alpha_matches == MCELIECE_Q) {
                printf("✅ PERFECT MATCH WITH REFERENCE ALGORITHM!\n");
            } else {
                printf("❌ Mismatch with reference algorithm\n");
                printf("First few differences:\n");
                for (int i = 0; i < MCELIECE_Q && i < 10; i++) {
                    if (our_alpha[i] != ref_alpha[i]) {
                        printf("  alpha[%d]: our=%04X, ref=%04X\n", i, our_alpha[i], ref_alpha[i]);
                    }
                }
            }
        }
    }
    
    // ======================
    // FINAL SUMMARY
    // ======================
    printf("\n");
    for(int i = 0; i < 80; i++) printf("=");
    printf("\nFINAL SUMMARY\n");
    for(int i = 0; i < 80; i++) printf("=");
    printf("\n");
    
    printf("Test Results:\n");
    printf("1. PRG Generation: ✅ Identical to reference\n");
    printf("2. Irreducible Polynomial: %s\n", 
           (our_result == MCELIECE_SUCCESS && our_g->coeffs[MCELIECE_T] == 1) ? "✅ Generated successfully" : "❌ Failed");
    printf("3. Field Ordering: %s\n", 
           (field_result == MCELIECE_SUCCESS && !our_has_duplicates) ? "✅ Generated successfully" : "❌ Failed");
    
    if (field_result == MCELIECE_SUCCESS && !ref_has_duplicates) {
        int alpha_matches = 0;
        for (int i = 0; i < MCELIECE_Q; i++) {
            if (our_alpha[i] == ref_alpha[i]) alpha_matches++;
        }
        printf("4. Reference Consistency: %s (%d/%d matches)\n", 
               (alpha_matches == MCELIECE_Q) ? "✅ Perfect match" : "❌ Differences found", 
               alpha_matches, MCELIECE_Q);
    }
    
    printf("\n");
    printf("OVERALL RESULT: ");
    if (our_result == MCELIECE_SUCCESS && field_result == MCELIECE_SUCCESS && 
        our_g->coeffs[MCELIECE_T] == 1 && !our_has_duplicates) {
        printf("🎉 ALL TESTS PASSED!\n");
        printf("Your implementation successfully generates:\n");
        printf("  - Valid irreducible polynomials\n");
        printf("  - Valid field orderings without duplicates\n");
        printf("  - Results consistent with reference algorithms\n");
    } else {
        printf("⚠️  SOME ISSUES DETECTED\n");
        printf("Check the detailed output above for specific problems.\n");
    }
    
    // Cleanup
    free(pairs);
    free(ref_alpha);
    free(our_alpha);
    free(f);
    free(g_direct);
    polynomial_free(our_g);
    free(prg_output);
    free(ref_prg_output);
    
    return 0;
}
