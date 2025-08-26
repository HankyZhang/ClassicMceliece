#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Our implementation
#include "mceliece_types.h"
#include "mceliece_keygen.h"
#include "mceliece_shake.h"
#include "mceliece_genpoly.h"

// Reference implementation
#include "reference_shake.h"
#include "mceliece6688128/gf.h"

// Define namespace to avoid conflicts with our functions
#define CRYPTO_NAMESPACE(x) ref_##x
#include "mceliece6688128/sk_gen.h"
#include "mceliece6688128/pk_gen.h"

// Constants
#define TEST_SYS_N 6688
#define TEST_SYS_T 128
#define TEST_GFBITS 13
#define TEST_SYS_Q (1 << TEST_GFBITS)  // 8192
#define TEST_SIGMA1 16
#define TEST_SIGMA2 32

// Utility functions
static inline uint16_t load_gf_le(const unsigned char *src) {
    return ((uint16_t)src[1] << 8) | src[0];
}

static inline uint32_t load4_le(const unsigned char *src) {
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8) | 
           ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

void print_comparison_header(const char* test_name) {
    printf("\n");
    for(int i = 0; i < 80; i++) printf("=");
    printf("\n");
    printf("%s\n", test_name);
    for(int i = 0; i < 80; i++) printf("=");
    printf("\n");
}

void print_hex_data_compact(const char* label, const uint8_t* data, size_t len, size_t max_show) {
    printf("%-25s: ", label);
    size_t show = (len < max_show) ? len : max_show;
    for (size_t i = 0; i < show; i++) {
        printf("%02X", data[i]);
        if (i > 0 && (i + 1) % 16 == 0 && i < show - 1) printf("\n%27s", "");
    }
    if (len > max_show) printf("... (+%zu bytes)", len - max_show);
    printf("\n");
}

void print_coefficients_comparison(const char* our_label, const char* ref_label, 
                                  const gf_elem_t* our_data, const gf* ref_data, 
                                  int count, int max_show) {
    int show = (count < max_show) ? count : max_show;
    
    printf("\n%-15s vs %-15s (showing %d/%d):\n", our_label, ref_label, show, count);
    printf("Index   Our Impl   Ref Impl   Match\n");
    printf("-----   --------   --------   -----\n");
    
    int matches = 0;
    for (int i = 0; i < show; i++) {
        gf our_val = (gf)our_data[i];
        gf ref_val = ref_data[i];
        int match = (our_val == ref_val);
        matches += match;
        
        printf("%3d     %04X       %04X       %s\n", 
               i, our_val, ref_val, match ? "✓" : "✗");
    }
    
    if (count > max_show) {
        // Check remaining coefficients
        for (int i = max_show; i < count; i++) {
            if ((gf)our_data[i] == ref_data[i]) matches++;
        }
        printf("...     ....       ....       ...\n");
    }
    
    printf("\nSummary: %d/%d coefficients match (%s)\n", 
           matches, count, (matches == count) ? "✅ PERFECT MATCH" : "❌ MISMATCH");
}

void print_alpha_comparison(const char* our_label, const char* ref_label,
                           const gf_elem_t* our_alpha, const gf_elem_t* ref_alpha,
                           int count, int max_show) {
    int show = (count < max_show) ? count : max_show;
    
    printf("\n%-15s vs %-15s (showing %d/%d):\n", our_label, ref_label, show, count);
    printf("Index   Our Alpha  Ref Alpha  Match\n");
    printf("-----   ---------  ---------  -----\n");
    
    int matches = 0;
    for (int i = 0; i < show; i++) {
        gf our_val = (gf)our_alpha[i];
        gf ref_val = (gf)ref_alpha[i];
        int match = (our_val == ref_val);
        matches += match;
        
        printf("%3d     %04X       %04X       %s\n", 
               i, our_val, ref_val, match ? "✓" : "✗");
    }
    
    if (count > max_show) {
        // Check remaining values
        for (int i = max_show; i < count; i++) {
            if ((gf)our_alpha[i] == (gf)ref_alpha[i]) matches++;
        }
        printf("...     ....       ....       ...\n");
    }
    
    printf("\nSummary: %d/%d alpha values match (%s)\n", 
           matches, count, (matches == count) ? "✅ PERFECT MATCH" : "❌ MISMATCH");
}

// Comparison function for field ordering pairs
typedef struct { uint32_t val; uint16_t pos; } pair_t;
int ref_field_cmp(const void *a, const void *b) {
    const pair_t *p1 = (const pair_t *)a;
    const pair_t *p2 = (const pair_t *)b;
    if (p1->val < p2->val) return -1;
    if (p1->val > p2->val) return 1;
    if (p1->pos < p2->pos) return -1;
    if (p1->pos > p2->pos) return 1;
    return 0;
}

int main() {
    printf("DIRECT IMPLEMENTATION COMPARISON TEST\n");
    printf("=====================================\n");
    printf("This test shows exact numerical outputs from both implementations\n");
    printf("when given identical input data.\n");

    // Use KAT seed 0 for reproducible results
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    printf("\nTest Input (KAT Seed 0):\n");
    print_hex_data_compact("Input Seed", seed, 32, 32);

    // Generate PRG output
    size_t s_len_bits = TEST_SYS_N;
    size_t field_ordering_len_bits = TEST_SIGMA2 * TEST_SYS_Q;
    size_t irreducible_poly_len_bits = TEST_SIGMA1 * TEST_SYS_T;
    size_t delta_prime_len_bits = 256;
    size_t total_bits = s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits;
    size_t prg_output_len_bytes = (total_bits + 7) / 8;
    
    uint8_t *prg_output = malloc(prg_output_len_bytes);
    if (!prg_output) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    mceliece_prg(seed, prg_output, prg_output_len_bytes);
    
    size_t s_len_bytes = (s_len_bits + 7) / 8;
    size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8;
    size_t irreducible_poly_len_bytes = (irreducible_poly_len_bits + 7) / 8;
    
    const uint8_t *field_section = prg_output + s_len_bytes;
    const uint8_t *poly_section = prg_output + s_len_bytes + field_ordering_len_bytes;
    
    printf("\nGenerated Data Sections:\n");
    printf("PRG Output Length: %zu bytes\n", prg_output_len_bytes);
    printf("Field Ordering Section: %zu bytes\n", field_ordering_len_bytes);
    printf("Irreducible Poly Section: %zu bytes\n", irreducible_poly_len_bytes);
    
    print_hex_data_compact("Field Section (first 64)", field_section, field_ordering_len_bytes, 64);
    print_hex_data_compact("Poly Section (first 32)", poly_section, irreducible_poly_len_bytes, 32);

    // ==========================================
    // TEST 1: IRREDUCIBLE POLYNOMIAL COMPARISON
    // ==========================================
    print_comparison_header("TEST 1: IRREDUCIBLE POLYNOMIAL GENERATION COMPARISON");
    
    printf("Input: %d coefficients from %zu-byte section\n", TEST_SYS_T, irreducible_poly_len_bytes);
    
    // Show the input f coefficients that both implementations will use
    printf("\nInput f coefficients (first 16):\n");
    printf("Index   16-bit LE   13-bit GF   Hex\n");
    printf("-----   ---------   ---------   ---\n");
    for (int i = 0; i < 16; i++) {
        uint16_t le_val = load_gf_le(poly_section + i * 2);
        uint16_t gf_val = le_val & ((1U << TEST_GFBITS) - 1);
        printf("%3d     %04X        %04X        %04X\n", i, le_val, gf_val, gf_val);
    }
    
    // Reference implementation
    gf *ref_f = malloc(sizeof(gf) * TEST_SYS_T);
    gf *ref_g = malloc(sizeof(gf) * TEST_SYS_T);
    if (!ref_f || !ref_g) {
        printf("❌ Memory allocation failed\n");
        free(prg_output);
        return -1;
    }
    
    // Extract f coefficients for reference
    for (int i = 0; i < TEST_SYS_T; i++) {
        ref_f[i] = load_gf_le(poly_section + i * 2) & ((1U << TEST_GFBITS) - 1);
    }
    
    printf("\nRunning reference genpoly_gen...\n");
    int ref_result = ref_genpoly_gen(ref_g, ref_f);
    printf("Reference result: %s\n", ref_result == 0 ? "✅ SUCCESS" : "❌ FAILED");
    
    if (ref_result == 0) {
        printf("Reference output g coefficients (first 16):\n");
        for (int i = 0; i < 16; i++) {
            printf("g[%2d] = %04X\n", i, ref_g[i]);
        }
    }
    
    // Our implementation
    polynomial_t *our_g = polynomial_create(TEST_SYS_T);
    if (!our_g) {
        printf("❌ Memory allocation failed\n");
        free(ref_f); free(ref_g); free(prg_output);
        return -1;
    }
    
    printf("\nRunning our generate_irreducible_poly_final...\n");
    mceliece_error_t our_result = generate_irreducible_poly_final(our_g, poly_section);
    printf("Our result: %s\n", our_result == MCELIECE_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");
    
    if (our_result == MCELIECE_SUCCESS) {
        printf("Our output g coefficients (first 16):\n");
        for (int i = 0; i < 16; i++) {
            printf("g[%2d] = %04X\n", i, (gf)our_g->coeffs[i]);
        }
        printf("Leading coefficient g[%d] = %04X (should be 0001)\n", 
               TEST_SYS_T, (gf)our_g->coeffs[TEST_SYS_T]);
    }
    
    // Compare polynomial results
    if (ref_result == 0 && our_result == MCELIECE_SUCCESS) {
        print_coefficients_comparison("Our g(x)", "Ref g(x)", 
                                     our_g->coeffs, ref_g, TEST_SYS_T, 32);
    }

    // ===================================
    // TEST 2: FIELD ORDERING COMPARISON  
    // ===================================
    print_comparison_header("TEST 2: FIELD ORDERING GENERATION COMPARISON");
    
    printf("Input: %d 32-bit values from %zu-byte section\n", TEST_SYS_Q, field_ordering_len_bytes);
    
    // Show some input permutation values
    printf("\nInput permutation values (first 16):\n");
    printf("Index   32-bit LE Value   Hex\n");
    printf("-----   ---------------   --------\n");
    for (int i = 0; i < 16; i++) {
        uint32_t val = load4_le(field_section + i * 4);
        printf("%3d     %10u         %08X\n", i, val, val);
    }
    
    // Our implementation
    gf_elem_t *our_alpha = malloc(TEST_SYS_Q * sizeof(gf_elem_t));
    if (!our_alpha) {
        printf("❌ Memory allocation failed\n");
        free(ref_f); free(ref_g); polynomial_free(our_g); free(prg_output);
        return -1;
    }
    
    printf("\nRunning our generate_field_ordering...\n");
    mceliece_error_t field_result = generate_field_ordering(our_alpha, field_section);
    printf("Our result: %s\n", field_result == MCELIECE_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");
    
    if (field_result == MCELIECE_SUCCESS) {
        printf("Our output alpha values (first 16):\n");
        for (int i = 0; i < 16; i++) {
            printf("alpha[%2d] = %04X\n", i, (gf)our_alpha[i]);
        }
    }
    
    // Reference-style field ordering for comparison
    printf("\nRunning reference-style field ordering logic...\n");
    gf_elem_t *ref_alpha = malloc(TEST_SYS_Q * sizeof(gf_elem_t));
    if (!ref_alpha) {
        printf("❌ Memory allocation failed\n");
        free(our_alpha); free(ref_f); free(ref_g); polynomial_free(our_g); free(prg_output);
        return -1;
    }
    
    // Reference field ordering implementation
    pair_t *pairs = malloc(TEST_SYS_Q * sizeof(pair_t));
    if (!pairs) {
        printf("❌ Memory allocation failed\n");
        free(ref_alpha); free(our_alpha); free(ref_f); free(ref_g); polynomial_free(our_g); free(prg_output);
        return -1;
    }
    
    // Extract values and create pairs
    for (int i = 0; i < TEST_SYS_Q; i++) {
        pairs[i].val = load4_le(field_section + i * 4);
        pairs[i].pos = (uint16_t)i;
    }
    
    qsort(pairs, TEST_SYS_Q, sizeof(pair_t), ref_field_cmp);
    
    // Check for duplicates
    int has_duplicates = 0;
    for (int i = 0; i < TEST_SYS_Q - 1; i++) {
        if (pairs[i].val == pairs[i+1].val) {
            has_duplicates = 1;
            break;
        }
    }
    
    if (has_duplicates) {
        printf("❌ Reference field ordering failed - duplicates found\n");
    } else {
        // Generate alpha values using bit-reversal
        for (int i = 0; i < TEST_SYS_Q; i++) {
            uint16_t pi = pairs[i].pos;
            uint16_t bitrev = 0;
            for (int j = 0; j < TEST_GFBITS; j++) {
                bitrev = (uint16_t)((bitrev << 1) | ((pi >> j) & 1U));
            }
            ref_alpha[i] = (gf_elem_t)(bitrev & ((1U << TEST_GFBITS) - 1U));
        }
        
        printf("✅ Reference field ordering succeeded\n");
        printf("Reference output alpha values (first 16):\n");
        for (int i = 0; i < 16; i++) {
            printf("alpha[%2d] = %04X\n", i, (gf)ref_alpha[i]);
        }
        
        // Compare field ordering results
        if (field_result == MCELIECE_SUCCESS) {
            print_alpha_comparison("Our Alpha", "Ref Alpha", 
                                  our_alpha, ref_alpha, TEST_SYS_Q, 32);
        }
    }
    
    // ======================
    // FINAL SUMMARY
    // ======================
    print_comparison_header("FINAL COMPARISON SUMMARY");
    
    int poly_matches = 0;
    int field_matches = 0;
    
    if (ref_result == 0 && our_result == MCELIECE_SUCCESS) {
        for (int i = 0; i < TEST_SYS_T; i++) {
            if ((gf)our_g->coeffs[i] == ref_g[i]) poly_matches++;
        }
        printf("Irreducible Polynomial: %d/%d coefficients match\n", poly_matches, TEST_SYS_T);
        printf("Leading coefficient: %s\n", 
               ((gf)our_g->coeffs[TEST_SYS_T] == 1) ? "✅ Correct (0001)" : "❌ Incorrect");
    }
    
    if (field_result == MCELIECE_SUCCESS && !has_duplicates) {
        for (int i = 0; i < TEST_SYS_Q; i++) {
            if ((gf)our_alpha[i] == (gf)ref_alpha[i]) field_matches++;
        }
        printf("Field Ordering: %d/%d alpha values match\n", field_matches, TEST_SYS_Q);
    }
    
    printf("\n");
    printf("OVERALL RESULT:\n");
    if (poly_matches == TEST_SYS_T && (gf)our_g->coeffs[TEST_SYS_T] == 1 && 
        field_matches == TEST_SYS_Q) {
        printf("🎉 PERFECT MATCH! Your implementation produces identical results!\n");
        printf("   Both irreducible polynomial and field ordering match the reference exactly.\n");
    } else {
        printf("⚠️  DIFFERENCES DETECTED:\n");
        if (poly_matches != TEST_SYS_T || (gf)our_g->coeffs[TEST_SYS_T] != 1) {
            printf("   - Irreducible polynomial differs from reference\n");
        }
        if (field_matches != TEST_SYS_Q) {
            printf("   - Field ordering differs from reference\n");
        }
        printf("   Check the detailed comparison tables above for specific differences.\n");
    }
    
    // Cleanup
    free(pairs);
    free(ref_alpha);
    free(our_alpha);
    free(ref_f);
    free(ref_g);
    polynomial_free(our_g);
    free(prg_output);
    
    return 0;
}
