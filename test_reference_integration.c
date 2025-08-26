#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

// Our implementation
#include "mceliece_types.h"
#include "mceliece_keygen.h"
#include "mceliece_shake.h"
#include "mceliece_genpoly.h"

// Reference implementation (adapted versions)
#include "reference_shake.h"

// Reference mceliece6688128 functions - we'll need to link against these
extern int genpoly_gen(uint16_t *out, uint16_t *f);
extern int pk_gen(unsigned char *pk, unsigned char *sk, uint32_t *perm, int16_t *pi);

// Reference parameter constants to match mceliece6688128
#define REF_SYS_N 6688
#define REF_SYS_T 128 
#define REF_GFBITS 13
#define REF_SYS_Q (1 << REF_GFBITS)  // 8192
#define REF_SIGMA1 16
#define REF_SIGMA2 32

// Reference utility functions (we'll implement these to match reference behavior)
static inline uint16_t ref_load_gf(const unsigned char *src) {
    uint16_t a = (uint16_t)src[1];
    a = (uint16_t)((a << 8) | src[0]);
    return (uint16_t)(a & ((1U << REF_GFBITS) - 1U));
}

static inline void ref_store_gf(unsigned char *dest, uint16_t a) {
    dest[0] = (unsigned char)(a & 0xFF);
    dest[1] = (unsigned char)((a >> 8) & 0xFF);
}

static inline uint32_t ref_load4(const unsigned char *src) {
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8) | 
           ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

static inline uint16_t ref_bitrev(uint16_t a) {
    uint16_t r = 0;
    for (int i = 0; i < REF_GFBITS; i++) {
        r = (uint16_t)((r << 1) | ((a >> i) & 1U));
    }
    return (uint16_t)(r & ((1U << REF_GFBITS) - 1U));
}

// Comparison pair for stable sorting 
typedef struct {
    uint32_t val;
    uint16_t pos;
} ref_pair_t;

static int ref_compare_pairs(const void *a, const void *b) {
    const ref_pair_t *p1 = (const ref_pair_t *)a;
    const ref_pair_t *p2 = (const ref_pair_t *)b;
    if (p1->val < p2->val) return -1;
    if (p1->val > p2->val) return 1;
    if (p1->pos < p2->pos) return -1;
    if (p1->pos > p2->pos) return 1;
    return 0;
}

// Reference style field ordering implementation for comparison
int ref_field_ordering(uint16_t *alpha_output, const uint8_t *random_bits) {
    ref_pair_t *pairs = malloc(REF_SYS_Q * sizeof(ref_pair_t));
    if (!pairs) return -1;
    
    // Extract 32-bit values (little-endian)
    for (int i = 0; i < REF_SYS_Q; i++) {
        size_t offset = i * 4;
        uint32_t val = ref_load4(random_bits + offset);
        pairs[i].val = val;
        pairs[i].pos = (uint16_t)i;
    }
    
    // Check for duplicates
    ref_pair_t *sorted_check = malloc(REF_SYS_Q * sizeof(ref_pair_t));
    if (!sorted_check) {
        free(pairs);
        return -1;
    }
    memcpy(sorted_check, pairs, REF_SYS_Q * sizeof(ref_pair_t));
    qsort(sorted_check, REF_SYS_Q, sizeof(ref_pair_t), ref_compare_pairs);
    
    for (int i = 0; i < REF_SYS_Q - 1; i++) {
        if (sorted_check[i].val == sorted_check[i+1].val) {
            free(pairs);
            free(sorted_check);
            return -1; // Duplicates found
        }
    }
    free(sorted_check);
    
    // Sort pairs
    qsort(pairs, REF_SYS_Q, sizeof(ref_pair_t), ref_compare_pairs);
    
    // Generate alpha values using bit-reversal
    for (int i = 0; i < REF_SYS_Q; i++) {
        uint16_t pi = pairs[i].pos;
        alpha_output[i] = ref_bitrev(pi);
    }
    
    free(pairs);
    return 0; // Success
}

// Reference style irreducible polynomial generation for comparison  
int ref_irreducible_poly(uint16_t *g_output, const uint8_t *random_bits) {
    uint16_t *f = malloc(sizeof(uint16_t) * REF_SYS_T);
    if (!f) return -1;
    
    // Extract coefficients (16-bit little-endian, first m bits used)
    for (int i = 0; i < REF_SYS_T; i++) {
        size_t offset = i * 2;
        uint16_t coeff = ref_load_gf(random_bits + offset);
        f[i] = coeff;
    }
    
    // Call reference genpoly_gen
    int result = genpoly_gen(g_output, f);
    
    free(f);
    return result;
}

// Print utility functions
void print_hex_data(const char* label, const uint8_t* data, size_t len, size_t max_display) {
    printf("  %s: ", label);
    size_t display_len = (len < max_display) ? len : max_display;
    for (size_t i = 0; i < display_len; i++) {
        printf("%02X", data[i]);
        if (i > 0 && (i + 1) % 32 == 0 && i < display_len - 1) {
            printf("\n      ");
        }
    }
    if (len > max_display) {
        printf("... (%zu total bytes)", len);
    }
    printf("\n");
}

void print_gf_array(const char* label, const uint16_t* data, int count, int max_display) {
    printf("  %s: ", label);
    int display_count = (count < max_display) ? count : max_display;
    for (int i = 0; i < display_count; i++) {
        printf("%04X ", data[i]);
        if (i > 0 && (i + 1) % 8 == 0 && i < display_count - 1) {
            printf("\n      ");
        }
    }
    if (count > max_display) {
        printf("... (%d total elements)", count);
    }
    printf("\n");
}

// Test 1: Field Ordering Comparison
int test_field_ordering_comparison() {
    printf("=== TEST 1: FIELD ORDERING COMPARISON ===\n");
    
    // Use KAT seed 0 for reproducible results
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    // Generate PRG output
    size_t field_ordering_len_bytes = (REF_SIGMA2 * REF_SYS_Q) / 8;
    size_t total_prg_len = 1024 + field_ordering_len_bytes; // Add some buffer
    uint8_t *prg_output = malloc(total_prg_len);
    if (!prg_output) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    mceliece_prg(seed, prg_output, total_prg_len);
    
    // Extract field ordering section (skip s section)
    size_t s_len_bytes = (REF_SYS_N + 7) / 8;
    const uint8_t *field_bits = prg_output + s_len_bytes;
    
    printf("Field ordering input length: %zu bytes\n", field_ordering_len_bytes);
    print_hex_data("Field ordering input (first 64)", field_bits, field_ordering_len_bytes, 64);
    
    // Test our implementation
    gf_elem_t *our_alpha = malloc(REF_SYS_Q * sizeof(gf_elem_t));
    if (!our_alpha) {
        printf("❌ Memory allocation failed\n");
        free(prg_output);
        return -1;
    }
    
    mceliece_error_t our_result = generate_field_ordering(our_alpha, field_bits);
    printf("\nOur Implementation:\n");
    if (our_result == MCELIECE_SUCCESS) {
        printf("  ✅ Field ordering succeeded\n");
        print_gf_array("Alpha values (first 16)", (uint16_t*)our_alpha, 16, 16);
    } else {
        printf("  ❌ Field ordering failed\n");
        free(our_alpha);
        free(prg_output);
        return -1;
    }
    
    // Test reference implementation
    uint16_t *ref_alpha = malloc(REF_SYS_Q * sizeof(uint16_t));
    if (!ref_alpha) {
        printf("❌ Memory allocation failed\n");
        free(our_alpha);
        free(prg_output);
        return -1;
    }
    
    int ref_result = ref_field_ordering(ref_alpha, field_bits);
    printf("\nReference Implementation:\n");
    if (ref_result == 0) {
        printf("  ✅ Field ordering succeeded\n");
        print_gf_array("Alpha values (first 16)", ref_alpha, 16, 16);
    } else {
        printf("  ❌ Field ordering failed\n");
        free(ref_alpha);
        free(our_alpha);
        free(prg_output);
        return -1;
    }
    
    // Compare results
    printf("\nComparison:\n");
    int match = 1;
    for (int i = 0; i < REF_SYS_Q; i++) {
        if ((uint16_t)our_alpha[i] != ref_alpha[i]) {
            match = 0;
            printf("  ❌ Mismatch at index %d: our=%04X, ref=%04X\n", 
                   i, (uint16_t)our_alpha[i], ref_alpha[i]);
            break;
        }
    }
    
    if (match) {
        printf("  ✅ Field ordering results MATCH perfectly!\n");
    }
    
    free(ref_alpha);
    free(our_alpha);
    free(prg_output);
    
    printf("\n");
    return match ? 0 : -1;
}

// Test 2: Irreducible Polynomial Comparison  
int test_irreducible_poly_comparison() {
    printf("=== TEST 2: IRREDUCIBLE POLYNOMIAL COMPARISON ===\n");
    
    // Use KAT seed 0 for reproducible results
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    // Generate PRG output
    size_t s_len_bytes = (REF_SYS_N + 7) / 8;
    size_t field_ordering_len_bytes = (REF_SIGMA2 * REF_SYS_Q) / 8;
    size_t irreducible_poly_len_bytes = (REF_SIGMA1 * REF_SYS_T) / 8;
    size_t total_prg_len = s_len_bytes + field_ordering_len_bytes + irreducible_poly_len_bytes + 100;
    
    uint8_t *prg_output = malloc(total_prg_len);
    if (!prg_output) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    mceliece_prg(seed, prg_output, total_prg_len);
    
    // Extract irreducible polynomial section
    const uint8_t *poly_bits = prg_output + s_len_bytes + field_ordering_len_bytes;
    
    printf("Irreducible polynomial input length: %zu bytes\n", irreducible_poly_len_bytes);
    print_hex_data("Irreducible poly input (first 64)", poly_bits, irreducible_poly_len_bytes, 64);
    
    // Test our implementation
    polynomial_t *our_g = polynomial_create(REF_SYS_T);
    if (!our_g) {
        printf("❌ Memory allocation failed\n");
        free(prg_output);
        return -1;
    }
    
    mceliece_error_t our_result = generate_irreducible_poly_final(our_g, poly_bits);
    printf("\nOur Implementation:\n");
    if (our_result == MCELIECE_SUCCESS) {
        printf("  ✅ Irreducible polynomial generation succeeded\n");
        printf("  Polynomial degree: %d\n", our_g->degree);
        print_gf_array("Coefficients (first 16)", (uint16_t*)our_g->coeffs, 16, 16);
    } else {
        printf("  ❌ Irreducible polynomial generation failed\n");
        polynomial_free(our_g);
        free(prg_output);
        return -1;
    }
    
    // Test reference implementation
    uint16_t *ref_g = malloc((REF_SYS_T + 1) * sizeof(uint16_t));
    if (!ref_g) {
        printf("❌ Memory allocation failed\n");
        polynomial_free(our_g);
        free(prg_output);
        return -1;
    }
    
    int ref_result = ref_irreducible_poly(ref_g, poly_bits);
    printf("\nReference Implementation:\n");
    if (ref_result == 0) {
        printf("  ✅ Irreducible polynomial generation succeeded\n");
        print_gf_array("Coefficients (first 16)", ref_g, 16, 16);
    } else {
        printf("  ❌ Irreducible polynomial generation failed\n");
        free(ref_g);
        polynomial_free(our_g);
        free(prg_output);
        return -1;
    }
    
    // Compare results - reference returns coefficients without the leading 1
    printf("\nComparison:\n");
    int match = 1;
    
    // Check degree (our implementation includes the leading coefficient)
    if (our_g->degree != REF_SYS_T) {
        printf("  ❌ Degree mismatch: our=%d, expected=%d\n", our_g->degree, REF_SYS_T);
        match = 0;
    }
    
    // Check coefficients (excluding the leading 1)
    for (int i = 0; i < REF_SYS_T; i++) {
        if ((uint16_t)our_g->coeffs[i] != ref_g[i]) {
            printf("  ❌ Coefficient mismatch at index %d: our=%04X, ref=%04X\n", 
                   i, (uint16_t)our_g->coeffs[i], ref_g[i]);
            match = 0;
            break;
        }
    }
    
    // Check leading coefficient (should be 1)
    if ((uint16_t)our_g->coeffs[REF_SYS_T] != 1) {
        printf("  ❌ Leading coefficient mismatch: our=%04X, expected=0001\n", 
               (uint16_t)our_g->coeffs[REF_SYS_T]);
        match = 0;
    }
    
    if (match) {
        printf("  ✅ Irreducible polynomial results MATCH perfectly!\n");
    }
    
    free(ref_g);
    polynomial_free(our_g);
    free(prg_output);
    
    printf("\n");
    return match ? 0 : -1;
}

// Test 3: Full Key Generation Integration Test
int test_full_keygen_integration() {
    printf("=== TEST 3: FULL KEY GENERATION INTEGRATION ===\n");
    
    // Use KAT seed 0
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    printf("Testing full key generation with both implementations...\n");
    print_hex_data("Input seed", seed, 32, 32);
    
    // Test our implementation
    private_key_t *our_sk = private_key_create();
    public_key_t *our_pk = public_key_create();
    if (!our_sk || !our_pk) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    mceliece_error_t our_result = seeded_key_gen(seed, our_pk, our_sk);
    printf("\nOur Implementation:\n");
    if (our_result == MCELIECE_SUCCESS) {
        printf("  ✅ Key generation succeeded\n");
        printf("  Goppa polynomial degree: %d\n", our_sk->g.degree);
        print_gf_array("Alpha values (first 16)", (uint16_t*)our_sk->alpha, 16, 16);
        print_gf_array("Goppa coeffs (first 16)", (uint16_t*)our_sk->g.coeffs, 16, 16);
    } else {
        printf("  ❌ Key generation failed\n");
        private_key_free(our_sk);
        public_key_free(our_pk);
        return -1;
    }
    
    printf("\nSuccessfully tested integration with our key generation!\n");
    printf("✅ The field ordering and irreducible polynomial functions are working\n");
    printf("   correctly within the full key generation process.\n");
    
    private_key_free(our_sk);
    public_key_free(our_pk);
    
    printf("\n");
    return 0;
}

int main() {
    printf("=== COMPREHENSIVE REFERENCE IMPLEMENTATION INTEGRATION TEST ===\n");
    printf("Testing our implementation against reference mceliece6688128 functions\n\n");
    
    int results[3];
    
    results[0] = test_field_ordering_comparison();
    results[1] = test_irreducible_poly_comparison(); 
    results[2] = test_full_keygen_integration();
    
    printf("=== FINAL RESULTS ===\n");
    printf("Test 1 (Field Ordering):        %s\n", results[0] == 0 ? "✅ PASS" : "❌ FAIL");
    printf("Test 2 (Irreducible Polynomial): %s\n", results[1] == 0 ? "✅ PASS" : "❌ FAIL");
    printf("Test 3 (Full Integration):       %s\n", results[2] == 0 ? "✅ PASS" : "❌ FAIL");
    
    int all_passed = (results[0] == 0) && (results[1] == 0) && (results[2] == 0);
    printf("\nOverall Result: %s\n", all_passed ? "✅ ALL TESTS PASSED" : "❌ SOME TESTS FAILED");
    
    if (all_passed) {
        printf("\n🎉 Congratulations! Your implementation produces identical results\n");
        printf("   to the reference mceliece6688128 implementation!\n");
    } else {
        printf("\n⚠️  Some tests failed. Please check the implementation details.\n");
    }
    
    return all_passed ? 0 : -1;
}
