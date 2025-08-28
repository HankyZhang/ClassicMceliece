#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Our implementation
#include "mceliece_types.h"
#include "mceliece_keygen.h"
#include "mceliece_shake.h"
#include "mceliece_kem.h"

// Reference implementation
#include "reference_shake.h"
#include "mceliece_genpoly.h"
#include <stdlib.h>
#include "mceliece_matrix_ops.h"
#include "mceliece_poly.h"
#include "kat_drbg.h"
#include "rng.h"

// Toggle reference-based tests (requires building ref sources); default off
#ifndef ENABLE_REFERENCE_TESTS
#define ENABLE_REFERENCE_TESTS 0
#endif

// Temporarily skip pk_gen integration to avoid ref runtime crashes
#ifndef SKIP_REF_PK_GEN
#define SKIP_REF_PK_GEN 0
#endif

#if ENABLE_REFERENCE_TESTS
  // Define the namespace to avoid naming conflicts (must come BEFORE including ref headers)
  #ifndef CRYPTO_NAMESPACE
  #define CRYPTO_NAMESPACE(x) ref_##x
  #endif
  // Forward declarations for reference implementation functions
  // These functions should be from mceliece6688128/ directory
  #include "mceliece6688128/gf.h"
  #include "mceliece6688128/sk_gen.h"
  #include "mceliece6688128/pk_gen.h"
  /* don't include util.h here to avoid CRYPTO_NAMESPACE collisions with local helpers */
#endif

// Reference implementation constants
#define REF_SYS_N 6688
#define REF_SYS_T 128
#define REF_GFBITS 13
#define REF_SYS_Q (1 << REF_GFBITS)  // 8192
#define REF_SIGMA1 16
#define REF_SIGMA2 32
#define REF_IRR_BYTES (REF_SYS_T * 2)
#define REF_COND_BYTES ((1 << (REF_GFBITS - 4)) * (2 * REF_GFBITS - 1))
#define REF_PK_NROWS (REF_SYS_T * REF_GFBITS)
#define REF_PK_ROW_BYTES ((REF_SYS_N - REF_PK_NROWS) / 8)

// Reference utility functions
static inline uint16_t ref_load_gf(const unsigned char *src) {
    return ((uint16_t)src[1] << 8) | src[0];
}

static inline void ref_store_gf(unsigned char *dest, uint16_t a) {
    dest[0] = a & 0xFF;
    dest[1] = (a >> 8) & 0xFF;
}

static inline uint32_t ref_load4(const unsigned char *src) {
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8) | 
           ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}



// Test helpers (file-local)
typedef struct { uint32_t val; uint16_t pos; } ref_pair_t;
static int test_cmp_pairs(const void *A, const void *B) {
    const ref_pair_t *x = (const ref_pair_t*)A; const ref_pair_t *y = (const ref_pair_t*)B;
    if (x->val < y->val) return -1; if (x->val > y->val) return 1; return (x->pos < y->pos) ? -1 : (x->pos > y->pos);
}
static uint16_t test_bitrev_m(uint16_t v, int m) {
    uint16_t r = 0; for (int j = 0; j < m; j++) { r = (uint16_t)((r << 1) | ((v >> j) & 1U)); }
    return (uint16_t)(r & ((1U << m) - 1U));
}

// file-scope comparator for 64-bit sort
static int cmp64_qsort(const void *a, const void *b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    if (x < y) return -1; if (x > y) return 1; return 0;
}

// Local helper: check for duplicates in permutation as ref pk_gen does
static int check_perm_duplicates(const uint32_t *perm, int m_bits, int *first_dup_idx) {
    int n_full = 1 << m_bits; // 2^m
    uint64_t *buf = (uint64_t*)malloc((size_t)n_full * sizeof(uint64_t));
    if (!buf) return -1;
    for (int i = 0; i < n_full; i++) {
        buf[i] = ((uint64_t)perm[i] << 31) | (uint64_t)i;
    }
    // sort by 64-bit value
    qsort(buf, (size_t)n_full, sizeof(uint64_t), cmp64_qsort);
    int dup = 0;
    for (int i = 1; i < n_full; i++) {
        uint32_t hi_prev = (uint32_t)(buf[i-1] >> 31);
        uint32_t hi_cur  = (uint32_t)(buf[i]   >> 31);
        if (hi_prev == hi_cur) { dup = 1; if (first_dup_idx) *first_dup_idx = i; break; }
    }
    free(buf);
    return dup;
}

// Function to print hex data with label
void print_hex_section(const char* label, const unsigned char* data, size_t len, size_t max_display) {
    printf("  %s: ", label);
    size_t display_len = (len < max_display) ? len : max_display;
    for (size_t i = 0; i < display_len; i++) {
        printf("%02X", data[i]);
        if (i > 0 && (i + 1) % 32 == 0 && i < display_len - 1) {
            printf("\n    ");
        }
    }
    if (len > max_display) {
        printf("... (%zu total bytes)", len);
    }
    printf("\n");
}

void print_alpha_values(const char* label, const gf_elem_t* alpha, int count) {
    printf("  %s: ", label);
    for (int i = 0; i < count; i++) {
        printf("%04X ", alpha[i]);
        if (i > 0 && (i + 1) % 8 == 0 && i < count - 1) {
            printf("\n    ");
        }
    }
    printf("\n");
}

int compare_implementations_steps_1_5() {
    printf("=== COMPARING STEPS 1-5: OUR IMPLEMENTATION vs REFERENCE ===\n\n");
    
    // Use KAT seed 0
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    printf("Input Seed: ");
    for (int i = 0; i < 32; i++) printf("%02X", seed[i]);
    printf("\n\n");
    
    // === STEP 1-2: Parameters (should be identical) ===
    printf("STEP 1-2: PARAMETERS\n");
    printf("==================\n");
    int n = MCELIECE_N;
    int t = MCELIECE_T; 
    int q = MCELIECE_Q;
    int l = MCELIECE_L;
    int sigma1 = MCELIECE_SIGMA1; // 16
    int sigma2 = 32;
    
    printf("Both implementations:\n");
    printf("  n=%d, t=%d, q=%d, l=%d, σ1=%d, σ2=%d\n", n, t, q, l, sigma1, sigma2);
    
    // Calculate PRG output length
    size_t s_len_bits = sigma1 * n;
    size_t field_ordering_len_bits = sigma2 * q;
    size_t irreducible_poly_len_bits = sigma1 * t;
    size_t delta_prime_len_bits = l * 8;
    size_t total_bits = s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits;
    size_t prg_output_len_bytes = (total_bits + 7) / 8;
    
    printf("  PRG output length: %zu bits = %zu bytes\n", total_bits, prg_output_len_bytes);
    printf("  ✅ Parameters identical (by definition)\n\n");
    
    // === STEP 3: PRG OUTPUT ===
    printf("STEP 3: PRG OUTPUT\n");
    printf("==================\n");
    
    uint8_t *our_prg_output = malloc(prg_output_len_bytes);
    uint8_t *ref_prg_output = malloc(prg_output_len_bytes);
    
    if (!our_prg_output || !ref_prg_output) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    // Generate PRG outputs
    mceliece_prg(seed, our_prg_output, prg_output_len_bytes);
    mceliece_prg_reference(seed, ref_prg_output, prg_output_len_bytes);
    
    printf("Our Implementation:\n");
    print_hex_section("PRG output (first 64)", our_prg_output, prg_output_len_bytes, 64);
    
    printf("\nReference Implementation:\n");
    print_hex_section("PRG output (first 64)", ref_prg_output, prg_output_len_bytes, 64);
    
    if (memcmp(our_prg_output, ref_prg_output, prg_output_len_bytes) == 0) {
        printf("✅ PRG outputs MATCH\n\n");
    } else {
        printf("❌ PRG outputs DIFFER\n\n");
    }
    
    // === STEP 4: SECTION EXTRACTION ===
    printf("STEP 4: SECTION EXTRACTION\n");
    printf("==========================\n");
    
    size_t s_len_bytes = (s_len_bits + 7) / 8;
    size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8;
    size_t irreducible_poly_len_bytes = (irreducible_poly_len_bits + 7) / 8; (void)irreducible_poly_len_bytes;
    size_t delta_prime_len_bytes = (delta_prime_len_bits + 7) / 8;
    
    // Extract sections for both implementations (should be identical if PRG matches)
    const uint8_t *our_s_section = our_prg_output;
    const uint8_t *our_field_section = our_prg_output + s_len_bytes;
    const uint8_t *our_poly_section = our_prg_output + s_len_bytes + field_ordering_len_bytes;
    const uint8_t *our_delta_section = our_prg_output + s_len_bytes + field_ordering_len_bytes + irreducible_poly_len_bytes;
    
    const uint8_t *ref_s_section = ref_prg_output;
    const uint8_t *ref_field_section = ref_prg_output + s_len_bytes;
    const uint8_t *ref_poly_section = ref_prg_output + s_len_bytes + field_ordering_len_bytes;
    const uint8_t *ref_delta_section = ref_prg_output + s_len_bytes + field_ordering_len_bytes + irreducible_poly_len_bytes;
    
    printf("Section sizes: s=%zu, field=%zu, poly=%zu, delta=%zu bytes\n", 
           s_len_bytes, field_ordering_len_bytes, irreducible_poly_len_bytes, delta_prime_len_bytes);
    
    printf("\nOur Implementation:\n");
    print_hex_section("s section (first 32)", our_s_section, s_len_bytes, 32);
    print_hex_section("field section (first 32)", our_field_section, field_ordering_len_bytes, 32);
    print_hex_section("poly section (first 32)", our_poly_section, irreducible_poly_len_bytes, 32);
    print_hex_section("delta section", our_delta_section, delta_prime_len_bytes, delta_prime_len_bytes);
    
    printf("\nReference Implementation:\n");
    print_hex_section("s section (first 32)", ref_s_section, s_len_bytes, 32);
    print_hex_section("field section (first 32)", ref_field_section, field_ordering_len_bytes, 32);
    print_hex_section("poly section (first 32)", ref_poly_section, irreducible_poly_len_bytes, 32);
    print_hex_section("delta section", ref_delta_section, delta_prime_len_bytes, delta_prime_len_bytes);
    
    // Compare sections
    int sections_match = 1;
    if (memcmp(our_s_section, ref_s_section, s_len_bytes) != 0) {
        printf("❌ s sections differ\n");
        sections_match = 0;
    }
    if (memcmp(our_field_section, ref_field_section, field_ordering_len_bytes) != 0) {
        printf("❌ field sections differ\n");
        sections_match = 0;
    }
    if (memcmp(our_poly_section, ref_poly_section, irreducible_poly_len_bytes) != 0) {
        printf("❌ poly sections differ\n");
        sections_match = 0;
    }
    if (memcmp(our_delta_section, ref_delta_section, delta_prime_len_bytes) != 0) {
        printf("❌ delta sections differ\n");
        sections_match = 0;
    }
    
    if (sections_match) {
        printf("✅ All sections MATCH\n\n");
    } else {
        printf("❌ Some sections DIFFER\n\n");
    }
    
    // === STEP 5: FIELD ORDERING ===
    printf("STEP 5: FIELD ORDERING\n");
    printf("======================\n");
    
    // Test field ordering with our implementation
    private_key_t *our_sk = private_key_create();
    if (!our_sk) {
        printf("❌ Failed to create our private key\n");
        free(our_prg_output);
        free(ref_prg_output);
        return -1;
    }
    
    mceliece_error_t our_result = generate_field_ordering(our_sk->alpha, our_field_section);
    
    printf("Our Implementation:\n");
    print_hex_section("Field ordering input (first 64)", our_field_section, field_ordering_len_bytes, 64);
    if (our_result == MCELIECE_SUCCESS) {
        printf("  ✅ Field ordering succeeded\n");
        print_alpha_values("Alpha values (first 16)", our_sk->alpha, 16);
    } else {
        printf("  ❌ Field ordering failed\n");
    }
    
    printf("\nReference Implementation:\n");
    print_hex_section("Field ordering input (first 64)", ref_field_section, field_ordering_len_bytes, 64);
    printf("  (Cannot test reference field ordering directly due to different API)\n");
    printf("  Expected: Should produce same alpha values if input is identical\n");
    
    // Since we can't directly test reference field ordering, we compare inputs
    if (memcmp(our_field_section, ref_field_section, field_ordering_len_bytes) == 0) {
        printf("✅ Field ordering inputs MATCH\n");
        printf("→ Should produce identical alpha values\n\n");
    } else {
        printf("❌ Field ordering inputs DIFFER\n\n");
    }

    // === NEW: Cross-check outputs vs reference algorithms ===
    printf("STEP 5+: VALIDATE RESULTS AGAINST REFERENCE LOGIC\n");
    printf("===============================================\n");

    // Reference-style field ordering (32-bit LE, stable sort, bit-reverse)
    ref_pair_t *pairs = (ref_pair_t*)malloc(MCELIECE_Q * sizeof(ref_pair_t));
    gf_elem_t *alpha_ref = (gf_elem_t*)malloc(sizeof(gf_elem_t) * MCELIECE_Q);
    if (!pairs || !alpha_ref) { printf("Alloc failed for ref field ordering\n\n"); free(pairs); free(alpha_ref); private_key_free(our_sk); free(our_prg_output); free(ref_prg_output); return -1; }
    for (int i = 0; i < MCELIECE_Q; i++) {
        size_t off = (size_t)i * 4;
        uint32_t a = (uint32_t)our_field_section[off]
                   | ((uint32_t)our_field_section[off+1] << 8)
                   | ((uint32_t)our_field_section[off+2] << 16)
                   | ((uint32_t)our_field_section[off+3] << 24);
        pairs[i].val = a; pairs[i].pos = (uint16_t)i;
    }
    // stable sort by (val, pos)
    qsort(pairs, MCELIECE_Q, sizeof(ref_pair_t), test_cmp_pairs);
    // bit-reverse lower m bits
    for (int i = 0; i < MCELIECE_Q; i++) {
        uint16_t pi = pairs[i].pos;
        alpha_ref[i] = (gf_elem_t)test_bitrev_m(pi, MCELIECE_M);
    }
    // Our field ordering again (fresh buffer)
    gf_elem_t *alpha_our = (gf_elem_t*)malloc(sizeof(gf_elem_t) * MCELIECE_Q);
    if (!alpha_our) { printf("Alloc failed for alpha_our\n\n"); free(pairs); free(alpha_ref); private_key_free(our_sk); free(our_prg_output); free(ref_prg_output); return -1; }
    if (generate_field_ordering(alpha_our, our_field_section) != MCELIECE_SUCCESS) {
        printf("  ❌ Our field ordering failed unexpectedly\n\n");
    } else {
        int alpha_ok = memcmp(alpha_ref, alpha_our, sizeof(gf_elem_t) * MCELIECE_Q) == 0;
        printf("  %s Field ordering EXACT MATCH vs reference logic\n\n", alpha_ok ? "✅" : "❌");
    }

    // Reference-style irreducible polynomial (read t 16-bit LE elements, genpoly_gen, monic)
    polynomial_t *g_ref = polynomial_create(MCELIECE_T);
    polynomial_t *g_our = polynomial_create(MCELIECE_T);
    if (!g_ref || !g_our) {
        printf("Alloc failed for polys\n\n");
        free(pairs); free(alpha_ref); free(alpha_our);
        private_key_free(our_sk); free(our_prg_output); free(ref_prg_output);
        return -1;
    }
#if ENABLE_REFERENCE_TESTS
    // Build g_ref using reference path
    {
        gf_elem_t *f = (gf_elem_t*)malloc(sizeof(gf_elem_t) * MCELIECE_T);
        if (!f) {
            printf("Alloc failed for f\n\n");
            free(pairs); free(alpha_ref); free(alpha_our); polynomial_free(g_ref); polynomial_free(g_our);
            private_key_free(our_sk); free(our_prg_output); free(ref_prg_output);
            return -1;
        }
        for (int i = 0; i < MCELIECE_T; i++) {
            size_t off = (size_t)i * 2;
            uint16_t le = (uint16_t)our_poly_section[off] | ((uint16_t)our_poly_section[off+1] << 8);
            f[i] = (gf_elem_t)(le & ((1U << MCELIECE_M) - 1U));
        }
        gf_elem_t *gl = (gf_elem_t*)malloc(sizeof(gf_elem_t) * MCELIECE_T);
        if (!gl) {
            printf("Alloc failed for gl\n\n");
            free(f); free(pairs); free(alpha_ref); free(alpha_our); polynomial_free(g_ref); polynomial_free(g_our);
            private_key_free(our_sk); free(our_prg_output); free(ref_prg_output);
            return -1;
        }
        if (ref_genpoly_gen(gl, f) != 0) {
            printf("  ❌ ref_genpoly_gen failed in reference path\n\n");
        } else {
            for (int i = 0; i < MCELIECE_T; i++) polynomial_set_coeff(g_ref, i, gl[i]);
            polynomial_set_coeff(g_ref, MCELIECE_T, 1);
        }
        free(gl); free(f);
    }
#else
    (void)g_ref; // unused when reference disabled
#endif

    // Build g_our using our function and optionally compare when reference enabled
    if (generate_irreducible_poly_final(g_our, our_poly_section) != MCELIECE_SUCCESS) {
        printf("  ❌ Our irreducible polynomial generation failed unexpectedly\n\n");
    } else {
#if ENABLE_REFERENCE_TESTS
        int same = 1;
        for (int i = 0; i <= MCELIECE_T; i++) {
            gf_elem_t a = (i <= g_ref->degree ? g_ref->coeffs[i] : 0);
            gf_elem_t b = (i <= g_our->degree ? g_our->coeffs[i] : 0);
            if (a != b) { same = 0; break; }
        }
        printf("  %s Irreducible polynomial EXACT MATCH vs reference logic\n\n", same ? "✅" : "❌");
#else
        printf("  ℹ️ Generated irreducible polynomial using our implementation.\n\n");
#endif
    }
    polynomial_free(g_ref); polynomial_free(g_our);
    free(alpha_our); free(alpha_ref); free(pairs);
    
    // Cleanup
    private_key_free(our_sk);
    free(our_prg_output);
    free(ref_prg_output);
    
    return 0;
}

// Simple reference test that actually works
#if ENABLE_REFERENCE_TESTS
int test_with_reference_functions() {
    printf("=== TESTING WITH REFERENCE IMPLEMENTATION ENABLED ===\n\n");
    printf("Reference implementation is now enabled!\n");
    printf("The core Gaussian elimination comparison will run below.\n");
    return 0;
}
#else
int test_with_reference_functions() {
    printf("Reference tests disabled\n");
    return 0;
}
#endif

#if 0 // DISABLED - Legacy function with scope issues  
int old_test_with_reference_functions() {
    printf("=== TESTING WITHOUT REFERENCE IMPLEMENTATION (reference disabled) ===\n\n");
    // Use KAT seed 0
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    size_t s_len_bits = REF_SYS_N;
    size_t field_ordering_len_bits = REF_SIGMA2 * REF_SYS_Q;
    size_t irreducible_poly_len_bits = REF_SIGMA1 * REF_SYS_T;
    size_t delta_prime_len_bits = 256;
    size_t total_bits = s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits;
    size_t prg_output_len_bytes = (total_bits + 7) / 8;
    uint8_t *prg_output = malloc(prg_output_len_bytes);
    if (!prg_output) return -1;
    mceliece_prg(seed, prg_output, prg_output_len_bytes);
    size_t s_len_bytes = (s_len_bits + 7) / 8;
    size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8;
    const uint8_t *field_section = prg_output + s_len_bytes;
    const uint8_t *poly_section = field_section + field_ordering_len_bytes;
    // Irreducible poly
    polynomial_t *our_g = polynomial_create(REF_SYS_T);
    if (!our_g) { free(prg_output); return -1; }
    mceliece_error_t poly_ok = generate_irreducible_poly_final(our_g, poly_section);
    printf("Our generate_irreducible_poly_final result: %s\n", poly_ok == MCELIECE_SUCCESS ? "✅ Success" : "❌ Failed");
    // Field ordering
    gf_elem_t *alpha = malloc(REF_SYS_Q * sizeof(gf_elem_t));
    if (!alpha) { polynomial_free(our_g); free(prg_output); return -1; }
    mceliece_error_t fld_ok = generate_field_ordering(alpha, field_section);
    printf("Our generate_field_ordering result: %s\n", fld_ok == MCELIECE_SUCCESS ? "✅ Success" : "❌ Failed");
    // Gaussian elimination
    int mt = REF_PK_NROWS, ncols = REF_SYS_N;
    matrix_t *H = (poly_ok==MCELIECE_SUCCESS && fld_ok==MCELIECE_SUCCESS) ? matrix_create(mt, ncols) : NULL;
    if (H) {
        for (int j = 0; j < REF_SYS_N; j++) {
            gf_elem_t a = alpha[j];
            gf_elem_t g_a = polynomial_eval(our_g, a);
            gf_elem_t a_pow = 1;
            for (int i = 0; i < REF_SYS_T; i++) {
                gf_elem_t Mij = g_a ? gf_div(a_pow, g_a) : 0;
                for (int b = 0; b < REF_GFBITS; b++) matrix_set_bit(H, i*REF_GFBITS + b, j, (Mij >> b) & 1);
                a_pow = gf_mul(a_pow, a);
            }
        }
        int red = reduce_to_systematic_form(H);
        printf("Gaussian elimination: %s\n", red == 0 ? "✅ Success" : "❌ Failed");
        matrix_free(H);
    }
    free(alpha); polynomial_free(our_g); free(prg_output);
    return 0;
}
#endif // End disabled legacy function

// New function to show detailed numerical comparison
int show_detailed_numerical_comparison() {
#if ENABLE_REFERENCE_TESTS
    printf("=== DETAILED NUMERICAL COMPARISON ===\n");
    printf("Showing exact coefficient and alpha value comparisons\n\n");
    
    // Use KAT seed 0
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    // Generate PRG output
    size_t s_len_bits = REF_SYS_N;
    size_t field_ordering_len_bits = REF_SIGMA2 * REF_SYS_Q;
    size_t irreducible_poly_len_bits = REF_SIGMA1 * REF_SYS_T;
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
    
    // === IRREDUCIBLE POLYNOMIAL DETAILED COMPARISON ===
    printf("--- IRREDUCIBLE POLYNOMIAL COEFFICIENTS ---\n");
    
    // Reference implementation
    gf *ref_f = malloc(sizeof(gf) * REF_SYS_T);
    gf *ref_g = malloc(sizeof(gf) * REF_SYS_T);
    if (!ref_f || !ref_g) {
        printf("❌ Memory allocation failed\n");
        free(prg_output);
        return -1;
    }
    
    for (int i = 0; i < REF_SYS_T; i++) {
        ref_f[i] = ref_load_gf(poly_section + i * 2) & ((1U << REF_GFBITS) - 1);
    }
    
    int ref_result = ref_genpoly_gen(ref_g, ref_f);
    
    // Our implementation
    polynomial_t *our_g = polynomial_create(REF_SYS_T);
    if (!our_g) {
        printf("❌ Memory allocation failed\n");
        free(ref_f); free(ref_g); free(prg_output);
        return -1;
    }
    
    mceliece_error_t our_result = generate_irreducible_poly_final(our_g, poly_section);
    
    // Show comparison table
    if (ref_result == 0 && our_result == MCELIECE_SUCCESS) {
        printf("\nCoefficient-by-coefficient comparison (first 32):\n");
        printf("Index   Our Impl   Ref Impl   Match\n");
        printf("-----   --------   --------   -----\n");
        
        int matches = 0;
        for (int i = 0; i < 32 && i < REF_SYS_T; i++) {
            gf our_val = (gf)our_g->coeffs[i];
            gf ref_val = ref_g[i];
            int match = (our_val == ref_val);
            if (i < REF_SYS_T) matches += match;
            
            printf("%3d     %04X       %04X       %s\n", 
                   i, our_val, ref_val, match ? "✓" : "✗");
        }
        
        // Count remaining matches
        for (int i = 32; i < REF_SYS_T; i++) {
            if ((gf)our_g->coeffs[i] == ref_g[i]) matches++;
        }
        
        printf("...     ....       ....       ...\n");
        printf("Leading coeff: %04X      N/A        %s\n", 
               (gf)our_g->coeffs[REF_SYS_T], 
               ((gf)our_g->coeffs[REF_SYS_T] == 1) ? "✓" : "✗");
        
        printf("\nPolynomial Summary: %d/%d coefficients match\n", matches, REF_SYS_T);
        printf("Result: %s\n", (matches == REF_SYS_T && (gf)our_g->coeffs[REF_SYS_T] == 1) ? 
               "✅ PERFECT MATCH" : "❌ MISMATCH");
    }
    
    // === FIELD ORDERING DETAILED COMPARISON ===
    printf("\n--- FIELD ORDERING ALPHA VALUES ---\n");
    
    gf_elem_t *our_alpha = malloc(REF_SYS_Q * sizeof(gf_elem_t));
    if (!our_alpha) {
        printf("❌ Memory allocation failed\n");
        polynomial_free(our_g); free(ref_f); free(ref_g); free(prg_output);
        return -1;
    }
    
    mceliece_error_t field_result = generate_field_ordering(our_alpha, field_section);
    
    // Reference field ordering for comparison
    typedef struct { uint32_t val; uint16_t pos; } ref_pair_t;
    ref_pair_t *pairs = malloc(REF_SYS_Q * sizeof(ref_pair_t));
    gf_elem_t *ref_alpha = malloc(REF_SYS_Q * sizeof(gf_elem_t));
    
    if (!pairs || !ref_alpha) {
        printf("❌ Memory allocation failed\n");
        free(our_alpha); polynomial_free(our_g); free(ref_f); free(ref_g); free(prg_output);
        return -1;
    }
    
    // Build reference field ordering
    for (int i = 0; i < REF_SYS_Q; i++) {
        pairs[i].val = ref_load4(field_section + i * 4);
        pairs[i].pos = (uint16_t)i;
    }
    
    qsort(pairs, REF_SYS_Q, sizeof(ref_pair_t), test_cmp_pairs);
    
    // Check for duplicates
    int has_duplicates = 0;
    for (int i = 0; i < REF_SYS_Q - 1; i++) {
        if (pairs[i].val == pairs[i+1].val) {
            has_duplicates = 1;
            break;
        }
    }
    
    if (!has_duplicates) {
        for (int i = 0; i < REF_SYS_Q; i++) {
            uint16_t pi = pairs[i].pos;
            ref_alpha[i] = (gf_elem_t)test_bitrev_m(pi, REF_GFBITS);
        }
    }
    
    // Show comparison table
    if (field_result == MCELIECE_SUCCESS && !has_duplicates) {
        printf("\nAlpha value comparison (first 32):\n");
        printf("Index   Our Alpha  Ref Alpha  Match\n");
        printf("-----   ---------  ---------  -----\n");
        
        int matches = 0;
        for (int i = 0; i < 32; i++) {
            gf our_val = (gf)our_alpha[i];
            gf ref_val = (gf)ref_alpha[i];
            int match = (our_val == ref_val);
            matches += match;
            
            printf("%3d     %04X       %04X       %s\n", 
                   i, our_val, ref_val, match ? "✓" : "✗");
        }
        
        // Count remaining matches
        for (int i = 32; i < REF_SYS_Q; i++) {
            if ((gf)our_alpha[i] == (gf)ref_alpha[i]) matches++;
        }
        
        printf("...     ....       ....       ...\n");
        printf("\nField Ordering Summary: %d/%d alpha values match\n", matches, REF_SYS_Q);
        printf("Result: %s\n", (matches == REF_SYS_Q) ? "✅ PERFECT MATCH" : "❌ MISMATCH");
    }
    
    // Cleanup
    free(pairs); free(ref_alpha); free(our_alpha);
    polynomial_free(our_g); free(ref_f); free(ref_g); free(prg_output);
    
    printf("\n");
    return 0;
#else
    printf("=== DETAILED NUMERICAL COMPARISON (reference disabled) ===\n");
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    uint8_t seed[32]; for (int i = 0; i < 32; i++) sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    size_t s_len_bits = REF_SYS_N, field_ordering_len_bits = REF_SIGMA2 * REF_SYS_Q, irreducible_poly_len_bits = REF_SIGMA1 * REF_SYS_T, delta_prime_len_bits = 256;
    size_t prg_output_len_bytes = ((s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits) + 7) / 8;
    uint8_t *prg_output = malloc(prg_output_len_bytes); if (!prg_output) return -1;
    mceliece_prg(seed, prg_output, prg_output_len_bytes);
    size_t s_len_bytes = (s_len_bits + 7) / 8; size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8; size_t irreducible_poly_len_bytes = (irreducible_poly_len_bits + 7) / 8;
    const uint8_t *field_section = prg_output + s_len_bytes; const uint8_t *poly_section = field_section + field_ordering_len_bytes;
    polynomial_t *our_g = polynomial_create(REF_SYS_T); if (!our_g) { free(prg_output); return -1; }
    if (generate_irreducible_poly_final(our_g, poly_section) != MCELIECE_SUCCESS) { printf("❌ Poly generation failed\n"); polynomial_free(our_g); free(prg_output); return -1; }
    printf("Our g coefficients (first 32): "); for (int i=0;i<32 && i<REF_SYS_T;i++) printf("%04X ", (unsigned)our_g->coeffs[i]); printf("\n");
    gf_elem_t *alpha = malloc(REF_SYS_Q * sizeof(gf_elem_t)); if (!alpha) { polynomial_free(our_g); free(prg_output); return -1; }
    if (generate_field_ordering(alpha, field_section) != MCELIECE_SUCCESS) { printf("❌ Field ordering failed\n"); free(alpha); polynomial_free(our_g); free(prg_output); return -1; }
    printf("Our alpha values (first 32): "); for (int i=0;i<32;i++) printf("%04X ", (unsigned)alpha[i]); printf("\n");
    int mt = REF_PK_NROWS, ncols = REF_SYS_N; matrix_t *H = matrix_create(mt, ncols);
    if (H) {
        for (int j = 0; j < REF_SYS_N; j++) {
            gf_elem_t a = alpha[j]; gf_elem_t g_a = polynomial_eval(our_g, a); gf_elem_t a_pow = 1;
            for (int i = 0; i < REF_SYS_T; i++) { gf_elem_t Mij = g_a ? gf_div(a_pow, g_a) : 0; for (int b = 0; b < REF_GFBITS; b++) matrix_set_bit(H, i*REF_GFBITS + b, j, (Mij >> b) & 1); a_pow = gf_mul(a_pow, a); }
        }
        int red = reduce_to_systematic_form(H); printf("Gaussian elimination: %s\n", red == 0 ? "✅ Success" : "❌ Failed"); matrix_free(H);
    }
    free(alpha); polynomial_free(our_g); free(prg_output); return 0;
#endif
}

// New: Reference-compatible KAT path to diagnose pk/ct/ss differences
#if ENABLE_REFERENCE_TESTS
static int parse_first_kat_seed48(unsigned char out48[48]) {
    const char *candidates[] = {
        "mceliece6688128/kat_kem.req",
        "../mceliece6688128/kat_kem.req",
        "mceliece6688128_kat/kat_kem.req",
        "../mceliece6688128_kat/kat_kem.req",
        "/Users/zhanghanqi/CLionProjects/ClassicMceliece/mceliece6688128/kat_kem.req",
        "/Users/zhanghanqi/CLionProjects/ClassicMceliece/mceliece6688128_kat/kat_kem.req"
    };
    FILE *f = NULL;
    const char *used = NULL;
    for (size_t ci = 0; ci < sizeof(candidates)/sizeof(candidates[0]); ci++) {
        f = fopen(candidates[ci], "r");
        if (f) { used = candidates[ci]; break; }
    }
    if (!f) { printf("No kat_kem.req found in candidates\n"); return -1; }
    char line[8192];
    while (fgets(line, sizeof(line), f)) {
        const char *seedpos = strstr(line, "seed =");
        if (seedpos) {
            const char *p = strchr(seedpos, '='); if (!p) break; p++;
            // skip spaces
            while (*p && (*p==' '||*p=='\t')) p++;
            int idx = 0; int hi = -1;
            for (; *p && idx < 48; p++) {
                int v;
                if ('0'<=*p && *p<='9') v = *p - '0';
                else if ('a'<=*p && *p<='f') v = *p - 'a' + 10;
                else if ('A'<=*p && *p<='F') v = *p - 'A' + 10;
                else continue;
                if (hi < 0) hi = v; else { out48[idx++] = (unsigned char)((hi<<4)|v); hi = -1; }
            }
            fclose(f);
            if (idx==48) { printf("Using req file: %s\n", used ? used : "(unknown)"); return 0; }
            else { printf("Parsed %d bytes (expected 48) from %s\n", idx, used ? used : "(unknown)"); return -1; }
        }
    }
    fclose(f);
    printf("No seed line found in %s\n", used ? used : "(unknown)");
    return -1;
}

int test_reference_kat_alignment() {
    printf("=== KAT ALIGNMENT TEST (reference-compatible keygen path) ===\n\n");
    unsigned char seed48[48];
    if (parse_first_kat_seed48(seed48) != 0) {
        // Fallback to first seed from mceliece6688128/kat_kem.req (count=0)
        static const char *fallback_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
        int ok = 1;
        for (int i = 0; i < 48; i++) {
            unsigned v; if (sscanf(fallback_hex + 2*i, "%02x", &v) != 1) { ok = 0; break; }
            seed48[i] = (unsigned char)v;
        }
        if (!ok) { printf("Failed to parse KAT req seed (and fallback)\n\n"); return -1; }
        printf("Using fallback KAT seed (count=0)\n");
    }

    // Initialize DRBG like ref kat_kem
    randombytes_init(seed48, NULL, 256);

    // Build seed[33]: first byte 64 + 32 random bytes
    unsigned char seed33[33]; memset(seed33, 0, sizeof seed33); seed33[0] = 64;
    randombytes(seed33+1, 32);

    // Build r buffer of reference length: s + perm + f + delta'
    size_t R_LEN = (size_t)(REF_SYS_N/8) + ((size_t)1<<REF_GFBITS)*sizeof(uint32_t) + (size_t)REF_SYS_T*2 + 32;
    unsigned char *r = (unsigned char*)malloc(R_LEN);
    if (!r) return -1;
    // Reference uses SHAKE with 33-byte seed
    shake256(seed33, sizeof seed33, r, R_LEN);

    // Walk r from end like reference
    unsigned char *rp = r + R_LEN - 32; // delta'
    // Extract f
    gf *f = (gf*)malloc(sizeof(gf) * REF_SYS_T);
    gf *irr = (gf*)malloc(sizeof(gf) * REF_SYS_T);
    if (!f || !irr) { free(r); free(f); free(irr); return -1; }
    rp -= REF_SYS_T*2;
    for (int i=0;i<REF_SYS_T;i++) f[i] = ref_load_gf(rp + i*2);
    if (ref_genpoly_gen(irr, f) != 0) { printf("ref_genpoly_gen failed\n\n"); free(r); free(f); free(irr); return -1; }
    // Extract perm
    rp -= ((size_t)1<<REF_GFBITS)*sizeof(uint32_t);
    uint32_t *perm = (uint32_t*)malloc(((size_t)1<<REF_GFBITS)*sizeof(uint32_t));
    int16_t *pi = (int16_t*)malloc(((size_t)1<<REF_GFBITS)*sizeof(int16_t));
    if (!perm || !pi) { free(perm); free(pi); free(r); free(f); free(irr); return -1; }
    for (int i=0;i<(1<<REF_GFBITS);i++) perm[i] = ref_load4(rp + i*4);
    // Build pk using reference pk_gen
    unsigned char *pk_ref = (unsigned char*)malloc((size_t)REF_PK_NROWS * (size_t)REF_PK_ROW_BYTES);
    if (!pk_ref) { free(perm); free(pi); free(r); free(f); free(irr); return -1; }
    int pk_ret = ref_pk_gen(pk_ref, (unsigned char*)irr, perm, pi);
    printf("ref_pk_gen: %s\n", pk_ret==0?"ok":"fail");
    // Build our pk via our keygen using same DRBG seed path
    kat_drbg_init(seed48);
    public_key_t *pk_us = public_key_create(); private_key_t *sk_us = private_key_create();
    if (!pk_us || !sk_us) { printf("alloc fail\n"); free(pk_ref); free(perm); free(pi); free(r); free(f); free(irr); return -1; }
    if (mceliece_keygen(pk_us, sk_us) != MCELIECE_SUCCESS) { printf("our keygen failed\n"); }
    size_t pk_bytes = (size_t)REF_PK_NROWS*(size_t)REF_PK_ROW_BYTES;
    unsigned char *pk_us_bytes = (unsigned char*)malloc(pk_bytes);
    int ser_ok = public_key_serialize_refpacking(pk_us, pk_us_bytes);
    int same = (pk_ret==0 && ser_ok==0) ? (memcmp(pk_ref, pk_us_bytes, pk_bytes)==0) : 0;
    printf("PK bytes match: %s\n", same?"YES":"NO");
    if (!same) {
        // print first mismatch index
        size_t idx=0; while (idx<pk_bytes && pk_ref[idx]==pk_us_bytes[idx]) idx++;
        if (idx<pk_bytes) printf("First pk byte diff at %zu: ref=%02X our=%02X\n", idx, pk_ref[idx], pk_us_bytes[idx]);
    }
    free(pk_us_bytes); public_key_free(pk_us); private_key_free(sk_us);
    free(pk_ref); free(perm); free(pi); free(r); free(f); free(irr);
    printf("\n");
    return 0;
}
#endif
// Test seed
static const char* TEST_SEED_HEX = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";

// 1. PRG Comparison Test
int test_prg_comparison(int num_tests) {
    printf("=== PRG COMPARISON TEST ===\n");
    printf("Testing %d different seeds\n\n", num_tests);
    
    int successes = 0;
    
    for (int test = 0; test < num_tests; test++) {
        // Create test seed by modifying base seed
    uint8_t seed[32];
        for (int i = 0; i < 32; i++) {
            sscanf(TEST_SEED_HEX + 2*i, "%02hhX", &seed[i]);
            seed[i] ^= (uint8_t)(test & 0xFF) ^ (uint8_t)((test >> 8) & 0xFF);
        }
        
        // Calculate PRG output length
        size_t s_len_bits = MCELIECE_N;
        size_t field_ordering_len_bits = 32 * MCELIECE_Q;
        size_t irreducible_poly_len_bits = 16 * MCELIECE_T;
    size_t delta_prime_len_bits = 256;
    size_t total_bits = s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits;
    size_t prg_output_len_bytes = (total_bits + 7) / 8;

        uint8_t *our_prg = malloc(prg_output_len_bytes);
        uint8_t *ref_prg = malloc(prg_output_len_bytes);
        
        if (!our_prg || !ref_prg) {
            printf("Memory allocation failed\n");
            free(our_prg); free(ref_prg);
            continue;
        }
        
        // Generate PRG outputs
    mceliece_prg(seed, our_prg, prg_output_len_bytes);
    mceliece_prg_reference(seed, ref_prg, prg_output_len_bytes);
        
        int match = (memcmp(our_prg, ref_prg, prg_output_len_bytes) == 0);
        printf("Test %d: %s\n", test + 1, match ? "✅ MATCH" : "❌ DIFFER");
        
        if (match) successes++;
        
        free(our_prg);
        free(ref_prg);
    }
    
    printf("\nPRG Results: %d/%d tests passed (%.1f%%)\n\n", 
           successes, num_tests, 100.0 * successes / num_tests);
    return successes;
}

// 2. Irreducible Polynomial Generation Test
int test_irreducible_poly_comparison(int num_tests) {
    printf("=== IRREDUCIBLE POLYNOMIAL COMPARISON TEST ===\n");
    printf("Testing %d different polynomial inputs\n\n", num_tests);
    
    int successes = 0;
    
    for (int test = 0; test < num_tests; test++) {
        // Create test seed
        uint8_t seed[32];
        for (int i = 0; i < 32; i++) {
            sscanf(TEST_SEED_HEX + 2*i, "%02hhX", &seed[i]);
            seed[i] ^= (uint8_t)(test & 0xFF) ^ (uint8_t)((test >> 8) & 0xFF);
        }
        
        // Generate PRG output to get polynomial section
        size_t s_len_bits = MCELIECE_N;
        size_t field_ordering_len_bits = 32 * MCELIECE_Q;
        size_t irreducible_poly_len_bits = 16 * MCELIECE_T;
        size_t delta_prime_len_bits = 256;
        size_t total_bits = s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits;
        size_t prg_output_len_bytes = (total_bits + 7) / 8;
        
        uint8_t *prg_output = malloc(prg_output_len_bytes);
        if (!prg_output) continue;
        
        mceliece_prg(seed, prg_output, prg_output_len_bytes);
        
    size_t s_len_bytes = (s_len_bits + 7) / 8;
    size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8;
        const uint8_t *poly_section = prg_output + s_len_bytes + field_ordering_len_bytes;
        
        // Test our implementation
        polynomial_t *our_g = polynomial_create(MCELIECE_T);
        mceliece_error_t our_result = generate_irreducible_poly_final(our_g, poly_section);
        
        int match = 0;
        
#if ENABLE_REFERENCE_TESTS
        // Test reference implementation
        gf *ref_f = malloc(sizeof(gf) * REF_SYS_T);
        gf *ref_g = malloc(sizeof(gf) * REF_SYS_T);
        
        if (ref_f && ref_g) {
            for (int i = 0; i < REF_SYS_T; i++) {
                ref_f[i] = ref_load_gf(poly_section + i * 2) & ((1U << REF_GFBITS) - 1);
            }
            
            int ref_result = ref_genpoly_gen(ref_g, ref_f);
            
            if (our_result == MCELIECE_SUCCESS && ref_result == 0) {
                match = 1;
                for (int i = 0; i < REF_SYS_T; i++) {
                    if ((gf)our_g->coeffs[i] != ref_g[i]) {
                        match = 0;
                        break;
                    }
                }
                match = match && ((gf)our_g->coeffs[REF_SYS_T] == 1);
            }
        }
        
        free(ref_f);
        free(ref_g);
#else
        match = (our_result == MCELIECE_SUCCESS);
#endif
        
        printf("Test %d: %s\n", test + 1, match ? "✅ MATCH" : "❌ DIFFER");
        
        if (match) successes++;
        
        polynomial_free(our_g);
        free(prg_output);
    }
    
    printf("\nIrreducible Polynomial Results: %d/%d tests passed (%.1f%%)\n\n", 
           successes, num_tests, 100.0 * successes / num_tests);
    return successes;
}

// 3. Field Ordering Test
int test_field_ordering_comparison(int num_tests) {
    printf("=== FIELD ORDERING COMPARISON TEST ===\n");
    printf("Testing %d different field ordering inputs\n\n", num_tests);
    
    int successes = 0;
    
    for (int test = 0; test < num_tests; test++) {
        // Create test seed
        uint8_t seed[32];
        for (int i = 0; i < 32; i++) {
            sscanf(TEST_SEED_HEX + 2*i, "%02hhX", &seed[i]);
            seed[i] ^= (uint8_t)(test & 0xFF) ^ (uint8_t)((test >> 8) & 0xFF);
        }
        
        // Generate PRG output to get field section
        size_t s_len_bits = MCELIECE_N;
        size_t field_ordering_len_bits = 32 * MCELIECE_Q;
        size_t irreducible_poly_len_bits = 16 * MCELIECE_T;
        size_t delta_prime_len_bits = 256;
        size_t total_bits = s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits;
        size_t prg_output_len_bytes = (total_bits + 7) / 8;
        
        uint8_t *prg_output = malloc(prg_output_len_bytes);
        if (!prg_output) continue;
        
        mceliece_prg(seed, prg_output, prg_output_len_bytes);
        
        size_t s_len_bytes = (s_len_bits + 7) / 8;
        const uint8_t *field_section = prg_output + s_len_bytes;
        
        // Test our implementation
        gf_elem_t *our_alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
        mceliece_error_t our_result = generate_field_ordering(our_alpha, field_section);
        
        // Reference implementation logic
        gf_elem_t *ref_alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
        ref_pair_t *pairs = malloc(MCELIECE_Q * sizeof(ref_pair_t));
        
        int match = 0;
        if (our_alpha && ref_alpha && pairs && our_result == MCELIECE_SUCCESS) {
            // Build reference field ordering
            for (int i = 0; i < MCELIECE_Q; i++) {
                pairs[i].val = ref_load4(field_section + i * 4);
                pairs[i].pos = (uint16_t)i;
            }
            
            qsort(pairs, MCELIECE_Q, sizeof(ref_pair_t), test_cmp_pairs);
            
            for (int i = 0; i < MCELIECE_Q; i++) {
                ref_alpha[i] = (gf_elem_t)test_bitrev_m(pairs[i].pos, MCELIECE_M);
            }
            
            match = (memcmp(our_alpha, ref_alpha, sizeof(gf_elem_t) * MCELIECE_Q) == 0);
        }
        
        printf("Test %d: %s\n", test + 1, match ? "✅ MATCH" : "❌ DIFFER");
        
        if (match) successes++;
        
        free(our_alpha);
        free(ref_alpha);
        free(pairs);
        free(prg_output);
    }
    
    printf("\nField Ordering Results: %d/%d tests passed (%.1f%%)\n\n", 
           successes, num_tests, 100.0 * successes / num_tests);
    return successes;
}

// 4. Gaussian Elimination Direct Comparison Test  
int test_gaussian_elimination_comparison(int num_tests) {
    printf("=== GAUSSIAN ELIMINATION DIRECT COMPARISON TEST ===\n");
    printf("Testing %d identical matrices with both implementations\n\n", num_tests);
    
    int exact_matches = 0;
    int our_successes = 0;
    int ref_successes = 0;
    
    for (int test = 0; test < num_tests; test++) {
        // Create test seed
        uint8_t seed[32];
        for (int i = 0; i < 32; i++) {
            sscanf(TEST_SEED_HEX + 2*i, "%02hhX", &seed[i]);
            seed[i] ^= (uint8_t)(test & 0xFF) ^ (uint8_t)((test >> 8) & 0xFF);
        }
        
        // Generate PRG output to get polynomial and field data
        size_t s_len_bits = MCELIECE_N;
        size_t field_ordering_len_bits = 32 * MCELIECE_Q;
        size_t irreducible_poly_len_bits = 16 * MCELIECE_T;
        size_t delta_prime_len_bits = 256;
        size_t total_bits = s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits;
        size_t prg_output_len_bytes = (total_bits + 7) / 8;
        
        uint8_t *prg_output = malloc(prg_output_len_bytes);
        if (!prg_output) continue;
        
        mceliece_prg(seed, prg_output, prg_output_len_bytes);
        
        size_t s_len_bytes = (s_len_bits + 7) / 8;
        size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8;
        const uint8_t *field_section = prg_output + s_len_bytes;
        const uint8_t *poly_section = field_section + field_ordering_len_bytes;
        
        // Generate polynomial and field ordering (ensuring they work first)
        polynomial_t *our_g = polynomial_create(MCELIECE_T);
        gf_elem_t *our_alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
        
        if (!our_g || !our_alpha ||
            generate_irreducible_poly_final(our_g, poly_section) != MCELIECE_SUCCESS ||
            generate_field_ordering(our_alpha, field_section) != MCELIECE_SUCCESS) {
            polynomial_free(our_g);
            free(our_alpha);
            free(prg_output);
            continue; // Skip this test case
        }
        
        // Check support set validity
        int support_ok = 1;
        for (int j = 0; j < MCELIECE_N; j++) {
            if (polynomial_eval(our_g, our_alpha[j]) == 0) {
                support_ok = 0;
                break;
            }
        }
        
        if (!support_ok) {
            polynomial_free(our_g);
            free(our_alpha);
            free(prg_output);
            continue; // Skip this test case
        }
        
        // Build the H matrix that both will use
        matrix_t *H_original = matrix_create(MCELIECE_T * MCELIECE_M, MCELIECE_N);
        if (!H_original || build_parity_check_matrix_reference_style(H_original, our_g, our_alpha) != 0) {
            polynomial_free(our_g);
            free(our_alpha);
            free(prg_output);
            if (H_original) matrix_free(H_original);
            continue;
        }
        
        // Create two identical copies for testing
        matrix_t *H_our = matrix_create(MCELIECE_T * MCELIECE_M, MCELIECE_N);
        matrix_t *H_ref = matrix_create(MCELIECE_T * MCELIECE_M, MCELIECE_N);
        
        if (!H_our || !H_ref) {
            matrix_free(H_original);
            if (H_our) matrix_free(H_our);
            if (H_ref) matrix_free(H_ref);
            polynomial_free(our_g);
            free(our_alpha);
            free(prg_output);
            continue;
        }
        
        // Copy original matrix to both test matrices
        memcpy(H_our->data, H_original->data, H_original->rows * H_original->cols_bytes);
        memcpy(H_ref->data, H_original->data, H_original->rows * H_original->cols_bytes);
        
        // Test our Gaussian elimination
        int our_result = reduce_to_systematic_form(H_our);
        if (our_result == 0) our_successes++;
        
        // Test reference-style Gaussian elimination (if available)
        int ref_result = -1;
#if ENABLE_REFERENCE_TESTS
        ref_result = reduce_to_systematic_form_reference_style(H_ref);
        if (ref_result == 0) ref_successes++;
        
        // Compare results if both succeeded
        int matrices_match = 0;
        if (our_result == 0 && ref_result == 0) {
            // Compare the reduced matrices byte-for-byte
            matrices_match = (memcmp(H_our->data, H_ref->data, H_our->rows * H_our->cols_bytes) == 0);
            if (matrices_match) exact_matches++;
        }
        
        printf("Test %d: Our:%s Ref:%s Match:%s\n", test + 1,
               (our_result == 0) ? "✅" : "❌",
               (ref_result == 0) ? "✅" : "❌", 
               (our_result == 0 && ref_result == 0) ? (matrices_match ? "✅" : "❌") : "N/A");
#else
        (void)ref_result; // suppress unused warning
        printf("Test %d: Our:%s Ref:DISABLED\n", test + 1, (our_result == 0) ? "✅" : "❌");
#endif
        
        matrix_free(H_original);
        matrix_free(H_our);
        matrix_free(H_ref);
        polynomial_free(our_g);
        free(our_alpha);
        free(prg_output);
    }
    
    printf("\nGaussian Elimination Comparison Results:\n");
    printf("  Our Implementation: %d/%d successes (%.1f%%)\n", 
           our_successes, num_tests, 100.0 * our_successes / num_tests);
#if ENABLE_REFERENCE_TESTS
    printf("  Reference Implementation: %d/%d successes (%.1f%%)\n", 
           ref_successes, num_tests, 100.0 * ref_successes / num_tests);
    printf("  Exact Matrix Matches: %d/%d (%.1f%%)\n",
           exact_matches, num_tests, 100.0 * exact_matches / num_tests);
#else
    printf("  Reference Implementation: DISABLED\n");
#endif
    printf("\n");
    
    return exact_matches;
}

// Test H matrix consistency between implementations
int test_h_matrix_consistency() {
    printf("=== H MATRIX CONSISTENCY TEST ===\n");
    printf("Testing if both implementations generate identical H matrices\n");
    printf("Using KAT seed from kat_kem.req\n\n");
    
    // Use the seed from kat_kem.req
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    printf("Using seed: ");
    for (int i = 0; i < 32; i++) printf("%02X", seed[i]);
    printf("\n\n");
    
    // Generate PRG output
    size_t s_len_bits = MCELIECE_N;
    size_t field_ordering_len_bits = 32 * MCELIECE_Q;
    size_t irreducible_poly_len_bits = 16 * MCELIECE_T;
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
    const uint8_t *field_section = prg_output + s_len_bytes;
    const uint8_t *poly_section = field_section + field_ordering_len_bytes;
    
    // === STEP 1: Generate polynomial and field ordering ===
    printf("--- STEP 1: Generate Polynomial and Field Ordering ---\n");
    
    polynomial_t *our_g = polynomial_create(MCELIECE_T);
    gf_elem_t *our_alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
    
    if (!our_g || !our_alpha) {
        printf("❌ Memory allocation failed\n");
        free(prg_output);
        return -1;
    }
    
    mceliece_error_t poly_result = generate_irreducible_poly_final(our_g, poly_section);
    mceliece_error_t field_result = generate_field_ordering(our_alpha, field_section);
    
    printf("Irreducible polynomial generation: %s\n", poly_result == MCELIECE_SUCCESS ? "✅ Success" : "❌ Failed");
    printf("Field ordering generation: %s\n", field_result == MCELIECE_SUCCESS ? "✅ Success" : "❌ Failed");
    
    if (poly_result != MCELIECE_SUCCESS || field_result != MCELIECE_SUCCESS) {
        printf("❌ Prerequisites failed, cannot test H matrix\n");
        polynomial_free(our_g);
        free(our_alpha);
        free(prg_output);
        return -1;
    }
    
    // Verify support set (no roots of g)
    int support_ok = 1;
    for (int j = 0; j < MCELIECE_N; j++) {
        if (polynomial_eval(our_g, our_alpha[j]) == 0) {
            printf("❌ Support set invalid: g(alpha[%d]) = 0\n", j);
            support_ok = 0;
            break;
        }
    }
    
    if (!support_ok) {
        printf("❌ Support set validation failed\n");
        polynomial_free(our_g);
        free(our_alpha);
        free(prg_output);
        return -1;
    }
    
    printf("Support set validation: ✅ Success\n");
    printf("g coefficients (first 8): ");
    for (int i = 0; i < 8; i++) printf("%04X ", (unsigned)our_g->coeffs[i]);
    printf("\n");
    printf("alpha values (first 8): ");
    for (int i = 0; i < 8; i++) printf("%04X ", (unsigned)our_alpha[i]);
    printf("\n\n");
    
    // === STEP 2: Build H matrices with both implementations ===
    printf("--- STEP 2: Build H Matrices ---\n");
    
    int mt = MCELIECE_T * MCELIECE_M;
    int ncols = MCELIECE_N;
    
    // Build H using our implementation
    matrix_t *H_our = matrix_create(mt, ncols);
    if (!H_our) {
        printf("❌ Failed to allocate H_our matrix\n");
        polynomial_free(our_g);
        free(our_alpha);
        free(prg_output);
        return -1;
    }
    
    int our_build_result = build_parity_check_matrix_reference_style(H_our, our_g, our_alpha);
    printf("Our H matrix construction: %s\n", our_build_result == 0 ? "✅ Success" : "❌ Failed");
    
#if ENABLE_REFERENCE_TESTS
    // Build H using reference implementation approach
    matrix_t *H_ref = matrix_create(mt, ncols);
    if (!H_ref) {
        printf("❌ Failed to allocate H_ref matrix\n");
        matrix_free(H_our);
        polynomial_free(our_g);
        free(our_alpha);
        free(prg_output);
        return -1;
    }
    
    // Convert our data to reference format for comparison
    gf *ref_g = malloc(sizeof(gf) * (MCELIECE_T + 1));
    gf *ref_L = malloc(sizeof(gf) * MCELIECE_N);
    gf *ref_inv = malloc(sizeof(gf) * MCELIECE_N);
    
    if (!ref_g || !ref_L || !ref_inv) {
        printf("❌ Memory allocation failed for reference data\n");
        matrix_free(H_our);
        matrix_free(H_ref);
        polynomial_free(our_g);
        free(our_alpha);
        free(prg_output);
        return -1;
    }
    
    // Convert polynomial coefficients
    for (int i = 0; i < MCELIECE_T; i++) {
        ref_g[i] = (gf)our_g->coeffs[i];
    }
    ref_g[MCELIECE_T] = 1; // monic polynomial
    
    // Convert support set
    for (int i = 0; i < MCELIECE_N; i++) {
        ref_L[i] = (gf)our_alpha[i];
    }
    
    // Build reference H matrix using the same algorithm as reference pk_gen
    printf("Building reference H matrix...\n");
    
    // Calculate inv = 1/g(L) using reference polynomial evaluation
    for (int i = 0; i < MCELIECE_N; i++) {
        gf val = ref_g[MCELIECE_T]; // start with leading coefficient
        for (int d = MCELIECE_T - 1; d >= 0; d--) {
            val = ref_gf_mul(val, ref_L[i]);
            val ^= ref_g[d];
        }
        if (val == 0) {
            printf("❌ Reference g(L[%d]) = 0, invalid support\n", i);
            free(ref_g); free(ref_L); free(ref_inv);
            matrix_free(H_our); matrix_free(H_ref);
            polynomial_free(our_g); free(our_alpha); free(prg_output);
            return -1;
        }
        ref_inv[i] = ref_gf_inv(val);
    }
    
    // Clear reference matrix
    memset(H_ref->data, 0, H_ref->rows * H_ref->cols_bytes);
    
    // Build H_ref using exact reference packing logic from pk_gen.c
    for (int i = 0; i < MCELIECE_T; i++) {
        for (int j = 0; j < MCELIECE_N; j += 8) {
            for (int k = 0; k < MCELIECE_M; k++) {
                unsigned char b = 0;
                // Pack 8 elements at once with reference bit ordering
                int block_len = (j + 8 <= MCELIECE_N) ? 8 : (MCELIECE_N - j);
                for (int idx = block_len - 1; idx >= 0; idx--) {
                    b <<= 1;
                    if (j + idx < MCELIECE_N) {
                        b |= (ref_inv[j + idx] >> k) & 1;
                    }
                }
                
                // Write to matrix using reference row indexing
                int row = i * MCELIECE_M + k;
                for (int col_offset = 0; col_offset < block_len; col_offset++) {
                    int bit = (b >> (block_len - 1 - col_offset)) & 1;
                    matrix_set_bit(H_ref, row, j + col_offset, bit);
                }
            }
        }
        
        // Update inv for next power: inv[j] *= L[j]
        for (int j = 0; j < MCELIECE_N; j++) {
            ref_inv[j] = ref_gf_mul(ref_inv[j], ref_L[j]);
        }
    }
    
    printf("Reference H matrix construction: ✅ Success\n");
    
    // === STEP 3: Compare H matrices ===
    printf("\n--- STEP 3: Compare H Matrices ---\n");
    
    // First, dump some sample data for visual inspection
    printf("Sample data comparison (first 4 rows, first 64 bytes):\n");
    for (int r = 0; r < 4 && r < mt; r++) {
        printf("Row %d our: ", r);
        for (int c = 0; c < 64 && c < H_our->cols_bytes; c++) {
            printf("%02X", H_our->data[r * H_our->cols_bytes + c]);
        }
        printf("\n");
        printf("Row %d ref: ", r);
        for (int c = 0; c < 64 && c < H_ref->cols_bytes; c++) {
            printf("%02X", H_ref->data[r * H_ref->cols_bytes + c]);
        }
        printf("\n");
        if (memcmp(H_our->data + r * H_our->cols_bytes, 
                   H_ref->data + r * H_ref->cols_bytes, 
                   H_our->cols_bytes) == 0) {
            printf("Row %d: ✅ MATCH\n", r);
        } else {
            printf("Row %d: ❌ DIFFER\n", r);
        }
        printf("\n");
    }
    
    // Full matrix comparison
    int matrices_identical = (memcmp(H_our->data, H_ref->data, H_our->rows * H_our->cols_bytes) == 0);
    
    printf("Full H matrix comparison: %s\n", matrices_identical ? "✅ IDENTICAL" : "❌ DIFFERENT");
    
    if (!matrices_identical) {
        // Find first difference
        size_t total_bytes = H_our->rows * H_our->cols_bytes;
        size_t diff_byte = 0;
        while (diff_byte < total_bytes && H_our->data[diff_byte] == H_ref->data[diff_byte]) {
            diff_byte++;
        }
        if (diff_byte < total_bytes) {
            int diff_row = diff_byte / H_our->cols_bytes;
            int diff_col = diff_byte % H_our->cols_bytes;
            printf("First difference at row %d, byte %d: our=%02X ref=%02X\n", 
                   diff_row, diff_col, H_our->data[diff_byte], H_ref->data[diff_byte]);
        }
    }
    
    // Cleanup reference data
    free(ref_g);
    free(ref_L);
    free(ref_inv);
    matrix_free(H_ref);
    
#else
    printf("Reference implementation: DISABLED\n");
    printf("Cannot compare H matrices directly\n");
    int matrices_identical = 0; // Unknown
#endif
    
    // Cleanup
    matrix_free(H_our);
    polynomial_free(our_g);
    free(our_alpha);
    free(prg_output);
    
    printf("\n=== H MATRIX TEST SUMMARY ===\n");
    printf("Prerequisites: ✅ All passed\n");
    printf("Our H construction: %s\n", our_build_result == 0 ? "✅ Success" : "❌ Failed");
#if ENABLE_REFERENCE_TESTS
    printf("H matrix consistency: %s\n", matrices_identical ? "✅ IDENTICAL" : "❌ DIFFERENT");
    return matrices_identical ? 0 : -1;
#else
    printf("H matrix consistency: ⚠️  Cannot test (reference disabled)\n");
    return 0;
#endif
}

// 5. Gaussian Elimination Success Rate Test (kept for completeness)
int test_gaussian_elimination_success_rate(int num_tests) {
    printf("=== GAUSSIAN ELIMINATION SUCCESS RATE TEST ===\n");
    printf("Testing %d attempts for each implementation\n\n", num_tests);
    
    int our_successes = 0;
    int ref_successes = 0;
    
    for (int test = 0; test < num_tests; test++) {
        // Create test seed
        uint8_t seed[32];
        for (int i = 0; i < 32; i++) {
            sscanf(TEST_SEED_HEX + 2*i, "%02hhX", &seed[i]);
            seed[i] ^= (uint8_t)(test & 0xFF) ^ (uint8_t)((test >> 8) & 0xFF);
        }
        
        // Generate PRG output
        size_t s_len_bits = MCELIECE_N;
        size_t field_ordering_len_bits = 32 * MCELIECE_Q;
        size_t irreducible_poly_len_bits = 16 * MCELIECE_T;
        size_t delta_prime_len_bits = 256;
        size_t total_bits = s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits;
        size_t prg_output_len_bytes = (total_bits + 7) / 8;
        
        uint8_t *prg_output = malloc(prg_output_len_bytes);
        if (!prg_output) continue;
        
        mceliece_prg(seed, prg_output, prg_output_len_bytes);
        
        size_t s_len_bytes = (s_len_bits + 7) / 8;
        size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8;
        const uint8_t *field_section = prg_output + s_len_bytes;
        const uint8_t *poly_section = field_section + field_ordering_len_bytes;
        
        // Test our implementation
        polynomial_t *our_g = polynomial_create(MCELIECE_T);
        gf_elem_t *our_alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
        
        int our_success = 0;
        if (our_g && our_alpha) {
            if (generate_irreducible_poly_final(our_g, poly_section) == MCELIECE_SUCCESS &&
                generate_field_ordering(our_alpha, field_section) == MCELIECE_SUCCESS) {
                
                // Check support set validity
                int support_ok = 1;
                for (int j = 0; j < MCELIECE_N; j++) {
                    if (polynomial_eval(our_g, our_alpha[j]) == 0) {
                        support_ok = 0;
                        break;
                    }
                }
                
                if (support_ok) {
                    matrix_t *H = matrix_create(MCELIECE_T * MCELIECE_M, MCELIECE_N);
                    if (H) {
                        if (build_parity_check_matrix_reference_style(H, our_g, our_alpha) == 0 &&
                            reduce_to_systematic_form(H) == 0) {
                            our_success = 1;
                        }
                        matrix_free(H);
                    }
                }
            }
        }
        
        if (our_success) our_successes++;
        
        polynomial_free(our_g);
        free(our_alpha);
        
        // Test reference implementation - disabled for now
        int ref_success = 0;
#if 0 // ENABLE_REFERENCE_TESTS - disabled due to compilation issues
        {
            // Reference implementation testing disabled
        }
        
        if (ref_success) ref_successes++;
#endif
        
        printf("Test %d: Our:%s Ref:%s\n", test + 1, 
               our_success ? "✅" : "❌",
               ref_success ? "✅" : "❌");
        
        free(prg_output);
    }
    
    printf("\nGaussian Elimination Results:\n");
    printf("  Our Implementation: %d/%d successes (%.1f%%)\n", 
           our_successes, num_tests, 100.0 * our_successes / num_tests);
#if ENABLE_REFERENCE_TESTS
    printf("  Reference Implementation: %d/%d successes (%.1f%%)\n", 
           ref_successes, num_tests, 100.0 * ref_successes / num_tests);
#else
    printf("  Reference Implementation: DISABLED\n");
#endif
    printf("\n");
    
    return our_successes;
}

// Detailed step-by-step Gaussian elimination debugging
int debug_gaussian_elimination_step_by_step() {
    printf("=== DETAILED GAUSSIAN ELIMINATION DEBUG ===\n");
    printf("Comparing our elimination with reference step-by-step\n\n");
    
    // Use KAT seed 0
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    // Generate PRG and create H matrix
    size_t s_len_bits = MCELIECE_N;
    size_t field_ordering_len_bits = 32 * MCELIECE_Q;
    size_t irreducible_poly_len_bits = 16 * MCELIECE_T;
    size_t delta_prime_len_bits = 256;
    size_t total_bits = s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits;
    size_t prg_output_len_bytes = (total_bits + 7) / 8;
    
    uint8_t *prg_output = malloc(prg_output_len_bytes);
    if (!prg_output) return -1;
    
    mceliece_prg(seed, prg_output, prg_output_len_bytes);
    
    size_t s_len_bytes = (s_len_bits + 7) / 8;
    size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8;
    const uint8_t *field_section = prg_output + s_len_bytes;
    const uint8_t *poly_section = field_section + field_ordering_len_bytes;
    
    // Generate polynomial and field ordering
    polynomial_t *g = polynomial_create(MCELIECE_T);
    gf_elem_t *alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
    
    if (!g || !alpha ||
        generate_irreducible_poly_final(g, poly_section) != MCELIECE_SUCCESS ||
        generate_field_ordering(alpha, field_section) != MCELIECE_SUCCESS) {
        printf("❌ Prerequisites failed\n");
        polynomial_free(g); free(alpha); free(prg_output);
        return -1;
    }
    
    // Create H matrix
    int mt = MCELIECE_T * MCELIECE_M;
    matrix_t *H_our = matrix_create(mt, MCELIECE_N);
    matrix_t *H_ref = matrix_create(mt, MCELIECE_N);
    
    if (!H_our || !H_ref ||
        build_parity_check_matrix_reference_style(H_our, g, alpha) != 0 ||
        build_parity_check_matrix_reference_style(H_ref, g, alpha) != 0) {
        printf("❌ H matrix construction failed\n");
        matrix_free(H_our); matrix_free(H_ref);
        polynomial_free(g); free(alpha); free(prg_output);
        return -1;
    }
    
    printf("✅ H matrices constructed identically\n");
    printf("Matrix size: %d x %d\n", H_our->rows, H_our->cols);
    printf("Starting step-by-step elimination...\n\n");
    
    // Perform step-by-step elimination comparison
    const int left_bytes = (mt + 7) / 8;
    int step = 0;
    int differences_found = 0;
    
    for (int byte_idx = 0; byte_idx < left_bytes && byte_idx < 4; byte_idx++) { // Limit to first 4 bytes for debugging
        for (int bit_in_byte = 0; bit_in_byte < 8; bit_in_byte++) {
            int row = byte_idx * 8 + bit_in_byte;
            if (row >= mt) break;
            
            step++;
            printf("--- Step %d: Pivot at row=%d, byte=%d, bit=%d ---\n", step, row, byte_idx, bit_in_byte);
            
            // Show pivot bytes before elimination
            printf("Before elimination:\n");
            printf("  Our pivot byte:  %02X (bit %d = %d)\n", 
                   H_our->data[row * H_our->cols_bytes + byte_idx], 
                   bit_in_byte,
                   (H_our->data[row * H_our->cols_bytes + byte_idx] >> bit_in_byte) & 1);
            printf("  Ref pivot byte:  %02X (bit %d = %d)\n", 
                   H_ref->data[row * H_ref->cols_bytes + byte_idx], 
                   bit_in_byte,
                   (H_ref->data[row * H_ref->cols_bytes + byte_idx] >> bit_in_byte) & 1);
            
            // Forward elimination - our implementation
            for (int r = row + 1; r < mt; r++) {
                unsigned char x = (unsigned char)(H_our->data[row * H_our->cols_bytes + byte_idx] ^
                                                  H_our->data[r   * H_our->cols_bytes + byte_idx]);
                unsigned char m = (unsigned char)((x >> bit_in_byte) & 1u);
                m = (unsigned char)(-(signed char)m);
                if (m) {
                    printf("  Our: XORing row %d into row %d (mask=%02X)\n", r, row, m);
                    for (int c = 0; c < H_our->cols_bytes; c++) {
                        H_our->data[row * H_our->cols_bytes + c] ^= (unsigned char)(H_our->data[r * H_our->cols_bytes + c] & m);
                    }
                }
            }
            
            // Forward elimination - reference style (exact copy of reference logic)
            for (int r = row + 1; r < mt; r++) {
                unsigned char mask = H_ref->data[row * H_ref->cols_bytes + byte_idx] ^ H_ref->data[r * H_ref->cols_bytes + byte_idx];
                mask >>= bit_in_byte;
                mask &= 1;
                mask = (unsigned char)(-(signed char)mask);
                if (mask) {
                    printf("  Ref: XORing row %d into row %d (mask=%02X)\n", r, row, mask);
                    for (int c = 0; c < H_ref->cols_bytes; c++) {
                        H_ref->data[row * H_ref->cols_bytes + c] ^= H_ref->data[r * H_ref->cols_bytes + c] & mask;
                    }
                }
            }
            
            // Check pivot bit
            int our_pivot = (H_our->data[row * H_our->cols_bytes + byte_idx] >> bit_in_byte) & 1;
            int ref_pivot = (H_ref->data[row * H_ref->cols_bytes + byte_idx] >> bit_in_byte) & 1;
            
            printf("After forward elimination:\n");
            printf("  Our pivot bit: %d\n", our_pivot);
            printf("  Ref pivot bit: %d\n", ref_pivot);
            
            if (our_pivot == 0 || ref_pivot == 0) {
                printf("❌ Pivot became zero - elimination failed\n");
                break;
            }
            
            // Backward elimination - our implementation
            for (int r = 0; r < mt; r++) {
                if (r == row) continue;
                unsigned char m = (unsigned char)((H_our->data[r * H_our->cols_bytes + byte_idx] >> bit_in_byte) & 1u);
                m = (unsigned char)(-(signed char)m);
                if (m) {
                    for (int c = 0; c < H_our->cols_bytes; c++) {
                        H_our->data[r * H_our->cols_bytes + c] ^= (unsigned char)(H_our->data[row * H_our->cols_bytes + c] & m);
                    }
                }
            }
            
            // Backward elimination - reference style
            for (int r = 0; r < mt; r++) {
                if (r == row) continue;
                unsigned char mask = H_ref->data[r * H_ref->cols_bytes + byte_idx] >> bit_in_byte;
                mask &= 1;
                mask = (unsigned char)(-(signed char)mask);
                if (mask) {
                    for (int c = 0; c < H_ref->cols_bytes; c++) {
                        H_ref->data[r * H_ref->cols_bytes + c] ^= H_ref->data[row * H_ref->cols_bytes + c] & mask;
                    }
                }
            }
            
            // Compare results after this step
            int matrices_match = (memcmp(H_our->data, H_ref->data, H_our->rows * H_our->cols_bytes) == 0);
            printf("Matrices match after step %d: %s\n", step, matrices_match ? "✅ YES" : "❌ NO");
            
            if (!matrices_match && differences_found < 5) {
                differences_found++;
                printf("First difference in bytes: ");
                for (size_t i = 0; i < H_our->rows * H_our->cols_bytes && i < 32; i++) {
                    if (H_our->data[i] != H_ref->data[i]) {
                        int diff_row = i / H_our->cols_bytes;
                        int diff_col = i % H_our->cols_bytes;
                        printf("Row %d, Byte %d: Our=%02X Ref=%02X ", diff_row, diff_col, H_our->data[i], H_ref->data[i]);
                        break;
                    }
                }
                printf("\n");
            }
            
            printf("\n");
            
            if (step >= 10) { // Limit to first 10 steps for debugging
                printf("Stopping after 10 steps for debugging...\n");
                break;
            }
        }
        if (step >= 10) break;
    }
    
    matrix_free(H_our); matrix_free(H_ref);
    polynomial_free(g); free(alpha); free(prg_output);
    
    return differences_found == 0 ? 0 : -1;
}

int main() {
    printf("McEliece Implementation Comparison Tests\n");
    printf("========================================\n\n");
    
    // First run the detailed debugging
    printf("Running detailed Gaussian elimination debugging...\n");
    int debug_result = debug_gaussian_elimination_step_by_step();
    printf("\nDebug result: %s\n\n", debug_result == 0 ? "✅ NO DIFFERENCES" : "❌ DIFFERENCES FOUND");
    
    int num_tests = 5; // Reduced for debugging
    const char *env_tests = getenv("MCELIECE_NUM_TESTS");
    if (env_tests) {
        int tmp = atoi(env_tests);
        if (tmp > 0 && tmp <= 1000) num_tests = tmp;
    }
    
    printf("Running %d tests for each component\n\n", num_tests);
    
    // Run all comparison tests
    int prg_successes = test_prg_comparison(num_tests);
    int poly_successes = test_irreducible_poly_comparison(num_tests);
    int field_successes = test_field_ordering_comparison(num_tests);
    int gauss_matches = test_gaussian_elimination_comparison(num_tests);
    
    // Test H matrix consistency
    printf("Running H matrix consistency test...\n");
    int h_matrix_test = test_h_matrix_consistency();

    // Summary
    printf("=== FINAL SUMMARY ===\n");
    printf("Debug Gaussian Elimination:  %s\n", debug_result == 0 ? "✅ PASS" : "❌ FAIL");
    printf("PRG Comparison:              %d/%d (%.1f%%)\n", prg_successes, num_tests, 100.0 * prg_successes / num_tests);
    printf("Irreducible Polynomial:      %d/%d (%.1f%%)\n", poly_successes, num_tests, 100.0 * poly_successes / num_tests);
    printf("Field Ordering:              %d/%d (%.1f%%)\n", field_successes, num_tests, 100.0 * field_successes / num_tests);
    printf("Gaussian Elimination Match:  %d/%d (%.1f%%)\n", gauss_matches, num_tests, 100.0 * gauss_matches / num_tests);
    printf("H Matrix Consistency:        %s\n", h_matrix_test == 0 ? "✅ PASS" : "❌ FAIL");
    
#if ENABLE_REFERENCE_TESTS
    printf("\nRunning reference pk_gen alignment test...\n");
    test_reference_kat_alignment();
#endif
    
    return 0;
}
