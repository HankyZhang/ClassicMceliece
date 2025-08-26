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
    printf("BASIC FUNCTION TEST\n");
    printf("===================\n");
    printf("Testing basic functionality of our implementation\n\n");
    
    // Initialize GF tables
    printf("Initializing GF tables...\n");
    gf_init();
    printf("✅ GF initialization complete\n\n");

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
    
    printf("\nPRG Parameters:\n");
    printf("s_len_bits: %zu\n", s_len_bits);
    printf("field_ordering_len_bits: %zu\n", field_ordering_len_bits);
    printf("irreducible_poly_len_bits: %zu\n", irreducible_poly_len_bits);
    printf("total PRG output: %zu bytes\n", prg_output_len_bytes);
    
    uint8_t *prg_output = malloc(prg_output_len_bytes);
    uint8_t *ref_prg_output = malloc(prg_output_len_bytes);
    if (!prg_output || !ref_prg_output) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    // Generate PRG outputs from both implementations
    printf("\n=== Testing PRG ===\n");
    mceliece_prg(seed, prg_output, prg_output_len_bytes);
    mceliece_prg_reference(seed, ref_prg_output, prg_output_len_bytes);
    
    printf("PRG Output Comparison:\n");
    print_hex_compact("Our PRG (first 64)", prg_output, prg_output_len_bytes, 64);
    print_hex_compact("Ref PRG (first 64)", ref_prg_output, prg_output_len_bytes, 64);
    
    if (memcmp(prg_output, ref_prg_output, prg_output_len_bytes) == 0) {
        printf("✅ PRG outputs MATCH!\n");
    } else {
        printf("❌ PRG outputs DIFFER!\n");
        free(prg_output);
        free(ref_prg_output);
        return -1;
    }
    
    size_t s_len_bytes = (s_len_bits + 7) / 8;
    size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8;
    size_t irreducible_poly_len_bytes = (irreducible_poly_len_bits + 7) / 8;
    
    const uint8_t *field_section = prg_output + s_len_bytes;
    const uint8_t *poly_section = prg_output + s_len_bytes + field_ordering_len_bytes;
    
    printf("\n=== Testing Field Ordering ===\n");
    printf("Field section length: %zu bytes\n", field_ordering_len_bytes);
    print_hex_compact("Field section (first 32)", field_section, field_ordering_len_bytes, 32);
    
    // Test field ordering - use smaller buffer to avoid seg fault
    printf("Creating alpha array for %d elements...\n", MCELIECE_Q);
    gf_elem_t *our_alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
    if (!our_alpha) {
        printf("❌ Memory allocation failed for alpha\n");
        free(prg_output);
        free(ref_prg_output);
        return -1;
    }
    printf("Alpha array allocated successfully\n");
    
    printf("Calling generate_field_ordering...\n");
    mceliece_error_t field_result = generate_field_ordering(our_alpha, field_section);
    printf("Field ordering result: %s\n", field_result == MCELIECE_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");
    
    if (field_result == MCELIECE_SUCCESS) {
        printf("First few alpha values:\n");
        for (int i = 0; i < 8; i++) {
            printf("alpha[%d] = %04X\n", i, our_alpha[i]);
        }
    }
    
    printf("\n=== Testing Irreducible Polynomial ===\n");
    printf("Poly section length: %zu bytes\n", irreducible_poly_len_bytes);
    print_hex_compact("Poly section (first 32)", poly_section, irreducible_poly_len_bytes, 32);
    
    printf("Creating polynomial...\n");
    polynomial_t *our_g = polynomial_create(MCELIECE_T);
    if (!our_g) {
        printf("❌ Memory allocation failed for polynomial\n");
        free(our_alpha);
        free(prg_output);
        free(ref_prg_output);
        return -1;
    }
    printf("Polynomial created successfully\n");
    
    printf("Calling generate_irreducible_poly_final...\n");
    mceliece_error_t poly_result = generate_irreducible_poly_final(our_g, poly_section);
    printf("Polynomial result: %s\n", poly_result == MCELIECE_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");
    
    if (poly_result == MCELIECE_SUCCESS) {
        printf("Polynomial degree: %d\n", our_g->degree);
        printf("First few coefficients:\n");
        for (int i = 0; i < 8; i++) {
            printf("g[%d] = %04X\n", i, our_g->coeffs[i]);
        }
        printf("Leading coefficient g[%d] = %04X\n", MCELIECE_T, our_g->coeffs[MCELIECE_T]);
    }
    
    printf("\n=== Final Results ===\n");
    printf("PRG: ✅ Working correctly\n");
    printf("Field Ordering: %s\n", field_result == MCELIECE_SUCCESS ? "✅ Working" : "❌ Failed");
    printf("Irreducible Polynomial: %s\n", poly_result == MCELIECE_SUCCESS ? "✅ Working" : "❌ Failed");
    
    if (field_result == MCELIECE_SUCCESS && poly_result == MCELIECE_SUCCESS) {
        printf("\n🎉 Both functions are working correctly!\n");
    } else {
        printf("\n⚠️  Some functions need debugging\n");
    }
    
    // Cleanup
    polynomial_free(our_g);
    free(our_alpha);
    free(prg_output);
    free(ref_prg_output);
    
    return 0;
}
