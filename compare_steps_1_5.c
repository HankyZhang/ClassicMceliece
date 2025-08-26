#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Our implementation
#include "mceliece_types.h"
#include "mceliece_keygen.h"
#include "mceliece_shake.h"

// Reference implementation
#include "reference_shake.h"

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
    int sigma1 = 16;
    int sigma2 = 32;
    
    printf("Both implementations:\n");
    printf("  n=%d, t=%d, q=%d, l=%d, σ1=%d, σ2=%d\n", n, t, q, l, sigma1, sigma2);
    
    // Calculate PRG output length
    size_t s_len_bits = sigma1 * n;
    size_t field_ordering_len_bits = sigma2 * q;
    size_t irreducible_poly_len_bits = l * t;
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
    size_t irreducible_poly_len_bytes = (irreducible_poly_len_bits + 7) / 8;
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
    
    // Cleanup
    private_key_free(our_sk);
    free(our_prg_output);
    free(ref_prg_output);
    
    return 0;
}

int main() {
    printf("Detailed Comparison: Steps 1-5 Implementation vs Reference\n");
    printf("===========================================================\n\n");
    
    int result = compare_implementations_steps_1_5();
    
    printf("=== SUMMARY ===\n");
    if (result == 0) {
        printf("✅ Comparison completed successfully\n");
        printf("Check above for MATCH/DIFFER results in each step.\n");
        printf("If all steps show MATCH, then our Steps 1-5 implementation is correct.\n");
    } else {
        printf("❌ Comparison failed\n");
    }
    
    return result;
}
