#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Our implementation
#include "mceliece_types.h"
#include "mceliece_keygen.h"
#include "mceliece_shake.h"

// Function to print hex data
void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 64; i++) {
        printf("%02X", data[i]);
        if (i > 0 && (i + 1) % 32 == 0) printf("\n    ");
    }
    if (len > 64) printf("... (%zu total bytes)", len);
    printf("\n");
}

int test_prg_output_consistency(const char* seed_hex) {
    printf("\n=== TESTING PRG OUTPUT CONSISTENCY ===\n");
    
    // Convert hex seed to bytes
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    print_hex("Input Seed", seed, 32);
    
    // Test PRG multiple times with same seed to ensure determinism
    size_t prg_len = 1000; // Test first 1000 bytes
    uint8_t *output1 = malloc(prg_len);
    uint8_t *output2 = malloc(prg_len);
    
    if (!output1 || !output2) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    // Generate PRG output twice
    mceliece_prg(seed, output1, prg_len);
    mceliece_prg(seed, output2, prg_len);
    
    // Check if they're identical
    if (memcmp(output1, output2, prg_len) == 0) {
        printf("✅ PRG output is deterministic\n");
    } else {
        printf("❌ PRG output is not deterministic!\n");
        print_hex("First call (first 64)", output1, 64);
        print_hex("Second call (first 64)", output2, 64);
        free(output1);
        free(output2);
        return -1;
    }
    
    print_hex("PRG output (first 64 bytes)", output1, 64);
    print_hex("PRG output (bytes 64-127)", output1 + 64, 64);
    
    free(output1);
    free(output2);
    return 0;
}

int test_field_ordering_consistency(const char* seed_hex) {
    printf("\n=== TESTING FIELD ORDERING CONSISTENCY ===\n");
    
    // Convert hex seed to bytes
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    // Generate PRG output
    int sigma2 = 32;
    int q_val = MCELIECE_Q;
    size_t field_ordering_len_bytes = (sigma2 * q_val + 7) / 8;
    size_t total_needed = 836 + field_ordering_len_bytes; // s_len + field_ordering
    
    uint8_t *E = malloc(total_needed);
    if (!E) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    mceliece_prg(seed, E, total_needed);
    
    // Extract field ordering section
    const uint8_t *field_ordering_bits_ptr = E + 836; // Skip s_len_bytes
    
    print_hex("Field ordering input (first 64)", field_ordering_bits_ptr, 64);
    
    // Test field ordering multiple times
    private_key_t *sk1 = private_key_create();
    private_key_t *sk2 = private_key_create();
    
    if (!sk1 || !sk2) {
        printf("❌ Key allocation failed\n");
        free(E);
        return -1;
    }
    
    // Generate field ordering twice
    mceliece_error_t result1 = generate_field_ordering(sk1->alpha, field_ordering_bits_ptr);
    mceliece_error_t result2 = generate_field_ordering(sk2->alpha, field_ordering_bits_ptr);
    
    if (result1 != MCELIECE_SUCCESS || result2 != MCELIECE_SUCCESS) {
        printf("❌ Field ordering failed (result1=%d, result2=%d)\n", result1, result2);
        private_key_free(sk1);
        private_key_free(sk2);
        free(E);
        return -1;
    }
    
    // Compare results
    if (memcmp(sk1->alpha, sk2->alpha, MCELIECE_Q * sizeof(gf_elem_t)) == 0) {
        printf("✅ Field ordering is deterministic\n");
    } else {
        printf("❌ Field ordering is not deterministic!\n");
        printf("First call alpha[0-7]: ");
        for (int i = 0; i < 8; i++) printf("%04X ", sk1->alpha[i]);
        printf("\n");
        printf("Second call alpha[0-7]: ");
        for (int i = 0; i < 8; i++) printf("%04X ", sk2->alpha[i]);
        printf("\n");
        private_key_free(sk1);
        private_key_free(sk2);
        free(E);
        return -1;
    }
    
    printf("Alpha values (first 16): ");
    for (int i = 0; i < 16; i++) {
        printf("%04X ", sk1->alpha[i]);
        if (i == 7) printf("\n                        ");
    }
    printf("\n");
    
    // Test if alpha values are distinct
    int duplicates = 0;
    for (int i = 0; i < MCELIECE_Q - 1; i++) {
        for (int j = i + 1; j < MCELIECE_Q; j++) {
            if (sk1->alpha[i] == sk1->alpha[j]) {
                duplicates++;
                if (duplicates <= 5) {
                    printf("❌ Duplicate found: alpha[%d] = alpha[%d] = %04X\n", i, j, sk1->alpha[i]);
                }
            }
        }
    }
    
    if (duplicates == 0) {
        printf("✅ All alpha values are distinct\n");
    } else {
        printf("❌ Found %d duplicate pairs\n", duplicates);
    }
    
    private_key_free(sk1);
    private_key_free(sk2);
    free(E);
    return (duplicates == 0) ? 0 : -1;
}

int main() {
    printf("Early Steps Consistency Test\n");
    printf("============================\n");
    
    // Use the KAT seed that was working
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    
    printf("Testing with KAT seed 0...\n");
    
    int prg_result = test_prg_output_consistency(seed_hex);
    int field_result = test_field_ordering_consistency(seed_hex);
    
    printf("\n=== SUMMARY ===\n");
    printf("PRG consistency: %s\n", prg_result == 0 ? "✅ PASS" : "❌ FAIL");
    printf("Field ordering consistency: %s\n", field_result == 0 ? "✅ PASS" : "❌ FAIL");
    
    if (prg_result == 0 && field_result == 0) {
        printf("\n✅ Steps 3-5 are internally consistent!\n");
        printf("🔍 To verify against reference, we need to compare these exact outputs\n");
        printf("   with what the reference implementation produces for the same seed.\n");
    } else {
        printf("\n❌ Found inconsistencies in our implementation\n");
    }
    
    return (prg_result == 0 && field_result == 0) ? 0 : 1;
}
