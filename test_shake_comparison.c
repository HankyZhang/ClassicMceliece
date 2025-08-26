#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Our implementation (now using reference SHAKE)
#include "mceliece_shake.h"

// Reference implementation for comparison
#include "reference_shake.h"

// Function to print hex data
void print_hex_comparison(const char* label, const unsigned char* data1, const unsigned char* data2, size_t len, const char* impl1, const char* impl2) {
    printf("%s:\n", label);
    printf("  %s: ", impl1);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02X", data1[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
    
    printf("  %s: ", impl2);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02X", data2[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
    
    if (memcmp(data1, data2, len) == 0) {
        printf("  ✅ MATCH\n");
    } else {
        printf("  ❌ DIFFERENT\n");
    }
    printf("\n");
}

int test_shake_with_kat_seed() {
    printf("=== Testing SHAKE implementations with KAT seed ===\n");
    
    // Convert KAT seed from hex
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    printf("Input seed: ");
    for (int i = 0; i < 32; i++) printf("%02X", seed[i]);
    printf("\n\n");
    
    // Test different output lengths
    size_t test_lengths[] = {32, 64, 136, 1000};
    int num_tests = sizeof(test_lengths) / sizeof(test_lengths[0]);
    
    for (int test = 0; test < num_tests; test++) {
        size_t len = test_lengths[test];
        uint8_t *our_output = malloc(len);
        uint8_t *ref_output = malloc(len);
        
        if (!our_output || !ref_output) {
            printf("❌ Memory allocation failed\n");
            return -1;
        }
        
        // Generate outputs
        mceliece_prg(seed, our_output, len);
        mceliece_prg_reference(seed, ref_output, len);
        
        char label[100];
        snprintf(label, sizeof(label), "SHAKE256 output (%zu bytes)", len);
        print_hex_comparison(label, our_output, ref_output, len, "Our SHAKE", "Ref SHAKE");
        
        free(our_output);
        free(ref_output);
    }
    
    return 0;
}

int test_shake_with_simple_inputs() {
    printf("=== Testing SHAKE implementations with simple inputs ===\n");
    
    // Test with empty input
    uint8_t empty_input[1] = {0};
    uint8_t our_output[64];
    uint8_t ref_output[64];
    
    mceliece_prg(empty_input, our_output, 64);
    mceliece_prg_reference(empty_input, ref_output, 64);
    
    print_hex_comparison("Empty input test", our_output, ref_output, 64, "Our SHAKE", "Ref SHAKE");
    
    // Test with simple pattern
    uint8_t pattern[32];
    for (int i = 0; i < 32; i++) pattern[i] = (uint8_t)i;
    
    mceliece_prg(pattern, our_output, 64);
    mceliece_prg_reference(pattern, ref_output, 64);
    
    print_hex_comparison("Pattern input test", our_output, ref_output, 64, "Our SHAKE", "Ref SHAKE");
    
    return 0;
}

int main() {
    printf("SHAKE Implementation Comparison Test\n");
    printf("===================================\n\n");
    
    int result1 = test_shake_with_simple_inputs();
    int result2 = test_shake_with_kat_seed();
    
    if (result1 == 0 && result2 == 0) {
        printf("=== SUMMARY ===\n");
        printf("Tests completed. Check above for MATCH/DIFFERENT results.\n");
        printf("If all tests show MATCH, our SHAKE implementation is correct.\n");
        printf("If any show DIFFERENT, we need to fix our SHAKE implementation.\n");
    } else {
        printf("❌ Some tests failed to run properly\n");
        return 1;
    }
    
    return 0;
}
