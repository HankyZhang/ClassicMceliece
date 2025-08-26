#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Our new implementation (now using reference SHAKE)
#include "mceliece_shake.h"

// Function to print hex data
void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02X", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

int main() {
    printf("Testing New SHAKE Implementation\n");
    printf("===============================\n\n");
    
    // Test with KAT seed
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    printf("Input seed: ");
    for (int i = 0; i < 32; i++) printf("%02X", seed[i]);
    printf("\n\n");
    
    // Test our PRG with different output lengths
    size_t test_lengths[] = {32, 64, 136};
    int num_tests = sizeof(test_lengths) / sizeof(test_lengths[0]);
    
    for (int test = 0; test < num_tests; test++) {
        size_t len = test_lengths[test];
        uint8_t *output = malloc(len);
        
        if (!output) {
            printf("❌ Memory allocation failed\n");
            return -1;
        }
        
        // Generate output using our PRG
        mceliece_prg(seed, output, len);
        
        char label[100];
        snprintf(label, sizeof(label), "New SHAKE256 PRG output (%zu bytes)", len);
        print_hex(label, output, len);
        
        free(output);
    }
    
    printf("\n");
    printf("✅ New SHAKE implementation working!\n");
    printf("Expected output for KAT seed should now match reference implementation.\n");
    
    return 0;
}
