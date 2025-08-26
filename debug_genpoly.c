#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Our implementation
#include "mceliece_types.h"
#include "mceliece_gf.h"
#include "mceliece_genpoly.h"

void debug_print_f(const gf_elem_t *f, int count) {
    printf("f array (first %d): ", count);
    for (int i = 0; i < count; i++) {
        printf("%04X ", f[i]);
    }
    printf("\n");
}

int main() {
    printf("DEBUG: GENPOLY_GEN STEP BY STEP\n");
    printf("===============================\n");
    
    // Initialize GF tables FIRST!
    printf("Step 0: Initializing GF tables...\n");
    gf_init();
    printf("✅ GF tables initialized\n");
    
    // Test with very simple input first
    printf("Step 1: Testing with simple input...\n");
    
    gf_elem_t *f = malloc(sizeof(gf_elem_t) * MCELIECE_T);
    gf_elem_t *result = malloc(sizeof(gf_elem_t) * MCELIECE_T);
    if (!f || !result) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    // Initialize with simple values
    printf("Step 2: Initializing f array...\n");
    for (int i = 0; i < MCELIECE_T; i++) {
        f[i] = 0;
    }
    f[0] = 1;  // f(x) = 1 + x^127
    f[MCELIECE_T - 1] = 1;
    
    debug_print_f(f, 8);
    printf("f[%d] = %04X (should be 1)\n", MCELIECE_T - 1, f[MCELIECE_T - 1]);
    
    // Test GF operations first
    printf("\nStep 3: Testing basic GF operations...\n");
    gf_elem_t a = 0x1234;
    gf_elem_t b = 0x5678;
    gf_elem_t c = gf_add(a, b);
    gf_elem_t d = gf_mul(a, b);
    printf("GF add: %04X + %04X = %04X\n", a, b, c);
    printf("GF mul: %04X * %04X = %04X\n", a, b, d);
    
    // Test memory allocation for internal structures
    printf("\nStep 4: Testing memory allocation sizes...\n");
    int t = MCELIECE_T;
    int m = MCELIECE_M;
    printf("t = %d, m = %d\n", t, m);
    
    size_t cols_size = sizeof(gf_elem_t) * t * t;
    size_t vt_size = sizeof(gf_elem_t) * t;
    size_t nbin = m * t;
    size_t A_size = (size_t)nbin * (size_t)nbin;
    size_t b_size = (size_t)nbin;
    
    printf("cols_size: %zu bytes (%zu MB)\n", cols_size, cols_size / (1024*1024));
    printf("vt_size: %zu bytes\n", vt_size);
    printf("nbin: %zu\n", nbin);
    printf("A_size: %zu bytes (%zu MB)\n", A_size, A_size / (1024*1024));
    printf("b_size: %zu bytes\n", b_size);
    
    // Check if these allocations would succeed
    printf("\nStep 5: Testing individual allocations...\n");
    
    gf_elem_t *test_cols = malloc(cols_size);
    if (test_cols) {
        printf("✅ cols allocation succeeded\n");
        free(test_cols);
    } else {
        printf("❌ cols allocation FAILED\n");
        free(f);
        free(result);
        return -1;
    }
    
    unsigned char *test_A = malloc(A_size);
    if (test_A) {
        printf("✅ A allocation succeeded\n");
        free(test_A);
    } else {
        printf("❌ A allocation FAILED - matrix too large!\n");
        printf("   Trying to allocate %zu MB for binary matrix\n", A_size / (1024*1024));
        free(f);
        free(result);
        return -1;
    }
    
    unsigned char *test_b = malloc(b_size);
    if (test_b) {
        printf("✅ b allocation succeeded\n");
        free(test_b);
    } else {
        printf("❌ b allocation FAILED\n");
        free(f);
        free(result);
        return -1;
    }
    
    printf("\nStep 6: All allocations successful, testing genpoly_gen...\n");
    printf("Calling genpoly_gen with simple input...\n");
    
    int gen_result = genpoly_gen(result, f);
    printf("genpoly_gen result: %s\n", gen_result == 0 ? "✅ SUCCESS" : "❌ FAILED");
    
    if (gen_result == 0) {
        printf("Output coefficients (first 8):\n");
        for (int i = 0; i < 8; i++) {
            printf("result[%d] = %04X\n", i, result[i]);
        }
    } else {
        printf("❌ genpoly_gen failed with code %d\n", gen_result);
    }
    
    // Try with different input
    printf("\nStep 7: Testing with different input...\n");
    for (int i = 0; i < MCELIECE_T; i++) {
        f[i] = (i % 256);  // Simple pattern
    }
    f[MCELIECE_T - 1] = 1;  // Ensure not zero
    
    debug_print_f(f, 8);
    
    printf("Calling genpoly_gen with pattern input...\n");
    int gen_result2 = genpoly_gen(result, f);
    printf("genpoly_gen result: %s\n", gen_result2 == 0 ? "✅ SUCCESS" : "❌ FAILED");
    
    if (gen_result2 == 0) {
        printf("Output coefficients (first 8):\n");
        for (int i = 0; i < 8; i++) {
            printf("result[%d] = %04X\n", i, result[i]);
        }
    }
    
    // Cleanup
    free(f);
    free(result);
    
    printf("\n✅ Debug test completed\n");
    return 0;
}
