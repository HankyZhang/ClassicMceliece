#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Our implementation
#include "mceliece_types.h"
#include "mceliece_poly.h"
#include "mceliece_genpoly.h"

int main() {
    printf("POLYNOMIAL TEST ONLY\n");
    printf("====================\n");
    
    // Test basic polynomial functionality
    printf("Creating polynomial with degree %d...\n", MCELIECE_T);
    polynomial_t *g = polynomial_create(MCELIECE_T);
    if (!g) {
        printf("❌ Polynomial creation failed\n");
        return -1;
    }
    printf("✅ Polynomial created successfully\n");
    printf("Max degree: %d, current degree: %d\n", g->max_degree, g->degree);
    
    // Test setting some coefficients
    printf("Setting test coefficients...\n");
    for (int i = 0; i < 8; i++) {
        polynomial_set_coeff(g, i, i + 1);
    }
    
    printf("Test coefficients:\n");
    for (int i = 0; i < 8; i++) {
        printf("g[%d] = %d\n", i, g->coeffs[i]);
    }
    
    // Test our genpoly_gen directly with simple input
    printf("\nTesting genpoly_gen directly...\n");
    
    gf_elem_t *f = malloc(sizeof(gf_elem_t) * MCELIECE_T);
    gf_elem_t *result = malloc(sizeof(gf_elem_t) * MCELIECE_T);
    if (!f || !result) {
        printf("❌ Memory allocation failed\n");
        polynomial_free(g);
        return -1;
    }
    
    // Simple test input - all zeros except last one
    for (int i = 0; i < MCELIECE_T; i++) {
        f[i] = 0;
    }
    f[MCELIECE_T - 1] = 1;  // Ensure it's not zero
    
    printf("Input f coefficients (first 8):\n");
    for (int i = 0; i < 8; i++) {
        printf("f[%d] = %04X\n", i, f[i]);
    }
    
    printf("Calling genpoly_gen...\n");
    int gen_result = genpoly_gen(result, f);
    printf("genpoly_gen result: %s\n", gen_result == 0 ? "✅ SUCCESS" : "❌ FAILED");
    
    if (gen_result == 0) {
        printf("Output coefficients (first 8):\n");
        for (int i = 0; i < 8; i++) {
            printf("result[%d] = %04X\n", i, result[i]);
        }
    }
    
    // Cleanup
    free(f);
    free(result);
    polynomial_free(g);
    
    printf("\n✅ Polynomial tests completed\n");
    return 0;
}
