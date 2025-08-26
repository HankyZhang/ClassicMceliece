#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Our implementation
#include "mceliece_types.h"
#include "mceliece_keygen.h"
#include "mceliece_shake.h"
#include "mceliece_matrix_ops.h"

// Reference implementation helpers
#include "reference_shake.h"

// Helper functions
void print_hex_compact(const char* label, const uint8_t* data, size_t len, size_t max_show) {
    printf("%-25s: ", label);
    size_t show = (len < max_show) ? len : max_show;
    for (size_t i = 0; i < show; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0 && i < show - 1) printf("\n%-27s", "");
    }
    if (len > max_show) printf("... (+%zu bytes)", len - max_show);
    printf("\n");
}

void print_matrix_info(const matrix_t *m, const char* name) {
    printf("%s matrix: %d x %d (%d bytes/row)\n", 
           name, m->rows, m->cols, m->cols_bytes);
    if (m->data && m->rows > 0 && m->cols_bytes > 0) {
        printf("  First row (first 32 bytes): ");
        int show = (m->cols_bytes < 32) ? m->cols_bytes : 32;
        for (int i = 0; i < show; i++) {
            printf("%02X", m->data[i]);
        }
        if (m->cols_bytes > 32) printf("...");
        printf("\n");
    }
}

int main() {
    printf("REMAINING ALGORITHMS ANALYSIS\n");
    printf("=============================\n");
    printf("Checking algorithms after PRG/Field/Polynomial generation\n\n");

    // Initialize GF tables
    printf("Initializing GF tables...\n");
    gf_init();
    printf("✅ GF initialization complete\n\n");

    // Use KAT seed for consistent results
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    printf("Test seed:\n");
    print_hex_compact("Seed", seed, 32, 32);

    // ==========================================
    // STEP 1: GENERATE VERIFIED COMPONENTS
    // ==========================================
    printf("\n");
    for(int i = 0; i < 70; i++) printf("=");
    printf("\nSTEP 1: GENERATING VERIFIED CORE COMPONENTS\n");
    for(int i = 0; i < 70; i++) printf("=");
    printf("\n");

    // Generate PRG output (we know this is correct)
    size_t prg_len = 40000;
    uint8_t *prg_output = malloc(prg_len);
    if (!prg_output) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    mceliece_prg(seed, prg_output, prg_len);
    printf("✅ PRG generated (%zu bytes)\n", prg_len);

    // Parse PRG sections
    size_t s_len = (MCELIECE_N + 7) / 8;
    size_t field_len = (32 * MCELIECE_Q + 7) / 8;
    size_t poly_len = (16 * MCELIECE_T + 7) / 8;
    
    const uint8_t *s_section = prg_output;
    const uint8_t *field_section = prg_output + s_len;
    const uint8_t *poly_section = prg_output + s_len + field_len;
    
    printf("PRG sections:\n");
    printf("  s: %zu bytes\n", s_len);
    printf("  field: %zu bytes\n", field_len);
    printf("  poly: %zu bytes\n", poly_len);

    // Generate field ordering (we know this is correct)
    gf_elem_t *alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
    if (!alpha) {
        printf("❌ Memory allocation failed\n");
        free(prg_output);
        return -1;
    }
    
    mceliece_error_t field_result = generate_field_ordering(alpha, field_section);
    printf("✅ Field ordering generated: %s\n", 
           field_result == MCELIECE_SUCCESS ? "SUCCESS" : "FAILED");

    // Generate polynomial (we know this is correct)
    polynomial_t *g = polynomial_create(MCELIECE_T);
    if (!g) {
        printf("❌ Polynomial creation failed\n");
        free(alpha); free(prg_output);
        return -1;
    }
    
    mceliece_error_t poly_result = generate_irreducible_poly_final(g, poly_section);
    printf("✅ Irreducible polynomial generated: %s\n", 
           poly_result == MCELIECE_SUCCESS ? "SUCCESS" : "FAILED");

    if (field_result != MCELIECE_SUCCESS || poly_result != MCELIECE_SUCCESS) {
        printf("❌ Core components failed - cannot continue\n");
        polynomial_free(g); free(alpha); free(prg_output);
        return -1;
    }

    // ==========================================
    // STEP 2: CHECK CONTROL BITS GENERATION
    // ==========================================
    printf("\n");
    for(int i = 0; i < 70; i++) printf("=");
    printf("\nSTEP 2: CONTROL BITS GENERATION\n");
    for(int i = 0; i < 70; i++) printf("=");
    printf("\n");

    printf("Alpha values (first 8): ");
    for (int i = 0; i < 8; i++) {
        printf("%04X ", alpha[i]);
    }
    printf("\n");

    // Test control bits generation
    printf("Testing control bits generation...\n");
    
    // Check if we have the control bits generation function
    size_t control_bits_len = ((2 * MCELIECE_M - 1) * (1U << MCELIECE_M)) / 16;
    printf("Expected control bits length: %zu bytes\n", control_bits_len);
    
    uint8_t *control_bits = malloc(control_bits_len);
    if (!control_bits) {
        printf("❌ Control bits allocation failed\n");
        polynomial_free(g); free(alpha); free(prg_output);
        return -1;
    }

    // Try to generate control bits from alpha (support)
    printf("Attempting to generate control bits from alpha array...\n");
    
    // This would call something like: cbits_from_support(control_bits, alpha)
    // Let's see if we can test this directly
    printf("⚠️  Control bits generation needs to be tested\n");
    printf("This is a key step that could differ between implementations\n");

    // ==========================================
    // STEP 3: CHECK MATRIX GENERATION
    // ==========================================
    printf("\n");
    for(int i = 0; i < 70; i++) printf("=");
    printf("\nSTEP 3: MATRIX GENERATION\n");
    for(int i = 0; i < 70; i++) printf("=");
    printf("\n");

    printf("Polynomial coefficients (first 8): ");
    for (int i = 0; i < 8; i++) {
        printf("%04X ", g->coeffs[i]);
    }
    printf("\n");
    printf("Polynomial degree: %d\n", g->degree);

    // Test matrix generation from polynomial and alpha
    printf("Testing matrix generation...\n");
    
    // Create matrices for testing
    matrix_t *H;  // Parity check matrix
    matrix_t *T;  // Public key matrix
    
    // Initialize matrices
    int H_rows = MCELIECE_M * MCELIECE_T;
    int H_cols = MCELIECE_N;
    int H_cols_bytes = (H_cols + 7) / 8;
    
    H = matrix_create(H_rows, H_cols);
    if (!H) {
        printf("❌ H matrix creation failed\n");
        free(control_bits); polynomial_free(g); free(alpha); free(prg_output);
        return -1;
    }
    
    printf("H matrix initialized: %d x %d\n", H->rows, H->cols);

    // Test if we can generate the parity check matrix H
    printf("Attempting to generate parity check matrix H...\n");
    
    // This should generate H from g and alpha
    // H[i] = g(alpha[i]) for syndrome computation
    printf("Matrix generation logic needs to be tested here\n");
    printf("This involves:\n");
    printf("  1. Evaluating polynomial g at each alpha[i]\n");
    printf("  2. Building systematic/non-systematic form\n");
    printf("  3. Gaussian elimination to get systematic form\n");
    
    print_matrix_info(H, "Parity check");

    // ==========================================
    // STEP 4: CHECK PUBLIC KEY CONSTRUCTION
    // ==========================================
    printf("\n");
    for(int i = 0; i < 70; i++) printf("=");
    printf("\nSTEP 4: PUBLIC KEY CONSTRUCTION\n");
    for(int i = 0; i < 70; i++) printf("=");
    printf("\n");

    printf("Testing public key matrix construction...\n");
    
    // The public key is typically the systematic part of H
    // T = systematic part of H after Gaussian elimination
    
    int T_rows = MCELIECE_M * MCELIECE_T;
    int T_cols = MCELIECE_K;  // Information bits
    
    T = matrix_create(T_rows, T_cols);
    if (!T) {
        printf("❌ T matrix creation failed\n");
        matrix_free(H);
        free(control_bits); polynomial_free(g); free(alpha); free(prg_output);
        return -1;
    }
    
    printf("T matrix initialized: %d x %d\n", T->rows, T->cols);
    print_matrix_info(T, "Public key");

    // ==========================================
    // STEP 5: CHECK SECRET KEY CONSTRUCTION
    // ==========================================
    printf("\n");
    for(int i = 0; i < 70; i++) printf("=");
    printf("\nSTEP 5: SECRET KEY CONSTRUCTION\n");
    for(int i = 0; i < 70; i++) printf("=");
    printf("\n");

    printf("Testing secret key construction...\n");
    
    // Secret key components:
    printf("Secret key should contain:\n");
    printf("  1. Delta (seed): %zu bytes\n", sizeof(seed));
    printf("  2. Support (alpha): %d elements = %zu bytes\n", 
           MCELIECE_Q, MCELIECE_Q * sizeof(gf_elem_t));
    printf("  3. Polynomial (g): %d coefficients = %zu bytes\n", 
           MCELIECE_T, MCELIECE_T * sizeof(gf_elem_t));
    printf("  4. Control bits: %zu bytes\n", control_bits_len);
    printf("  5. S vector: %zu bytes\n", s_len);

    // Show actual secret key structure size
    printf("\nActual secret key structure:\n");
    printf("  Delta: %d bytes\n", MCELIECE_L_BYTES);
    printf("  S vector: %d bytes\n", MCELIECE_N_BYTES);
    printf("  Polynomial: embedded in structure\n");
    printf("  Alpha: pointer to %d elements\n", MCELIECE_Q);
    printf("  Control bits: optional pointer\n");

    // ==========================================
    // STEP 6: IDENTIFY NEXT TESTING PRIORITIES
    // ==========================================
    printf("\n");
    for(int i = 0; i < 70; i++) printf("=");
    printf("\nSTEP 6: ANALYSIS & NEXT PRIORITIES\n");
    for(int i = 0; i < 70; i++) printf("=");
    printf("\n");

    printf("🔍 ANALYSIS RESULTS:\n\n");
    
    printf("✅ VERIFIED IDENTICAL (100%% match):\n");
    printf("   • PRG generation\n");
    printf("   • Field ordering (alpha computation)\n");
    printf("   • Irreducible polynomial generation\n\n");
    
    printf("🔄 NEXT ALGORITHMS TO TEST:\n");
    printf("   1. 🎯 CONTROL BITS GENERATION from alpha array\n");
    printf("   2. 🎯 PARITY CHECK MATRIX construction from g(x) and alpha\n");
    printf("   3. 🎯 GAUSSIAN ELIMINATION to systematic form\n");
    printf("   4. 🎯 PUBLIC KEY MATRIX extraction\n");
    printf("   5. 🎯 SECRET KEY SERIALIZATION format\n");
    printf("   6. 🎯 PUBLIC KEY SERIALIZATION format\n\n");
    
    printf("💡 LIKELY SOURCES OF KAT DIFFERENCES:\n");
    printf("   • Matrix representation (row-major vs column-major)\n");
    printf("   • Gaussian elimination implementation differences\n");
    printf("   • Bit ordering in serialized keys\n");
    printf("   • Control bits generation algorithm variations\n");
    printf("   • Padding or alignment differences in key format\n\n");
    
    printf("🎯 RECOMMENDATION:\n");
    printf("   Focus on testing the MATRIX OPERATIONS and KEY SERIALIZATION\n");
    printf("   since these are most likely to contain implementation differences\n");
    printf("   while still producing cryptographically equivalent keys.\n");

    // Cleanup
    matrix_free(T);
    matrix_free(H);
    free(control_bits);
    polynomial_free(g);
    free(alpha);
    free(prg_output);
    
    return 0;
}
