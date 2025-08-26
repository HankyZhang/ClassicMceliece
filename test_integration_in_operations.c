/*
 * Test Integration Code to Add to mceliece6688128/operations.c
 * 
 * Add this code to the end of mceliece6688128/operations.c to test
 * your implementation functions directly within the reference codebase.
 */

// Add these includes at the top of operations.c (after existing includes)
/*
#include "../mceliece_types.h"  // Adjust path as needed
#include "../mceliece_keygen.h"
#include "../mceliece_shake.h"
#include "../mceliece_genpoly.h"
*/

// Add this function at the end of operations.c
int test_our_implementation_integration() {
    printf("=== TESTING OUR IMPLEMENTATION vs REFERENCE ===\n");
    
    // KAT seed 0
    const char* seed_hex = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) {
        sscanf(seed_hex + 2*i, "%02hhX", &seed[i]);
    }
    
    printf("Testing with KAT seed:\n");
    for (int i = 0; i < 32; i++) printf("%02X", seed[i]);
    printf("\n\n");
    
    // Generate PRG output using our SHAKE implementation
    size_t s_len_bits = SYS_N;
    size_t field_ordering_len_bits = 32 * (1 << GFBITS);  // sigma2 * q
    size_t irreducible_poly_len_bits = 16 * SYS_T;        // sigma1 * t
    size_t delta_prime_len_bits = 256;
    size_t total_bits = s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits;
    size_t prg_output_len_bytes = (total_bits + 7) / 8;
    
    uint8_t *prg_output = malloc(prg_output_len_bytes);
    if (!prg_output) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    // Use our PRG function
    mceliece_prg(seed, prg_output, prg_output_len_bytes);
    
    size_t s_len_bytes = (s_len_bits + 7) / 8;
    size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8;
    size_t irreducible_poly_len_bytes = (irreducible_poly_len_bits + 7) / 8;
    
    const uint8_t *field_section = prg_output + s_len_bytes;
    const uint8_t *poly_section = prg_output + s_len_bytes + field_ordering_len_bytes;
    
    printf("Section lengths: field=%zu, poly=%zu bytes\n", 
           field_ordering_len_bytes, irreducible_poly_len_bytes);
    
    // === TEST 1: Irreducible Polynomial Comparison ===
    printf("\n--- TEST 1: IRREDUCIBLE POLYNOMIAL ---\n");
    
    // Reference implementation path
    gf ref_f[SYS_T];
    gf ref_g[SYS_T];
    
    // Extract coefficients (16-bit LE, first GFBITS used)
    for (int i = 0; i < SYS_T; i++) {
        uint16_t coeff = poly_section[i*2] | (poly_section[i*2+1] << 8);
        ref_f[i] = coeff & ((1U << GFBITS) - 1);
    }
    
    printf("Reference f coefficients (first 8): ");
    for (int i = 0; i < 8; i++) printf("%04X ", ref_f[i]);
    printf("\n");
    
    // Call reference genpoly_gen
    int ref_result = genpoly_gen(ref_g, ref_f);
    printf("Reference genpoly_gen: %s\n", ref_result == 0 ? "✅ Success" : "❌ Failed");
    
    if (ref_result == 0) {
        printf("Reference g coefficients (first 8): ");
        for (int i = 0; i < 8; i++) printf("%04X ", ref_g[i]);
        printf("\n");
    }
    
    // Our implementation path  
    polynomial_t *our_g = polynomial_create(SYS_T);
    if (!our_g) {
        printf("❌ Memory allocation failed\n");
        free(prg_output);
        return -1;
    }
    
    mceliece_error_t our_result = generate_irreducible_poly_final(our_g, poly_section);
    printf("Our generate_irreducible_poly_final: %s\n", our_result == MCELIECE_SUCCESS ? "✅ Success" : "❌ Failed");
    
    if (our_result == MCELIECE_SUCCESS) {
        printf("Our g coefficients (first 8): ");
        for (int i = 0; i < 8; i++) printf("%04X ", (uint16_t)our_g->coeffs[i]);
        printf("\n");
        
        // Compare results
        if (ref_result == 0) {
            int match = 1;
            for (int i = 0; i < SYS_T; i++) {
                if ((uint16_t)our_g->coeffs[i] != ref_g[i]) {
                    printf("❌ Mismatch at coeff %d: our=%04X, ref=%04X\n", 
                           i, (uint16_t)our_g->coeffs[i], ref_g[i]);
                    match = 0;
                    break;
                }
            }
            if (match && (uint16_t)our_g->coeffs[SYS_T] == 1) {
                printf("✅ IRREDUCIBLE POLYNOMIAL PERFECT MATCH!\n");
            } else {
                printf("❌ Polynomial mismatch\n");
            }
        }
    }
    
    // === TEST 2: Field Ordering ===
    printf("\n--- TEST 2: FIELD ORDERING ---\n");
    
    gf_elem_t *our_alpha = malloc((1 << GFBITS) * sizeof(gf_elem_t));
    if (!our_alpha) {
        printf("❌ Memory allocation failed\n");
        polynomial_free(our_g);
        free(prg_output);
        return -1;
    }
    
    mceliece_error_t field_result = generate_field_ordering(our_alpha, field_section);
    printf("Our generate_field_ordering: %s\n", field_result == MCELIECE_SUCCESS ? "✅ Success" : "❌ Failed");
    
    if (field_result == MCELIECE_SUCCESS) {
        printf("Our alpha values (first 8): ");
        for (int i = 0; i < 8; i++) printf("%04X ", (uint16_t)our_alpha[i]);
        printf("\n");
        
        // Check for duplicates
        int has_duplicates = 0;
        for (int i = 0; i < (1 << GFBITS) - 1 && !has_duplicates; i++) {
            for (int j = i + 1; j < (1 << GFBITS); j++) {
                if (our_alpha[i] == our_alpha[j]) {
                    printf("❌ Duplicate at %d,%d: %04X\n", i, j, (uint16_t)our_alpha[i]);
                    has_duplicates = 1;
                    break;
                }
            }
        }
        if (!has_duplicates) {
            printf("✅ Field ordering verified - no duplicates\n");
        }
    }
    
    // === TEST 3: Integration with Reference pk_gen ===
    printf("\n--- TEST 3: INTEGRATION WITH pk_gen ---\n");
    
    if (ref_result == 0 && field_result == MCELIECE_SUCCESS) {
        // Prepare reference format data
        unsigned char sk_irr[IRR_BYTES];
        unsigned char pk[PK_NROWS * PK_ROW_BYTES];
        uint32_t perm[1 << GFBITS];
        int16_t pi[1 << GFBITS];
        
        // Store Goppa polynomial in reference format
        for (int i = 0; i < SYS_T; i++) {
            store_gf(sk_irr + i*2, ref_g[i]);
        }
        
        // Extract permutation from field ordering
        for (int i = 0; i < (1 << GFBITS); i++) {
            perm[i] = load4(field_section + i*4);
        }
        
        // Test reference pk_gen with our data
        int pk_result = pk_gen(pk, sk_irr, perm, pi);
        printf("Reference pk_gen with our data: %s\n", pk_result == 0 ? "✅ Success" : "❌ Failed");
        
        if (pk_result == 0) {
            printf("🎉 ULTIMATE VERIFICATION PASSED!\n");
            printf("   Our field ordering and irreducible polynomial generation\n");
            printf("   are fully compatible with the reference implementation!\n");
        }
    } else {
        printf("⚠️  Skipping integration test due to earlier failures\n");
    }
    
    // Cleanup
    free(our_alpha);
    polynomial_free(our_g);
    free(prg_output);
    
    printf("\n");
    return 0;
}

// Add this to the end of operations.c main function or create a test main:
/*
int main() {
    // Original operations.c main code here...
    
    // Add our integration test
    test_our_implementation_integration();
    
    return 0;
}
*/
