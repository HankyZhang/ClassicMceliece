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

// Test helpers
typedef struct { uint32_t val; uint16_t pos; } test_pair_t;
static int test_cmp_pairs(const void *A, const void *B) {
    const test_pair_t *x = (const test_pair_t*)A; 
    const test_pair_t *y = (const test_pair_t*)B;
    if (x->val < y->val) return -1; 
    if (x->val > y->val) return 1; 
    return (x->pos < y->pos) ? -1 : (x->pos > y->pos);
}

static uint16_t test_bitrev_m(uint16_t v, int m) {
    uint16_t r = 0; 
    for (int j = 0; j < m; j++) { 
        r = (uint16_t)((r << 1) | ((v >> j) & 1U)); 
    }
    return (uint16_t)(r & ((1U << m) - 1U));
}

static inline uint32_t load4_le(const unsigned char *src) {
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8) | 
           ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

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
    printf("FIELD ORDERING NUMERICAL COMPARISON TEST\n");
    printf("=========================================\n");
    printf("Testing field ordering with side-by-side comparison\n\n");
    
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
    
    uint8_t *prg_output = malloc(prg_output_len_bytes);
    uint8_t *ref_prg_output = malloc(prg_output_len_bytes);
    if (!prg_output || !ref_prg_output) {
        printf("❌ Memory allocation failed\n");
        return -1;
    }
    
    // Generate PRG outputs from both implementations
    mceliece_prg(seed, prg_output, prg_output_len_bytes);
    mceliece_prg_reference(seed, ref_prg_output, prg_output_len_bytes);
    
    if (memcmp(prg_output, ref_prg_output, prg_output_len_bytes) == 0) {
        printf("✅ PRG outputs MATCH - inputs will be identical!\n\n");
    } else {
        printf("❌ PRG outputs DIFFER - stopping test\n");
        free(prg_output);
        free(ref_prg_output);
        return -1;
    }
    
    size_t s_len_bytes = (s_len_bits + 7) / 8;
    size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8;
    
    const uint8_t *field_section = prg_output + s_len_bytes;
    
    printf("Field Ordering Input Data:\n");
    printf("Field section length: %zu bytes (%d 32-bit values)\n", field_ordering_len_bytes, MCELIECE_Q);
    print_hex_compact("Field section (first 64)", field_section, field_ordering_len_bytes, 64);
    
    // Show some input values
    printf("\nInput 32-bit values (first 16):\n");
    printf("Index   Value (LE)    Hex        Binary (first 8 bits)\n");
    printf("-----   ----------    --------   --------------------\n");
    for (int i = 0; i < 16; i++) {
        uint32_t val = load4_le(field_section + i * 4);
        printf("%3d     %10u    %08X\n", i, val, val);
    }

    // ==========================================
    // TEST 1: OUR IMPLEMENTATION
    // ==========================================
    printf("\n");
    for(int i = 0; i < 80; i++) printf("=");
    printf("\nTEST 1: OUR FIELD ORDERING IMPLEMENTATION\n");
    for(int i = 0; i < 80; i++) printf("=");
    printf("\n");
    
    gf_elem_t *our_alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
    if (!our_alpha) {
        printf("❌ Memory allocation failed\n");
        free(prg_output);
        free(ref_prg_output);
        return -1;
    }
    
    printf("Calling our generate_field_ordering...\n");
    mceliece_error_t field_result = generate_field_ordering(our_alpha, field_section);
    printf("Result: %s\n", field_result == MCELIECE_SUCCESS ? "✅ SUCCESS" : "❌ FAILED");
    
    if (field_result == MCELIECE_SUCCESS) {
        printf("\nOur output alpha values (first 32):\n");
        printf("Index   Alpha Value   Hex    Binary (first 8 bits)\n");
        printf("-----   -----------   ----   --------------------\n");
        for (int i = 0; i < 32; i++) {
            printf("%3d     %5d         %04X\n", i, our_alpha[i], our_alpha[i]);
        }
        
        // Check for duplicates
        printf("\nChecking for duplicates in our output...\n");
        int our_has_duplicates = 0;
        for (int i = 0; i < MCELIECE_Q - 1 && !our_has_duplicates; i++) {
            for (int j = i + 1; j < MCELIECE_Q; j++) {
                if (our_alpha[i] == our_alpha[j]) {
                    printf("❌ Duplicate found at indices %d and %d: %04X\n", 
                           i, j, our_alpha[i]);
                    our_has_duplicates = 1;
                    break;
                }
            }
            if (i > 0 && i % 1000 == 0) {
                printf("  Checked %d values...\n", i);
            }
        }
        
        if (!our_has_duplicates) {
            printf("✅ No duplicates found - field ordering is valid!\n");
        }
    }
    
    // ==========================================
    // TEST 2: REFERENCE-STYLE IMPLEMENTATION
    // ==========================================
    printf("\n");
    for(int i = 0; i < 80; i++) printf("=");
    printf("\nTEST 2: REFERENCE-STYLE FIELD ORDERING\n");
    for(int i = 0; i < 80; i++) printf("=");
    printf("\n");
    
    test_pair_t *pairs = malloc(MCELIECE_Q * sizeof(test_pair_t));
    gf_elem_t *ref_alpha = malloc(MCELIECE_Q * sizeof(gf_elem_t));
    if (!pairs || !ref_alpha) {
        printf("❌ Memory allocation failed\n");
        free(our_alpha);
        free(prg_output);
        free(ref_prg_output);
        return -1;
    }
    
    printf("Building reference algorithm...\n");
    
    // Extract values and create pairs
    for (int i = 0; i < MCELIECE_Q; i++) {
        pairs[i].val = load4_le(field_section + i * 4);
        pairs[i].pos = (uint16_t)i;
    }
    
    printf("Sorting %d pairs...\n", MCELIECE_Q);
    qsort(pairs, MCELIECE_Q, sizeof(test_pair_t), test_cmp_pairs);
    
    // Check for duplicates in reference path
    printf("Checking for duplicates in reference algorithm...\n");
    int ref_has_duplicates = 0;
    for (int i = 0; i < MCELIECE_Q - 1; i++) {
        if (pairs[i].val == pairs[i+1].val) {
            ref_has_duplicates = 1;
            printf("❌ Duplicate values found at indices %d and %d: %08X\n", 
                   i, i+1, pairs[i].val);
            break;
        }
    }
    
    if (ref_has_duplicates) {
        printf("❌ Reference algorithm found duplicates - test invalid\n");
    } else {
        printf("✅ No duplicates in reference algorithm\n");
        
        // Generate alpha values using bit-reversal
        printf("Generating alpha values using bit-reversal...\n");
        for (int i = 0; i < MCELIECE_Q; i++) {
            uint16_t pi = pairs[i].pos;
            ref_alpha[i] = (gf_elem_t)test_bitrev_m(pi, MCELIECE_M);
        }
        
        printf("Reference output alpha values (first 32):\n");
        printf("Index   Alpha Value   Hex    Original Pos   After Sort\n");
        printf("-----   -----------   ----   ------------   ----------\n");
        for (int i = 0; i < 32; i++) {
            printf("%3d     %5d         %04X   %5d          %08X\n", 
                   i, ref_alpha[i], ref_alpha[i], pairs[i].pos, pairs[i].val);
        }
    }
    
    // ==========================================
    // TEST 3: NUMERICAL COMPARISON
    // ==========================================
    if (field_result == MCELIECE_SUCCESS && !ref_has_duplicates) {
        printf("\n");
        for(int i = 0; i < 80; i++) printf("=");
        printf("\nTEST 3: NUMERICAL COMPARISON\n");
        for(int i = 0; i < 80; i++) printf("=");
        printf("\n");
        
        printf("Comparing alpha values...\n");
        printf("Index   Our Alpha  Ref Alpha  Match   Diff\n");
        printf("-----   ---------  ---------  -----   ----\n");
        
        int matches = 0;
        int first_mismatch = -1;
        for (int i = 0; i < MCELIECE_Q; i++) {
            int match = (our_alpha[i] == ref_alpha[i]);
            if (match) {
                matches++;
            } else if (first_mismatch == -1) {
                first_mismatch = i;
            }
            
            if (i < 32) {  // Show first 32 for detailed view
                printf("%3d     %04X       %04X       %s     %s\n", 
                       i, our_alpha[i], ref_alpha[i], 
                       match ? "✓" : "✗",
                       match ? "   " : "<<<");
            }
        }
        
        printf("...     ....       ....       ...     ...\n");
        
        printf("\nComparison Summary:\n");
        printf("Total values: %d\n", MCELIECE_Q);
        printf("Matches: %d\n", matches);
        printf("Mismatches: %d\n", MCELIECE_Q - matches);
        
        if (matches == MCELIECE_Q) {
            printf("🎉 PERFECT MATCH! Your field ordering is identical to reference!\n");
        } else {
            printf("⚠️  Found %d differences\n", MCELIECE_Q - matches);
            if (first_mismatch >= 0) {
                printf("First mismatch at index %d: our=%04X, ref=%04X\n", 
                       first_mismatch, our_alpha[first_mismatch], ref_alpha[first_mismatch]);
            }
        }
        
        printf("\nMatch percentage: %.2f%%\n", (100.0 * matches) / MCELIECE_Q);
    }
    
    // ======================
    // FINAL SUMMARY
    // ======================
    printf("\n");
    for(int i = 0; i < 80; i++) printf("=");
    printf("\nFINAL SUMMARY\n");
    for(int i = 0; i < 80; i++) printf("=");
    printf("\n");
    
    printf("Test Results:\n");
    printf("1. PRG Generation: ✅ Identical to reference\n");
    printf("2. Our Field Ordering: %s\n", 
           (field_result == MCELIECE_SUCCESS) ? "✅ Generated successfully" : "❌ Failed");
    printf("3. Reference Field Ordering: %s\n", 
           !ref_has_duplicates ? "✅ Generated successfully" : "❌ Failed");
    
    if (field_result == MCELIECE_SUCCESS && !ref_has_duplicates) {
        int matches = 0;
        for (int i = 0; i < MCELIECE_Q; i++) {
            if (our_alpha[i] == ref_alpha[i]) matches++;
        }
        printf("4. Numerical Comparison: %s (%d/%d matches)\n", 
               (matches == MCELIECE_Q) ? "✅ Perfect match" : "❌ Differences found", 
               matches, MCELIECE_Q);
        
        if (matches == MCELIECE_Q) {
            printf("\n🎉 CONGRATULATIONS!\n");
            printf("Your field ordering implementation produces IDENTICAL results\n");
            printf("to the reference algorithm. This proves your implementation is correct!\n");
        } else {
            printf("\n🔍 DEBUGGING NEEDED\n");
            printf("Your implementation differs from the reference. Check:\n");
            printf("  - Input parsing (32-bit little-endian values)\n");
            printf("  - Sorting algorithm (stable sort by value, then position)\n");
            printf("  - Bit-reversal implementation\n");
        }
    }
    
    // Cleanup
    free(pairs);
    free(ref_alpha);
    free(our_alpha);
    free(prg_output);
    free(ref_prg_output);
    
    return 0;
}
