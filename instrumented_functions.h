#ifndef INSTRUMENTED_FUNCTIONS_H
#define INSTRUMENTED_FUNCTIONS_H

#include "function_profiler.h"
#include "mceliece_kem.h"
#include "mceliece_keygen.h"
#include "mceliece_encode.h"
#include "mceliece_decode.h"
#include "mceliece_genpoly.h"
#include "mceliece_matrix_ops.h"
#include "mceliece_vector.h"
#include "mceliece_shake.h"

// Enable/disable profiling
extern int g_profiling_enabled;

// Instrumented wrapper functions that add profiling to key operations
// These will call the profiler before/after the actual implementation

// Key generation components
mceliece_error_t instrumented_seeded_key_gen(const uint8_t *delta, public_key_t *pk, private_key_t *sk);
mceliece_error_t instrumented_irreducible_poly_gen(const gf_elem_t *f, polynomial_t *poly);
mceliece_error_t instrumented_systematic_form(matrix_t *T, gf_elem_t *alpha, polynomial_t *g);
void instrumented_controlbits_from_pi(uint8_t *controlbits, const int16_t *pi, size_t *cb_len);

// Encapsulation components
mceliece_error_t instrumented_fixed_weight_vector(uint8_t *e, int n, int t);
void instrumented_encode_vector(const uint8_t *e, const matrix_t *T, uint8_t *ciphertext);

// Decapsulation components  
mceliece_error_t instrumented_decode_goppa(const uint8_t *v, const polynomial_t *g, 
                                         const gf_elem_t *L, uint8_t *e, int *success);
void instrumented_compute_syndrome(const uint8_t *e, const polynomial_t *g, 
                                 const gf_elem_t *alpha, gf_elem_t *syndrome);
mceliece_error_t instrumented_berlekamp_massey(const gf_elem_t *syndrome, polynomial_t *sigma);
mceliece_error_t instrumented_chien_search(const polynomial_t *sigma, const gf_elem_t *alpha, 
                                          int *found_positions, int *num_found);

// Matrix operations
void instrumented_matrix_vector_multiply(const matrix_t *M, const uint8_t *v, uint8_t *result);
mceliece_error_t instrumented_matrix_row_echelon(matrix_t *M);

// Polynomial operations
gf_elem_t instrumented_polynomial_eval(const polynomial_t *poly, gf_elem_t x);

// Hash operations
void instrumented_shake256(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len);

// Utility functions to enable/disable profiling
void enable_function_profiling(void);
void disable_function_profiling(void);
int is_profiling_enabled(void);

// Macro to conditionally profile a function call
#define PROFILE_CALL(func_name, call) \
    do { \
        if (g_profiling_enabled) { \
            PROFILE_START(func_name); \
            call; \
            PROFILE_END(func_name); \
        } else { \
            call; \
        } \
    } while(0)

#endif // INSTRUMENTED_FUNCTIONS_H
