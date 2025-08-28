
#include "mceliece_decode.h"
#include "controlbits.h"


// Calculate syndrome from a received vector r (reference-style, like mceliece6688128/synd.c)
// Input: r is a length-n bit vector where r[0..mt-1] contains the ciphertext bits and the rest are zero
// Output: syndrome[0..2t-1]
void compute_syndrome(const uint8_t *received, const polynomial_t *g,
                      const gf_elem_t *alpha, gf_elem_t *syndrome) {
    if (!received || !g || !alpha || !syndrome) return;
    const char *env_debug = getenv("MCELIECE_DEBUG");
    int dbg_enabled = env_debug && env_debug[0] == '1';

    // Syndrome definition for H = [I | T] with H_{i,j} = α_j^i / g(α_j):
    // s_j = Σ_{i∈I} α_i^j / g(α_i)
    // where I is the set of error positions

    for (int j = 0; j < 2 * MCELIECE_T; j++) {
        syndrome[j] = 0;

        for (int i = 0; i < MCELIECE_N; i++) {
            if (vector_get_bit(received, i)) {
                gf_elem_t alpha_i = alpha[i];
                gf_elem_t g_alpha_i = polynomial_eval(g, alpha_i);

                if (g_alpha_i != 0) {
                    gf_elem_t alpha_power = gf_pow(alpha_i, j);
                    gf_elem_t g_squared = gf_mul(g_alpha_i, g_alpha_i);
                    gf_elem_t term = gf_div(alpha_power, g_squared);
                    syndrome[j] = gf_add(syndrome[j], term);
                }
            }

        }
        if (dbg_enabled && ((j & 7) == 7)) { printf("[decode] syndrome j=%d computed\n", j); fflush(stdout); }
    }
}


// Berlekamp-Massey Algorithm according to Classic McEliece specification
// Input: syndrome sequence s[0], s[1], ..., s[2t-1]
// Output: error locator polynomial sigma and error evaluator polynomial omega
mceliece_error_t berlekamp_massey(const gf_elem_t *syndrome,
                                  polynomial_t *sigma) {
    if (!syndrome || !sigma) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }
    const char *env_debug = getenv("MCELIECE_DEBUG");
    int dbg_enabled = env_debug && env_debug[0] == '1';

    // Initialize polynomials
    polynomial_t *C = polynomial_create(MCELIECE_T);  // Current connection polynomial
    polynomial_t *B = polynomial_create(MCELIECE_T);  // Backup polynomial
    polynomial_t *T = polynomial_create(MCELIECE_T);  // Temporary polynomial

    if (!C || !B || !T) {
        polynomial_free(C);
        polynomial_free(B);
        polynomial_free(T);
        return MCELIECE_ERROR_MEMORY;
    }

    // Initial state: C(x) = 1, B(x) = 1
    polynomial_set_coeff(C, 0, 1);
    polynomial_set_coeff(B, 0, 1);

    int L = 0;          // Current LFSR length
    int m = 1;          // Step counter since last L update
    gf_elem_t b = 1;    // Last best discrepancy

    // Iterate through each syndrome element
    for (int N = 0; N < 2 * MCELIECE_T; N++) {
        // Calculate discrepancy d_N = s_N + Σ C_i * s_{N-i}
        gf_elem_t d = syndrome[N];

        for (int i = 1; i <= L && (N - i) >= 0; i++) {
            if (i <= C->degree && C->coeffs[i] != 0) {
                d = gf_add(d, gf_mul(C->coeffs[i], syndrome[N - i]));
            }
        }

        if (d == 0) {
            // Discrepancy is 0, no correction needed
            m++;
        } else {
            // Discrepancy is non-zero, correction needed

            // Save current C to T: T(x) = C(x)
            polynomial_copy(T, C);

            // Correction: C(x) = C(x) - (d/b) * x^m * B(x)
            if (b != 0) {
                gf_elem_t correction_coeff = gf_div(d, b);

                for (int i = 0; i <= B->degree; i++) {
                    if (B->coeffs[i] != 0 && (i + m) <= C->max_degree) {
                        gf_elem_t term = gf_mul(correction_coeff, B->coeffs[i]);
                        gf_elem_t current_coeff = (i + m <= C->degree) ? C->coeffs[i + m] : 0;
                        gf_elem_t new_coeff = gf_add(current_coeff, term);
                        polynomial_set_coeff(C, i + m, new_coeff);
                    }
                }
            }

            // Check if L needs to be updated
            if (2 * L <= N) {
                L = N + 1 - L;
                polynomial_copy(B, T);  // B(x) = T(x) (the old C(x))
                b = d;
                m = 1;
            } else {
                m++;
            }
        }
        if (dbg_enabled && ((N & 7) == 7)) { printf("[BM] processed N=%d\n", N); fflush(stdout); }
    }

    // Output error locator polynomial
    polynomial_copy(sigma, C);

    // Cleanup
    polynomial_free(C);
    polynomial_free(B);
    polynomial_free(T);

    return MCELIECE_SUCCESS;
}

// Chien Search: Find roots of error locator polynomial
// Our BM produces a locator defined in terms of α_j^{-1}, so check σ(α_j^{-1}) = 0
mceliece_error_t chien_search(const polynomial_t *sigma, const gf_elem_t *alpha,
                              int *error_positions, int *num_errors) {
    if (!sigma || !alpha || !error_positions || !num_errors) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }
    const char *env_debug = getenv("MCELIECE_DEBUG");
    int dbg_enabled = env_debug && env_debug[0] == '1';

    *num_errors = 0;

    // For each element alpha[j] in the support set, check if σ(α_j^{-1}) = 0
    for (int j = 0; j < MCELIECE_N; j++) {
        if (alpha[j] == 0) continue;
        gf_elem_t alpha_inv = gf_inv(alpha[j]);
        gf_elem_t result = polynomial_eval(sigma, alpha_inv);

        if (result == 0) {
            // Found a root, corresponding to error position
            error_positions[*num_errors] = j;
            (*num_errors)++;
            if (dbg_enabled) { printf("[Chien] root at j=%d (errors=%d)\n", j, *num_errors); fflush(stdout); }

            if (*num_errors >= MCELIECE_T) break;  // At most t errors
        }
    }

    if (dbg_enabled) { printf("[Chien] total errors=%d\n", *num_errors); fflush(stdout); }
    return MCELIECE_SUCCESS;
}



// 完整的解码算法
mceliece_error_t decode_goppa(const uint8_t *received, const polynomial_t *g,
                              const gf_elem_t *alpha, uint8_t *error_vector,
                              int *decode_success) {
    if (!received || !g || !alpha || !error_vector || !decode_success) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    *decode_success = 0;

    // 步骤1：计算伴随式
    gf_elem_t *syndrome = malloc(2 * MCELIECE_T * sizeof(gf_elem_t));
    if (!syndrome) return MCELIECE_ERROR_MEMORY;

    compute_syndrome(received, g, alpha, syndrome);

    // Check if syndrome is all zero (no errors)
    int has_error = 0;
    for (int i = 0; i < 2 * MCELIECE_T; i++) {
        if (syndrome[i] != 0) {
            has_error = 1;
            break;
        }
    }

    if (!has_error) {
        // No errors
        memset(error_vector, 0, MCELIECE_N_BYTES);
        *decode_success = 1;
        free(syndrome);
        return MCELIECE_SUCCESS;
    }

    // 步骤2：使用Berlekamp-Massey算法求解错误定位多项式
    polynomial_t *sigma = polynomial_create(MCELIECE_T);
    polynomial_t *omega = polynomial_create(MCELIECE_T - 1);

    if (!sigma || !omega) {
        free(syndrome);
        polynomial_free(sigma);
        polynomial_free(omega);
        return MCELIECE_ERROR_MEMORY;
    }

    mceliece_error_t ret = berlekamp_massey(syndrome, sigma);
    if (ret != MCELIECE_SUCCESS) {
        free(syndrome);
        polynomial_free(sigma);
        polynomial_free(omega);
        return ret;
    }

    // 步骤3：使用Chien搜索找到错误位置
    int *error_positions = malloc(MCELIECE_T * sizeof(int));
    if (!error_positions) {
        free(syndrome);
        polynomial_free(sigma);
        polynomial_free(omega);
        return MCELIECE_ERROR_MEMORY;
    }

    int num_errors;
    ret = chien_search(sigma, alpha, error_positions, &num_errors);
    if (ret != MCELIECE_SUCCESS) {
        free(syndrome);
        polynomial_free(sigma);
        free(error_positions);
        return ret;
    }

    // No early rejection based on locator degree; proceed to construct error vector

    // Step 4: Construct error vector
    memset(error_vector, 0, MCELIECE_N_BYTES);

    for (int i = 0; i < num_errors; i++) {
        // Validate error position
        if (error_positions[i] >= 0 && error_positions[i] < MCELIECE_N) {
            vector_set_bit(error_vector, error_positions[i], 1);
        } else {
            // Invalid error position, decoding failed
            *decode_success = 0;
            free(syndrome);
            polynomial_free(sigma);
            free(error_positions);
            return MCELIECE_SUCCESS;
        }
    }

    // Final validation: recompute syndrome from recovered error vector and compare
    gf_elem_t *syndrome_check = malloc(2 * MCELIECE_T * sizeof(gf_elem_t));
    if (!syndrome_check) {
        free(syndrome);
        polynomial_free(sigma);
        free(error_positions);
        return MCELIECE_ERROR_MEMORY;
    }
    compute_syndrome(error_vector, g, alpha, syndrome_check);

    int match = 1;
    for (int i = 0; i < 2 * MCELIECE_T; i++) {
        if (syndrome[i] != syndrome_check[i]) { match = 0; break; }
    }
    int actual_weight = vector_weight(error_vector, MCELIECE_N_BYTES);
    *decode_success = (match && actual_weight == MCELIECE_T);
    free(syndrome_check);

    // 清理内存
    free(syndrome);
    polynomial_free(sigma);
    free(error_positions);

    return MCELIECE_SUCCESS;
}

// decode algorithm
mceliece_error_t decode_ciphertext(const uint8_t *ciphertext, const private_key_t *sk,
                                   uint8_t *error_vector, int *success) {
    if (!ciphertext || !sk || !error_vector || !success) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    *success = 0;

    // According to Classic McEliece spec, the ciphertext C = H*e where H = [I_mt | T]
    // So C already IS the syndrome! We can directly pass it to Goppa decoding.
    //
    // The "received" vector for syndrome computation should be the actual error pattern
    // we're trying to recover, but since we don't know it yet, we use the syndrome directly.

    // Proper approach (reference style): use ciphertext bits as the first mt bits
    // of the received vector r, with the rest zero, and decode using support L
    // derived from controlbits.

    int mt = MCELIECE_M * MCELIECE_T;
    uint8_t *v = malloc(MCELIECE_N_BYTES);
    if (!v) return MCELIECE_ERROR_MEMORY;
    memset(v, 0, MCELIECE_N_BYTES);
    for (int i = 0; i < mt; i++) {
        int bit_value = vector_get_bit(ciphertext, i);
        vector_set_bit(v, i, bit_value);
    }
    // Derive support set L from controlbits (Benes), same as reference decrypt.c
    long long w = MCELIECE_M;
    long long n_full = 1LL << w;
    size_t expected_cb_len = (size_t)((((2 * w - 1) * n_full / 2) + 7) / 8);
    gf_elem_t *L = NULL;
    if (sk->controlbits && sk->controlbits_len == expected_cb_len) {
        L = (gf_elem_t*)malloc(sizeof(gf_elem_t) * MCELIECE_N);
        if (L) {
            support_from_cbits(L, sk->controlbits, MCELIECE_M, MCELIECE_N);
            const char *env_debug = getenv("MCELIECE_DEBUG");
            int dbg_enabled = env_debug && env_debug[0] == '1';
            if (dbg_enabled) {
                int mismatch = 0;
                for (int j = 0; j < MCELIECE_N; j++) if (L[j] != sk->alpha[j]) { mismatch++; break; }
                printf("[decode] L vs alpha mismatch: %s\n", mismatch ? "YES" : "NO");
                fflush(stdout);
            }
        }
    }
    mceliece_error_t ret = decode_goppa(v, &sk->g, L ? L : sk->alpha, error_vector, success);
    if (L) free(L);
    free(v);
    return ret;
}

