#include "mceliece_keygen.h"
#include "mceliece_genpoly.h"
#include "kat_drbg.h"
#include "mceliece_kem.h"

static inline uint16_t bitrev_m_u16(uint16_t x, int m) {
    uint16_t r = 0;
    for (int j = 0; j < m; j++) {
        r = (uint16_t)((r << 1) | ((x >> j) & 1U));
    }
    return (uint16_t)(r & ((1U << m) - 1U));
}



typedef struct {
    uint32_t val; // <--- 必须是 uint32_t！
    uint16_t pos;
} pair_t;

int compare_pairs(const void *a, const void *b) {
    const pair_t *p1 = (const pair_t *)a;
    const pair_t *p2 = (const pair_t *)b;
    if (p1->val < p2->val) return -1;
    if (p1->val > p2->val) return 1;
    // 如果值相同，按原始位置排序以保证稳定性（可选，但良好实践）
    if (p1->pos < p2->pos) return -1;
    if (p1->pos > p2->pos) return 1;
    return 0;
}

// SeededKeyGen算法
mceliece_error_t seeded_key_gen(const uint8_t *delta, public_key_t *pk, private_key_t *sk) {
    if (!delta || !pk || !sk) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    int n_bits = MCELIECE_N; // n=6688

    int t_bits = MCELIECE_T; // t=128
    int q_val = MCELIECE_Q;  // q=8192

    // l 是会话密钥长度，也是种子的长度 (in bits)
    // 规范 9.1: The integer l is 256.
    int l_bits = 256;

    // σ₁ 和 σ₂ 也是规范定义的整数
    // 规范 9.1: The integer σ₁ is 16.
    // 规范 9.1: The integer σ₂ is 32.
    int sigma1 = 16;
    int sigma2 = 32;

    // --- 计算各个部分的比特长度 ---
    // 规范 8.3 (SeededKeyGen) / 8.1 / 8.2 描述了 E 的构成
    // E = s || (bits for FieldOrdering) || (bits for Irreducible) || δ'
    // 长度: n + σ₂q + σ₁t + l bits

    int s_len_bits = n_bits;
    int field_ordering_len_bits = sigma2 * q_val;
    int irreducible_poly_len_bits = sigma1 * t_bits;
    int delta_prime_len_bits = l_bits;

    size_t prg_output_len_bits = s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits;

    // 将总比特长度转换为字节长度，向上取整
    size_t prg_output_len_bytes = (prg_output_len_bits + 7) / 8;

    // --- 计算各个部分的字节长度和偏移量 ---
    size_t s_len_bytes = (s_len_bits + 7) / 8;
    size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8;
    size_t irreducible_poly_len_bytes = (irreducible_poly_len_bits + 7) / 8;
    size_t delta_prime_len_bytes = (delta_prime_len_bits + 7) / 8; // 应该是 32

    // 验证一下总长度是否匹配
    if (prg_output_len_bytes != s_len_bytes + field_ordering_len_bytes + irreducible_poly_len_bytes + delta_prime_len_bytes) {
        // 这在某些边界条件下可能不成立，但对于 McEliece 参数通常成立。
        // 一个更安全的方式是直接使用比特偏移量。但我们先用字节。
    }

    // --- 准备 PRG 输出缓冲区 ---
    uint8_t *E = malloc(prg_output_len_bytes);
    if (!E) return MCELIECE_ERROR_MEMORY;

    // 复制初始种子到私钥
    memcpy(sk->delta, delta, delta_prime_len_bytes);

    int max_attempts = 400; // allow retries in both modes; in KAT, DRBG provides fresh bytes per attempt
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        // 1. Generate long random string E using internal PRG from delta.
        //    In KAT mode we must NOT consume the global DRBG here to match PQClean.
        mceliece_prg(sk->delta, E, prg_output_len_bytes);

        // 2. Extract next retry seed delta' from the end of E
        uint8_t delta_prime[MCELIECE_L_BYTES];
        memcpy(delta_prime, E + prg_output_len_bytes - delta_prime_len_bytes, delta_prime_len_bytes);

        // 3. Split E into parts (using byte offsets)
        const uint8_t *s_bits_ptr = E;
        const uint8_t *field_ordering_bits_ptr = E + s_len_bytes;
        const uint8_t *irreducible_poly_bits_ptr = field_ordering_bits_ptr + field_ordering_len_bytes;

        // 4. Generate support set alpha
        if (generate_field_ordering(sk->alpha, field_ordering_bits_ptr) != MCELIECE_SUCCESS) {
            if (!kat_drbg_is_inited()) printf("[keygen] attempt %d: generate_field_ordering failed (duplicates)\n", attempt+1);
            memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
            continue;
        }

        // 5. Generate Goppa polynomial g
        if (generate_irreducible_poly_final(&sk->g, irreducible_poly_bits_ptr) != MCELIECE_SUCCESS) {
            if (!kat_drbg_is_inited()) printf("[keygen] attempt %d: generate_irreducible_poly_final failed\n", attempt+1);
            memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
            continue;
        }

        // Ensure alpha is a support set for g (no roots of g)
        int is_support_set = 1;
        for (int i = 0; i < n_bits; ++i) {
            if (polynomial_eval(&sk->g, sk->alpha[i]) == 0) {
                if (!kat_drbg_is_inited()) printf("[keygen] attempt %d: support check failed: g(alpha[%d])=0\n", attempt+1, i);
                is_support_set = 0;
                break;
            }
        }
        if (!is_support_set) {
            memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
            continue;
        }

        // 6. Generate public key T and record permutation p and row ops U
        if (sk->p) { free(sk->p); sk->p = NULL; }
        sk->p = malloc(sizeof(int) * MCELIECE_N);
        if (!sk->p) { memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES); continue; }
        // Build H and reduce with recording to capture U in sk
        int mt = MCELIECE_M * MCELIECE_T;
        int n = MCELIECE_N;
        matrix_t *Htmp = matrix_create(mt, n);
        if (!Htmp) { if (!kat_drbg_is_inited()) printf("[keygen] attempt %d: matrix_create Htmp failed\n", attempt+1); free(sk->p); sk->p = NULL; memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES); continue; }
        for (int i = 0; i < MCELIECE_T; i++) {
            for (int j = 0; j < MCELIECE_N; j++) {
                gf_elem_t alpha_power = gf_pow(sk->alpha[j], i);
                gf_elem_t g_alpha = polynomial_eval(&sk->g, sk->alpha[j]);
                if (g_alpha == 0) { if (!kat_drbg_is_inited()) printf("[keygen] attempt %d: encountered g(alpha[%d])=0 during H build\n", attempt+1, j); matrix_free(Htmp); free(sk->p); sk->p=NULL; memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES); goto retry; }
                gf_elem_t M_ij = gf_div(alpha_power, g_alpha);
                for (int bit = 0; bit < MCELIECE_M; bit++) {
                    int bit_value = (M_ij >> bit) & 1;
                    matrix_set_bit(Htmp, i * MCELIECE_M + bit, j, bit_value);
                }
            }
        }
        if (sk->U) { matrix_free((matrix_t*)sk->U); sk->U = NULL; }
        if (sk->U_inv) { matrix_free((matrix_t*)sk->U_inv); sk->U_inv = NULL; }
        sk->U = (void*)matrix_create(mt, mt);
        if (!sk->U) { if (!kat_drbg_is_inited()) printf("[keygen] attempt %d: matrix_create U failed\n", attempt+1); matrix_free(Htmp); free(sk->p); sk->p = NULL; memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES); continue; }
        if (reduce_to_systematic_form_record(Htmp, (matrix_t*)sk->U, sk->p) != 0) {
            if (!kat_drbg_is_inited()) printf("[keygen] attempt %d: reduce_to_systematic_form_record failed (singular)\n", attempt+1);
            free(sk->p); sk->p = NULL;
            matrix_free((matrix_t*)sk->U); sk->U = NULL;
            matrix_free(Htmp);
            memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
            continue;
        }
        // Extract T from reduced Htmp
        for (int i = 0; i < mt; i++) {
            for (int j = 0; j < (MCELIECE_N - mt); j++) {
                int bit = matrix_get_bit(Htmp, i, mt + j);
                matrix_set_bit(&pk->T, i, j, bit);
            }
        }
        // Reorder first n support elements to match systematic columns: alpha'[sys] = alpha[orig]
        {
            int ncols = MCELIECE_N;
            gf_elem_t *alpha_prime = malloc(sizeof(gf_elem_t) * ncols);
            if (!alpha_prime) { matrix_free(Htmp); free(sk->p); sk->p=NULL; matrix_free((matrix_t*)sk->U); sk->U=NULL; memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES); continue; }
            for (int j = 0; j < ncols; j++) alpha_prime[j] = 0;
            for (int orig = 0; orig < ncols; orig++) {
                int sys = sk->p[orig];
                alpha_prime[sys] = sk->alpha[orig];
            }
            // write back first n reordered
            for (int j = 0; j < ncols; j++) sk->alpha[j] = alpha_prime[j];
            free(alpha_prime);
        }
        // Precompute U_inv
        sk->U_inv = (void*)matrix_create(mt, mt);
        if (!sk->U_inv || matrix_invert((matrix_t*)sk->U, (matrix_t*)sk->U_inv) != 0) {
            if (!kat_drbg_is_inited()) printf("[keygen] attempt %d: matrix_invert(U) failed\n", attempt+1);
            if (sk->U_inv) { matrix_free((matrix_t*)sk->U_inv); sk->U_inv = NULL; }
            free(sk->p); sk->p = NULL; matrix_free((matrix_t*)sk->U); sk->U = NULL; matrix_free(Htmp);
            memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
            continue;
        }
        matrix_free(Htmp);

        // Self-verify only in non-KAT mode to avoid consuming DRBG differently
        if (!kat_drbg_is_inited()) {
            uint8_t ciphertext[MCELIECE_MT_BYTES];
            uint8_t session_key1[MCELIECE_L_BYTES];
            uint8_t session_key2[MCELIECE_L_BYTES];
            mceliece_error_t vret = mceliece_encap(pk, ciphertext, session_key1);
            if (vret != MCELIECE_SUCCESS) {
                if (!kat_drbg_is_inited()) printf("[keygen] attempt %d: self-encap failed (%d)\n", attempt+1, vret);
                matrix_free((matrix_t*)sk->U); sk->U = NULL;
                matrix_free((matrix_t*)sk->U_inv); sk->U_inv = NULL;
                free(sk->p); sk->p = NULL;
                memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
                continue;
            }
            vret = mceliece_decap(ciphertext, sk, session_key2);
            if (vret != MCELIECE_SUCCESS || memcmp(session_key1, session_key2, MCELIECE_L_BYTES) != 0) {
                if (!kat_drbg_is_inited()) printf("[keygen] attempt %d: self-verify KEM mismatch\n", attempt+1);
                matrix_free((matrix_t*)sk->U); sk->U = NULL;
                matrix_free((matrix_t*)sk->U_inv); sk->U_inv = NULL;
                free(sk->p); sk->p = NULL;
                memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
                continue;
            }
        }

        // --- All steps successful! ---

        // 7. Save other parts of private key
        // Copy s (length n)
        memcpy(sk->s, s_bits_ptr, (n_bits + 7) / 8);

        // Other parts of private key (c, g, alpha) are already in sk structure
        // keep sk->p for decapsulation transform

        free(E);
        return MCELIECE_SUCCESS;
retry: ;
    }

    // Reached maximum attempts, generation failed
    free(E);
    return MCELIECE_ERROR_KEYGEN_FAIL;
}



mceliece_error_t generate_field_ordering(gf_elem_t *alpha, const uint8_t *random_bits) {
    int q = MCELIECE_Q;
    int m = MCELIECE_M;
    int sigma2_bits = 32;
    int sigma2_bytes = sigma2_bits / 8;

    // Field ordering generation function

    pair_t *pairs = malloc(q * sizeof(pair_t));
    if (!pairs) {
        return MCELIECE_ERROR_MEMORY;
    }

    // 1. 从随机比特生成 q 个 32-bit 的整数 a_i (小端序，参考实现常见打包)
    for (int i = 0; i < q; i++) {
        int offset = i * sigma2_bytes;
        uint32_t a_i = (uint32_t)random_bits[offset] |
                       ((uint32_t)random_bits[offset + 1] << 8) |
                       ((uint32_t)random_bits[offset + 2] << 16) |
                       ((uint32_t)random_bits[offset + 3] << 24);
        pairs[i].val = a_i;
        pairs[i].pos = i;
    }

    // 2. Check for duplicate values
    pair_t *sorted_for_check = malloc(q * sizeof(pair_t));
    if (!sorted_for_check) { free(pairs); return MCELIECE_ERROR_MEMORY; }
    memcpy(sorted_for_check, pairs, q * sizeof(pair_t));
    qsort(sorted_for_check, q, sizeof(pair_t), compare_pairs);

    int has_duplicates = 0;
    for (int i = 0; i < q - 1; i++) {
        if (sorted_for_check[i].val == sorted_for_check[i+1].val) {
            has_duplicates = 1;
            break;
        }
    }
    free(sorted_for_check);

    if (has_duplicates) {
        free(pairs);
        return MCELIECE_ERROR_KEYGEN_FAIL;
    }

    // 3. 按值对 (a_i, i) 进行字典序排序（稳定地）
    qsort(pairs, q, sizeof(pair_t), compare_pairs);

    // 4. 定义置换 pi，pi[i] 是排序后第 i 个元素的原始位置
    uint16_t *pi = malloc(q * sizeof(uint16_t));
    if (!pi) { free(pairs); return MCELIECE_ERROR_MEMORY; }
    for(int i = 0; i < q; ++i) {
        pi[i] = pairs[i].pos;
    }

    free(pairs); // pairs 不再需要

    // 5. 根据置换 pi 生成最终的 alpha 序列
    //    NIST 参考实现使用 bit-reversed 映射：alpha[i] = bitrev_m( pi[i] )
    for (int i = 0; i < q; i++) {
        uint16_t v = pi[i] & ((1U << m) - 1U);
        alpha[i] = (gf_elem_t)bitrev_m_u16(v, m);
    }

    free(pi);
    return MCELIECE_SUCCESS;
}




mceliece_error_t generate_irreducible_poly_final(polynomial_t *g, const uint8_t *random_bits) {
    int t = MCELIECE_T;
    int m = MCELIECE_M;

    memset(g->coeffs, 0, (g->max_degree + 1) * sizeof(gf_elem_t));
    g->degree = -1;

    // Reference packs sigma1=16 bits per coefficient, but reads across byte boundary over the entire stream
    int coeff_pool_bytes = (MCELIECE_SIGMA1 * MCELIECE_T) / 8; // 2 * t bytes
    if (coeff_pool_bytes <= 0) coeff_pool_bytes = (MCELIECE_SIGMA1 * MCELIECE_T) / 8;

    // Build f(x) with degree < t from random bits: sliding bit window over the entire pool
    gf_elem_t *f = malloc(sizeof(gf_elem_t) * t);
    if (!f) return MCELIECE_ERROR_MEMORY;
    int bitpos = 0;
    for (int i = 0; i < t; i++) {
        uint32_t acc = 0;
        int byte_idx = bitpos >> 3;
        int bit_off = bitpos & 7;
        if (byte_idx < coeff_pool_bytes) acc |= (uint32_t)random_bits[byte_idx];
        if (byte_idx + 1 < coeff_pool_bytes) acc |= (uint32_t)random_bits[byte_idx + 1] << 8;
        if (byte_idx + 2 < coeff_pool_bytes) acc |= (uint32_t)random_bits[byte_idx + 2] << 16;
        acc >>= bit_off;
        f[i] = (gf_elem_t)(acc & ((1u << m) - 1));
        bitpos += MCELIECE_SIGMA1;
    }
    if (f[t - 1] == 0) f[t - 1] = 1;

    // Compute connection polynomial coefficients via genpoly_gen
    gf_elem_t *gl = malloc(sizeof(gf_elem_t) * t);
    if (!gl) { free(f); return MCELIECE_ERROR_MEMORY; }
    if (genpoly_gen(gl, f) != 0) { free(f); free(gl); return MCELIECE_ERROR_KEYGEN_FAIL; }

    // Form monic g(x) = x^t + sum_{i=0}^{t-1} gl[i] x^i
    for (int i = 0; i < t; i++) polynomial_set_coeff(g, i, gl[i]);
    polynomial_set_coeff(g, t, 1);

    free(f);
    free(gl);
    return MCELIECE_SUCCESS;
}



/* mat_gen and mat_gen_with_transforms were unused. Removed for clarity. */



// Private key creation
private_key_t* private_key_create(void) {
    private_key_t *sk = malloc(sizeof(private_key_t));
    if (!sk) return NULL;

    memset(sk, 0, sizeof(private_key_t));
    sk->p = NULL;
    sk->U = NULL;
    sk->U_inv = NULL;

    // 初始化Goppa多项式
    polynomial_t *g = polynomial_create(MCELIECE_T);
    if (!g) {
        free(sk);
        return NULL;
    }
    sk->g = *g;
    free(g);  // 只释放结构体，不释放coeffs

    // 分配alpha数组
    sk->alpha = calloc(MCELIECE_Q, sizeof(gf_elem_t));
    if (!sk->alpha) {
        free(sk->g.coeffs);
        free(sk);
        return NULL;
    }

    // 设置默认c值（对于μ=ν=0）
    sk->c = (1ULL << 32) - 1;

    return sk;
}

// Private key deallocation
void private_key_free(private_key_t *sk) {
    if (sk) {
        if (sk->p) free(sk->p);
        if (sk->U) matrix_free((matrix_t*)sk->U);
        if (sk->U_inv) matrix_free((matrix_t*)sk->U_inv);
        if (sk->g.coeffs) free(sk->g.coeffs);
        if (sk->alpha) free(sk->alpha);
        free(sk);
    }
}

// Public key creation
public_key_t* public_key_create(void) {
    public_key_t *pk = malloc(sizeof(public_key_t));
    if (!pk) return NULL;

    matrix_t *T = matrix_create(MCELIECE_M * MCELIECE_T, MCELIECE_K);
    if (!T) {
        free(pk);
        return NULL;
    }

    pk->T = *T;
    free(T);  // 只释放结构体，不释放data

    return pk;
}

// Public key deallocation
void public_key_free(public_key_t *pk) {
    if (pk) {
        if (pk->T.data) free(pk->T.data);
        free(pk);
    }
}
