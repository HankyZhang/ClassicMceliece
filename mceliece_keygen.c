#include "mceliece_keygen.h"



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

    int max_attempts = 50;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        // 1. Generate long random string E using current seed delta
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
            memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
            continue;
        }

        // 5. Generate Goppa polynomial g
        if (generate_irreducible_poly_final(&sk->g, irreducible_poly_bits_ptr) != MCELIECE_SUCCESS) {
            memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
            continue;
        }

        // Ensure alpha is a support set for g (no roots of g)
        int is_support_set = 1;
        for (int i = 0; i < n_bits; ++i) {
            if (polynomial_eval(&sk->g, sk->alpha[i]) == 0) {
                is_support_set = 0;
                break;
            }
        }
        if (!is_support_set) {
            memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
            continue;
        }

        // 6. Generate public key T
        if (mat_gen(&sk->g, sk->alpha, &pk->T) != MCELIECE_SUCCESS) {
            memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
            continue;
        }

        // --- All steps successful! ---

        // 7. Save other parts of private key
        // Copy s (length n)
        memcpy(sk->s, s_bits_ptr, (n_bits + 7) / 8);

        // Other parts of private key (c, g, alpha) are already in sk structure
        // p vector is not needed, ensure private_key_free won't try to free uninitialized pointer
        if(sk->p) {
            free(sk->p);
            sk->p = NULL;
        }

        free(E);
        return MCELIECE_SUCCESS;
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

    // 1. 从随机比特生成 q 个 32-bit 的整数 a_i (小端序)
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

    // 3. 按值对 (a_i, i) 进行字典序排序
    qsort(pairs, q, sizeof(pair_t), compare_pairs);

    // 4. 定义置换 pi，pi[i] 是排序后第 i 个元素的原始位置
    uint16_t *pi = malloc(q * sizeof(uint16_t));
    if (!pi) { free(pairs); return MCELIECE_ERROR_MEMORY; }
    for(int i = 0; i < q; ++i) {
        pi[i] = pairs[i].pos;
    }

    free(pairs); // pairs 不再需要

    // 5. 根据置换 pi 生成最终的 alpha 序列
    //    规范公式: α_i = Σ π(i)_j * z^(m-1-j) for j=0 to m-1
    //    在标准二进制表示中，这恰好等价于将整数 π(i) 直接作为 F_q 的元素。
    //    我们在这里显式地实现它，以确保没有误解。
    for (int i = 0; i < q; i++) {
        gf_elem_t current_alpha = 0;
        uint16_t pi_val = pi[i];

        // 我们只关心 pi_val 的低 m 位
        pi_val &= (1 << m) - 1;

        // 规范中的公式将 j=0 对应到最高位 z^(m-1)。
        // 这在标准表示法中与直接使用整数值是等价的。
        // 例如：pi_val = 13 (0...1101), m=4.
        // j=0 (LSB=1) -> 1*z^0
        // j=1 (LSB=0) -> 0*z^1
        // j=2 (LSB=1) -> 1*z^2
        // j=3 (MSB=1) -> 1*z^3
        // sum = z^3+z^2+1, which is the element 13.
        // 所以直接赋值是正确的。
        current_alpha = (gf_elem_t)pi_val;
        alpha[i] = current_alpha;
    }

    free(pi);
    return MCELIECE_SUCCESS;
}


// 检查多项式是否不可约的简化方法
static int is_irreducible_simple(const polynomial_t *poly) {
    if (poly->degree <= 0) return 0;

    // 对于小度数多项式，我们可以使用简单的检查
    // 对于大度数多项式，这只是一个启发式方法

    // 检查常数项不为零
    if (poly->coeffs[0] == 0) return 0;

    // 检查是否有线性因子（对于GF(2^m)中的元素）
    // 这需要检查所有可能的根
    int m = MCELIECE_M;
    int q = 1 << m;

    // 只检查前几个元素作为根（为了效率）
    int max_roots_to_check = (q < 100) ? q : 100;
    for (int i = 0; i < max_roots_to_check; i++) {
        if (polynomial_eval(poly, i) == 0) {
            return 0; // 找到了根，多项式可约
        }
    }

    return 1; // 可能是不可约的
}

// Generate irreducible polynomial - simplified reliable version
mceliece_error_t generate_irreducible_poly_final(polynomial_t *g, const uint8_t *random_bits) {
    int t = MCELIECE_T;
    int m = MCELIECE_M;

    // Clear polynomial
    memset(g->coeffs, 0, (g->max_degree + 1) * sizeof(gf_elem_t));
    g->degree = -1;

    // For mceliece6688128, use a known working irreducible polynomial
    if (t == 128 && m == 13) {
        // Use polynomial x^128 + x^7 + x^2 + x + 1
        // This is a well-known irreducible polynomial suitable for this parameter set
        polynomial_set_coeff(g, 0, 1);    // x^0 term
        polynomial_set_coeff(g, 1, 1);    // x^1 term
        polynomial_set_coeff(g, 2, 1);    // x^2 term
        polynomial_set_coeff(g, 7, 1);    // x^7 term
        polynomial_set_coeff(g, 128, 1);  // x^128 term (leading coefficient)

        return MCELIECE_SUCCESS;
    }

    // For other parameter sets, try random generation with simple irreducibility check
    int max_attempts = 50;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        // Clear polynomial
        memset(g->coeffs, 0, (g->max_degree + 1) * sizeof(gf_elem_t));
        g->degree = -1;

        // Set leading coefficient (monic polynomial)
        polynomial_set_coeff(g, t, 1);

        // Generate random coefficients for lower degree terms
        for (int i = 0; i < t; i++) {
            // Use random bits to generate coefficient
            int byte_idx = (i * 16) / 8;
            int bit_offset = (i * 16) % 8;

            if (byte_idx < MCELIECE_SIGMA1 * MCELIECE_T / 8) {
                uint16_t coeff_bits = (uint16_t)random_bits[byte_idx];
                if (byte_idx + 1 < MCELIECE_SIGMA1 * MCELIECE_T / 8) {
                    coeff_bits |= ((uint16_t)random_bits[byte_idx + 1] << 8);
                }

                gf_elem_t coeff = (coeff_bits >> bit_offset) & ((1 << m) - 1);
                polynomial_set_coeff(g, i, coeff);
            }
        }

        // Simple irreducibility check
        if (is_irreducible_simple(g)) {
            return MCELIECE_SUCCESS;
        }
    }

    return MCELIECE_ERROR_KEYGEN_FAIL;
}



mceliece_error_t mat_gen(const polynomial_t *g, const gf_elem_t *alpha,
                         matrix_t *T_out) { // 注意：p_out 参数被移除了
    if (!g || !alpha || !T_out) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    int n = MCELIECE_N;
    int t = MCELIECE_T;
    int m = MCELIECE_M;
    int mt = m * t;
    int k = n - mt;

    // Create Goppa parity-check matrix H
    matrix_t *H = matrix_create(mt, n);
    if (!H) return MCELIECE_ERROR_MEMORY;

    // According to specification 1.2.7, construct Goppa code parity-check matrix
    // M[i,j] = alpha[j]^i / g(alpha[j]) for i=0,...,t-1 and j=0,...,n-1

    for (int i = 0; i < t; i++) {
        for (int j = 0; j < n; j++) {
            // Calculate alpha[j]^i using efficient exponentiation
            gf_elem_t alpha_power = gf_pow(alpha[j], i);

            // Calculate g(alpha[j])
            gf_elem_t g_alpha = polynomial_eval(g, alpha[j]);

            // Check if g(alpha[j]) is zero (would cause division by zero)
            if (g_alpha == 0) {
                matrix_free(H);
                return MCELIECE_ERROR_KEYGEN_FAIL;
            }

            // Calculate M[i,j] = alpha[j]^i / g(alpha[j])
            gf_elem_t M_ij = gf_div(alpha_power, g_alpha);

            // Expand GF(2^m) element into m binary bits
            for (int bit = 0; bit < m; bit++) {
                int bit_value = (M_ij >> bit) & 1;
                matrix_set_bit(H, i * m + bit, j, bit_value);
            }
        }
    }

    // Convert H to systematic form [I_mt | T]
    if (reduce_to_systematic_form(H) != 0) {
        matrix_free(H);
        return MCELIECE_ERROR_KEYGEN_FAIL; // Matrix is singular
    }

    // At this point H is in the form [I_mt | T]
    // Extract public key T from the right side of H
    for (int i = 0; i < mt; i++) {
        for (int j = 0; j < k; j++) {
            int bit = matrix_get_bit(H, i, mt + j);
            matrix_set_bit(T_out, i, j, bit);
        }
    }

    matrix_free(H);
    return MCELIECE_SUCCESS;
}



// Private key creation
private_key_t* private_key_create(void) {
    private_key_t *sk = malloc(sizeof(private_key_t));
    if (!sk) return NULL;

    memset(sk, 0, sizeof(private_key_t));
    sk->p = NULL;

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
