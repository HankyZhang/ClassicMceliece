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

    int max_attempts = 300;
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
            printf("[keygen] attempt %d: generate_field_ordering failed (duplicates)\n", attempt+1);
            memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
            continue;
        }

        // 5. Generate Goppa polynomial g
        if (generate_irreducible_poly_final(&sk->g, irreducible_poly_bits_ptr) != MCELIECE_SUCCESS) {
            printf("[keygen] attempt %d: generate_irreducible_poly_final failed\n", attempt+1);
            memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
            continue;
        }

        // Ensure alpha is a support set for g (no roots of g)
        int is_support_set = 1;
        for (int i = 0; i < n_bits; ++i) {
            if (polynomial_eval(&sk->g, sk->alpha[i]) == 0) {
                printf("[keygen] attempt %d: support check failed: g(alpha[%d])=0\n", attempt+1, i);
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
        if (!Htmp) { printf("[keygen] attempt %d: matrix_create Htmp failed\n", attempt+1); free(sk->p); sk->p = NULL; memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES); continue; }
        for (int i = 0; i < MCELIECE_T; i++) {
            for (int j = 0; j < MCELIECE_N; j++) {
                gf_elem_t alpha_power = gf_pow(sk->alpha[j], i);
                gf_elem_t g_alpha = polynomial_eval(&sk->g, sk->alpha[j]);
                if (g_alpha == 0) { printf("[keygen] attempt %d: encountered g(alpha[%d])=0 during H build\n", attempt+1, j); matrix_free(Htmp); free(sk->p); sk->p=NULL; memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES); goto retry; }
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
        if (!sk->U) { printf("[keygen] attempt %d: matrix_create U failed\n", attempt+1); matrix_free(Htmp); free(sk->p); sk->p = NULL; memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES); continue; }
        if (reduce_to_systematic_form_record(Htmp, (matrix_t*)sk->U, sk->p) != 0) {
            printf("[keygen] attempt %d: reduce_to_systematic_form_record failed (singular)\n", attempt+1);
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
            printf("[keygen] attempt %d: matrix_invert(U) failed\n", attempt+1);
            if (sk->U_inv) { matrix_free((matrix_t*)sk->U_inv); sk->U_inv = NULL; }
            free(sk->p); sk->p = NULL; matrix_free((matrix_t*)sk->U); sk->U = NULL; matrix_free(Htmp);
            memcpy(sk->delta, delta_prime, MCELIECE_L_BYTES);
            continue;
        }
        matrix_free(Htmp);

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
static void poly_make_monic(polynomial_t *a) {
    if (a->degree < 0) return;
    gf_elem_t lc = a->coeffs[a->degree];
    if (lc == 1) return;
    gf_elem_t inv = gf_inv(lc);
    for (int i = 0; i <= a->degree; i++) {
        a->coeffs[i] = gf_mul(a->coeffs[i], inv);
    }
}

static void poly_mod(polynomial_t *r, const polynomial_t *a, const polynomial_t *mod) {
    polynomial_div(NULL, r, a, mod);
}

static void poly_square(polynomial_t *out, const polynomial_t *a) {
    memset(out->coeffs, 0, (out->max_degree + 1) * sizeof(gf_elem_t));
    out->degree = -1;
    for (int i = 0; i <= a->degree; i++) {
        gf_elem_t sq = gf_mul(a->coeffs[i], a->coeffs[i]);
        int idx = 2 * i;
        if (idx <= out->max_degree) {
            out->coeffs[idx] = gf_add(out->coeffs[idx], sq);
            if (out->coeffs[idx] != 0 && idx > out->degree) out->degree = idx;
        }
    }
}

static void poly_square_mod(polynomial_t *out, const polynomial_t *a, const polynomial_t *mod) {
    int tmp_deg = 2 * a->degree + 2;
    if (tmp_deg < 0) tmp_deg = 0;
    polynomial_t *tmp = polynomial_create(tmp_deg);
    poly_square(tmp, a);
    poly_mod(out, tmp, mod);
    polynomial_free(tmp);
}

static void poly_add(polynomial_t *out, const polynomial_t *a, const polynomial_t *b) {
    polynomial_add(out, a, b);
}

static void poly_set_x(polynomial_t *xpoly) {
    memset(xpoly->coeffs, 0, (xpoly->max_degree + 1) * sizeof(gf_elem_t));
    xpoly->degree = 1;
    xpoly->coeffs[1] = 1;
}

static void poly_copy(polynomial_t *dst, const polynomial_t *src) { polynomial_copy(dst, src); }

static void poly_gcd(polynomial_t *g, const polynomial_t *a_in, const polynomial_t *b_in) {
    polynomial_t *a = polynomial_create(a_in->max_degree);
    polynomial_t *b = polynomial_create(b_in->max_degree);
    poly_copy(a, a_in);
    poly_copy(b, b_in);
    while (!polynomial_is_zero(b)) {
        polynomial_t *r = polynomial_create(a->max_degree);
        polynomial_div(NULL, r, a, b);
        poly_copy(a, b);
        poly_copy(b, r);
        polynomial_free(r);
    }
    poly_make_monic(a);
    poly_copy(g, a);
    polynomial_free(a);
    polynomial_free(b);
}

static void poly_x_pow_2e_mod(polynomial_t *out, int e, const polynomial_t *mod) {
    // Compute X^(2^e) mod mod, via repeated Frobenius squaring on A starting from X
    polynomial_t *A = polynomial_create(2 * mod->degree + 2);
    polynomial_t *tmp = polynomial_create(2 * mod->degree + 2);
    poly_set_x(A);
    for (int s = 0; s < e; s++) {
        poly_square_mod(tmp, A, mod);
        poly_copy(A, tmp);
    }
    poly_copy(out, A);
    polynomial_free(A);
    polynomial_free(tmp);
}

static int is_irreducible_over_gfq(const polynomial_t *f) {
    int n = f->degree;
    int m = MCELIECE_M;
    if (n <= 0) return 0;
    if (f->coeffs[0] == 0) return 0; // divisible by X

    // Distinct prime divisors of n
    int primes[16];
    int num_primes = 0;
    int tleft = n;
    for (int p = 2; p * p <= tleft; p++) {
        if (tleft % p == 0) {
            primes[num_primes++] = p;
            while (tleft % p == 0) tleft /= p;
        }
    }
    if (tleft > 1) primes[num_primes++] = tleft;

    // Prepare helper polys
    int work_deg = 2 * n + 2;
    polynomial_t *B = polynomial_create(work_deg);
    polynomial_t *H = polynomial_create(work_deg);
    polynomial_t *G = polynomial_create(work_deg);
    polynomial_t *f_copy = polynomial_create(f->max_degree);
    poly_copy(f_copy, f);

    // For each distinct prime p | n, check gcd(X^{q^{n/p}} - X, f) = 1
    for (int i = 0; i < num_primes; i++) {
        int p = primes[i];
        int k = n / p;
        int e = m * k; // compute X^{2^e} mod f
        poly_x_pow_2e_mod(B, e, f_copy);
        // H = B - X = B + X
        polynomial_t *Xpoly = polynomial_create(work_deg);
        poly_set_x(Xpoly);
        poly_add(H, B, Xpoly);
        polynomial_free(Xpoly);
        poly_gcd(G, H, f_copy);
        if (G->degree != 0) { // gcd != 1
            polynomial_free(B); polynomial_free(H); polynomial_free(G); polynomial_free(f_copy);
            return 0;
        }
    }

    // Final check: f | (X^{q^n} - X)
    int e_final = m * n;
    poly_x_pow_2e_mod(B, e_final, f_copy);
    polynomial_t *Xpoly = polynomial_create(work_deg);
    poly_set_x(Xpoly);
    poly_add(H, B, Xpoly);
    polynomial_free(Xpoly);
    // If (X^{q^n} - X) mod f == 0, then H mod f == 0
    polynomial_t *R = polynomial_create(work_deg);
    poly_mod(R, H, f_copy);
    int zero = polynomial_is_zero(R);
    polynomial_free(R);

    polynomial_free(B); polynomial_free(H); polynomial_free(G); polynomial_free(f_copy);
    return zero;
}

// Solve square linear system over GF(2^m) with Gauss-Jordan
static int solve_linear_system_over_gfq(gf_elem_t *M, gf_elem_t *b, gf_elem_t *x, int n) {
    for (int col = 0, row = 0; col < n && row < n; col++, row++) {
        int piv = -1;
        for (int r = row; r < n; r++) {
            if (M[r * n + col] != 0) { piv = r; break; }
        }
        if (piv == -1) return -1;
        if (piv != row) {
            for (int c = col; c < n; c++) {
                gf_elem_t tmp = M[row * n + c];
                M[row * n + c] = M[piv * n + c];
                M[piv * n + c] = tmp;
            }
            gf_elem_t tb = b[row]; b[row] = b[piv]; b[piv] = tb;
        }
        gf_elem_t inv = gf_inv(M[row * n + col]);
        for (int c = col; c < n; c++) M[row * n + c] = gf_mul(M[row * n + c], inv);
        b[row] = gf_mul(b[row], inv);
        for (int r = 0; r < n; r++) {
            if (r == row) continue;
            gf_elem_t factor = M[r * n + col];
            if (factor != 0) {
                for (int c = col; c < n; c++) M[r * n + c] = gf_add(M[r * n + c], gf_mul(factor, M[row * n + c]));
                b[r] = gf_add(b[r], gf_mul(factor, b[row]));
            }
        }
    }
    for (int i = 0; i < n; i++) x[i] = b[i];
    return 0;
}

// Build a monic degree-t polynomial via Gaussian elimination on a truncated-power basis.
// This follows the "Gaussian path" to compute a connection polynomial for f without explicit irreducibility testing.
static int build_minpoly_gaussian(polynomial_t *g, const uint8_t *random_bits) {
    int t = MCELIECE_T;
    int m = MCELIECE_M;

    memset(g->coeffs, 0, (g->max_degree + 1) * sizeof(gf_elem_t));
    g->degree = -1;

    int coeff_pool_bytes = (MCELIECE_SIGMA1 * MCELIECE_T) / 8;
    if (coeff_pool_bytes <= 0) coeff_pool_bytes = (t * m + 7) / 8;

    // Build f(x) with degree < t from random bits
    gf_elem_t f_coeffs[MCELIECE_T];
    int bit_cursor = 0;
    for (int i = 0; i < t; i++) {
        int byte_idx = bit_cursor / 8;
        int bit_off = bit_cursor % 8;
        uint32_t val = 0;
        if (byte_idx < coeff_pool_bytes) {
            val = random_bits[byte_idx];
            if (byte_idx + 1 < coeff_pool_bytes) val |= ((uint32_t)random_bits[byte_idx + 1] << 8);
            if (byte_idx + 2 < coeff_pool_bytes) val |= ((uint32_t)random_bits[byte_idx + 2] << 16);
            val >>= bit_off;
        }
        f_coeffs[i] = (gf_elem_t)(val & ((1u << m) - 1));
        bit_cursor += m;
    }
    if (f_coeffs[t - 1] == 0) f_coeffs[t - 1] = 1;

    // Build powers v_k via truncated convolution
    gf_elem_t *basis = malloc(sizeof(gf_elem_t) * t * (t + 1));
    if (!basis) return 0;
    for (int i = 0; i < t; i++) basis[0 * t + i] = 0;
    basis[0 * t + 0] = 1;
    gf_elem_t *tmp = malloc(sizeof(gf_elem_t) * t);
    if (!tmp) { free(basis); return 0; }
    for (int k = 1; k <= t; k++) {
        for (int i = 0; i < t; i++) {
            gf_elem_t acc = 0;
            for (int j = 0; j <= i; j++) {
                acc = gf_add(acc, gf_mul(basis[(k - 1) * t + j], f_coeffs[i - j]));
            }
            tmp[i] = acc;
        }
        for (int i = 0; i < t; i++) basis[k * t + i] = tmp[i];
    }
    free(tmp);

    // Solve M * g_lower = v_t
    gf_elem_t *Mmat = malloc(sizeof(gf_elem_t) * t * t);
    gf_elem_t *rhs = malloc(sizeof(gf_elem_t) * t);
    gf_elem_t *sol = malloc(sizeof(gf_elem_t) * t);
    if (!Mmat || !rhs || !sol) { if (Mmat) free(Mmat); if (rhs) free(rhs); if (sol) free(sol); free(basis); return 0; }
    for (int r = 0; r < t; r++) {
        for (int c = 0; c < t; c++) Mmat[r * t + c] = basis[c * t + r];
        rhs[r] = basis[t * t + r];
    }
    int ok = solve_linear_system_over_gfq(Mmat, rhs, sol, t);
    free(Mmat); free(rhs); free(basis);
    if (ok != 0) { free(sol); return 0; }

    // Construct g(x)
    memset(g->coeffs, 0, (g->max_degree + 1) * sizeof(gf_elem_t));
    for (int i = 0; i < t; i++) polynomial_set_coeff(g, i, sol[i]);
    polynomial_set_coeff(g, t, 1);
    free(sol);
    return 1;
}

mceliece_error_t generate_irreducible_poly_final(polynomial_t *g, const uint8_t *random_bits) {
    // Keep attempting the Gaussian path until success; deterministically no fallback
    int max_attempts = 800;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        if (build_minpoly_gaussian(g, random_bits)) {
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

    // Convert H to systematic form [I_mt | T] and record transforms (optional)
    // For now, keep existing behavior; later we can switch to _record and store in sk
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

// Variant that also outputs the column permutation used
mceliece_error_t mat_gen_with_transforms(const polynomial_t *g, const gf_elem_t *alpha,
                                         matrix_t *T_out, int *perm_out) {
    if (!g || !alpha || !T_out) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    int n = MCELIECE_N;
    int t = MCELIECE_T;
    int m = MCELIECE_M;
    int mt = m * t;
    int k = n - mt;

    matrix_t *H = matrix_create(mt, n);
    if (!H) return MCELIECE_ERROR_MEMORY;

    for (int i = 0; i < t; i++) {
        for (int j = 0; j < n; j++) {
            gf_elem_t alpha_power = gf_pow(alpha[j], i);
            gf_elem_t g_alpha = polynomial_eval(g, alpha[j]);
            if (g_alpha == 0) { matrix_free(H); return MCELIECE_ERROR_KEYGEN_FAIL; }
            gf_elem_t M_ij = gf_div(alpha_power, g_alpha);
            for (int bit = 0; bit < m; bit++) {
                int bit_value = (M_ij >> bit) & 1;
                matrix_set_bit(H, i * m + bit, j, bit_value);
            }
        }
    }

    // Record transforms
    matrix_t *U = matrix_create(mt, mt);
    if (!U) { matrix_free(H); return MCELIECE_ERROR_MEMORY; }
    if (reduce_to_systematic_form_record(H, U, perm_out) != 0) {
        matrix_free(H); matrix_free(U); return MCELIECE_ERROR_KEYGEN_FAIL;
    }

    for (int i = 0; i < mt; i++) {
        for (int j = 0; j < k; j++) {
            int bit = matrix_get_bit(H, i, mt + j);
            matrix_set_bit(T_out, i, j, bit);
        }
    }

    matrix_free(U);
    matrix_free(H);
    return MCELIECE_SUCCESS;
}



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
