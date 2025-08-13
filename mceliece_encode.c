#inlcude "mceliece_types.h"



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




mceliece_error_t fixed_weight_vector(uint8_t *e, int n, int t) {
    memset(e, 0, (n + 7) / 8);

    // 根据规范 2.1 FixedWeight() 算法
    // 1. 生成 σ₁τ 个随机比特，其中 τ ≥ t
    int tau = t + 10; // 确保 τ ≥ t，增加一些余量
    size_t random_bytes_len = tau * 2; // σ₁ = 16 bits = 2 bytes per position
    uint8_t *random_bytes = malloc(random_bytes_len);
    if (!random_bytes) return MCELIECE_ERROR_MEMORY;

    mceliece_prg((const uint8_t*)"a_seed_for_fixed_weight_vector", random_bytes, random_bytes_len);

    // 2. 为每个 j ∈ {0, 1, ..., τ-1}，定义 d_j
    int *d_values = malloc(tau * sizeof(int));
    if (!d_values) { free(random_bytes); return MCELIECE_ERROR_MEMORY; }

    for (int j = 0; j < tau; j++) {
        // 取 σ₁ 比特块的前 m 位作为整数
        uint16_t d_j = (uint16_t)random_bytes[j * 2] |
                       ((uint16_t)random_bytes[j * 2 + 1] << 8);
        d_values[j] = d_j % n; // 范围在 {0, 1, ..., n-1}
    }

    // 3. 定义 a_0, a_1, ..., a_{t-1} 为从 d_0, d_1, ..., d_{τ-1} 中选择的前 t 个唯一条目
    int *positions = malloc(t * sizeof(int));
    if (!positions) { free(random_bytes); free(d_values); return MCELIECE_ERROR_MEMORY; }

    int unique_count = 0;
    int max_attempts = tau * 2; // 防止无限循环
    int attempts = 0;

    for (int i = 0; i < tau && unique_count < t && attempts < max_attempts; i++) {
        int pos = d_values[i];
        int is_unique = 1;

        // 检查该位置是否已经存在
        for (int j = 0; j < unique_count; j++) {
            if (positions[j] == pos) {
                is_unique = 0;
                break;
            }
        }

        if (is_unique) {
            positions[unique_count] = pos;
            unique_count++;
        }
        attempts++;
    }

    // 如果找不到足够的唯一位置，重新生成
    if (unique_count < t) {
        free(positions);
        free(d_values);
        free(random_bytes);
        return MCELIECE_ERROR_KEYGEN_FAIL; // 重新尝试
    }

    // 4. 在这些位置上将向量 e 的比特位置为 1
    for (int i = 0; i < t; i++) {
        vector_set_bit(e, positions[i], 1);
    }

    free(positions);
    free(d_values);
    free(random_bytes);
    return MCELIECE_SUCCESS;
}


// Encode算法：C = He，其中H = (I_mt | T)
void encode_vector(const uint8_t *error_vector, const matrix_t *T, uint8_t *ciphertext) {
    if (!error_vector || !T || !ciphertext) return;

    int mt = MCELIECE_M * MCELIECE_T;
    int mt_bytes = (mt + 7) / 8;

    // 清零密文
    memset(ciphertext, 0, mt_bytes);

    // C = H * e，其中H = (I_mt | T)
    // 由于H的前mt列是单位矩阵，所以前mt位的C直接等于e的前mt位

    // 复制e的前mt位到C
    for (int i = 0; i < mt; i++) {
        // 1. 从 error_vector 获取比特值 (0 或 1)
        int bit = vector_get_bit(error_vector, i);

        // 2. 将获取到的比特值直接设置到 ciphertext 中
        vector_set_bit(ciphertext, i, bit);
    }

    // 计算T矩阵与e的后k位的乘积，并异或到C中
    for (int row = 0; row < mt; row++) {
        int sum = 0;
        for (int col = 0; col < T->cols; col++) {
            int e_bit = vector_get_bit(error_vector, mt + col);
            int T_bit = matrix_get_bit(T, row, col);
            sum ^= (e_bit & T_bit);
        }

        if (sum) {
            // 直接异或当前位
            int current_bit = vector_get_bit(ciphertext, row);
            vector_set_bit(ciphertext, row, current_bit ^ 1);
        }
    }
}



