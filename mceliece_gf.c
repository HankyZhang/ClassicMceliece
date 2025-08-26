#include "mceliece_gf.h"

// Forward declaration for initialization
static gf_elem_t gf_mul_for_init(gf_elem_t a, gf_elem_t b);

gf_elem_t *gf_log = NULL;
gf_elem_t *gf_antilog = NULL;

void gf_init(void) {
    // ----> 新增：在函数开头进行内存分配 <----
    if (gf_log == NULL) { // 确保只分配一次
        gf_log = malloc(MCELIECE_Q * sizeof(gf_elem_t));
        if (gf_log == NULL) {
            fprintf(stderr, "Failed to allocate memory for gf_log\n");
            exit(1);
        }
    }
    if (gf_antilog == NULL) {
        gf_antilog = malloc(MCELIECE_Q * sizeof(gf_elem_t));
        if (gf_antilog == NULL) {
            fprintf(stderr, "Failed to allocate memory for gf_antilog\n");
            exit(1);
        }
    }

    // Initialize GF(2^13) lookup tables using generator element 3
    const gf_elem_t generator = 3;
    gf_elem_t p = 1;
    int i;

    assert(MCELIECE_M == 13);
    assert(MCELIECE_Q == 8192);

    for (i = 0; i < MCELIECE_Q - 1; i++) {
        gf_antilog[i] = p;
        gf_log[p] = (gf_elem_t)i;
        gf_elem_t old_p = p;
        p = gf_mul_for_init(p, generator);

        // Check for infinite loop condition
        if (i > 0 && p == 1) {
            break;
        }

        // Prevent potential infinite loops
        if (i > 0 && p == old_p) {
            fprintf(stderr, "ERROR: GF table generation stuck at iteration %d\n", i);
            exit(1);
        }
    }

    gf_log[0] = 0;
    // Ensure table closure: needed for inv(1) which accesses index Q-1
    gf_antilog[MCELIECE_Q - 1] = 1;
}


gf_elem_t gf_add(gf_elem_t a, gf_elem_t b) {
    return a ^ b;
}

/*
 * 这是一个已知正确的、用于初始化的GF(2^m)乘法实现。
 * 它使用标准的“俄罗斯农夫乘法”(位移和异或)算法。
 */
static gf_elem_t gf_mul_for_init(gf_elem_t a, gf_elem_t b) {
    // According to Classic McEliece specification, for m=13 the irreducible polynomial is:
    // x^13 + x^4 + x^3 + x + 1
    // In binary: 10000000011011 = 0x201B
    // For reduction, we use the polynomial without the leading bit: 0x001B
    const gf_elem_t reducing_poly = 0x001B;
    gf_elem_t r = 0;
    gf_elem_t temp_a = a;  // 使用临时变量，不修改原始参数

    // 我们将循环 m 次 (m=13)
    for (int i = 0; i < MCELIECE_M; i++) {
        // 如果 b 的当前最低位是 1
        if (b & 1) {
            r ^= temp_a;
        }

        // b 右移一位，准备处理下一位
        b >>= 1;

        // temp_a 左移一位 (相当于 temp_a = temp_a * x)
        // 检查最高位 (x^12) 是否为 1
        if (temp_a & (1 << (MCELIECE_M - 1))) {
            // 如果是，左移后会溢出，需要进行模约简
            // 1. 先左移
            temp_a <<= 1;
            // 2. 然后与约简多项式异或
            temp_a ^= reducing_poly;
        } else {
            // 如果不是，直接左移即可
            temp_a <<= 1;
        }
        // Ensure temp_a stays within the field bounds (13 bits)
        temp_a &= ((1 << MCELIECE_M) - 1);
    }

    // Ensure result stays within the field bounds (13 bits)
    return r & ((1 << MCELIECE_M) - 1);
}


// Correct GF(2^13) multiplication using bit-level reduction (matches reference math)
gf_elem_t gf_mul(gf_elem_t a, gf_elem_t b) {
    if (a == 0 || b == 0) {
        return 0;
    }
    
    int log_a = gf_log[a];
    int log_b = gf_log[b];
    int sum_log = log_a + log_b;
    if (sum_log >= MCELIECE_Q - 1) {
        sum_log -= (MCELIECE_Q - 1);
    }
    return gf_antilog[sum_log];
}

// GF(2^13) 求逆
gf_elem_t gf_inv(gf_elem_t a) {
    if (a == 0) {
        return 0;
    }
    // 确保 log[a] 在范围内，避免负数索引
    if (gf_log[a] == 0 && a != 1) return 0; // 处理未初始化或无效情况
    return gf_antilog[(MCELIECE_Q - 1) - gf_log[a]];
}

// GF(2^13)除法
gf_elem_t gf_div(gf_elem_t a, gf_elem_t b) {
    if (b == 0) return 0;  // 除零错误
    return gf_mul(a, gf_inv(b));
}

// GF(2^13)幂运算
gf_elem_t gf_pow(gf_elem_t base, int exp) {
    if (exp == 0) return 1;
    if (base == 0) return 0;

    gf_elem_t result = 1;
    base = base & ((1 << MCELIECE_M) - 1);

    while (exp > 0) {
        if (exp & 1) {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }

    return result;
}

// 从比特向量表示转换为GF元素
gf_elem_t bits_to_gf(const uint8_t *bits, int start_bit) {
    gf_elem_t result = 0;

    for (int i = 0; i < MCELIECE_M; i++) {
        int byte_idx = (start_bit + i) / 8;
        int bit_idx = (start_bit + i) % 8;

        if (bits[byte_idx] & (1 << bit_idx)) {
            result |= (1 << i);
        }
    }

    return result;
}

// 从GF元素转换为比特向量表示
void gf_to_bits(gf_elem_t elem, uint8_t *bits, int start_bit) {
    for (int i = 0; i < MCELIECE_M; i++) {
        int byte_idx = (start_bit + i) / 8;
        int bit_idx = (start_bit + i) % 8;

        if (elem & (1 << i)) {
            bits[byte_idx] |= (1 << bit_idx);
        } else {
            bits[byte_idx] &= ~(1 << bit_idx);
        }
    }
}














