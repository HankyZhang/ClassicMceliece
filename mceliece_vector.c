#include "mceliece_vector.h"

// 矩阵位设置
void vector_set_bit(uint8_t *vec, int bit_idx, int value) {
    int byte_idx = bit_idx / 8;
    int bit_pos = bit_idx % 8;
    if (value) {
        vec[byte_idx] |= (1 << bit_pos);
    } else {
        vec[byte_idx] &= ~(1 << bit_pos);
    }
}

// 向量位获取
int vector_get_bit(const uint8_t *vec, int bit_idx) {
    int byte_idx = bit_idx / 8;
    int bit_pos = bit_idx % 8;
    return (vec[byte_idx] >> bit_pos) & 1;
}

// 向量权重计算
int vector_weight(const uint8_t *vec, int len_bytes) {
    int weight = 0;
    for (int i = 0; i < len_bytes; i++) {
        uint8_t byte = vec[i];
        // 计算字节中1的个数（Brian Kernighan算法）
        while (byte) {
            byte &= byte - 1;
            weight++;
        }
    }
    return weight;
}