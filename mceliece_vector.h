
#ifndef CLASSICMCELIECE_MCELIECE_VECTOR_H
#define CLASSICMCELIECE_MCELIECE_VECTOR_H

#include <stdint.h>
#include <stddef.h>
#include "mceliece_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Bit manipulation functions for binary vectors
void vector_set_bit(uint8_t *vec, int bit_idx, int value);
void vector_clear_bit(uint8_t *vec, int bit_idx);
int  vector_get_bit(const uint8_t *vec, int bit_idx);

// Vector utility functions
int  vector_weight(const uint8_t *vec, int len_bytes);  // Calculate Hamming weight
void vector_xor(uint8_t *result, const uint8_t *a, const uint8_t *b, int len_bytes);
void vector_copy(uint8_t *dst, const uint8_t *src, int len_bytes);
void vector_zero(uint8_t *vec, int len_bytes);

#ifdef __cplusplus
}
#endif

#endif //CLASSICMCELIECE_MCELIECE_VECTOR_H
