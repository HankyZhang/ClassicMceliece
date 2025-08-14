#ifndef CLASSICMCELIECE_MCELIECE_ENCODE_H
#define CLASSICMCELIECE_MCELIECE_ENCODE_H

#include <stdint.h>
#include <stddef.h>
#include "mceliece_types.h"
#include "mceliece_shake.h"
#include "mceliece_vector.h"

#ifdef __cplusplus
extern "C" {
#endif

// Generate a random vector with fixed Hamming weight t
// Used in the encapsulation phase to generate the error vector e
mceliece_error_t fixed_weight_vector(uint8_t *output, int vector_len, int target_weight);

// Encode an error vector using the public key matrix T
// Computes C = H * e where H = [I_mt | T]
void encode_vector(const uint8_t *error_vector, const matrix_t *T, uint8_t *ciphertext);

#ifdef __cplusplus
}
#endif

#endif //CLASSICMCELIECE_MCELIECE_ENCODE_H