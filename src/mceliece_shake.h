#ifndef CLASSICMCELIECE_MCELIECE_SHAKE_H
#define CLASSICMCELIECE_MCELIECE_SHAKE_H

#include <stdint.h>
#include <stddef.h>
#include "mceliece_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// SHAKE256 context structure
typedef struct {
    uint64_t state[25];       // Keccak state (25 * 64-bit words)
    uint8_t buffer[136];      // 1088/8 = 136 bytes for SHAKE256
    int buffer_pos;           // Current position in buffer
    int squeezing;            // Flag indicating if we're in squeezing phase
} shake256_ctx;

// SHAKE256 functions
void shake256_init(shake256_ctx *ctx);
void shake256_absorb(shake256_ctx *ctx, const uint8_t *input, size_t len);
void shake256_finalize(shake256_ctx *ctx);
void shake256_squeeze(shake256_ctx *ctx, uint8_t *output, size_t len);

// High-level SHAKE256 function
void shake256(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len);

// McEliece-specific hash functions
void mceliece_hash(uint8_t prefix, const uint8_t *input, size_t input_len, uint8_t *output);
void mceliece_prg(const uint8_t *seed, uint8_t *output, size_t output_len);

#ifdef __cplusplus
}
#endif

#endif //CLASSICMCELIECE_MCELIECE_SHAKE_H
