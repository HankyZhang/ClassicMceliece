#ifndef MCELIECE_KAT_DRBG_H
#define MCELIECE_KAT_DRBG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize global SHAKE256-based DRBG with a 48-byte seed
void kat_drbg_init(const uint8_t seed48[48]);

// Generate len bytes from the global DRBG
void kat_drbg_randombytes(uint8_t *out, size_t len);

// Returns 1 if DRBG has been initialized, else 0
int kat_drbg_is_inited(void);

// Expand r exactly like PQClean: out = SHAKE256(seed,33,len); also outputs delta (seed tail)
void kat_expand_r(uint8_t *out, size_t len, uint8_t delta_out32[32]);

// Return current delta (kg_seed[1..32]) without advancing or updating internal state
void kat_get_delta(uint8_t out32[32]);

#ifdef __cplusplus
}
#endif

#endif // MCELIECE_KAT_DRBG_H


