#ifndef REFERENCE_SHAKE_H
#define REFERENCE_SHAKE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Reference FIPS202 SHAKE256 implementation
void SHAKE256(unsigned char *output, size_t outputByteLen, const unsigned char *input, size_t inputByteLen);

// Compatibility function for our McEliece PRG
void mceliece_prg_reference(const uint8_t *seed, uint8_t *output, size_t output_len);

#ifdef __cplusplus
}
#endif

#endif // REFERENCE_SHAKE_H
