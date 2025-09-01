#ifndef MCELIECE_KEM_COMPLETE_H
#define MCELIECE_KEM_COMPLETE_H

#include <stdint.h>
#include "mceliece_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Complete KEM interface matching NIST API
int crypto_kem_keypair_complete(unsigned char *pk, unsigned char *sk);

// Test function to verify complete implementation
int test_complete_keygen_with_kat(void);

#ifdef __cplusplus
}
#endif

#endif // MCELIECE_KEM_COMPLETE_H
