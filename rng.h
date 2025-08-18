#ifndef RNG_H
#define RNG_H

#include <stddef.h>

/* NIST AES-256-CTR DRBG API used by PQCgenKAT */

void randombytes_init(const unsigned char *entropy_input,
                      const unsigned char *personalization_string,
                      int security_strength);

void randombytes(unsigned char *x, unsigned long long xlen);

#endif /* RNG_H */

