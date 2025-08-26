#ifndef SIMPLEFIPS202_H
#define SIMPLEFIPS202_H

#include <stddef.h>

/* Provide a minimal SHAKE256() API that maps to local implementation */

void shake256(const unsigned char *input, size_t inlen, unsigned char *output, size_t outlen);

static inline void SHAKE256(unsigned char *output, size_t outlen, const unsigned char *input, size_t inlen) {
    shake256(input, inlen, output, outlen);
}

#endif


