#ifndef CONTROLBITS_H
#define CONTROLBITS_H

#include <stdint.h>
#include <stddef.h>

/* Compute control bits for a Benes network from a permutation pi of size n=2^w.
 * out must point to ((2*w-1)*n/16) bytes, zeroed by the caller or by the impl.
 * Named uniquely to avoid collisions with existing API. */
void cbits_from_perm_ns(uint8_t *out, const int16_t *pi, long long w, long long n);


/* Self-test: verify that applying Benes layers defined by control bits routes identity to pi */
int controlbits_verify(const uint8_t *cbits, long long w, long long n, const int16_t *pi);

#endif /* CONTROLBITS_H */

