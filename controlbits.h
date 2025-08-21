#ifndef CONTROLBITS_H
#define CONTROLBITS_H

#include <stdint.h>
#include <stddef.h>
#include "mceliece_types.h"

/* Compute control bits for a Benes network from a permutation pi of size n=2^w.
 * out must point to ((2*w-1)*n/16) bytes, zeroed by the caller or by the impl.
 * Named uniquely to avoid collisions with existing API. */
void cbits_from_perm_ns(uint8_t *out, const int16_t *pi, long long w, long long n);


/* Self-test: verify that applying Benes layers defined by control bits routes identity to pi */
int controlbits_verify(const uint8_t *cbits, long long w, long long n, const int16_t *pi);

// Derive permutation pi from control bits (apply Benes to identity)
void cbits_pi_from_cbits(const uint8_t *cbits, long long w, long long n, int16_t *pi_out);

// Derive support L[0..N-1] from control bits (matches PQClean support_gen semantics)
void support_from_cbits(gf_elem_t *L, const uint8_t *cbits, long long w, int N);

#endif /* CONTROLBITS_H */

