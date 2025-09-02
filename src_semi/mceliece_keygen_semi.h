#ifndef CLASSICMCELIECE_MCELIECE_KEYGEN_SEMI_H
#define CLASSICMCELIECE_MCELIECE_KEYGEN_SEMI_H

#include <stdint.h>
#include <stddef.h>
#include "../src/mceliece_types.h"
#include "../src/mceliece_matrix_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

// Build H and reduce it to semi-systematic form using reference-style walk
int reduce_to_semisystematic_reference_style(matrix_t *H, uint64_t *pivots);

// SeededKeyGen variant producing semi-systematic public key; stores pivots in sk->c
mceliece_error_t seeded_key_gen_semi(const uint8_t *delta, public_key_t *pk, private_key_t *sk);

// Serialize secret key including pivots field c per semi-systematic spec
int private_key_serialize_semi(const private_key_t *sk, uint8_t *out, size_t out_capacity, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // CLASSICMCELIECE_MCELIECE_KEYGEN_SEMI_H



