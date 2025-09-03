#ifndef CLASSICMCELIECE_MCELIECE_KEYGEN_SEMI_H
#define CLASSICMCELIECE_MCELIECE_KEYGEN_SEMI_H

#include <stdint.h>
#include <stddef.h>
#include "../src/mceliece_types.h"
#include "../src/mceliece_matrix_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

// Build H and reduce it to semi-systematic form using reference-style walk.
// Also records the column permutation into col_perm (length MCELIECE_N) if non-NULL,
// and updates the global permutation pi (length 1<<MCELIECE_M) in-place like reference mov_columns.
int reduce_to_semisystematic_reference_style(matrix_t *H, uint64_t *pivots, int16_t *col_perm, int16_t *pi);

// SeededKeyGen variant producing semi-systematic public key; stores pivots in sk->c
mceliece_error_t seeded_key_gen_semi(const uint8_t *delta, public_key_t *pk, private_key_t *sk);

// Serialize secret key including pivots field c per semi-systematic spec
int private_key_serialize_semi(const private_key_t *sk, uint8_t *out, size_t out_capacity, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // CLASSICMCELIECE_MCELIECE_KEYGEN_SEMI_H




