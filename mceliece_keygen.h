
#ifndef CLASSICMCELIECE_MCELIECE_KEYGEN_H
#define CLASSICMCELIECE_MCELIECE_KEYGEN_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "mceliece_types.h"
#include "mceliece_gf.h"
#include "mceliece_poly.h"
#include "mceliece_matrix_ops.h"
#include "mceliece_shake.h"

#ifdef __cplusplus
extern "C" {
#endif

// Core key generation functions
mceliece_error_t seeded_key_gen(const uint8_t *delta, public_key_t *pk, private_key_t *sk);

// Field ordering algorithm - generates support elements for Goppa code
mceliece_error_t generate_field_ordering(gf_elem_t *alpha_output, const uint8_t *random_bits);

// Irreducible polynomial generation algorithm
mceliece_error_t generate_irreducible_poly_final(polynomial_t *g, const uint8_t *random_bits);

// Matrix generation helpers were removed (no longer used)

// Control bits computation for Benes network (for permutation)
mceliece_error_t controlbitsfrompermutation(uint8_t *output, const int *perm, int n);

// Key structure management
private_key_t* private_key_create(void);
void private_key_free(private_key_t *sk);
public_key_t* public_key_create(void);
void public_key_free(public_key_t *pk);

// Serialize public key T into a flat buffer with reference packing (MSB-first)
// out length must be MCELIECE_PUBLICKEY_BYTES
static inline int public_key_serialize_refpacking(const public_key_t *pk, uint8_t *out) {
    if (!pk || !out) return -1;
    int mt = pk->T.rows;
    int out_row_bytes = pk->T.cols / 8;
    if (mt != MCELIECE_M * MCELIECE_T || out_row_bytes != MCELIECE_K_BYTES) return -1;
    return matrix_export_right_block_reference_packing(&pk->T, 0, out, out_row_bytes);
}

#ifdef __cplusplus
}
#endif

#endif //CLASSICMCELIECE_MCELIECE_KEYGEN_H
