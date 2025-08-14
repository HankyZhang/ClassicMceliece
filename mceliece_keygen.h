
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

// Matrix generation - derives public key matrix T from Goppa code
mceliece_error_t mat_gen(const polynomial_t *g, const gf_elem_t *alpha, matrix_t *T_out);
// Variant that records the column permutation used to reach systematic form
mceliece_error_t mat_gen_with_transforms(const polynomial_t *g, const gf_elem_t *alpha,
                                         matrix_t *T_out, int *perm_out);

// Control bits computation for Benes network (for permutation)
mceliece_error_t controlbitsfrompermutation(uint8_t *output, const int *perm, int n);

// Key structure management
private_key_t* private_key_create(void);
void private_key_free(private_key_t *sk);
public_key_t* public_key_create(void);
void public_key_free(public_key_t *pk);

#ifdef __cplusplus
}
#endif

#endif //CLASSICMCELIECE_MCELIECE_KEYGEN_H
