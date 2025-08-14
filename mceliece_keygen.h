
#ifndef CLASSICMCELIECE_MCELIECE_KEYGEN_H
#define CLASSICMCELIECE_MCELIECE_KEYGEN_H

#include "stdio.h"
#include <stdint.h>
#include "mceliece_types.h" // 需要 mceliece_error_t 和 polynomial_t
mceliece_error_t seeded_key_gen(const uint8_t *delta, public_key_t *pk, private_key_t *sk);
    mceliece_error_t generate_field_ordering(gf_elem_t *alpha_output, const uint8_t *random_bits);
    mceliece_error_t generate_irreducible_poly_final(polynomial_t *g, const uint8_t *random_bits);
    // MatGen 与编码
    mceliece_error_t mat_gen(const polynomial_t *g, const gf_elem_t *alpha, matrix_t *T_out);

    private_key_t* private_key_create(void);
    void private_key_free(private_key_t *sk);
    public_key_t* public_key_create(void);
    void public_key_free(public_key_t *pk);

#endif //CLASSICMCELIECE_MCELIECE_KEYGEN_H
