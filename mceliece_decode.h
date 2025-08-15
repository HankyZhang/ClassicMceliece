#ifndef MCELIECE_DECODE_H
#define MCELIECE_DECODE_H

#include <stdint.h>
#include <stddef.h>
#include "mceliece_types.h"
#include "mceliece_matrix_ops.h"
#include "mceliece_gf.h"
#include "mceliece_vector.h"
#include "mceliece_poly.h"

#ifdef __cplusplus
extern "C" {
#endif

// Syndrome computation - calculates syndrome for received vector
void compute_syndrome(const uint8_t *received, const polynomial_t *g,
                      const gf_elem_t *alpha, gf_elem_t *syndrome);

// Berlekamp-Massey algorithm - compute only error locator polynomial sigma
mceliece_error_t berlekamp_massey(const gf_elem_t *syndrome,
                                 polynomial_t *sigma);

// Chien search - finds roots of error locator polynomial
mceliece_error_t chien_search(const polynomial_t *sigma, const gf_elem_t *alpha,
                             int *error_positions, int *num_errors);

// Goppa code decoding - recovers error vector from syndrome
mceliece_error_t decode_goppa(const uint8_t *received, const polynomial_t *g,
                             const gf_elem_t *alpha, uint8_t *error_vector,
                             int *decode_success);



#ifdef __cplusplus
}
#endif

#endif // MCELIECE_DECODE_H
