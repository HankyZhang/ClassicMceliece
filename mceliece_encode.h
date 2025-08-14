
#ifndef CLASSICMCELIECE_MCELIECE_ENCODE_C_H
#define CLASSICMCELIECE_MCELIECE_ENCODE_C_H

#include <stdint.h>
#include "mceliece_types.h"

    mceliece_error_t fixed_weight_vector(uint8_t *output, int vector_len, int target_weight);
    void encode_vector(const uint8_t *error_vector, const matrix_t *T, uint8_t *ciphertext);





#endif //CLASSICMCELIECE_MCELIECE_ENCODE_C_H
