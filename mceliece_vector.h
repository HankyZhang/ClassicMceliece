
#ifndef CLASSICMCELIECE_MCELIECE_VECTOR_H
#define CLASSICMCELIECE_MCELIECE_VECTOR_H

void vector_set_bit(uint8_t *vec, int bit_idx, int value);
void vector_clear_bit(uint8_t *vec, int bit_idx);
int  vector_get_bit(const uint8_t *vec, int bit_idx);
int  vector_weight(const uint8_t *vec, int len_bytes);


#endif //CLASSICMCELIECE_MCELIECE_VECTOR_H
