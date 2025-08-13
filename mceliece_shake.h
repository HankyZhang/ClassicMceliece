//
// Created by 张涵琦 on 2025/8/13.
//

#ifndef CLASSICMCELIECE_MCELIECE_SHAKE_H
#define CLASSICMCELIECE_MCELIECE_SHAKE_H

    void shake256_init(shake256_ctx *ctx);
    void shake256_absorb(shake256_ctx *ctx, const uint8_t *input, size_t len);
    void shake256_finalize(shake256_ctx *ctx);
    void shake256_squeeze(shake256_ctx *ctx, uint8_t *output, size_t len);
    void shake256(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len);
    void mceliece_hash(uint8_t prefix, const uint8_t *input, size_t input_len, uint8_t *output);
    void mceliece_prg(const uint8_t *seed, uint8_t *output, size_t output_len);

#endif //CLASSICMCELIECE_MCELIECE_SHAKE_H
