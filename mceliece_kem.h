#ifndef MCELIECE_KEM_H
#define MCELIECE_KEM_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "mceliece_types.h"
#include "mceliece_shake.h"
#include "mceliece_decode.h"
#include "mceliece_encode.h"
#include "mceliece_keygen.h"
#include "mceliece_poly.h"

#ifdef __cplusplus
extern "C" {
#endif

    // 核心接口

    mceliece_error_t mceliece_keygen(public_key_t *pk, private_key_t *sk);
    mceliece_error_t mceliece_encap(const public_key_t *pk, uint8_t *ciphertext, uint8_t *session_key);
    mceliece_error_t mceliece_decap(const uint8_t *ciphertext, const private_key_t *sk, uint8_t *session_key);

    // 测试函数
    void test_mceliece(void);

#ifdef __cplusplus
}
#endif

#endif // MCELIECE_H
