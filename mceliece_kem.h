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
    // Deterministic KAT interface driven by 48-byte seed per NIST KAT (parse external vectors)
    mceliece_error_t mceliece_kat_from_seed(const uint8_t *seed48,
                                            public_key_t *pk_out,
                                            private_key_t *sk_out,
                                            uint8_t *ciphertext_out,
                                            uint8_t *session_key_out);

    // KAT file adapter: read kat_kem.req and write kat_kem.rsp
    void run_kat_file(const char *req_path, const char *rsp_path);
    
    
    // 测试函数
    void test_mceliece(void);
    void run_all_tests(void);
    void test_basic_functions(void);
    void test_bm_chien(void);
    void test_decap_pipeline(void);
void test_stress(void);
void test_tamper(void);
void test_seeded(void);
void test_roundtrip(void);
void test_tamper_sweep(void);
void test_decap_full(void);
void test_decap_audit(void);

#ifdef __cplusplus
}
#endif

#endif // MCELIECE_H
