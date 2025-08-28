
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
    // pk->T already contains only the right block (systematic part), so export entire matrix
    return matrix_export_right_block_reference_packing(&pk->T, 0, out, out_row_bytes);
}

// Serialize secret key exactly like the reference layout:
// sk = delta(32) || pivots(8 bytes, 0xFFFFFFFF) || irr(T*2 bytes, LE) || controlbits(COND_BYTES) || s(n/8)
static inline int private_key_serialize_refpacking(const private_key_t *sk, uint8_t *out, size_t out_capacity, size_t *out_len) {
    if (!sk || !out) return -1;
    const int t = MCELIECE_T;
    const int m = MCELIECE_M;
    const size_t irr_bytes = (size_t)t * 2; // T coefficients, 2 bytes each (LE)
    const size_t cb_len = sk->controlbits_len > 0 ? sk->controlbits_len : (size_t)((2 * m - 1) * (1u << (m - 4))); // reference formula
    const size_t s_len = MCELIECE_N_BYTES;
    const size_t total = 32 + 8 + irr_bytes + cb_len + s_len;
    if (out_capacity < total) return -1;

    size_t off = 0;
    // delta
    memcpy(out + off, sk->delta, 32); off += 32;
    // pivots: reference stores store8(0xFFFFFFFF) => little-endian 4xFF then 4x00
    out[off+0] = 0xFF; out[off+1] = 0xFF; out[off+2] = 0xFF; out[off+3] = 0xFF;
    out[off+4] = 0x00; out[off+5] = 0x00; out[off+6] = 0x00; out[off+7] = 0x00;
    off += 8;
    // irr = lower T coeffs of g, LE, masked to m bits
    for (int i = 0; i < t; i++) {
        uint16_t c = (uint16_t)(sk->g.coeffs[i] & ((1u << m) - 1u));
        out[off + 2*i + 0] = (uint8_t)(c & 0xFFu);
        out[off + 2*i + 1] = (uint8_t)((c >> 8) & 0xFFu);
    }
    off += irr_bytes;
    // controlbits
    if (!sk->controlbits || cb_len == 0) return -1;
    memcpy(out + off, sk->controlbits, cb_len); off += cb_len;
    // s
    memcpy(out + off, sk->s, s_len); off += s_len;

    if (out_len) *out_len = off;
    return 0;
}

// Return the number of attempts used by the most recent successful seeded_key_gen.
// 0 means not run yet; >0 means success after that many attempts.
int get_last_seeded_key_gen_attempts(void);

#ifdef __cplusplus
}
#endif

#endif //CLASSICMCELIECE_MCELIECE_KEYGEN_H
