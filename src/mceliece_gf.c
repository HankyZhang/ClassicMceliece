// Fast GF(2^13) with log/antilog tables (correct, table-based)
#include "mceliece_gf.h"
#include "mceliece_types.h" // for MCELIECE_M/MCELIECE_Q
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifndef GFBITS
#define GFBITS MCELIECE_M
#endif
#ifndef GFMASK
#define GFMASK ((1u << GFBITS) - 1u)
#endif

// Irreducible polynomial for GF(2^13): x^13 + x^4 + x^3 + x + 1
#define GF_POLY 0x201B

gf_elem_t *gf_log = NULL;
gf_elem_t *gf_antilog = NULL;

static inline int wrap_exp(int e) {
    int m = (int)MCELIECE_Q - 1;
    e %= m;
    if (e < 0) e += m;
    return e;
}

// Bitwise multiply (for table initialization only)
static gf_elem_t gf_mul_for_init(gf_elem_t a, gf_elem_t b) {
    unsigned int aa = a & GFMASK;
    unsigned int bb = b & GFMASK;
    unsigned int acc = 0;
    while (bb) {
        if (bb & 1u) acc ^= aa;
        bb >>= 1;
        aa <<= 1;
        if (aa & (1u << MCELIECE_M)) {
            aa ^= GF_POLY;
        }
    }
    return (gf_elem_t)(acc & GFMASK);
}

void gf_init(void) {
    if (!gf_log) {
        gf_log = (gf_elem_t*)malloc((size_t)MCELIECE_Q * sizeof(gf_elem_t));
        assert(gf_log);
    }
    if (!gf_antilog) {
        gf_antilog = (gf_elem_t*)malloc((size_t)MCELIECE_Q * sizeof(gf_elem_t));
        assert(gf_antilog);
    }
    memset(gf_log, 0, (size_t)MCELIECE_Q * sizeof(gf_elem_t));
    memset(gf_antilog, 0, (size_t)MCELIECE_Q * sizeof(gf_elem_t));

    assert(MCELIECE_M == 13 && MCELIECE_Q == 8192);
    const gf_elem_t generator = 3; // primitive element used to generate the field
    gf_elem_t p = 1;

    for (int i = 0; i < (int)MCELIECE_Q - 1; i++) {
        gf_antilog[i] = p;
        gf_log[p] = (gf_elem_t)i;
        p = gf_mul_for_init(p, generator);
        if (i > 0 && p == 1) break; // completed cycle
    }
    // Optional mirror so index (Q-1) maps cleanly to 1; indices are wrapped anyway
    gf_antilog[MCELIECE_Q - 1] = 1;
    gf_log[0] = 0; // never used; keep defined
}

gf_elem_t gf_add(gf_elem_t a, gf_elem_t b) { return (gf_elem_t)(a ^ b); }

gf_elem_t gf_mul(gf_elem_t a, gf_elem_t b) {
    if ((a & GFMASK) == 0 || (b & GFMASK) == 0) return 0;
    int la = gf_log[a & GFMASK];
    int lb = gf_log[b & GFMASK];
    int idx = wrap_exp(la + lb);
    return gf_antilog[idx];
}

gf_elem_t gf_inv(gf_elem_t a) {
    a &= GFMASK;
    if (a == 0) return 0;
    if (a == 1) return 1;
    int la = gf_log[a];
    int idx = wrap_exp(((int)MCELIECE_Q - 1) - la);
    return gf_antilog[idx];
}

gf_elem_t gf_div(gf_elem_t a, gf_elem_t b) {
    a &= GFMASK; b &= GFMASK;
    if (b == 0) return 0;
    if (a == 0) return 0;
    int la = gf_log[a];
    int lb = gf_log[b];
    int idx = wrap_exp(la - lb);
    return gf_antilog[idx];
}

gf_elem_t gf_pow(gf_elem_t base, int exp) {
    if (exp == 0) return 1;
    if ((base & GFMASK) == 0) return 0;
    gf_elem_t result = 1;
    base &= GFMASK;
    while (exp > 0) {
        if (exp & 1) result = gf_mul(result, base);
        base = gf_mul(base, base);
        exp >>= 1;
    }
    return result;
}

gf_elem_t bits_to_gf(const uint8_t *bits, int start_bit) {
    gf_elem_t result = 0;
    for (int i = 0; i < MCELIECE_M; i++) {
        int byte_idx = (start_bit + i) / 8;
        int bit_idx = (start_bit + i) % 8;
        if (bits[byte_idx] & (1 << bit_idx)) result |= (1 << i);
    }
    return result;
}

void gf_to_bits(gf_elem_t elem, uint8_t *bits, int start_bit) {
    for (int i = 0; i < MCELIECE_M; i++) {
        int byte_idx = (start_bit + i) / 8;
        int bit_idx = (start_bit + i) % 8;
        if (elem & (1 << i)) bits[byte_idx] |= (1 << bit_idx);
        else bits[byte_idx] &= (unsigned char)~(1 << bit_idx);
    }
}














