// Implement GF arithmetic over GF(2^13) without external references
#include "mceliece_gf.h"
#include "mceliece_types.h" // for MCELIECE_M

#ifndef GFBITS
#define GFBITS MCELIECE_M
#endif
#ifndef GFMASK
#define GFMASK ((1u << GFBITS) - 1u)
#endif

// Irreducible polynomial for GF(2^13): x^13 + x^4 + x^3 + x + 1 (0x201B)
#define GF_POLY 0x201B
#define GF_MASK ((1u << MCELIECE_M) - 1u)

// No table-based init required for polynomial-basis arithmetic
void gf_init(void) { (void)0; }

gf_elem_t gf_add(gf_elem_t a, gf_elem_t b) { return (gf_elem_t)(a ^ b); }

// Polynomial-basis multiplication modulo GF_POLY
static inline gf_elem_t gf_reduce(uint32_t acc) {
    // Reduce acc (up to 2*MCELIECE_M-2 bits) modulo GF_POLY
    for (int bit = (MCELIECE_M * 2 - 2); bit >= MCELIECE_M; bit--) {
        if ((acc >> bit) & 1u) {
            acc ^= ((uint32_t)GF_POLY) << (bit - MCELIECE_M);
        }
    }
    return (gf_elem_t)(acc & GF_MASK);
}

gf_elem_t gf_mul(gf_elem_t a, gf_elem_t b) {
    uint32_t acc = 0;
    uint32_t aa = a & GF_MASK;
    uint32_t bb = b & GF_MASK;
    while (bb) {
        if (bb & 1u) acc ^= aa;
        bb >>= 1;
        aa <<= 1;
        if (aa & (1u << MCELIECE_M)) {
            aa ^= GF_POLY;
        }
    }
    return (gf_elem_t)(acc & GF_MASK);
}

// Inversion via exponentiation: a^(2^m-2)
gf_elem_t gf_inv(gf_elem_t den) {
    if ((den & GF_MASK) == 0) return 0;
    // 2^m - 2 for m=13 is 8190
    return gf_pow(den, (1 << MCELIECE_M) - 2);
}

gf_elem_t gf_div(gf_elem_t a, gf_elem_t b) {
    if ((b & GF_MASK) == 0) return 0;
    return gf_mul(a, gf_inv(b));
}

gf_elem_t gf_pow(gf_elem_t base, int exp) {
    gf_elem_t result = 1;
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














