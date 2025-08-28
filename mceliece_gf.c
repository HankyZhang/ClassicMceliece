// Implement GF arithmetic; delegate core ops to the reference gf for exact parity
#include "mceliece_gf.h"
#include "mceliece_types.h" // for MCELIECE_M

// Bring in reference gf symbols under ref_ namespace
#ifndef CRYPTO_NAMESPACE
#define CRYPTO_NAMESPACE(x) ref_##x
#endif
#include "mceliece6688128/gf.h"

// Avoid macro remapping our function names
#undef gf_add
#undef gf_mul
#undef gf_frac
#undef gf_inv
#undef GF_mul

#ifndef GFBITS
#define GFBITS MCELIECE_M
#endif
#ifndef GFMASK
#define GFMASK ((1u << GFBITS) - 1u)
#endif

// No table-based init required
void gf_init(void) { (void)0; }

gf_elem_t gf_add(gf_elem_t a, gf_elem_t b) { return (gf_elem_t)(a ^ b); }

// Delegate core ops to reference GF for parity
gf_elem_t gf_mul(gf_elem_t in0, gf_elem_t in1) { return (gf_elem_t)ref_gf_mul((gf)in0, (gf)in1); }

gf_elem_t gf_inv(gf_elem_t den) {
    if ((den & GFMASK) == 0) return 0;
    return (gf_elem_t)ref_gf_inv((gf)den);
}

gf_elem_t gf_div(gf_elem_t a, gf_elem_t b) {
    if ((b & GFMASK) == 0) return 0;
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














