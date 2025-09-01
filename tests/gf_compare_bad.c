#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "mceliece_types.h"
#include "mceliece_gf.h"

// This test compares our known-correct GF(2^13) implementation in src/mceliece_gf.c
// against a table-based implementation under test (embedded below and intentionally
// using a potentially incorrect reduction/generator). It reports mismatches to help
// diagnose why the alternative code is wrong.

// ------------------- BEGIN: alternative (buggy) implementation -------------------

static gf_elem_t *bad_gf_log = NULL;
static gf_elem_t *bad_gf_antilog = NULL;

static gf_elem_t bad_gf_mul_for_init(gf_elem_t a, gf_elem_t b) {
    // Alternative uses reducing_poly = 0x001B (this is likely the issue)
    const gf_elem_t reducing_poly = 0x001B;
    gf_elem_t r = 0;
    gf_elem_t temp_a = a;
    for (int i = 0; i < MCELIECE_M; i++) {
        if (b & 1) r ^= temp_a;
        b >>= 1;
        if (temp_a & (1 << (MCELIECE_M - 1))) {
            temp_a <<= 1;
            temp_a ^= reducing_poly;
        } else {
            temp_a <<= 1;
        }
        temp_a &= ((1 << MCELIECE_M) - 1);
    }
    return r & ((1 << MCELIECE_M) - 1);
}

static void bad_gf_init(void) {
    if (!bad_gf_log) {
        bad_gf_log = (gf_elem_t*)malloc(MCELIECE_Q * sizeof(gf_elem_t));
        if (!bad_gf_log) { fprintf(stderr, "alloc bad_gf_log failed\n"); exit(1); }
    }
    if (!bad_gf_antilog) {
        bad_gf_antilog = (gf_elem_t*)malloc(MCELIECE_Q * sizeof(gf_elem_t));
        if (!bad_gf_antilog) { fprintf(stderr, "alloc bad_gf_antilog failed\n"); exit(1); }
    }
    memset(bad_gf_log, 0, MCELIECE_Q * sizeof(gf_elem_t));
    memset(bad_gf_antilog, 0, MCELIECE_Q * sizeof(gf_elem_t));

    const gf_elem_t generator = 3;
    gf_elem_t p = 1;
    for (int i = 0; i < MCELIECE_Q - 1; i++) {
        bad_gf_antilog[i] = p;
        bad_gf_log[p] = (gf_elem_t)i;
        gf_elem_t old_p = p;
        p = bad_gf_mul_for_init(p, generator);
        if (i > 0 && p == 1) break;
        if (i > 0 && p == old_p) {
            fprintf(stderr, "ERROR: stuck during table generation at i=%d\n", i);
            exit(1);
        }
    }
    bad_gf_log[0] = 0;
    // Optional safety mirror so index (Q-1) also maps to 1
    bad_gf_antilog[MCELIECE_Q - 1] = 1;
}

static gf_elem_t bad_gf_add(gf_elem_t a, gf_elem_t b) { return (gf_elem_t)(a ^ b); }

static inline int wrap_exp(int e) {
    int m = MCELIECE_Q - 1;
    e %= m;
    if (e < 0) e += m;
    return e;
}

static gf_elem_t bad_gf_mul(gf_elem_t a, gf_elem_t b) {
    if (a == 0 || b == 0) return 0;
    int log_a = bad_gf_log[a];
    int log_b = bad_gf_log[b];
    int sum_log = wrap_exp(log_a + log_b);
    return bad_gf_antilog[sum_log];
}

static gf_elem_t bad_gf_inv(gf_elem_t a) {
    if (a == 0) return 0;
    if (a == 1) return 1;
    int log_a = bad_gf_log[a];
    int idx = wrap_exp((MCELIECE_Q - 1) - log_a);
    return bad_gf_antilog[idx];
}

static gf_elem_t bad_gf_div(gf_elem_t a, gf_elem_t b) {
    if (b == 0) return 0;
    if (a == 0) return 0;
    int log_a = bad_gf_log[a];
    int log_b = bad_gf_log[b];
    int diff = wrap_exp(log_a - log_b);
    return bad_gf_antilog[diff];
}

static gf_elem_t bad_gf_pow(gf_elem_t base, int exp) {
    if (exp == 0) return 1;
    if (base == 0) return 0;
    gf_elem_t result = 1;
    base &= ((1 << MCELIECE_M) - 1);
    while (exp > 0) {
        if (exp & 1) result = bad_gf_mul(result, base);
        base = bad_gf_mul(base, base);
        exp >>= 1;
    }
    return result;
}

// ------------------- END: alternative (buggy) implementation -------------------

static uint32_t rng_state = 0xC0FFEEu;
static inline uint32_t rng_next(void) {
    rng_state = rng_state * 1664525u + 1013904223u; // LCG
    return rng_state;
}

int main(void) {
    printf("GF(2^%d) comparison test (ours vs alternative)\n", MCELIECE_M);
    assert(MCELIECE_M == 13 && MCELIECE_Q == 8192);

    // Initialize both
    gf_init();
    bad_gf_init();

    int mismul = 0, misinv = 0, misdiv = 0, mispow = 0;
    int printed = 0;

    // Random pair testing for multiplication
    const int NUM_RANDOM = 200000;
    for (int i = 0; i < NUM_RANDOM; i++) {
        gf_elem_t a = (gf_elem_t)(rng_next() & (MCELIECE_Q - 1));
        gf_elem_t b = (gf_elem_t)(rng_next() & (MCELIECE_Q - 1));
        gf_elem_t good = gf_mul(a, b);
        gf_elem_t bad  = bad_gf_mul(a, b);
        if (good != bad) {
            mismul++;
            if (printed < 10) {
                printf("MUL mismatch: a=%04x b=%04x good=%04x bad=%04x\n", a, b, good, bad);
                printed++;
            }
        }
    }

    // Inverse/Division/Pow identities (sampled)
    printed = 0;
    for (int i = 1; i < MCELIECE_Q; i += 7) {
        gf_elem_t inv_good = gf_inv((gf_elem_t)i);
        gf_elem_t inv_bad  = bad_gf_inv((gf_elem_t)i);
        if (gf_mul((gf_elem_t)i, inv_good) != 1) { misinv++; if (printed < 5) { printf("INV(good) wrong for %04x\n", i); printed++; } }
        if ((i != 0) && (bad_gf_mul((gf_elem_t)i, inv_bad) != 1)) { misinv++; if (printed < 5) { printf("INV(bad) wrong for %04x\n", i); printed++; } }

        gf_elem_t d_good = gf_div((gf_elem_t)i, (gf_elem_t)(i));
        gf_elem_t d_bad  = bad_gf_div((gf_elem_t)i, (gf_elem_t)(i));
        if (d_good != 1) { misdiv++; }
        if (d_bad != 1) { misdiv++; }

        gf_elem_t pw_good = gf_pow((gf_elem_t)i, (1 << MCELIECE_M) - 1); // a^(2^m-1) == 1
        gf_elem_t pw_bad  = bad_gf_pow((gf_elem_t)i, (1 << MCELIECE_M) - 1);
        if (pw_good != 1) { mispow++; }
        if (pw_bad != 1) { mispow++; }
    }

    printf("\nSummary:\n");
    printf("  mul mismatches (random %d pairs): %d\n", NUM_RANDOM, mismul);
    printf("  inv identity mismatches: %d\n", misinv);
    printf("  div identity mismatches: %d\n", misdiv);
    printf("  pow identity mismatches: %d\n", mispow);

    if (bad_gf_log) free(bad_gf_log);
    if (bad_gf_antilog) free(bad_gf_antilog);

    return (mismul + misinv + misdiv + mispow) ? 1 : 0;
}


