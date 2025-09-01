#include "mceliece_genpoly.h"
#include "mceliece_gf.h"
#include "debuglog.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Reference-aligned minimal connection polynomial (Berlekamp-Massey form)
// We build the (t+1) x t matrix M whose rows are 1, f, f^2, ..., f^t
// over GF(2^m) and perform the same elimination as the reference to recover
// the connection polynomial coefficients in the last row.

// Vector multiply in GF((2^m)^t) with reference reduction: x^t + x^7 + x^2 + x + 1
// Matches reference GF_mul used in genpoly_gen
static inline void gf_vec_mul(gf_elem_t *out, const gf_elem_t *in0, const gf_elem_t *in1, int t) {
    // convolution
    int prod_len = t * 2 - 1;
    gf_elem_t *prod = (gf_elem_t*)alloca((size_t)prod_len * sizeof(gf_elem_t));
    for (int i = 0; i < prod_len; i++) prod[i] = 0;
    for (int i = 0; i < t; i++) {
        for (int j = 0; j < t; j++) {
            prod[i + j] ^= gf_mul(in0[i], in1[j]);
        }
    }
    // reduce high terms using fixed pentanomial
    for (int i = (t - 1) * 2; i >= t; i--) {
        gf_elem_t v = prod[i];
        prod[i - t + 7] ^= v;
        prod[i - t + 2] ^= v;
        prod[i - t + 1] ^= v;
        prod[i - t + 0] ^= v;
    }
    for (int i = 0; i < t; i++) out[i] = prod[i];
}

// Convert the GF(2^m) linear system to a binary  (m*t) x (m*t) system
// For equation set M * g = v  over GF(2^m), expand each coefficient into m bits
// Build m x m binary matrix representing linear map x -> coeff * x in GF(2^m)
static void build_mul_block(gf_elem_t coeff, int m, unsigned char *block /* size m*m */) {
    // Column k corresponds to input basis vector e_k (1<<k)
    // Row r is output bit r of coeff * e_k
    for (int r = 0; r < m; r++) {
        for (int c = 0; c < m; c++) block[r * m + c] = 0;
    }
    for (int c = 0; c < m; c++) {
        gf_elem_t basis = (gf_elem_t)(1u << c);
        gf_elem_t w = gf_mul(coeff, basis);
        for (int r = 0; r < m; r++) {
            block[r * m + c] = (unsigned char)((w >> r) & 1u);
        }
    }
}

// Build (t+1) x t matrix of GF(2^m) elements: mat[row][col]
// row 0: 1,0,...,0; row 1: f; row 2: f^2; ...; row t: f^t
static int build_power_matrix(const gf_elem_t *f, int t, gf_elem_t *mat /* (t+1)*t */) {
    for (int i = 0; i < t; i++) mat[i] = (i == 0) ? 1 : 0;
    memcpy(&mat[1 * t], f, (size_t)t * sizeof(gf_elem_t));
    gf_elem_t *prev = (gf_elem_t*)malloc((size_t)t * sizeof(gf_elem_t));
    gf_elem_t *next = (gf_elem_t*)malloc((size_t)t * sizeof(gf_elem_t));
    if (!prev || !next) { free(prev); free(next); return -1; }
    memcpy(prev, &mat[1 * t], (size_t)t * sizeof(gf_elem_t));
    for (int r = 2; r <= t; r++) {
        gf_vec_mul(next, prev, f, t);
        memcpy(&mat[r * t], next, (size_t)t * sizeof(gf_elem_t));
        gf_elem_t *tmp = prev; prev = next; next = tmp;
    }
    free(prev); free(next);
    return 0;
}

// Gaussian elimination over F2 on (n x n) matrix A with rhs b; both use 0/1 bytes
// Solve for connection polynomial via GF(2^m) elimination
// mat is (t+1) x t; we perform in-place operations akin to reference
static int solve_connection_poly(gf_elem_t *mat, int t) {
    for (int j = 0; j < t; j++) {
        for (int k = j + 1; k < t; k++) {
            if (mat[j * t + j] == 0) {
                for (int r = j; r <= t; r++) mat[r * t + j] ^= mat[r * t + k];
            }
        }
        if (mat[j * t + j] == 0) return -1;
        gf_elem_t inv = gf_pow(mat[j * t + j], MCELIECE_Q - 2);
        for (int r = j; r <= t; r++) mat[r * t + j] = gf_mul(mat[r * t + j], inv);
        for (int k = 0; k < t; k++) if (k != j) {
            gf_elem_t tmp = mat[j * t + k];
            for (int r = j; r <= t; r++) mat[r * t + k] ^= gf_mul(mat[r * t + j], tmp);
        }
    }
    return 0;
}

// Extract solution vector x of length (m*t) from reduced A,b (assumes near-RREF)
// Nothing needed: coefficients are extracted directly once matrix is reduced

// Pack x (m*t bits) into g_lower[t] over GF(2^m), diagonal-basis mapping
// Not used in compact GF elimination path

int genpoly_gen(gf_elem_t *out, const gf_elem_t *f) {
    gf_init();
    const int t = MCELIECE_T;

    // Allocate (t+1) x t matrix in row-major: row r, col c at mat[r*t + c]
    gf_elem_t *mat = (gf_elem_t*)malloc((size_t)(t + 1) * (size_t)t * sizeof(gf_elem_t));
    if (!mat) return -1;

    // mat[0][:] = [1, 0, ..., 0]
    for (int i = 0; i < t; i++) mat[0 * t + i] = (i == 0) ? 1 : 0;
    // mat[1][:] = f
    memcpy(&mat[1 * t], f, (size_t)t * sizeof(gf_elem_t));
    // mat[2]..mat[t] by polynomial multiplication truncated to degree < t
    for (int r = 2; r <= t; r++) {
        gf_vec_mul(&mat[r * t], &mat[(r - 1) * t], f, t);
    }

    if (dbg_enabled_us() || (getenv("MCELIECE_DEBUG_GENPOLY") && getenv("MCELIECE_DEBUG_GENPOLY")[0] == '1')) {
        for (int r = 0; r < 4 && r <= t; r++) {
            printf("[genpoly] mat[%d][:] (first 32): ", r);
            for (int i = 0; i < t && i < 32; i++) {
                printf("%04X%s", (unsigned)mat[r * t + i], (i+1)%16==0?"\n":" ");
            }
            if ((t < 32) && (t % 16 != 0)) printf("\n");
        }
        fflush(stdout);
    }

    // Reference-style elimination on columns using mask-based pivot fix
    if (dbg_enabled_us() || (getenv("MCELIECE_DEBUG_GENPOLY") && getenv("MCELIECE_DEBUG_GENPOLY")[0] == '1')) {
        printf("[genpoly] row t BEFORE elim: ");
        for (int i = 0; i < t; i++) {
            printf("%04X%s", (unsigned)mat[t * t + i], (i+1)%16==0?"\n":" ");
        }
        if (t % 16 != 0) printf("\n");
        fflush(stdout);
    }
    for (int j = 0; j < t; j++) {
        if (dbg_enabled_us() || (getenv("MCELIECE_DEBUG_GENPOLY") && getenv("MCELIECE_DEBUG_GENPOLY")[0] == '1')) {
            printf("[genpoly] BEFORE pivot j=%d: diag=%04X\n", j, (unsigned)mat[j * t + j]);
            printf("[genpoly] row t: ");
            for (int i = 0; i < t; i++) {
                printf("%04X%s", (unsigned)mat[t * t + i], (i+1)%16==0?"\n":" ");
            }
            if (t % 16 != 0) printf("\n");
            fflush(stdout);
        }
        for (int k = j + 1; k < t; k++) {
            gf_elem_t mask = (mat[j * t + j] == 0) ? (gf_elem_t)0xFFFF : (gf_elem_t)0x0000;
            for (int r = j; r <= t; r++) {
                mat[r * t + j] ^= (gf_elem_t)(mat[r * t + k] & mask);
            }
        }
        if (mat[j * t + j] == 0) { free(mat); return -1; }
        gf_elem_t inv = gf_inv(mat[j * t + j]);
        for (int r = j; r <= t; r++) mat[r * t + j] = gf_mul(mat[r * t + j], inv);
        for (int k = 0; k < t; k++) if (k != j) {
            gf_elem_t tk = mat[j * t + k];
            for (int r = j; r <= t; r++) mat[r * t + k] ^= gf_mul(mat[r * t + j], tk);
        }
        if (dbg_enabled_us() || (getenv("MCELIECE_DEBUG_GENPOLY") && getenv("MCELIECE_DEBUG_GENPOLY")[0] == '1')) {
            printf("[genpoly] AFTER pivot j=%d: diag=%04X\n", j, (unsigned)mat[j * t + j]);
            printf("[genpoly] row t: ");
            for (int i = 0; i < t; i++) {
                printf("%04X%s", (unsigned)mat[t * t + i], (i+1)%16==0?"\n":" ");
            }
            if (t % 16 != 0) printf("\n");
            fflush(stdout);
        }
    }

    // Output last row as coefficients
    for (int i = 0; i < t; i++) out[i] = mat[t * t + i];
    free(mat);
    return 0;
}


