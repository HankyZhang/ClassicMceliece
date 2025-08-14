#include "mceliece_genpoly.h"
#include "mceliece_gf.h"
#include <string.h>
#include <stdlib.h>

// Scalar, bitslice-inspired implementation that avoids liboqs code.
// We construct the 128x128 binary matrix from the linear recurrences of f
// and perform Gaussian elimination over F2 to recover g.

// Build the Krylov-like matrix M (t x t) over GF(2^m): columns are f^k mod x^t
static int build_Krylov_columns(const gf_elem_t *f, int t, gf_elem_t *cols) {
    // cols[k * t + i] = coefficient x^i of (f^k mod x^t)
    // k=0..t-1, i=0..t-1
    // v0 = 1
    for (int i = 0; i < t; i++) cols[0 * t + i] = (i == 0) ? 1 : 0;
    // Temporary vector for multiplication
    gf_elem_t *prev = (gf_elem_t*)malloc(sizeof(gf_elem_t) * t);
    gf_elem_t *next = (gf_elem_t*)malloc(sizeof(gf_elem_t) * t);
    if (!prev || !next) { if (prev) free(prev); if (next) free(next); return -1; }
    for (int i = 0; i < t; i++) prev[i] = cols[i];
    for (int k = 1; k < t; k++) {
        // next = prev * f truncated to deg < t
        for (int i = 0; i < t; i++) {
            gf_elem_t acc = 0;
            for (int j = 0; j <= i; j++) acc = gf_add(acc, gf_mul(prev[j], f[i - j]));
            next[i] = acc;
        }
        for (int i = 0; i < t; i++) cols[k * t + i] = next[i];
        // swap
        gf_elem_t *tmp = prev; prev = next; next = tmp;
    }
    free(prev); free(next);
    return 0;
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

static void expand_to_binary_system(const gf_elem_t *M, const gf_elem_t *v, int m, int t,
                                   unsigned char *A, unsigned char *b) {
    // A is (m*t) x (m*t) over F2, stored row-major, 1 byte per entry (0/1)
    // b is length (m*t)
    memset(A, 0, (size_t)(m * t) * (size_t)(m * t));
    memset(b, 0, (size_t)(m * t));
    unsigned char *block = (unsigned char*)malloc((size_t)m * (size_t)m);
    if (!block) return;
    for (int rg = 0; rg < t; rg++) {
        for (int cg = 0; cg < t; cg++) {
            gf_elem_t coeff = M[rg * t + cg];
            build_mul_block(coeff, m, block);
            // Place block at rows [rg*m .. rg*m+m), cols [cg*m .. cg*m+m)
            for (int r = 0; r < m; r++) {
                int row = rg * m + r;
                unsigned char *dst = &A[row * (m * t) + cg * m];
                memcpy(dst, &block[r * m], (size_t)m);
            }
        }
        // RHS
        gf_elem_t rhs = v[rg];
        for (int bit = 0; bit < m; bit++) {
            int row = rg * m + bit;
            b[row] = (rhs >> bit) & 1;
        }
    }
    free(block);
}

// Gaussian elimination over F2 on (n x n) matrix A with rhs b; both use 0/1 bytes
static int gauss_binary(unsigned char *A, unsigned char *b, int n) {
    int row = 0;
    for (int col = 0; col < n && row < n; col++) {
        int piv = -1;
        for (int r = row; r < n; r++) {
            if (A[r * n + col]) { piv = r; break; }
        }
        if (piv == -1) continue; // free variable; acceptable for our case
        if (piv != row) {
            for (int c = col; c < n; c++) {
                unsigned char tmp = A[row * n + c];
                A[row * n + c] = A[piv * n + c];
                A[piv * n + c] = tmp;
            }
            unsigned char tb = b[row]; b[row] = b[piv]; b[piv] = tb;
        }
        for (int r = 0; r < n; r++) {
            if (r == row) continue;
            if (A[r * n + col]) {
                for (int c = col; c < n; c++) A[r * n + c] ^= A[row * n + c];
                b[r] ^= b[row];
            }
        }
        row++;
    }
    return 0;
}

// Extract solution vector x of length (m*t) from reduced A,b (assumes near-RREF)
static void back_solve_binary(const unsigned char *A, const unsigned char *b, int n,
                              unsigned char *x) {
    memset(x, 0, n);
    // simple back substitution for upper-triangular pattern
    for (int i = n - 1; i >= 0; i--) {
        int sum = b[i];
        int pivot_col = -1;
        for (int j = 0; j < n; j++) {
            if (A[i * n + j]) { pivot_col = j; break; }
        }
        if (pivot_col == -1) continue;
        for (int j = pivot_col + 1; j < n; j++) {
            if (A[i * n + j] && x[j]) sum ^= 1;
        }
        x[pivot_col] = (unsigned char)(sum & 1);
    }
}

// Pack x (m*t bits) into g_lower[t] over GF(2^m), diagonal-basis mapping
static void pack_solution_to_g(const unsigned char *x, int m, int t, gf_elem_t *g_lower) {
    for (int i = 0; i < t; i++) g_lower[i] = 0;
    for (int cg = 0; cg < t; cg++) {
        gf_elem_t acc = 0;
        for (int bit = 0; bit < m; bit++) {
            int col = cg * m + bit;
            acc |= ((gf_elem_t)(x[col] & 1) << bit);
        }
        g_lower[cg] = acc;
    }
}

int genpoly_gen(gf_elem_t *out, const gf_elem_t *f) {
    const int t = MCELIECE_T;
    const int m = MCELIECE_M;

    // 1) Build columns v0..v_{t-1} and compute v_t
    gf_elem_t *cols = (gf_elem_t*)malloc(sizeof(gf_elem_t) * t * t);
    if (!cols) return -1;
    if (build_Krylov_columns(f, t, cols) != 0) { free(cols); return -1; }

    gf_elem_t *vt = (gf_elem_t*)malloc(sizeof(gf_elem_t) * t);
    if (!vt) { free(cols); return -1; }
    // vt = v_{t-1} * f
    for (int i = 0; i < t; i++) {
        gf_elem_t acc = 0;
        for (int j = 0; j <= i; j++) acc = gf_add(acc, gf_mul(cols[(t - 1) * t + j], f[i - j]));
        vt[i] = acc;
    }

    // 2) Expand to binary system and solve
    int nbin = m * t;
    unsigned char *A = (unsigned char*)malloc((size_t)nbin * (size_t)nbin);
    unsigned char *b = (unsigned char*)malloc((size_t)nbin);
    unsigned char *x = (unsigned char*)malloc((size_t)nbin);
    if (!A || !b || !x) { if (A) free(A); if (b) free(b); if (x) free(x); free(cols); free(vt); return -1; }

    expand_to_binary_system(cols, vt, m, t, A, b);
    gauss_binary(A, b, nbin);
    back_solve_binary(A, b, nbin, x);

    // 3) Pack solution to out[] (degree t-1..0). Leading monic coef is implied outside
    pack_solution_to_g(x, m, t, out);

    free(A); free(b); free(x); free(cols); free(vt);
    return 0;
}


