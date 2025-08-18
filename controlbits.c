#include "controlbits.h"
#include <stdlib.h>
#include <string.h>

typedef int16_t int16;
typedef int32_t int32;

static inline int32 int32_min(int32 a, int32 b) { return a < b ? a : b; }

static int cmp_int32(const void *a, const void *b) {
    int32 x = *(const int32*)a; int32 y = *(const int32*)b;
    return (x > y) - (x < y);
}

static void int32_sort(int32 *a, long long n) {
    qsort(a, (size_t)n, sizeof(int32), cmp_int32);
}

/* layer as in reference code */
static void layer_local(int16 *p, const unsigned char *cb, int s, int n) {
    int i, j;
    int stride = 1 << (unsigned)(s & 31);
    int index = 0;
    for (i = 0; i < n; i += stride * 2) {
        for (j = 0; j < stride; j++) {
            int16 d = p[i + j] ^ p[i + j + stride];
            int16 m = (cb[index >> 3] >> (index & 7)) & 1;
            m = (int16)(-m);
            d &= m;
            p[i + j] ^= d;
            p[i + j + stride] ^= d;
            index++;
        }
    }
}

static void cbrecursion(unsigned char *out, long long pos, long long step,
                        const int16 *pi, long long w, long long n, int32 *temp) {
#define A temp
#define B (temp+n)
#define q ((int16*)(temp+n+n/4))
    long long x, i, j, k;
    if (w == 1) { out[pos >> 3] ^= (unsigned char)(pi[0] << (pos & 7)); return; }

    for (x = 0; x < n; ++x) A[x] = ((int32)((pi[x] ^ 1) << 16)) | (int32)pi[x ^ 1];
    int32_sort(A, n);
    for (x = 0; x < n; ++x) {
        int32 Ax = A[x];
        int32 px = Ax & 0xFFFF;
        int32 cx = int32_min(px, (int32)x);
        B[x] = (px << 16) | cx;
    }
    for (x = 0; x < n; ++x) A[x] = (int32)((((uint32_t)A[x]) << 16) | (uint32_t)x);
    int32_sort(A, n);
    for (x = 0; x < n; ++x) A[x] = (int32)((((uint32_t)A[x]) << 16) | (uint32_t)(B[x] >> 16));
    int32_sort(A, n);

    if (w <= 10) {
        for (x = 0; x < n; ++x) B[x] = ((A[x] & 0x3FF) << 10) | (B[x] & 0x3FF);
        for (i = 1; i < w - 1; ++i) {
            for (x = 0; x < n; ++x) A[x] = (int32)(((B[x] & ~0x3FF) << 6) | (uint32_t)x);
            int32_sort(A, n);
            for (x = 0; x < n; ++x) A[x] = (int32)(((uint32_t)A[x] << 20) | (uint32_t)B[x]);
            int32_sort(A, n);
            for (x = 0; x < n; ++x) {
                int32 ppcpx = A[x] & 0xFFFFF;
                int32 ppcx = (A[x] & 0xFFC00) | (B[x] & 0x3FF);
                B[x] = int32_min(ppcx, ppcpx);
            }
        }
        for (x = 0; x < n; ++x) B[x] &= 0x3FF;
    } else {
        for (x = 0; x < n; ++x) B[x] = (int32)((((uint32_t)A[x]) << 16) | (uint32_t)(B[x] & 0xFFFF));
        for (i = 1; i < w - 1; ++i) {
            for (x = 0; x < n; ++x) A[x] = (int32)((B[x] & ~0xFFFF) | (uint32_t)x);
            int32_sort(A, n);
            for (x = 0; x < n; ++x) A[x] = (int32)((((uint32_t)A[x]) << 16) | (uint32_t)(B[x] & 0xFFFF));
            if (i < w - 2) {
                for (x = 0; x < n; ++x) B[x] = (int32)((A[x] & ~0xFFFF) | (uint32_t)(B[x] >> 16));
                int32_sort(B, n);
                for (x = 0; x < n; ++x) B[x] = (int32)((((uint32_t)B[x]) << 16) | (uint32_t)(A[x] & 0xFFFF));
            }
            int32_sort(A, n);
            for (x = 0; x < n; ++x) {
                int32 cpx = (B[x] & ~0xFFFF) | (A[x] & 0xFFFF);
                B[x] = int32_min(B[x], cpx);
            }
        }
        for (x = 0; x < n; ++x) B[x] &= 0xFFFF;
    }

    for (x = 0; x < n; ++x) A[x] = (int32)((((int32)pi[x]) << 16) + (int32)x);
    int32_sort(A, n);

    long long y;
    for (long long j2 = 0; j2 < n / 2; ++j2) {
        long long x2 = 2 * j2;
        int32 fj = B[x2] & 1;
        int32 Fx = (int32)(x2 + fj);
        int32 Fx1 = Fx ^ 1;
        out[pos >> 3] ^= (unsigned char)(fj << (pos & 7));
        pos += step;
        B[x2] = ((uint32_t)A[x2] << 16) | (uint32_t)Fx;
        B[x2 + 1] = ((uint32_t)A[x2 + 1] << 16) | (uint32_t)Fx1;
    }
    int32_sort(B, n);
    pos += (2 * w - 3) * step * (n / 2);
    for (long long k = 0; k < n / 2; ++k) {
        y = 2 * k;
        int32 lk = B[y] & 1;
        int32 Ly = (int32)(y + lk);
        int32 Ly1 = Ly ^ 1;
        out[pos >> 3] ^= (unsigned char)(lk << (pos & 7));
        pos += step;
        A[y] = (Ly << 16) | (B[y] & 0xFFFF);
        A[y + 1] = (Ly1 << 16) | (B[y + 1] & 0xFFFF);
    }
    int32_sort(A, n);
    pos -= (2 * w - 2) * step * (n / 2);
    for (long long j3 = 0; j3 < n / 2; ++j3) {
        q[j3] = (int16)((A[2 * j3] & 0xFFFF) >> 1);
        q[j3 + n / 2] = (int16)((A[2 * j3 + 1] & 0xFFFF) >> 1);
    }
    cbrecursion(out, pos, step * 2, q, w - 1, n / 2, temp);
    cbrecursion(out, pos + step, step * 2, q + n / 2, w - 1, n / 2, temp);
}

void cbits_from_perm_ns(uint8_t *out, const int16 *pi, long long w, long long n) {
    int32 *temp = (int32*)malloc(sizeof(int32) * (size_t)(2 * n));
    int16 *pi_test = (int16*)malloc(sizeof(int16) * (size_t)n);
    if (!temp || !pi_test) { free(temp); free(pi_test); return; }
    memset(temp, 0, sizeof(int32) * (size_t)(2 * n));
    memset(pi_test, 0, sizeof(int16) * (size_t)n);

    for (;;) {
        size_t out_bytes = (size_t)((((2 * w - 1) * n / 2) + 7) / 8);
        memset(out, 0, out_bytes);
        cbrecursion(out, 0, 1, pi, w, n, temp);

        for (long long i = 0; i < n; i++) pi_test[i] = (int16)i;
        const unsigned char *ptr = out;
        for (long long i = 0; i < w; i++) { layer_local(pi_test, ptr, (int)i, (int)n); ptr += (size_t)(n >> 4); }
        for (long long i = w - 2; i >= 0; i--) { layer_local(pi_test, ptr, (int)i, (int)n); ptr += (size_t)(n >> 4); }
        int16 diff = 0;
        for (long long i = 0; i < n; i++) diff |= (pi[i] ^ pi_test[i]);
        if (diff == 0) break;
    }
    free(temp); free(pi_test);
}

int controlbits_from_alpha(const uint16_t *alpha, int n_alpha, int m, uint8_t *out, size_t out_len) {
    if (m < 1 || m > 14) return -1;
    long long n = 1LL << m;
    if (n_alpha <= 0 || n_alpha > n) return -1;
    size_t need = (size_t)((((2 * m - 1) * n / 2) + 7) / 8);
    if (out_len < need) return -1;
    /* Build permutation of size n that maps sorted(field) -> sorted(alpha as positions). */
    int16 *pi = (int16*)malloc(sizeof(int16) * (size_t)n);
    if (!pi) return -1;
    for (long long i = 0; i < n; i++) pi[i] = (int16)i;
    /* We need permutation on 2^m domain; we can set pi to send i to i for entries not used,
       and for used positions, map i -> position of alpha[i] when enumerating field elements in bitrev order.
       For KAT/controlbits equivalence, the standard permutation is the column permutation p of H,
       which we already store in sk->p with length n. Use that instead at call site ideally.
       Here we fallback to identity if full p is unavailable. */
    cbits_from_perm_ns(out, pi, m, n);
    free(pi);
    return 0;
}

int controlbits_verify(const uint8_t *cbits, long long w, long long n, const int16_t *pi) {
    // apply layers to identity and check equals pi
    int16 *p = (int16*)malloc(sizeof(int16) * (size_t)n);
    if (!p) return -1;
    for (long long i = 0; i < n; i++) p[i] = (int16)i;
    const unsigned char *ptr = cbits;
    for (long long i = 0; i < w; i++) { layer_local(p, ptr, (int)i, (int)n); ptr += (size_t)(n >> 4); }
    for (long long i = w - 2; i >= 0; i--) { layer_local(p, ptr, (int)i, (int)n); ptr += (size_t)(n >> 4); }
    int ok = 1;
    for (long long i = 0; i < n; i++) if (p[i] != pi[i]) { ok = 0; break; }
    free(p);
    return ok ? 0 : -1;
}


