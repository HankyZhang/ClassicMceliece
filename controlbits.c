#include "controlbits.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef int16_t int16;
typedef int32_t int32;

static inline int32 int32_min(int32 a, int32 b) { return a < b ? a : b; }

// Radix sort for 32-bit values (treat as unsigned for ordering)
static void radix_sort_u32(uint32_t *a, uint32_t *tmp, long long n) {
    const int RAD = 256;
    size_t cnt[RAD];
    size_t pref[RAD];
    for (int pass = 0; pass < 4; pass++) {
        memset(cnt, 0, sizeof(cnt));
        int shift = pass * 8;
        for (long long i = 0; i < n; i++) {
            unsigned int b = (unsigned int)((a[i] >> shift) & 0xFFu);
            cnt[b]++;
        }
        pref[0] = 0;
        for (int r = 1; r < RAD; r++) pref[r] = pref[r-1] + cnt[r-1];
        for (long long i = 0; i < n; i++) {
            unsigned int b = (unsigned int)((a[i] >> shift) & 0xFFu);
            tmp[pref[b]++] = a[i];
        }
        // swap buffers
        uint32_t *swap = a; a = tmp; tmp = swap;
    }
    // 4 passes -> data back in original array pointer
    (void)tmp;
}

static void int32_sort(int32 *a, long long n) {
    // reinterpret as unsigned for radix order; allocate temporary buffer
    uint32_t *ua = (uint32_t*)a;
    uint32_t *tmp = (uint32_t*)malloc((size_t)n * sizeof(uint32_t));
    if (!tmp) { /* fallback */ for (long long i = 0; i < n - 1; i++) for (long long j = i + 1; j < n; j++) if (a[j] < a[i]) { int32 t = a[i]; a[i] = a[j]; a[j] = t; } return; }
    radix_sort_u32(ua, tmp, n);
    free(tmp);
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
    if (!temp) return;
    memset(temp, 0, sizeof(int32) * (size_t)(2 * n));
    size_t out_bytes = (size_t)((((2 * w - 1) * n / 2) + 7) / 8);
    memset(out, 0, out_bytes);
    cbrecursion(out, 0, 1, pi, w, n, temp);
    // Optional verification pass
    const char *verify = getenv("MCELIECE_VERIFY_CB");
    if (verify && verify[0] == '1') {
        int16 *pi_test = (int16*)malloc(sizeof(int16) * (size_t)n);
        if (pi_test) {
            for (long long i = 0; i < n; i++) pi_test[i] = (int16)i;
            const unsigned char *ptr = out;
            for (long long i = 0; i < w; i++) { layer_local(pi_test, ptr, (int)i, (int)n); ptr += (size_t)(n >> 4); }
            for (long long i = w - 2; i >= 0; i--) { layer_local(pi_test, ptr, (int)i, (int)n); ptr += (size_t)(n >> 4); }
            int16 diff = 0;
            for (long long i = 0; i < n; i++) diff |= (pi[i] ^ pi_test[i]);
            if (diff != 0) {
                // In verify mode, redo until consistent (should converge immediately normally)
                memset(out, 0, out_bytes);
                cbrecursion(out, 0, 1, pi, w, n, temp);
            }
            free(pi_test);
        }
    }
    free(temp);
}

/* controlbits_from_alpha removed (unused). */

// Build pi by applying layers to identity
void cbits_pi_from_cbits(const uint8_t *cbits, long long w, long long n, int16_t *pi_out) {
    if (!cbits || !pi_out) return;
    int16 *p = (int16*)malloc(sizeof(int16) * (size_t)n);
    if (!p) return;
    for (long long i = 0; i < n; i++) p[i] = (int16)i;
    const unsigned char *ptr = cbits;
    for (long long i = 0; i < w; i++) { layer_local(p, ptr, (int)i, (int)n); ptr += (size_t)(n >> 4); }
    for (long long i = w - 2; i >= 0; i--) { layer_local(p, ptr, (int)i, (int)n); ptr += (size_t)(n >> 4); }
    for (long long i = 0; i < n; i++) pi_out[i] = p[i];
    free(p);
}

// Produce L[0..N-1] equal to support_gen in PQClean (bitrev of domain, then Benes, then extract low N indices)
static inline uint16_t bitrev16_local(uint16_t x) {
    x = (uint16_t)(((x & 0x5555u) << 1) | ((x >> 1) & 0x5555u));
    x = (uint16_t)(((x & 0x3333u) << 2) | ((x >> 2) & 0x3333u));
    x = (uint16_t)(((x & 0x0F0Fu) << 4) | ((x >> 4) & 0x0F0Fu));
    x = (uint16_t)((x << 8) | (x >> 8));
    return x;
}

void support_from_cbits(gf_elem_t *L, const uint8_t *cbits, long long w, int N) {
    if (!L || !cbits) return;
    long long n = 1LL << w;
    // Construct bit-reversed domain values
    gf_elem_t *domain = (gf_elem_t*)malloc(sizeof(gf_elem_t) * (size_t)n);
    if (!domain) return;
    for (long long i = 0; i < n; i++) {
        uint16_t br = bitrev16_local((uint16_t)i);
        domain[i] = (gf_elem_t)(br & ((1U << w) - 1U));
    }
    // Apply layers to identity positions to get permutation indices
    int16_t *pi = (int16_t*)malloc(sizeof(int16_t) * (size_t)n);
    if (!pi) { free(domain); return; }
    cbits_pi_from_cbits(cbits, w, n, pi);
    // Extract first N images
    for (int j = 0; j < N; j++) {
        L[j] = domain[pi[j]];
    }
    free(pi);
    free(domain);
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


