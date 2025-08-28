#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

// Our implementation
#include "mceliece_types.h"
#include "mceliece_keygen.h"
#include "mceliece_shake.h"
#include "mceliece_gf.h"
#include "mceliece_poly.h"
#include "mceliece_matrix_ops.h"
#include "kat_drbg.h"

// Reference implementation headers (called directly, no code reproduced)
#ifndef CRYPTO_NAMESPACE
#define CRYPTO_NAMESPACE(x) ref_##x
#endif

#include "mceliece6688128/params.h"
#include "mceliece6688128/gf.h"
#include "mceliece6688128/util.h"
#include "mceliece6688128/sk_gen.h"     // genpoly_gen
#include "mceliece6688128/pk_gen.h"     // pk_gen
#include "mceliece6688128/crypto_hash.h" // shake
#include "mceliece6688128/nist/rng.h"    // randombytes_init, randombytes

// qsort comparator for 64-bit values
static int cmp64_qsort(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    if (x < y) return -1; if (x > y) return 1; return 0;
}

// Small log helpers
static void print_hex(FILE *fp, const char *label, const unsigned char *buf, size_t len, size_t max_show)
{
    fprintf(fp, "%s (%zu bytes): ", label, len);
    size_t n = len < max_show ? len : max_show;
    for (size_t i = 0; i < n; i++) fprintf(fp, "%02X", buf[i]);
    if (n < len) fprintf(fp, "...(%zu)", len);
    fprintf(fp, "\n");
}

static void print_gf_array(FILE *fp, const char *label, const gf *a, size_t count, size_t max_show)
{
    fprintf(fp, "%s (%zu): ", label, count);
    size_t n = count < max_show ? count : max_show;
    for (size_t i = 0; i < n; i++) fprintf(fp, "%04X ", (unsigned)a[i]);
    if (n < count) fprintf(fp, "...(%zu)", count);
    fprintf(fp, "\n");
}

static void print_u16_array(FILE *fp, const char *label, const uint16_t *a, size_t count, size_t max_show)
{
    fprintf(fp, "%s (%zu): ", label, count);
    size_t n = count < max_show ? count : max_show;
    for (size_t i = 0; i < n; i++) fprintf(fp, "%04X ", (unsigned)a[i]);
    if (n < count) fprintf(fp, "...(%zu)", count);
    fprintf(fp, "\n");
}

static void print_byte_bits(FILE *fp, unsigned char b)
{
    for (int i = 7; i >= 0; i--) fputc(((b >> i) & 1) ? '1' : '0', fp);
}

static int parse_req_seed48(const char *path, unsigned char out48[48])
{
    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }
    char line[4096];
    while (fgets(line, sizeof line, f)) {
        const char *p = strstr(line, "seed =");
        if (!p) continue;
        p = strchr(p, '='); if (!p) continue; p++;
        while (*p == ' ' || *p == '\t') p++;
        int idx = 0, hi = -1;
        for (; *p && idx < 48; p++) {
            int v;
            if (*p >= '0' && *p <= '9') v = *p - '0';
            else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
            else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
            else continue;
            if (hi < 0) hi = v; else { out48[idx++] = (unsigned char)((hi<<4)|v); hi = -1; }
        }
        fclose(f);
        return (idx == 48) ? 0 : -2;
    }
    fclose(f);
    return -3;
}

static void trace_reference(const unsigned char seed48[48], FILE *fp)
{
    fprintf(fp, "=== Reference implementation data flow ===\n");

    // Initialize DRBG (KAT style)
    randombytes_init((unsigned char *)seed48, NULL, 256);

    // Build 33-byte seed: first byte fixed 64, rest from DRBG
    unsigned char seed33[33];
    memset(seed33, 0, sizeof seed33);
    seed33[0] = 64;
    randombytes(seed33 + 1, 32);
    print_hex(fp, "seed33", seed33, sizeof seed33, sizeof seed33);

    // Total r buffer length taken directly from reference params
    size_t rlen = (size_t)(SYS_N/8) + ((size_t)1 << GFBITS) * sizeof(uint32_t) + (size_t)SYS_T * 2 + 32;
    unsigned char *r = (unsigned char*)malloc(rlen);
    if (!r) {
        fprintf(fp, "alloc r failed\n");
        return;
    }

    // PRG (reference): r = SHAKE256(seed33, 33, rlen)
    shake(r, rlen, seed33, 33);
    print_hex(fp, "PRG output r (first 64)", r, rlen, 64);

    // Walk r from tail to extract inputs as reference does
    unsigned char *rp = r + rlen;

    // delta' (ignored for now)
    rp -= 32;

    // f input for genpoly_gen
    gf f[SYS_T];
    rp -= (size_t)SYS_T * 2;
    for (int i = 0; i < SYS_T; i++) f[i] = load_gf(rp + i*2);
    print_gf_array(fp, "genpoly_gen input f", f, SYS_T, 32);

    // Run genpoly_gen
    gf irr[SYS_T];
    int genpoly_ret = genpoly_gen(irr, f);
    fprintf(fp, "genpoly_gen() => %s\n", genpoly_ret == 0 ? "OK" : "FAIL");
    if (genpoly_ret == 0) {
        print_gf_array(fp, "genpoly_gen output irr", irr, SYS_T, 32);
        // persist reference irr for comparison
        FILE *fi = fopen("reference_irr.bin", "wb");
        if (fi) { fwrite(irr, sizeof(gf), (size_t)SYS_T, fi); fclose(fi); }
    }

    // perm input for pk_gen
    rp -= ((size_t)1 << GFBITS) * sizeof(uint32_t);
    uint32_t *perm = (uint32_t*)malloc(((size_t)1 << GFBITS) * sizeof(uint32_t));
    int16_t *pi = (int16_t*)malloc(((size_t)1 << GFBITS) * sizeof(int16_t));
    if (!perm || !pi) {
        fprintf(fp, "alloc perm/pi failed\n");
        free(r); free(perm); free(pi);
        return;
    }
    for (int i = 0; i < (1 << GFBITS); i++) perm[i] = load4(rp + i*4);
    fprintf(fp, "perm[0..7]: ");
    for (int i = 0; i < 8; i++) fprintf(fp, "%08X ", (unsigned)perm[i]);
    fprintf(fp, "\n");

    // Pack irr for pk_gen sk input
    unsigned char irr_bytes[IRR_BYTES];
    for (int i = 0; i < SYS_T; i++) store_gf(irr_bytes + i*2, irr[i]);

    // Synthesize pi from perm ourselves (identical to reference sorting) to build alpha_ref reliably
    {
        size_t q = (size_t)1 << GFBITS;
        uint64_t *buf = (uint64_t*)malloc(q * sizeof(uint64_t));
        int16_t *pi_sorted = (int16_t*)malloc(q * sizeof(int16_t));
        if (buf && pi_sorted) {
            for (size_t i = 0; i < q; i++) buf[i] = ((uint64_t)perm[i] << 31) | (uint64_t)i;
            qsort(buf, q, sizeof(uint64_t), cmp64_qsort);
            for (size_t i = 0; i < q; i++) pi_sorted[i] = (int16_t)(buf[i] & GFMASK);
            uint16_t *alpha_ref = (uint16_t*)malloc(q * sizeof(uint16_t));
            if (alpha_ref) {
                for (size_t i = 0; i < q; i++) alpha_ref[i] = (uint16_t)bitrev((gf)pi_sorted[i]);
                FILE *fa = fopen("reference_alpha.bin", "wb");
                if (fa) { fwrite(alpha_ref, sizeof(uint16_t), q, fa); fclose(fa); }
                fprintf(fp, "reference alpha (first 32): ");
                for (int i = 0; i < 32 && i < (int)q; i++) fprintf(fp, "%04X ", (unsigned)alpha_ref[i]);
                fprintf(fp, "\n");
                free(alpha_ref);
            }
        }
        if (buf) free(buf);
        if (pi_sorted) free(pi_sorted);
    }

    // pk_gen
    unsigned char *pk = (unsigned char*)malloc((size_t)PK_NROWS * (size_t)PK_ROW_BYTES);
    if (!pk) {
        fprintf(fp, "alloc pk failed\n");
        free(r); free(perm); free(pi);
        return;
    }
    int pk_ret = pk_gen(pk, irr_bytes, perm, pi);
    fprintf(fp, "pk_gen() => %s\n", pk_ret == 0 ? "OK" : "FAIL");
    if (pk_ret == 0) {
        print_hex(fp, "pk (first 64)", pk, (size_t)PK_NROWS * (size_t)PK_ROW_BYTES, 64);
    }

    free(pk);
    free(perm);
    free(pi);
    free(r);
}

static void trace_ours(const unsigned char seed48[48], FILE *fp)
{
    fprintf(fp, "=== Our implementation data flow ===\n");

    // Initialize our DRBG from the same KAT seed48 for comparable PRG
    gf_init();
    kat_drbg_init(seed48);

    // According to ISO flow, total PRG output covers s, field ordering, polynomial, delta'
    size_t prg_len = (size_t)(MCELIECE_N/8) + ((size_t)MCELIECE_Q) * 4 + (size_t)MCELIECE_T * 2 + 32;
    unsigned char *prg = (unsigned char*)malloc(prg_len);
    if (!prg) {
        fprintf(fp, "alloc prg failed\n");
        return;
    }
    // Our PRG: takes 32-byte seed; derive from seed48 deterministically via kat_expand_r seed33
    unsigned char delta[32];
    unsigned char *tmp_r = (unsigned char*)malloc(prg_len);
    if (!tmp_r) { fprintf(fp, "alloc tmp_r failed\n"); free(prg); return; }
    kat_expand_r(tmp_r, prg_len, delta); // fills like reference shake(seed33,33,prg_len)
    memcpy(prg, tmp_r, prg_len);
    free(tmp_r);

    print_hex(fp, "PRG output r (first 64)", prg, prg_len, 64);

    // Slice sections
    size_t off = 0;
    const unsigned char *s_section = prg + off; off += (size_t)(MCELIECE_N/8);
    const unsigned char *field_section = prg + off; off += ((size_t)MCELIECE_Q) * 4;
    const unsigned char *poly_section = prg + off; off += (size_t)MCELIECE_T * 2;
    const unsigned char *delta_prime = prg + off; (void)delta_prime;

    print_hex(fp, "s section (first 32)", s_section, (size_t)(MCELIECE_N/8), 32);
    print_hex(fp, "field section (first 64)", field_section, ((size_t)MCELIECE_Q) * 4, 64);
    print_hex(fp, "poly section (first 32)", poly_section, (size_t)MCELIECE_T * 2, 32);

    // Irreducible polynomial (our)
    polynomial_t *g = polynomial_create(MCELIECE_T);
    if (!g) { fprintf(fp, "alloc poly failed\n"); free(prg); return; }
    mceliece_error_t poly_ok = generate_irreducible_poly_final(g, poly_section);
    fprintf(fp, "generate_irreducible_poly_final() => %s\n", poly_ok == MCELIECE_SUCCESS ? "OK" : "FAIL");
    if (poly_ok == MCELIECE_SUCCESS) {
        fprintf(fp, "g coeffs (first 32): ");
        for (int i = 0; i < 32 && i <= g->degree; i++) fprintf(fp, "%04X ", (unsigned)g->coeffs[i]);
        fprintf(fp, "\n");
        // persist our g's lower T coefficients for comparison; also assert monic
        int monic = (g->degree >= MCELIECE_T) ? (g->coeffs[MCELIECE_T] == 1) : 0;
        fprintf(fp, "g is monic: %s\n", monic ? "YES" : "NO");
        FILE *fo = fopen("our_irr.bin", "wb");
        if (fo) {
            fwrite(g->coeffs, sizeof(gf_elem_t), (size_t)MCELIECE_T, fo);
            fclose(fo);
        }
    }

    // Field ordering (our)
    gf_elem_t *alpha = (gf_elem_t*)malloc(sizeof(gf_elem_t) * MCELIECE_Q);
    // Optional: reference alpha buffer
    uint16_t *alpha_ref_buf = NULL; size_t alpha_ref_len = 0;
    if (!alpha) { fprintf(fp, "alloc alpha failed\n"); polynomial_free(g); free(prg); return; }
    mceliece_error_t fld_ok = generate_field_ordering(alpha, field_section);
    fprintf(fp, "generate_field_ordering() => %s\n", fld_ok == MCELIECE_SUCCESS ? "OK" : "FAIL");
    if (fld_ok == MCELIECE_SUCCESS) {
        fprintf(fp, "alpha (first 32): ");
        for (int i = 0; i < 32; i++) fprintf(fp, "%04X ", (unsigned)alpha[i]);
        fprintf(fp, "\n");

        // Load reference alpha produced by pk_gen/bitrev and compare
        FILE *fa = fopen("reference_alpha.bin", "rb");
        if (fa) {
            size_t q = (size_t)MCELIECE_Q;
            uint16_t *alpha_ref = (uint16_t*)malloc(q * sizeof(uint16_t));
            if (alpha_ref) {
                size_t rd = fread(alpha_ref, sizeof(uint16_t), q, fa);
                if (rd == q) {
                    int same = memcmp(alpha_ref, alpha, q * sizeof(uint16_t)) == 0;
                    fprintf(fp, "Field ordering alpha match (full Q): %s\n", same ? "YES" : "NO");
                    // Keep a copy to drive H construction for exact reference comparison
                    alpha_ref_buf = alpha_ref; alpha_ref_len = q;
                    // Compute our inv LSBs for alpha_ref (j=0..7, k=0)
                    // Print our inv values for alpha_ref j=0..7
                    fprintf(fp, "Our vs Ref inv using alpha_ref (j=0..7):\n");
                    {
                        gf_elem_t invj_arr[8];
                        gf ref_inv_arr[8];
                        for (int j0 = 0; j0 < 8; j0++) {
                            gf_elem_t a13 = (gf_elem_t)(alpha_ref_buf[j0] & ((1u << MCELIECE_M) - 1u));
                            gf_elem_t val = polynomial_eval(g, a13);
                            invj_arr[j0] = (val == 0) ? 0 : gf_inv(val);
                            // compute via reference gf as well (Horner with ref_gf_mul)
                            gf Lj = (gf)a13;
                            gf ref_val = 1;
                            for (int d = MCELIECE_T - 1; d >= 0; d--) { ref_val = ref_gf_mul(ref_val, Lj); ref_val ^= (gf)g->coeffs[d]; }
                            ref_inv_arr[j0] = ref_gf_inv(ref_val ? ref_val : 1);
                        }
                        fprintf(fp, "  our: ");
                        for (int j0 = 0; j0 < 8; j0++) fprintf(fp, "%04X ", (unsigned)invj_arr[j0]);
                        fprintf(fp, "\n  ref: ");
                        for (int j0 = 0; j0 < 8; j0++) fprintf(fp, "%04X ", (unsigned)ref_inv_arr[j0]);
                        fprintf(fp, "\n");
                        fprintf(fp, "Our inv LSBs using alpha_ref (k=0, j=0..7):  ");
                        for (int j0 = 0; j0 < 8; j0++) fputc((invj_arr[j0] & 1) ? '1' : '0', fp);
                        fputc('\n', fp);
                    }
                    // Side-by-side g(L) values for j=0..7
                    fprintf(fp, "g(L) compare using alpha_ref (j=0..7):\n");
                    // Build ref_g coeffs
                    gf ref_g[MCELIECE_T + 1];
                    for (int ii = 0; ii < MCELIECE_T; ii++) ref_g[ii] = (gf)g->coeffs[ii];
                    ref_g[MCELIECE_T] = 1;
                    for (int j0 = 0; j0 < 8; j0++) {
                        gf Lj = (gf)(alpha_ref_buf[j0] & ((1u << MCELIECE_M) - 1u));
                        gf ref_val = ref_g[MCELIECE_T];
                        for (int d = MCELIECE_T - 1; d >= 0; d--) { ref_val = ref_gf_mul(ref_val, Lj); ref_val ^= ref_g[d]; }
                        gf_elem_t our_val = polynomial_eval(g, (gf_elem_t)Lj);
                        fprintf(fp, "j=%d ref=%04X our=%04X\n", j0, (unsigned)ref_val, (unsigned)our_val);
                    }
                    if (!same) {
                        size_t idx = 0; while (idx < q && alpha_ref[idx] == alpha[idx]) idx++;
                        if (idx < q) fprintf(fp, "First alpha diff at %zu: ref=%04X our=%04X\n", idx, (unsigned)alpha_ref[idx], (unsigned)alpha[idx]);
                    }
                } else {
                    fprintf(fp, "reference_alpha.bin short read (%zu)\n", rd);
                    free(alpha_ref);
                }
            }
            fclose(fa);
        } else {
            fprintf(fp, "reference_alpha.bin not found for comparison\n");
        }
    }

    // Matrix generation + Gaussian elimination (our)
    int mt = MCELIECE_T * MCELIECE_M;
    matrix_t *H = matrix_create(mt, MCELIECE_N);
    if (!H) { fprintf(fp, "alloc H failed\n"); free(alpha); polynomial_free(g); free(prg); return; }
    const gf_elem_t *alpha_for_H = alpha;
    if (alpha_ref_buf && alpha_ref_len == (size_t)MCELIECE_Q) {
        alpha_for_H = (const gf_elem_t*)alpha_ref_buf;
    }
    // Debug: compute our inv_pre using the same support that will be used to build H
    {
        gf_elem_t inv_pre[8];
        for (int j = 0; j < 8; j++) {
            gf_elem_t a13 = (gf_elem_t)(alpha_for_H[j] & ((1u << MCELIECE_M) - 1u));
            gf_elem_t val = 1;
            for (int d = MCELIECE_T - 1; d >= 0; d--) { val = gf_mul(val, a13); val ^= (gf_elem_t)g->coeffs[d]; }
            inv_pre[j] = (val == 0) ? 0 : gf_inv(val);
        }
        fprintf(fp, "Our(inv_pre) LSBs with support-for-H (k=0, j=0..7): ");
        for (int j = 0; j < 8; j++) fputc((inv_pre[j] & 1) ? '1' : '0', fp);
        fputc('\n', fp);
    }
    int build_ok = build_parity_check_matrix_reference_style(H, g, alpha_for_H);
    fprintf(fp, "build_parity_check_matrix_reference_style() => %s\n", build_ok == 0 ? "OK" : "FAIL");
    if (build_ok == 0) {
        // Compute expected first-byte for row0 using reference GF and compare to our packed byte
        {
            // Build ref inv for i=0, k=0
            gf ref_gcoeffs[MCELIECE_T + 1];
            for (int ii = 0; ii < MCELIECE_T; ii++) ref_gcoeffs[ii] = (gf)g->coeffs[ii];
            ref_gcoeffs[MCELIECE_T] = 1;
            gf inv_row0[8];
            for (int j0 = 0; j0 < 8; j0++) {
                gf a = (gf)(alpha_for_H[j0] & ((1u << MCELIECE_M) - 1u));
                gf v = ref_gcoeffs[MCELIECE_T];
                for (int d = MCELIECE_T - 1; d >= 0; d--) { v = ref_gf_mul(v, a); v ^= ref_gcoeffs[d]; }
                inv_row0[j0] = ref_gf_inv(v ? v : 1);
            }
            unsigned char b0 = 0;
            for (int tbit = 7; tbit >= 0; tbit--) { b0 <<= 1; b0 |= (unsigned char)(inv_row0[tbit] & 1); }
            fprintf(fp, "Ref-expected row0 first byte (k=0): %02X\n", b0);
        }
        // Repack our H using two packing variants for comparison
        size_t packed_bytes = (size_t)H->rows * (size_t)H->cols_bytes;
        unsigned char *packed_ref = (unsigned char*)malloc(packed_bytes);
        unsigned char *packed_alt = (unsigned char*)malloc(packed_bytes);
        if (packed_ref && packed_alt) {
            // Variant A: reference MSB-first per-8-columns (MSB=col j+7)
            if (matrix_export_right_block_reference_packing(H, 0, packed_ref, H->cols_bytes) == 0) {
                FILE *fh = fopen("our_H_refpacking.bin", "wb");
                if (fh) { fwrite(packed_ref, 1, packed_bytes, fh); fclose(fh); }
            }
            // Variant B: alternate MSB-first with MSB=col j
            memset(packed_alt, 0, packed_bytes);
            for (int r = 0; r < H->rows; r++) {
                for (int j = 0; j < H->cols; j += 8) {
                    unsigned char b = 0;
                    int block_len = (j + 8 <= H->cols) ? 8 : (H->cols - j);
                    for (int t = 0; t < block_len; t++) {
                        b <<= 1;
                        int bit = matrix_get_bit(H, r, j + t) & 1;
                        b |= (unsigned char)bit;
                    }
                    packed_alt[r * H->cols_bytes + j/8] = b;
                }
            }
            FILE *fh2 = fopen("our_H_altpacking.bin", "wb");
            if (fh2) { fwrite(packed_alt, 1, packed_bytes, fh2); fclose(fh2); }
        }
        if (packed_ref) free(packed_ref);
        if (packed_alt) free(packed_alt);
        int red = reduce_to_systematic_form(H);
        fprintf(fp, "reduce_to_systematic_form() => %s\n", red == 0 ? "OK" : "FAIL");
    }

    matrix_free(H);
    if (alpha_ref_buf) free(alpha_ref_buf);
    free(alpha);
    polynomial_free(g);
    free(prg);
}

int main(int argc, char **argv)
{
    const char *req_path = "/Users/zhanghanqi/CLionProjects/ClassicMceliece/mceliece6688128/kat_kem.req";
    if (argc > 1) req_path = argv[1];

    unsigned char seed48[48];
    if (parse_req_seed48(req_path, seed48) != 0) {
        fprintf(stderr, "Failed to parse seed from %s: %s\n", req_path, strerror(errno));
        return 1;
    }

    // Logs
    FILE *ref_fp = fopen("reference_dataflow.log", "w");
    FILE *our_fp = fopen("our_dataflow.log", "w");
    if (!ref_fp || !our_fp) {
        fprintf(stderr, "Failed to open log files\n");
        if (ref_fp) fclose(ref_fp);
        if (our_fp) fclose(our_fp);
        return 1;
    }

    // Print seed
    fprintf(ref_fp, "Using seed from %s\n", req_path);
    print_hex(ref_fp, "seed48", seed48, 48, 48);
    fprintf(our_fp, "Using seed from %s\n", req_path);
    print_hex(our_fp, "seed48", seed48, 48, 48);

    // Run both traces
    trace_reference(seed48, ref_fp);
    trace_ours(seed48, our_fp);

    // Build reference-style H matrix from extracted inputs again for comparison
    // Re-run minimal reference extraction to get irr and perm, then build H like pk_gen before elimination
    {
        randombytes_init((unsigned char *)seed48, NULL, 256);
        unsigned char seed33[33]; memset(seed33, 0, sizeof seed33); seed33[0] = 64; randombytes(seed33 + 1, 32);
        size_t rlen = (size_t)(SYS_N/8) + ((size_t)1 << GFBITS) * sizeof(uint32_t) + (size_t)SYS_T * 2 + 32;
        unsigned char *r = (unsigned char*)malloc(rlen);
        if (r) {
            shake(r, rlen, seed33, 33);
            unsigned char *rp = r + rlen;
            rp -= 32; // delta'
            // Extract f from r and compute irr via genpoly_gen (like reference)
            gf f_in[SYS_T];
            gf irr[SYS_T];
            rp -= (size_t)SYS_T * 2;
            for (int i = 0; i < SYS_T; i++) f_in[i] = load_gf(rp + i*2);
            if (genpoly_gen(irr, f_in) != 0) {
                fprintf(ref_fp, "genpoly_gen() failed in reconstruction path\n");
                free(r);
                return 0;
            }
            rp -= ((size_t)1 << GFBITS) * sizeof(uint32_t);
            uint32_t *perm = (uint32_t*)malloc(((size_t)1 << GFBITS) * sizeof(uint32_t));
            if (perm) {
                for (int i = 0; i < (1 << GFBITS); i++) perm[i] = load4(rp + i*4);
                // build pi via uint64 sort
                size_t nfull = (size_t)1 << GFBITS;
                uint64_t *buf = (uint64_t*)malloc(nfull * sizeof(uint64_t));
                int16_t *pi = (int16_t*)malloc(nfull * sizeof(int16_t));
                if (buf && pi) {
                    for (size_t i = 0; i < nfull; i++) buf[i] = ((uint64_t)perm[i] << 31) | (uint64_t)i;
                    qsort(buf, nfull, sizeof(uint64_t), cmp64_qsort);
                    for (size_t i = 0; i < nfull; i++) pi[i] = (int16_t)(buf[i] & GFMASK);
                    // compute L via bitrev
                    gf *L = (gf*)malloc((size_t)SYS_N * sizeof(gf));
                    gf *inv = (gf*)malloc((size_t)SYS_N * sizeof(gf));
                    if (L && inv) {
                        for (int i = 0; i < SYS_N; i++) L[i] = bitrev((gf)pi[i]);
                        // inv = 1/g(L)
                        for (int i = 0; i < SYS_N; i++) {
                            gf val = 1; // monic leading coefficient
                            for (int d = SYS_T - 1; d >= 0; d--) { val = gf_mul(val, L[i]); val ^= irr[d]; }
                            inv[i] = gf_inv(val);
                        }
                        // Dump ref L and inv for j=0..7 and bit-slices for row0
                        fprintf(ref_fp, "Ref L[0..7]: ");
                        for (int j0 = 0; j0 < 8; j0++) fprintf(ref_fp, "%04X ", (unsigned)L[j0]);
                        fprintf(ref_fp, "\n");
                        fprintf(ref_fp, "Ref inv[0..7]: ");
                        for (int j0 = 0; j0 < 8; j0++) fprintf(ref_fp, "%04X ", (unsigned)inv[j0]);
                        fprintf(ref_fp, "\n");
                        // Dump ref inv bits for row0/j=0..7
                        fprintf(ref_fp, "Ref inv bits (row0, k=0..%d, cols 0..7):\n", GFBITS-1);
                        for (int k = 0; k < GFBITS; k++) {
                            fprintf(ref_fp, "k=%2d: ", k);
                            for (int j0 = 0; j0 < 8; j0++) fputc(((inv[j0] >> k) & 1) ? '1' : '0', ref_fp);
                            fputc('\n', ref_fp);
                        }
                        // LSBs at k=0 side-by-side label
                        fprintf(ref_fp, "Ref inv LSBs (k=0, j=0..7): ");
                        for (int j0 = 0; j0 < 8; j0++) fputc((inv[j0] & 1) ? '1' : '0', ref_fp);
                        fputc('\n', ref_fp);
                        // build H matrix bytes like pk_gen packing
                        size_t cols_bytes = (size_t)SYS_N/8;
                        size_t rows = (size_t)PK_NROWS;
                        unsigned char *mat = (unsigned char*)calloc(rows * cols_bytes, 1);
                        if (mat) {
                            for (int i = 0; i < SYS_T; i++) {
                                for (int j = 0; j < SYS_N; j += 8) {
                                    for (int k = 0; k < GFBITS; k++) {
                                        unsigned char b = 0;
                                        int block_len = (j + 8 <= SYS_N) ? 8 : (SYS_N - j);
                                        for (int idx = block_len - 1; idx >= 0; idx--) {
                                            b <<= 1;
                                            if (j + idx < SYS_N) b |= (unsigned char)((inv[j + idx] >> k) & 1);
                                        }
                                        int row = i * GFBITS + k;
                                        mat[row * cols_bytes + (size_t)j/8] = b;
                                    }
                                }
                                for (int j = 0; j < SYS_N; j++) inv[j] = gf_mul(inv[j], L[j]);
                            }
                            FILE *fh = fopen("reference_H.bin", "wb");
                            if (fh) { fwrite(mat, 1, rows * cols_bytes, fh); fclose(fh); }
                            free(mat);
                        }
                        // Persist first-row first byte b (reconstructed)
                        unsigned char b0 = 0; for (int tbit = 7; tbit >= 0; tbit--) { b0 <<= 1; b0 |= (unsigned char)(inv[tbit] & 1); }
                        fprintf(ref_fp, "Ref reconstructed row0 first byte: %02X\n", b0);
                        free(L);
                        free(inv);
                    }
                    free(pi);
                    free(buf);
                }
                free(perm);
            }
            free(r);
        }
    }

    // Compare H matrices
    {
        FILE *f1 = fopen("reference_H.bin", "rb");
        FILE *f2 = fopen("our_H_refpacking.bin", "rb");
        int same = 0;
        if (f1 && f2) {
            fseek(f1, 0, SEEK_END); long n1 = ftell(f1); fseek(f1, 0, SEEK_SET);
            fseek(f2, 0, SEEK_END); long n2 = ftell(f2); fseek(f2, 0, SEEK_SET);
            if (n1 == n2 && n1 > 0) {
                unsigned char *b1 = (unsigned char*)malloc((size_t)n1);
                unsigned char *b2 = (unsigned char*)malloc((size_t)n2);
                if (b1 && b2) {
                    fread(b1, 1, (size_t)n1, f1);
                    fread(b2, 1, (size_t)n2, f2);
                    same = (memcmp(b1, b2, (size_t)n1) == 0);
                    if (!same) {
                        size_t idx = 0; while (idx < (size_t)n1 && b1[idx] == b2[idx]) idx++;
                        fprintf(ref_fp, "H matrix first byte diff at %zu: ref=%02X our=%02X\n", idx, b1[idx], b2[idx]);
                        fprintf(our_fp, "H matrix first byte diff at %zu: ref=%02X our=%02X\n", idx, b1[idx], b2[idx]);
                    }
                }
                free(b1); free(b2);
            }
        }
        if (f1) fclose(f1);
        if (f2) fclose(f2);
        fprintf(stdout, "H matrix identical: %s\n", same ? "YES" : "NO");
        fprintf(ref_fp, "H matrix identical: %s\n", same ? "YES" : "NO");
        fprintf(our_fp, "H matrix identical: %s\n", same ? "YES" : "NO");

        // Dump first row bytes from both matrices for packing inspection
        f1 = fopen("reference_H.bin", "rb");
        f2 = fopen("our_H_refpacking.bin", "rb");
        if (f1 && f2) {
            size_t row_bytes = (size_t)SYS_N/8;
            unsigned char *row_ref = (unsigned char*)malloc(row_bytes);
            unsigned char *row_our = (unsigned char*)malloc(row_bytes);
            if (row_ref && row_our) {
                size_t rd1 = fread(row_ref, 1, row_bytes, f1);
                size_t rd2 = fread(row_our, 1, row_bytes, f2);
                if (rd1 == row_bytes && rd2 == row_bytes) {
                    fprintf(ref_fp, "Row0 first 8 bytes (ref): ");
                    for (int i = 0; i < 8 && (size_t)i < row_bytes; i++) fprintf(ref_fp, "%02X ", row_ref[i]);
                    fprintf(ref_fp, "\nRow0 first byte bits (ref): "); print_byte_bits(ref_fp, row_ref[0]); fprintf(ref_fp, "\n");
                    fprintf(our_fp, "Row0 first 8 bytes (our):  ");
                    for (int i = 0; i < 8 && (size_t)i < row_bytes; i++) fprintf(our_fp, "%02X ", row_our[i]);
                    fprintf(our_fp, "\nRow0 first byte bits (our):  "); print_byte_bits(our_fp, row_our[0]); fprintf(our_fp, "\n");
                }
            }
            free(row_ref); free(row_our);
        }
        if (f1) fclose(f1);
        if (f2) fclose(f2);
    }

    // Our-side inv bit dump for row0 using our poly and alpha
    {
        // Recreate PRG sections via kat_expand_r to avoid RNG drift
        size_t prg_len = (size_t)(MCELIECE_N/8) + ((size_t)MCELIECE_Q) * 4 + (size_t)MCELIECE_T * 2 + 32;
        unsigned char *prg = (unsigned char*)malloc(prg_len);
        unsigned char delta[32];
        if (prg) {
            kat_expand_r(prg, prg_len, delta);
            size_t off = (size_t)(MCELIECE_N/8);
            const unsigned char *field_section = prg + off; off += ((size_t)MCELIECE_Q) * 4;
            const unsigned char *poly_section = prg + off;
            polynomial_t *g = polynomial_create(MCELIECE_T);
            gf_elem_t *alpha = (gf_elem_t*)malloc((size_t)MCELIECE_Q * sizeof(gf_elem_t));
            if (g && alpha && generate_irreducible_poly_final(g, poly_section) == MCELIECE_SUCCESS &&
                generate_field_ordering(alpha, field_section) == MCELIECE_SUCCESS) {
                gf_elem_t inv8[8];
                for (int j = 0; j < 8; j++) {
                    gf_elem_t val = polynomial_eval(g, alpha[j]);
                    inv8[j] = (val == 0) ? 0 : gf_inv(val);
                }
                fprintf(our_fp, "Our L[0..7]:  ");
                for (int j0 = 0; j0 < 8; j0++) fprintf(our_fp, "%04X ", (unsigned)alpha[j0]);
                fprintf(our_fp, "\n");
                fprintf(our_fp, "Our inv[0..7]: ");
                for (int j0 = 0; j0 < 8; j0++) fprintf(our_fp, "%04X ", (unsigned)inv8[j0]);
                fprintf(our_fp, "\n");
                fprintf(our_fp, "Our inv bits (row0, k=0..%d, cols 0..7):\n", MCELIECE_M-1);
                for (int k = 0; k < MCELIECE_M; k++) {
                    fprintf(our_fp, "k=%2d: ", k);
                    for (int j0 = 0; j0 < 8; j0++) fputc(((inv8[j0] >> k) & 1) ? '1' : '0', our_fp);
                    fputc('\n', our_fp);
                }
                fprintf(our_fp, "Our inv LSBs (k=0, j=0..7):  ");
                for (int j0 = 0; j0 < 8; j0++) fputc((inv8[j0] & 1) ? '1' : '0', our_fp);
                fputc('\n', our_fp);

                // GF test: compare g(L) and inv using our gf vs reference gf for j=0..7
                gf ref_g[MCELIECE_T + 1];
                for (int i = 0; i < MCELIECE_T; i++) ref_g[i] = (gf)g->coeffs[i];
                ref_g[MCELIECE_T] = 1;
                fprintf(our_fp, "GF compare g(L[j]) and inv (j=0..7):\n");
                for (int j = 0; j < 8; j++) {
                    // reference Horner
                    gf Lj = (gf)alpha[j];
                    gf ref_val = ref_g[MCELIECE_T];
                    for (int d = MCELIECE_T - 1; d >= 0; d--) { ref_val = ref_gf_mul(ref_val, Lj); ref_val ^= ref_g[d]; }
                    gf our_val = polynomial_eval(g, (gf_elem_t)Lj);
                    gf ref_inv = ref_gf_inv(ref_val ? ref_val : 1);
                    gf our_inv = gf_inv(our_val);
                    fprintf(our_fp, "j=%d ref_val=%04X our_val=%04X ref_inv=%04X our_inv=%04X\n",
                            j, (unsigned)ref_val, (unsigned)our_val, (unsigned)ref_inv, (unsigned)our_inv);
                }
            }
            if (alpha) free(alpha);
            if (g) polynomial_free(g);
            free(prg);
        }
    }

    // Compare irreducible polynomial (reference irr vs our g[0..T-1])
    {
        FILE *fr = fopen("reference_irr.bin", "rb");
        FILE *fo = fopen("our_irr.bin", "rb");
        int same = 0;
        if (fr && fo) {
            gf ref_irr[SYS_T];
            gf_elem_t our_irr[SYS_T];
            size_t rd1 = fread(ref_irr, sizeof(gf), (size_t)SYS_T, fr);
            size_t rd2 = fread(our_irr, sizeof(gf_elem_t), (size_t)SYS_T, fo);
            if (rd1 == (size_t)SYS_T && rd2 == (size_t)SYS_T) {
                same = (memcmp(ref_irr, our_irr, (size_t)SYS_T * sizeof(gf)) == 0);
                if (!same) {
                    int idx = 0; while (idx < SYS_T && ref_irr[idx] == (gf)our_irr[idx]) idx++;
                    if (idx < SYS_T) {
                        fprintf(ref_fp, "Irr poly first coeff diff at %d: ref=%04X our=%04X\n", idx, (unsigned)ref_irr[idx], (unsigned)our_irr[idx]);
                        fprintf(our_fp, "Irr poly first coeff diff at %d: ref=%04X our=%04X\n", idx, (unsigned)ref_irr[idx], (unsigned)our_irr[idx]);
                    }
                }
            }
        }
        if (fr) fclose(fr);
        if (fo) fclose(fo);
        fprintf(stdout, "Irreducible polynomial identical: %s\n", same ? "YES" : "NO");
        fprintf(ref_fp, "Irreducible polynomial identical: %s\n", same ? "YES" : "NO");
        fprintf(our_fp, "Irreducible polynomial identical: %s\n", same ? "YES" : "NO");
    }

    fclose(ref_fp);
    fclose(our_fp);

    // Also echo short summary to stdout
    printf("Wrote reference flow to reference_dataflow.log\n");
    printf("Wrote our flow to our_dataflow.log\n");
    return 0;
}


