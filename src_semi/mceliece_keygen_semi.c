#include "mceliece_keygen_semi.h"
#include "../src/mceliece_keygen.h"
#include "../src/mceliece_genpoly.h"
#include "../src/mceliece_kem.h"
#include "../src/debuglog.h"
#include "../src/hierarchical_profiler.h"
#include "../src/kat_drbg.h"
#include "../src/controlbits.h"

static inline int extract_pivots_and_reorder_like_ref(matrix_t *H, int16_t *pi_out, uint64_t *pivots_out) {
    int mt = H->rows;
    int n = H->cols;
    int left_bytes = (mt + 7) / 8;
    int block_idx = (mt - 32) / 8; // PK_NROWS-32 byte index
    if (mt % 8 != 0) return -1;
    if (!pivots_out) return -1;

    uint64_t buf[64] = {0};
    for (int i = 0; i < 32; i++) {
        buf[i] = 0;
        // load 8 bytes from the (mt-32+i)-th row at block_idx
        int row = (mt - 32) + i;
        const uint8_t *p = &H->data[row * H->cols_bytes + block_idx];
        uint64_t v = 0;
        for (int b = 7; b >= 0; b--) { v <<= 8; v |= p[b]; }
        buf[i] = v;
    }

    // Gaussian elimination on 32x64 slice to find ctz indices
    uint64_t ctz_list[32] = {0};
    *pivots_out = 0ULL;
    for (int i = 0; i < 32; i++) {
        uint64_t t = buf[i];
        for (int j = i + 1; j < 32; j++) t |= buf[j];
        if (t == 0) return -1;
        int s = 0;
        while (((t >> s) & 1ULL) == 0ULL && s < 64) s++;
        ctz_list[i] = (uint64_t)s;
        *pivots_out |= (1ULL << s);
        for (int j = i + 1; j < 32; j++) { uint64_t mask = -((buf[i] >> s) & 1ULL); buf[i] ^= (buf[j] & mask); }
        for (int j = i + 1; j < 32; j++) { uint64_t mask = -((buf[j] >> s) & 1ULL); buf[j] ^= (buf[i] & mask); }
    }

    // Reorder columns in-place for the selected byte block
    for (int i = 0; i < mt; i++) {
        uint8_t *p = &H->data[i * H->cols_bytes + block_idx];
        uint64_t t = 0;
        for (int b = 7; b >= 0; b--) { t <<= 8; t |= p[b]; }
        for (int j = 0; j < 32; j++) {
            uint64_t d = (t >> j) ^ (t >> ctz_list[j]);
            d &= 1ULL;
            t ^= (d << ctz_list[j]);
            t ^= (d << j);
        }
        for (int b = 0; b < 8; b++) { p[b] = (uint8_t)(t & 0xFFu); t >>= 8; }
    }

    (void)pi_out; // not used in semi path
    return 0;
}

int reduce_to_semisystematic_reference_style(matrix_t *H, uint64_t *pivots) {
    if (!H || !pivots) return -1;
    // Perform the same left-walk elimination, but when reaching last 32 rows, run mov_columns equivalent
    int mt = H->rows;
    int left_bytes = (mt + 7) / 8;
    for (int byte_idx = 0; byte_idx < left_bytes; byte_idx++) {
        for (int bit_in_byte = 0; bit_in_byte < 8; bit_in_byte++) {
            int row = byte_idx * 8 + bit_in_byte;
            if (row >= mt) break;

            if (row == mt - 32) {
                if (extract_pivots_and_reorder_like_ref(H, NULL, pivots) != 0) return -1;
            }

            for (int r = row + 1; r < mt; r++) {
                unsigned char x = (unsigned char)(H->data[row * H->cols_bytes + byte_idx] ^
                                                  H->data[r   * H->cols_bytes + byte_idx]);
                unsigned char m = (unsigned char)((x >> bit_in_byte) & 1u);
                m = (unsigned char)(-(signed char)m);
                for (int c = 0; c < H->cols_bytes; c++) {
                    H->data[row * H->cols_bytes + c] ^= (unsigned char)(H->data[r * H->cols_bytes + c] & m);
                }
            }

            if (((H->data[row * H->cols_bytes + byte_idx] >> bit_in_byte) & 1u) == 0u) {
                return -1;
            }

            for (int r = 0; r < mt; r++) {
                if (r == row) continue;
                unsigned char m = (unsigned char)((H->data[r * H->cols_bytes + byte_idx] >> bit_in_byte) & 1u);
                m = (unsigned char)(-(signed char)m);
                for (int c = 0; c < H->cols_bytes; c++) {
                    H->data[r * H->cols_bytes + c] ^= (unsigned char)(H->data[row * H->cols_bytes + c] & m);
                }
            }
        }
    }
    return 0;
}

mceliece_error_t seeded_key_gen_semi(const uint8_t *delta, public_key_t *pk, private_key_t *sk) {
    if (!delta || !pk || !sk) return MCELIECE_ERROR_INVALID_PARAM;

    // Reuse seeded_key_gen steps until building H, then use semi reduction
    int n_bits = MCELIECE_N;
    int t_bits = MCELIECE_T;
    int q_val = MCELIECE_Q;
    int l_bits = 256;
    int sigma1 = 16;
    int sigma2 = 32;

    size_t s_len_bits = n_bits;
    size_t field_ordering_len_bits = (size_t)sigma2 * (size_t)q_val;
    size_t irreducible_poly_len_bits = (size_t)sigma1 * (size_t)t_bits;
    size_t delta_prime_len_bits = (size_t)l_bits;
    size_t prg_output_len_bits = s_len_bits + field_ordering_len_bits + irreducible_poly_len_bits + delta_prime_len_bits;
    size_t prg_output_len_bytes = (prg_output_len_bits + 7) / 8;
    size_t s_len_bytes = (s_len_bits + 7) / 8;
    size_t field_ordering_len_bytes = (field_ordering_len_bits + 7) / 8;
    size_t irreducible_poly_len_bytes = (irreducible_poly_len_bits + 7) / 8;
    size_t delta_prime_len_bytes = (delta_prime_len_bits + 7) / 8;

    uint8_t *E = (uint8_t*)malloc(prg_output_len_bytes);
    if (!E) return MCELIECE_ERROR_MEMORY;

    if (kat_drbg_is_inited()) {
        kat_get_delta(sk->delta);
    } else {
        memcpy(sk->delta, delta, delta_prime_len_bytes);
    }

    int max_attempts = 50;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        if (kat_drbg_is_inited()) {
            uint8_t delta_prime[32];
            kat_expand_r(E, prg_output_len_bytes, delta_prime);
        } else {
            mceliece_prg(sk->delta, E, prg_output_len_bytes);
        }

        uint8_t delta_prime[32];
        memcpy(delta_prime, E + prg_output_len_bytes - delta_prime_len_bytes, delta_prime_len_bytes);

        const uint8_t *s_bits_ptr = E;
        const uint8_t *field_ordering_bits_ptr = E + s_len_bytes;
        const uint8_t *irreducible_poly_bits_ptr = field_ordering_bits_ptr + field_ordering_len_bytes;

        if (generate_irreducible_poly_final(&sk->g, irreducible_poly_bits_ptr) != MCELIECE_SUCCESS) {
            memcpy(sk->delta, delta_prime, 32);
            continue;
        }
        if (generate_field_ordering(sk->alpha, field_ordering_bits_ptr) != MCELIECE_SUCCESS) {
            memcpy(sk->delta, delta_prime, 32);
            continue;
        }
        int is_support_set = 1;
        for (int i = 0; i < n_bits; ++i) {
            if (polynomial_eval(&sk->g, sk->alpha[i]) == 0) { is_support_set = 0; break; }
        }
        if (!is_support_set) { memcpy(sk->delta, delta_prime, 32); continue; }

        int mt = MCELIECE_M * MCELIECE_T;
        int n = MCELIECE_N;
        matrix_t *Htmp = matrix_create(mt, n);
        if (!Htmp) { memcpy(sk->delta, delta_prime, 32); continue; }
        if (build_parity_check_matrix_reference_style(Htmp, &sk->g, sk->alpha) != 0) {
            matrix_free(Htmp); memcpy(sk->delta, delta_prime, 32); continue;
        }
        uint64_t pivots = 0;
        if (reduce_to_semisystematic_reference_style(Htmp, &pivots) != 0) {
            matrix_free(Htmp); memcpy(sk->delta, delta_prime, 32); continue;
        }
        // store pivots in secret key
        sk->c = pivots;
        // extract T block
        for (int i = 0; i < mt; i++) {
            for (int j = 0; j < (MCELIECE_N - mt); j++) {
                int bit = matrix_get_bit(Htmp, i, mt + j);
                matrix_set_bit(&pk->T, i, j, bit);
            }
        }
        matrix_free(Htmp);

        // controlbits same as systematic path
        long long m = MCELIECE_M;
        long long n_full = 1LL << m;
        size_t pi_bytes = sizeof(int16_t) * (size_t)n_full;
        int16_t *pi = (int16_t*)malloc(pi_bytes);
        int16_t *val_to_index = (int16_t*)malloc(sizeof(int16_t) * (size_t)n_full);
        if (!pi || !val_to_index) { free(pi); free(val_to_index); free(E); return MCELIECE_ERROR_MEMORY; }
        for (long long i = 0; i < n_full; i++) {
            uint16_t x = (uint16_t)i; uint16_t r = 0; for (int bi = 0; bi < MCELIECE_M; bi++) { r = (uint16_t)((r << 1) | ((x >> bi) & 1U)); }
            uint16_t v = (uint16_t)(r & ((1U << MCELIECE_M) - 1U)); val_to_index[v] = (int16_t)i;
        }
        for (long long i = 0; i < n_full; i++) pi[i] = (int16_t)i;
        for (int j = 0; j < MCELIECE_Q; j++) { uint16_t a = (uint16_t)sk->alpha[j]; int16_t src = val_to_index[a]; pi[j] = src; }
        free(val_to_index);
        size_t cb_len = (size_t)((((2 * m - 1) * n_full / 2) + 7) / 8);
        if (sk->controlbits) { free(sk->controlbits); sk->controlbits = NULL; }
        sk->controlbits = (uint8_t*)malloc(cb_len);
        if (!sk->controlbits) { free(pi); free(E); return MCELIECE_ERROR_MEMORY; }
        memset(sk->controlbits, 0, cb_len);
        cbits_from_perm_ns(sk->controlbits, pi, m, n_full);
        sk->controlbits_len = cb_len;
        free(pi);

        memcpy(sk->s, s_bits_ptr, (n_bits + 7) / 8);

        free(E);
        return MCELIECE_SUCCESS;
    }

    free(E);
    return MCELIECE_ERROR_KEYGEN_FAIL;
}

int private_key_serialize_semi(const private_key_t *sk, uint8_t *out, size_t out_capacity, size_t *out_len) {
    if (!sk || !out) return -1;
    const int t = MCELIECE_T;
    const int m = MCELIECE_M;
    const size_t irr_bytes = (size_t)t * 2;
    const size_t cb_len = sk->controlbits_len > 0 ? sk->controlbits_len : (size_t)((2 * m - 1) * (1u << (m - 4)));
    const size_t s_len = MCELIECE_N_BYTES;
    const size_t total = 32 + 8 + irr_bytes + cb_len + s_len;
    if (out_capacity < total) return -1;
    size_t off = 0;
    memcpy(out + off, sk->delta, 32); off += 32;
    // pivots value sk->c as 8 bytes little-endian
    uint64_t piv = sk->c;
    out[off+0] = (uint8_t)(piv & 0xFFu);
    out[off+1] = (uint8_t)((piv >> 8) & 0xFFu);
    out[off+2] = (uint8_t)((piv >> 16) & 0xFFu);
    out[off+3] = (uint8_t)((piv >> 24) & 0xFFu);
    out[off+4] = (uint8_t)((piv >> 32) & 0xFFu);
    out[off+5] = (uint8_t)((piv >> 40) & 0xFFu);
    out[off+6] = (uint8_t)((piv >> 48) & 0xFFu);
    out[off+7] = (uint8_t)((piv >> 56) & 0xFFu);
    off += 8;
    for (int i = 0; i < t; i++) {
        uint16_t c = (uint16_t)(sk->g.coeffs[i] & ((1u << m) - 1u));
        out[off + 2*i + 0] = (uint8_t)(c & 0xFFu);
        out[off + 2*i + 1] = (uint8_t)((c >> 8) & 0xFFu);
    }
    off += irr_bytes;
    if (!sk->controlbits || cb_len == 0) return -1;
    memcpy(out + off, sk->controlbits, cb_len); off += cb_len;
    memcpy(out + off, sk->s, s_len); off += s_len;
    if (out_len) *out_len = off;
    return 0;
}


