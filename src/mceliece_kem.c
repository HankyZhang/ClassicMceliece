#include "mceliece_kem.h"
#include "kat_drbg.h"
#include <ctype.h>
#include "controlbits.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "debuglog.h"
#include "hierarchical_profiler.h"
#ifdef USE_REF_RANDOMBYTES
#include "mceliece6688128/nist/rng.h"
#endif
// Semi-systematic keygen API
#include "../src_semi/mceliece_keygen_semi.h"

// Reference KAT API not used; we emit rsp using our implementation
// PQClean-style helpers for KAT parity
static inline uint16_t pqclean_load_gf_le(const unsigned char *src) {
    uint16_t a = (uint16_t)src[1];
    a = (uint16_t)((a << 8) | src[0]);
    uint16_t mask = (uint16_t)((1U << MCELIECE_M) - 1U);
    return (uint16_t)(a & mask);
}

static void gen_e_pqclean(unsigned char *e) {
    PROFILE_GEN_E_PQCLEAN_START();
    int i, j, eq, count;
    union {
        uint16_t nums[ MCELIECE_T * 2 ];
        unsigned char bytes[ MCELIECE_T * 2 * sizeof(uint16_t) ];
    } buf;
    uint16_t ind[ MCELIECE_T ];
    unsigned char val[ MCELIECE_T ];

    for (;;) {
        kat_drbg_randombytes(buf.bytes, sizeof(buf.bytes));
        for (i = 0; i < MCELIECE_T * 2; i++) {
            buf.nums[i] = pqclean_load_gf_le(buf.bytes + i * 2);
        }
        count = 0;
        for (i = 0; i < MCELIECE_T * 2 && count < MCELIECE_T; i++) {
            if (buf.nums[i] < MCELIECE_N) ind[count++] = buf.nums[i];
        }
        if (count < MCELIECE_T) continue;
        eq = 0;
        for (i = 1; i < MCELIECE_T; i++) {
            for (j = 0; j < i; j++) {
                if (ind[i] == ind[j]) { eq = 1; }
            }
        }
        if (eq == 0) break;
    }

    for (j = 0; j < MCELIECE_T; j++) {
        val[j] = (unsigned char)(1U << (ind[j] & 7));
    }
    for (i = 0; i < MCELIECE_N / 8; i++) {
        unsigned char acc = 0;
        for (j = 0; j < MCELIECE_T; j++) {
            unsigned char mask = (unsigned char)(-(unsigned char)((uint16_t)i == (ind[j] >> 3)));
            acc |= (unsigned char)(val[j] & mask);
        }
        e[i] = acc;
    }
    PROFILE_GEN_E_PQCLEAN_END();
}

// KeyGen算法
mceliece_error_t mceliece_keygen(public_key_t *pk, private_key_t *sk) {
    if (!pk || !sk) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    // 生成一个一次性的随机种子 delta
    uint8_t delta[MCELIECE_L_BYTES];
    if (kat_drbg_is_inited()) {
        // In KAT mode, avoid consuming extra bytes; seeded_key_gen will draw E directly from DRBG
        memset(delta, 0, sizeof(delta));
    } else {
        // 非KAT模式：优先使用参考实现的 DRBG (randombytes)，退化到 OS 随机/PRG
        #include <time.h>
        #ifdef USE_REF_RANDOMBYTES
        unsigned char entropy_input[48];
        FILE *ur48 = fopen("/dev/urandom", "rb");
        if (ur48) {
            size_t got = fread(entropy_input, 1, sizeof(entropy_input), ur48);
            fclose(ur48);
            if (got != sizeof(entropy_input)) {
                for (size_t i = 0; i < sizeof(entropy_input); i++) {
                    entropy_input[i] = (unsigned char)((rand() >> (i % 7)) ^ ((unsigned)time(NULL) >> (i % 5)));
                }
            }
        } else {
            for (size_t i = 0; i < sizeof(entropy_input); i++) {
                entropy_input[i] = (unsigned char)((rand() >> (i % 7)) ^ ((unsigned)time(NULL) >> (i % 5)));
            }
        }
        randombytes_init(entropy_input, NULL, 256);
        randombytes(delta, 32);
        #else
        FILE *ur = fopen("/dev/urandom", "rb");
        size_t need = 32;
        if (ur) {
            size_t got = fread(delta, 1, need, ur);
            fclose(ur);
            if (got != need) {
                // fallback
                uint8_t seed_buf[32];
                for (size_t i = 0; i < sizeof(seed_buf); i++) {
                    seed_buf[i] = (uint8_t)((rand() >> (i % 7)) ^ ((unsigned)time(NULL) >> (i % 5)));
                }
                mceliece_prg(seed_buf, delta, 32);
            }
        } else {
            uint8_t seed_buf[32];
            for (size_t i = 0; i < sizeof(seed_buf); i++) {
                seed_buf[i] = (uint8_t)((rand() >> (i % 7)) ^ ((unsigned)time(NULL) >> (i % 5)));
            }
            mceliece_prg(seed_buf, delta, 32);
        }
        #endif
    }

    return seeded_key_gen(delta, pk, sk);
}


// Encap algorithm (non-pc parameter sets)
mceliece_error_t mceliece_encap(const public_key_t *pk, uint8_t *ciphertext, uint8_t *session_key) {
    if (!pk || !ciphertext || !session_key) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }
    const char *env_debug = getenv("MCELIECE_DEBUG");
    int dbg_enabled = (!kat_drbg_is_inited()) && env_debug && env_debug[0] == '1';
    
    int max_attempts = 10;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        // Step 1: Generate fixed weight vector e (KAT: draw directly from DRBG for exact matching)
        if (dbg_enabled) { printf("[encap] generating error vector e...\n"); fflush(stdout); }
        uint8_t *e = malloc(MCELIECE_N_BYTES);
        if (!e) return MCELIECE_ERROR_MEMORY;
        
        mceliece_error_t ret;
        if (kat_drbg_is_inited()) {
            memset(e, 0, MCELIECE_N_BYTES);
            gen_e_pqclean(e);
            dbg_hex_us("encap.e.first128B", e, MCELIECE_N_BYTES, 128);
            ret = MCELIECE_SUCCESS;
        } else {
            ret = fixed_weight_vector(e, MCELIECE_N, MCELIECE_T);
        }
        if (ret != MCELIECE_SUCCESS) {
            free(e);
            if (ret == MCELIECE_ERROR_KEYGEN_FAIL) {
                // Retry
                continue;
            }
            return ret;
        }
        
        // Step 2: Calculate C = Encode(e, T)
        if (dbg_enabled) { printf("[encap] encoding ciphertext C = H*e...\n"); fflush(stdout); }
        PROFILE_ENCODE_VECTOR_START();
        encode_vector(e, &pk->T, ciphertext);
        PROFILE_ENCODE_VECTOR_END();
        dbg_hex_us("encap.C.first64B", ciphertext, MCELIECE_MT_BYTES, 64);
        
        
        
        // Step 3: Calculate K = Hash(1, e, C) exactly like reference (no extra prefix byte)
        if (dbg_enabled) { printf("[encap] deriving session key...\n"); fflush(stdout); }
        // Construct hash input: prefix 1 + e + C
        size_t hash_input_len = 1 + MCELIECE_N_BYTES + MCELIECE_MT_BYTES;
        uint8_t *hash_input = malloc(hash_input_len);
        if (!hash_input) {
            free(e);
            return MCELIECE_ERROR_MEMORY;
        }
        
        hash_input[0] = 1;  // prefix
        memcpy(hash_input + 1, e, MCELIECE_N_BYTES);
        memcpy(hash_input + 1 + MCELIECE_N_BYTES, ciphertext, MCELIECE_MT_BYTES);
        
        // Reference hashes the raw bytes (1||e||C) with SHAKE256 to 32 bytes
        PROFILE_SHAKE256_START();
        shake256(hash_input, hash_input_len, session_key, 32);
        PROFILE_SHAKE256_END();
        
        free(e);
        free(hash_input);
        if (dbg_enabled) { printf("[encap] done.\n"); fflush(stdout); }
        return MCELIECE_SUCCESS;
    }
    
    return MCELIECE_ERROR_KEYGEN_FAIL; // Reached maximum attempts
}




// Decap algorithm (non-pc parameter sets)
mceliece_error_t mceliece_decap(const uint8_t *ciphertext, const private_key_t *sk, 
                               uint8_t *session_key) {
    if (!ciphertext || !sk || !session_key) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }
    const char *env_debug = getenv("MCELIECE_DEBUG");
    int dbg_enabled = (!kat_drbg_is_inited()) && env_debug && env_debug[0] == '1';
    
    // Step 1: Set b = 1
    uint8_t b = 1;
    
    // Step 3: Try to decode
    uint8_t *e = malloc(MCELIECE_N_BYTES);
    if (!e) return MCELIECE_ERROR_MEMORY;
    
    // Build v = (C, 0, ..., 0) and decode directly using reordered support sk->alpha
    if (dbg_enabled) { printf("[decap] building v=(C,0,...) and decoding...\n"); fflush(stdout); }
    PROFILE_START("build_v_vector");
    uint8_t *v = calloc(MCELIECE_N_BYTES, 1);
    if (!v) { free(e); return MCELIECE_ERROR_MEMORY; }
    int mt = MCELIECE_M * MCELIECE_T;
    for (int i = 0; i < mt; i++) {
        int bit = vector_get_bit(ciphertext, i);
        vector_set_bit(v, i, bit);
    }
    PROFILE_END("build_v_vector");

    int decode_success;
    mceliece_error_t ret;
    // Force Benes: require controlbits and correct length; do not fallback
    long long m = MCELIECE_M; long long n_full = 1LL << m;
    size_t expected_cb_len = (size_t)((((2 * m - 1) * n_full / 2) + 7) / 8);
    if (!sk->controlbits || sk->controlbits_len != expected_cb_len) {
        free(v); free(e);
        return MCELIECE_ERROR_INVALID_PARAM;
    }
    gf_elem_t *L = (gf_elem_t*)malloc(sizeof(gf_elem_t) * MCELIECE_N);
    if (!L) { free(v); free(e); return MCELIECE_ERROR_MEMORY; }
    PROFILE_START("support_from_cbits");
    support_from_cbits(L, sk->controlbits, MCELIECE_M, MCELIECE_N);
    PROFILE_END("support_from_cbits");
    ret = decode_goppa(v, &sk->g, L, e, &decode_success);
    if (dbg_enabled) { printf("[decap] decode_success=%d\n", decode_success); fflush(stdout); }
    free(L);
    free(v);
    
    if (ret != MCELIECE_SUCCESS) {
        free(e);
        return ret;
    }
    
    if (!decode_success) {
        // Decoding failed, use backup vector s
        if (!kat_drbg_is_inited()) printf("Debug: Decoding failed, using backup vector s\n");
        memcpy(e, sk->s, MCELIECE_N_BYTES);
        b = 0;
    } else {
        if (!kat_drbg_is_inited()) printf("Debug: Decoding succeeded, using recovered error vector\n");
    }
    
    // Step 4: Calculate K = Hash(b, e, C) exactly like reference (no extra prefix byte)
    size_t hash_input_len = 1 + MCELIECE_N_BYTES + MCELIECE_MT_BYTES;
    uint8_t *hash_input = malloc(hash_input_len);
    if (!hash_input) {
        free(e);
        return MCELIECE_ERROR_MEMORY;
    }
    
    hash_input[0] = b;  // prefix
    memcpy(hash_input + 1, e, MCELIECE_N_BYTES);
    memcpy(hash_input + 1 + MCELIECE_N_BYTES, ciphertext, MCELIECE_MT_BYTES);
    
    // Reference hashes the raw bytes (b||e||C) with SHAKE256 to 32 bytes
    PROFILE_SHAKE256_START();
    shake256(hash_input, hash_input_len, session_key, 32);
    PROFILE_SHAKE256_END();
    
    free(e);
    free(hash_input);
    return MCELIECE_SUCCESS;
}


// 测试函数
void test_mceliece(void) {
    printf("Testing Classic McEliece implementation...\n");
    

    
    // 创建密钥
    public_key_t *pk = public_key_create();
    private_key_t *sk = private_key_create();
    
    if (!pk || !sk) {
        printf("Failed to create key structures\n");
        return;
    }
    
    // 生成密钥对
    printf("Generating key pair...\n");
    mceliece_error_t ret = mceliece_keygen(pk, sk);
    if (ret != MCELIECE_SUCCESS) {
        printf("Key generation failed: %d\n", ret);
        public_key_free(pk);
        private_key_free(sk);
        return;
    }
    printf("Key generation successful!\n");
    
    // 封装
    printf("Testing encapsulation...\n");
    uint8_t ciphertext[MCELIECE_MT_BYTES];
    uint8_t session_key1[MCELIECE_L_BYTES];
    
    ret = mceliece_encap(pk, ciphertext, session_key1);
    if (ret != MCELIECE_SUCCESS) {
        printf("Encapsulation failed: %d\n", ret);
        public_key_free(pk);
        private_key_free(sk);
        return;
    }
    printf("Encapsulation successful!\n");
    
    // 解封装
    printf("Testing decapsulation...\n");
    uint8_t session_key2[MCELIECE_L_BYTES];
    
    // Simplified test removed for now
    
    ret = mceliece_decap(ciphertext, sk, session_key2);
    if (ret != MCELIECE_SUCCESS) {
        printf("Decapsulation failed: %d\n", ret);
        public_key_free(pk);
        private_key_free(sk);
        return;
    }
    
    // 验证会话密钥是否相同
    int keys_match = 1;
    for (int i = 0; i < MCELIECE_L_BYTES; i++) {
        if (session_key1[i] != session_key2[i]) {
            keys_match = 0;
            break;
        }
    }
    
    if (keys_match) {
        printf("Decapsulation successful! Session keys match.\n");
    } else {
        printf("Decapsulation failed! Session keys don't match.\n");
        printf("Debug: First 16 bytes of session key 1: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", session_key1[i]);
        }
        printf("\n");
        printf("Debug: First 16 bytes of session key 2: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", session_key2[i]);
        }
        printf("\n");
    }
    
    // 清理
    public_key_free(pk);
    private_key_free(sk);
    
    printf("Test completed.\n");
}

void run_all_tests(void) {
    printf("=== Running Comprehensive Test Suite ===\n\n");
    
    // Test 1: Basic functionality
    printf("1. Basic McEliece Test:\n");
    test_mceliece();
    printf("\n");
    
    // Test 2: Multiple rounds
    printf("2. Multiple Round Test (5 iterations):\n");
    int success_count = 0;
    for (int i = 0; i < 5; i++) {
        printf("  Round %d: ", i + 1);
        
        public_key_t *pk = public_key_create();
        private_key_t *sk = private_key_create();
        
        if (!pk || !sk) {
            printf("FAILED (memory allocation)\n");
            continue;
        }
        
        // Key generation
        mceliece_error_t ret = mceliece_keygen(pk, sk);
        if (ret != MCELIECE_SUCCESS) {
            printf("FAILED (keygen: %d)\n", ret);
            public_key_free(pk);
            private_key_free(sk);
            continue;
        }
        
        // Encapsulation
        uint8_t ciphertext[MCELIECE_MT_BYTES];
        uint8_t session_key1[MCELIECE_L_BYTES];
        ret = mceliece_encap(pk, ciphertext, session_key1);
        if (ret != MCELIECE_SUCCESS) {
            printf("FAILED (encap: %d)\n", ret);
            public_key_free(pk);
            private_key_free(sk);
            continue;
        }
        
        // Decapsulation
        uint8_t session_key2[MCELIECE_L_BYTES];
        ret = mceliece_decap(ciphertext, sk, session_key2);
        if (ret != MCELIECE_SUCCESS) {
            printf("FAILED (decap: %d)\n", ret);
            public_key_free(pk);
            private_key_free(sk);
            continue;
        }
        
        // Verify keys match
        int keys_match = 1;
        for (int j = 0; j < MCELIECE_L_BYTES; j++) {
            if (session_key1[j] != session_key2[j]) {
                keys_match = 0;
                break;
            }
        }
        
        if (keys_match) {
            printf("PASSED\n");
            success_count++;
        } else {
            printf("FAILED (key mismatch)\n");
        }
        
        public_key_free(pk);
        private_key_free(sk);
    }
    
    printf("  Success rate: %d/5 (%.1f%%)\n\n", success_count, success_count * 20.0);
    
    // Test 3: Parameter verification
    printf("3. Parameter Verification:\n");
    printf("  m = %d (field extension degree)\n", MCELIECE_M);
    printf("  n = %d (code length)\n", MCELIECE_N);
    printf("  t = %d (error correction capability)\n", MCELIECE_T);
    printf("  k = %d (code dimension)\n", MCELIECE_K);
    printf("  q = %d (field size)\n", MCELIECE_Q);
    printf("  Expected: k = n - m*t = %d - %d*%d = %d\n", 
           MCELIECE_N, MCELIECE_M, MCELIECE_T, MCELIECE_N - MCELIECE_M * MCELIECE_T);
    
    if (MCELIECE_K == MCELIECE_N - MCELIECE_M * MCELIECE_T) {
        printf("  ✓ Parameter consistency check PASSED\n");
    } else {
        printf("  ✗ Parameter consistency check FAILED\n");
    }
    
    printf("\n=== Test Suite Complete ===\n");
    if (success_count == 5) {
        printf("🎉 All tests PASSED! System appears to be working correctly.\n");
    } else if (success_count >= 3) {
        printf("⚠️  Most tests passed (%d/5). System mostly functional.\n", success_count);
    } else {
        printf("❌ Multiple test failures (%d/5). System needs debugging.\n", success_count);
    }
}

// Targeted BM+Chien test: generate a weight-t error, compute its syndrome from the definition,
// run BM to get sigma, and Chien to recover indices; compare with ground truth.
void test_bm_chien(void) {
    printf("\n=== BM+Chien Targeted Test ===\n");

    // Prepare a random private key context to get g and alpha
    public_key_t *pk = public_key_create();
    private_key_t *sk = private_key_create();
    if (!pk || !sk) {
        printf("Setup failed (alloc)\n");
        return;
    }
    if (mceliece_keygen(pk, sk) != MCELIECE_SUCCESS) {
        printf("Setup failed (keygen)\n");
        public_key_free(pk);
        private_key_free(sk);
        return;
    }

    // 1) Create a random weight-t error vector e
    uint8_t *e = malloc(MCELIECE_N_BYTES);
    if (!e) { public_key_free(pk); private_key_free(sk); return; }
    if (fixed_weight_vector(e, MCELIECE_N, MCELIECE_T) != MCELIECE_SUCCESS) {
        printf("Error vector generation failed\n");
        free(e);
        public_key_free(pk);
        private_key_free(sk);
        return;
    }

    // Record ground-truth positions
    /* removed unused ground-truth positions array */

    // 2) Compute syndrome s_j = sum_{i in I} alpha_i^j / g(alpha_i)^2 using compute_syndrome on e
    gf_elem_t *syndrome = malloc(sizeof(gf_elem_t) * 2 * MCELIECE_T);
    if (!syndrome) { free(e); public_key_free(pk); private_key_free(sk); return; }
    compute_syndrome(e, &sk->g, sk->alpha, syndrome);

    // 3) Run BM to get sigma, omega
    polynomial_t *sigma = polynomial_create(MCELIECE_T);
    if (!sigma) {
        printf("Alloc failed (polys)\n");
        free(e); free(syndrome);
        public_key_free(pk); private_key_free(sk);
        return;
    }
    if (berlekamp_massey(syndrome, sigma) != MCELIECE_SUCCESS) {
        printf("BM failed\n");
        free(e); free(syndrome);
        polynomial_free(sigma);
        public_key_free(pk); private_key_free(sk);
        return;
    }
    printf("Sigma degree: %d (expected %d)\n", sigma->degree, MCELIECE_T);

    // 4) Chien search
    int *found = malloc(sizeof(int) * MCELIECE_T);
    int num_found = 0;
    if (!found) { free(e); free(syndrome); polynomial_free(sigma); public_key_free(pk); private_key_free(sk); return; }
    if (chien_search(sigma, sk->alpha, found, &num_found) != MCELIECE_SUCCESS) {
        printf("Chien failed\n");
        free(found); free(e); free(syndrome);
        polynomial_free(sigma);
        public_key_free(pk); private_key_free(sk);
        return;
    }
    printf("Chien found %d positions\n", num_found);

    // 5) Compare with ground truth count and weight
    int wt = vector_weight(e, MCELIECE_N_BYTES);
    printf("Ground truth weight: %d (expected %d)\n", wt, MCELIECE_T);

    if (num_found == wt && wt == MCELIECE_T) {
        printf("BM+Chien test: PASS (counts match)\n");
    } else {
        printf("BM+Chien test: FAIL (counts mismatch)\n");
    }

    free(found);
    polynomial_free(sigma);
    free(syndrome);
    free(e);
    public_key_free(pk);
    private_key_free(sk);
}

// Stress test: run many KEM rounds
void test_stress(void) {
    printf("\n=== Stress Test (50 rounds) ===\n");
    int rounds = 50;
    int ok = 0;
    for (int r = 0; r < rounds; r++) {
        public_key_t *pk = public_key_create();
        private_key_t *sk = private_key_create();
        if (!pk || !sk) { printf("alloc fail\n"); break; }
        if (mceliece_keygen(pk, sk) != MCELIECE_SUCCESS) { printf("keygen fail\n"); public_key_free(pk); private_key_free(sk); continue; }
        uint8_t C[MCELIECE_MT_BYTES];
        uint8_t K1[MCELIECE_L_BYTES], K2[MCELIECE_L_BYTES];
        if (mceliece_encap(pk, C, K1) != MCELIECE_SUCCESS) { printf("encap fail\n"); public_key_free(pk); private_key_free(sk); continue; }
        if (mceliece_decap(C, sk, K2) != MCELIECE_SUCCESS) { printf("decap fail\n"); public_key_free(pk); private_key_free(sk); continue; }
        int same = memcmp(K1, K2, MCELIECE_L_BYTES) == 0;
        if (!same) printf("Round %d mismatch\n", r+1);
        ok += same;
        public_key_free(pk); private_key_free(sk);
    }
    printf("Success: %d/%d\n", ok, rounds);
}

// Tamper test: flip bits in C and check decap fails (uses backup)
void test_tamper(void) {
    printf("\n=== Tamper Test ===\n");
    public_key_t *pk = public_key_create();
    private_key_t *sk = private_key_create();
    if (!pk || !sk) { printf("alloc fail\n"); return; }
    if (mceliece_keygen(pk, sk) != MCELIECE_SUCCESS) { printf("keygen fail\n"); goto done; }
    uint8_t C[MCELIECE_MT_BYTES];
    uint8_t K1[MCELIECE_L_BYTES], K2[MCELIECE_L_BYTES];
    if (mceliece_encap(pk, C, K1) != MCELIECE_SUCCESS) { printf("encap fail\n"); goto done; }
    // Flip 3 bits in C
    for (int i = 0; i < 3; i++) {
        int bit = (i * 17) % (MCELIECE_M * MCELIECE_T);
        C[bit / 8] ^= (1u << (bit % 8));
    }
    if (mceliece_decap(C, sk, K2) != MCELIECE_SUCCESS) { printf("decap err\n"); goto done; }
    int same = memcmp(K1, K2, MCELIECE_L_BYTES) == 0;
    printf("Keys match after tamper? %s (expected: no)\n", same ? "YES" : "NO");
done:
    public_key_free(pk); private_key_free(sk);
}

// Hex parser for KAT
static int hex2bin(const char *hex, uint8_t *out, size_t outlen) {
    size_t n = 0; int nybble = -1;
    for (const char *p = hex; *p && n < outlen; p++) {
        if (isspace((unsigned char)*p)) continue;
        int v;
        if ('0' <= *p && *p <= '9') v = *p - '0';
        else if ('a' <= *p && *p <= 'f') v = *p - 'a' + 10;
        else if ('A' <= *p && *p <= 'F') v = *p - 'A' + 10;
        else break;
        if (nybble < 0) { nybble = v; }
        else { out[n++] = (uint8_t)((nybble << 4) | v); nybble = -1; }
    }
    return (int)n;
}

void run_kat_file(const char *req_path, const char *rsp_path) {
    FILE *fin = fopen(req_path, "r");
    if (!fin) { printf("KAT: cannot open req %s\n", req_path); return; }
    FILE *fout = fopen(rsp_path, "w");
    if (!fout) { printf("KAT: cannot open rsp %s\n", rsp_path); fclose(fin); return; }

    // Match reference header exactly
    fprintf(fout, "# kem/%s\n\n", "mceliece6688128");

    char line[8192];
    uint8_t seed48[48];
    int count = -1;
    while (fgets(line, sizeof(line), fin)) {
        if (strncmp(line, "count =", 7) == 0) {
            count = atoi(line + 7);
            fprintf(fout, "count = %d\n", count);
        } else if (strncmp(line, "seed =", 6) == 0) {
            const char *hex = strchr(line, '=');
            if (!hex) continue; hex++;
            while (*hex && isspace((unsigned char)*hex)) hex++;
            int got = hex2bin(hex, seed48, sizeof seed48);
            if (got != 48) { printf("KAT: bad seed at count %d\n", count); continue; }

            // Initialize RNGs: reference RNG for ref crypto, our DRBG for fallback
            kat_drbg_init(seed48);

            // Emit exactly as NIST KAT using reference crypto API to match bytes/format
            fprintf(fout, "seed = ");
            for (int i = 0; i < 48; i++) fprintf(fout, "%02X", seed48[i]);
            fprintf(fout, "\n");

            // Fallback to our serialization (won't match reference bytes exactly)
            public_key_t *pk = public_key_create();
            private_key_t *sk = private_key_create();
            if (!pk || !sk) { 
                printf("KAT: alloc fail\n"); 
                break; 
            }
            int use_semi = 0; 
            const char *semi_env = getenv("MCELIECE_SEMI");
            if (semi_env && semi_env[0] == '1') use_semi = 1;
            printf("KAT: count=%d MCELIECE_SEMI=%s use_semi=%d\n", count, semi_env ? semi_env : "(null)", use_semi);
            mceliece_error_t kgret;
            if (use_semi) {
                uint8_t dummy_delta[MCELIECE_L_BYTES]; 
                memset(dummy_delta, 0, sizeof dummy_delta);
                printf("KAT: invoking seeded_key_gen_semi()\n");
                kgret = seeded_key_gen_semi(dummy_delta, pk, sk);
            } else {
                printf("KAT: invoking mceliece_keygen()\n");
                kgret = mceliece_keygen(pk, sk);
            }
            printf("KAT: keygen returned %d\n", (int)kgret);
            if (kgret != MCELIECE_SUCCESS) { 
                printf("KAT: keygen fail\n"); 
                public_key_free(pk); 
                private_key_free(sk); 
                continue; 
            }
            uint8_t ct[MCELIECE_MT_BYTES]; 
            uint8_t ss[MCELIECE_L_BYTES];
            if (mceliece_encap(pk, ct, ss) != MCELIECE_SUCCESS) { 
                printf("KAT: encap fail\n"); 
                public_key_free(pk); 
                private_key_free(sk); 
                continue; 
            }
            fprintf(fout, "pk = ");
            int out_row_bytes = pk->T.cols / 8;
            unsigned char *Tser = (unsigned char*)malloc((size_t)pk->T.rows * (size_t)out_row_bytes);
            if (Tser && public_key_serialize_refpacking(pk, Tser) == 0) {
                for (int r = 0; r < pk->T.rows; r++) {
                    const unsigned char *row = Tser + (size_t)r * out_row_bytes;
                    for (int b = 0; b < out_row_bytes; b++) fprintf(fout, "%02X", row[b]);
                }
            }
            if (Tser) free(Tser);
            fprintf(fout, "\n");
            // Serialize secret key (reference packing for systematic; semi uses semi serializer)
            size_t sk_cap = (size_t)32 + 8 + (size_t)(2 * MCELIECE_T) + sk->controlbits_len + (size_t)MCELIECE_N_BYTES;
            unsigned char *sk_bytes = (unsigned char*)malloc(sk_cap);
            size_t sk_len = 0;
            int sk_ok = 0;
            if (use_semi) {
                if (sk_bytes && private_key_serialize_semi(sk, sk_bytes, sk_cap, &sk_len) == 0) sk_ok = 1;
            } else {
                if (sk_bytes && private_key_serialize_refpacking(sk, sk_bytes, sk_cap, &sk_len) == 0) sk_ok = 1;
            }
            if (sk_ok) {
                fprintf(fout, "sk = ");
                for (size_t i = 0; i < sk_len; i++) fprintf(fout, "%02X", sk_bytes[i]);
                fprintf(fout, "\n");
            } else {
                fprintf(fout, "sk = ");
                for (int i = 0; i < MCELIECE_N_BYTES; i++) fprintf(fout, "%02X", sk->s[i]);
                fprintf(fout, "\n");
            }
            if (sk_bytes) free(sk_bytes);
            fprintf(fout, "ct = "); for (int i = 0; i < MCELIECE_MT_BYTES; i++) fprintf(fout, "%02X", ct[i]); fprintf(fout, "\n");
            fprintf(fout, "ss = "); for (int i = 0; i < MCELIECE_L_BYTES; i++) fprintf(fout, "%02X", ss[i]); fprintf(fout, "\n\n");
            public_key_free(pk); private_key_free(sk);
        }
    }
    fclose(fin); fclose(fout);
    printf("KAT: wrote %s\n", rsp_path);
}

// Helper: dump set bit positions of a bit-vector of length n
static void dump_positions(FILE *f, const char *label, const uint8_t *vec, int n_bits) {
    fprintf(f, "%s e: positions ", label);
    int first = 1;
    for (int i = 0; i < n_bits; i++) {
        if (vector_get_bit(vec, i)) {
            if (!first) fprintf(f, " ");
            fprintf(f, "%d", i);
            first = 0;
        }
    }
    fprintf(f, "\n");
}

void run_kat_int(const char *req_path, const char *int_path) {
    FILE *fin = fopen(req_path, "r");
    if (!fin) { printf("KAT-INT: cannot open req %s\n", req_path); return; }
    FILE *fout = fopen(int_path, "w");
    if (!fout) { printf("KAT-INT: cannot open out %s\n", int_path); fclose(fin); return; }

    char line[8192];
    uint8_t seed48[48];
    int count = -1;
    while (fgets(line, sizeof(line), fin)) {
        if (strncmp(line, "count =", 7) == 0) {
            count = atoi(line + 7);
        } else if (strncmp(line, "seed =", 6) == 0) {
            const char *hex = strchr(line, '=');
            if (!hex) continue; hex++;
            while (*hex && isspace((unsigned char)*hex)) hex++;
            // reuse hex2bin from this file
            int got = hex2bin(hex, seed48, sizeof seed48);
            if (got != 48) { printf("KAT-INT: bad seed at count %d\n", count); continue; }

            // Re-init DRBG and run full keygen + generate e using the same sampler as encap, then decode
            kat_drbg_init(seed48);

            public_key_t *pk = public_key_create();
            private_key_t *sk = private_key_create();
            if (!pk || !sk) { printf("KAT-INT: alloc fail\n"); break; }
            if (mceliece_keygen(pk, sk) != MCELIECE_SUCCESS) { 
                printf("KAT-INT: keygen fail\n"); 
                public_key_free(pk); 
                private_key_free(sk); 
                continue; 
            }

            // encrypt e using PQClean-style sampler
            uint8_t e_enc[MCELIECE_N_BYTES]; 
            memset(e_enc, 0, sizeof e_enc);
            gen_e_pqclean(e_enc);
            dump_positions(fout, "encrypt", e_enc, MCELIECE_N);

            // ciphertext from e
            uint8_t C[MCELIECE_MT_BYTES]; 
            encode_vector(e_enc, &pk->T, C);

            // decap to get e_dec
            uint8_t e_dec[MCELIECE_N_BYTES]; int succ = 0;
            if (decode_ciphertext(C, sk, e_dec, &succ) != MCELIECE_SUCCESS) { 
                printf("KAT-INT: decode err\n"); 
                public_key_free(pk); 
                private_key_free(sk); 
                continue; 
            }
            if (!succ) memcpy(e_dec, sk->s, MCELIECE_N_BYTES);
            dump_positions(fout, "decrypt", e_dec, MCELIECE_N);

            public_key_free(pk); private_key_free(sk);
        }
    }
    fclose(fin); fclose(fout);
    printf("KAT-INT: wrote %s\n", int_path);
}

// Deterministic test using fixed seed
void test_seeded(void) {
    printf("\n=== Seeded Deterministic Test ===\n");
    public_key_t *pk = public_key_create();
    private_key_t *sk = private_key_create();
    if (!pk || !sk) { printf("alloc fail\n"); return; }
    uint8_t seed[MCELIECE_L_BYTES];
    memset(seed, 0xA5, sizeof(seed));
    if (seeded_key_gen(seed, pk, sk) != MCELIECE_SUCCESS) { printf("seeded keygen fail\n"); goto done; }
    uint8_t C[MCELIECE_MT_BYTES];
    uint8_t K1[MCELIECE_L_BYTES], K2[MCELIECE_L_BYTES];
    if (mceliece_encap(pk, C, K1) != MCELIECE_SUCCESS) { printf("encap fail\n"); goto done; }
    if (mceliece_decap(C, sk, K2) != MCELIECE_SUCCESS) { printf("decap fail\n"); goto done; }
    printf("Keys match: %s\n", memcmp(K1, K2, MCELIECE_L_BYTES) == 0 ? "YES" : "NO");
done:
    public_key_free(pk); private_key_free(sk);
}

// Roundtrip: generate e, compute C=H e, decode e back
void test_roundtrip(void) {
    printf("\n=== Roundtrip Encode/Decode Test ===\n");
    public_key_t *pk = public_key_create();
    private_key_t *sk = private_key_create();
    if (!pk || !sk) { printf("alloc fail\n"); return; }
    if (mceliece_keygen(pk, sk) != MCELIECE_SUCCESS) { printf("keygen fail\n"); goto done; }
    uint8_t e[MCELIECE_N_BYTES];
    memset(e, 0, sizeof(e));
    if (fixed_weight_vector(e, MCELIECE_N, MCELIECE_T) != MCELIECE_SUCCESS) { printf("fw fail\n"); goto done; }
    uint8_t C[MCELIECE_MT_BYTES];
    encode_vector(e, &pk->T, C);
    int succ = 0;
    uint8_t e_rec[MCELIECE_N_BYTES];
    memset(e_rec, 0, sizeof(e_rec));
    if (decode_ciphertext(C, sk, e_rec, &succ) != MCELIECE_SUCCESS) { printf("decode err\n"); goto done; }
    int ok = succ && (memcmp(e, e_rec, MCELIECE_N_BYTES) == 0);
    printf("Recovered e exactly: %s\n", ok ? "YES" : "NO");
done:
    public_key_free(pk); private_key_free(sk);
}

// Tamper sweep: flip k bits and observe decap fallback
void test_tamper_sweep(void) {
    printf("\n=== Tamper Sweep (k=1..16) ===\n");
    public_key_t *pk = public_key_create();
    private_key_t *sk = private_key_create();
    if (!pk || !sk) { printf("alloc fail\n"); return; }
    if (mceliece_keygen(pk, sk) != MCELIECE_SUCCESS) { printf("keygen fail\n"); goto done; }
    uint8_t C0[MCELIECE_MT_BYTES];
    uint8_t K1[MCELIECE_L_BYTES], K2[MCELIECE_L_BYTES];
    if (mceliece_encap(pk, C0, K1) != MCELIECE_SUCCESS) { printf("encap fail\n"); goto done; }
    for (int k = 1; k <= 16; k++) {
        uint8_t C[MCELIECE_MT_BYTES]; memcpy(C, C0, sizeof(C));
        for (int i = 0; i < k; i++) {
            int bit = (i * 37) % (MCELIECE_M * MCELIECE_T);
            C[bit / 8] ^= (1u << (bit % 8));
        }
        if (mceliece_decap(C, sk, K2) != MCELIECE_SUCCESS) { printf("k=%d decap err\n", k); continue; }
        int same = memcmp(K1, K2, MCELIECE_L_BYTES) == 0;
        printf("k=%d: keys match? %s\n", k, same ? "YES" : "NO");
    }
done:
    public_key_free(pk); private_key_free(sk);
}

// Full decap verification: compare decoded e with original e, and C == H*e
void test_decap_full(void) {
    printf("\n=== Full Decapsulation Verification ===\n");
    public_key_t *pk = public_key_create();
    private_key_t *sk = private_key_create();
    if (!pk || !sk) { printf("alloc fail\n"); return; }
    if (mceliece_keygen(pk, sk) != MCELIECE_SUCCESS) { printf("keygen fail\n"); goto done; }

    // 1) Generate e and C = H e
    uint8_t e[MCELIECE_N_BYTES];
    memset(e, 0, sizeof(e));
    if (fixed_weight_vector(e, MCELIECE_N, MCELIECE_T) != MCELIECE_SUCCESS) { printf("fw fail\n"); goto done; }
    uint8_t C[MCELIECE_MT_BYTES];
    encode_vector(e, &pk->T, C);

    // 2) Decap to get e_rec
    uint8_t e_rec[MCELIECE_N_BYTES];
    int succ = 0;
    if (decode_ciphertext(C, sk, e_rec, &succ) != MCELIECE_SUCCESS) { printf("decode err\n"); goto done; }
    printf("Decoding success flag: %d\n", succ);

    // 3) Verify e_rec has weight t and equals e
    int wt = vector_weight(e_rec, MCELIECE_N_BYTES);
    printf("Recovered weight: %d (expected %d)\n", wt, MCELIECE_T);
    printf("Recovered equals original e: %s\n", memcmp(e, e_rec, MCELIECE_N_BYTES) == 0 ? "YES" : "NO");

    // 4) Verify C == H*e_rec
    uint8_t C_chk[MCELIECE_MT_BYTES];
    encode_vector(e_rec, &pk->T, C_chk);
    printf("C == H*e_rec: %s\n", memcmp(C, C_chk, MCELIECE_MT_BYTES) == 0 ? "YES" : "NO");

done:
    public_key_free(pk); private_key_free(sk);
}

// Audit decap across multiple randomly generated e; ensure e_rec has weight t and C==H*e_rec
void test_decap_audit(void) {
    printf("\n=== Decapsulation Audit (20 rounds) ===\n");
    public_key_t *pk = public_key_create();
    private_key_t *sk = private_key_create();
    if (!pk || !sk) { printf("alloc fail\n"); return; }
    if (mceliece_keygen(pk, sk) != MCELIECE_SUCCESS) { printf("keygen fail\n"); goto done; }
    int pass = 0;
    for (int r = 0; r < 20; r++) {
        uint8_t e[MCELIECE_N_BYTES]; memset(e, 0, sizeof(e));
        if (fixed_weight_vector(e, MCELIECE_N, MCELIECE_T) != MCELIECE_SUCCESS) { printf("fw fail\n"); break; }
        uint8_t C[MCELIECE_MT_BYTES]; encode_vector(e, &pk->T, C);
        uint8_t e_rec[MCELIECE_N_BYTES]; int succ = 0;
        if (decode_ciphertext(C, sk, e_rec, &succ) != MCELIECE_SUCCESS) { printf("decode err\n"); break; }
        int wt = vector_weight(e_rec, MCELIECE_N_BYTES);
        uint8_t C_chk[MCELIECE_MT_BYTES]; encode_vector(e_rec, &pk->T, C_chk);
        int ok = succ && wt == MCELIECE_T && memcmp(C, C_chk, MCELIECE_MT_BYTES) == 0;
        pass += ok;
        if (!ok) printf("Round %d FAILED (succ=%d wt=%d)\n", r+1, succ, wt);
    }
    printf("Audit pass: %d/20\n", pass);
done:
    public_key_free(pk); private_key_free(sk);
}

// Debug decapsulation pipeline: compare syndrome from true e vs from v=(C,0,...)
void test_decap_pipeline(void) {
    printf("\n=== Decapsulation Pipeline Debug ===\n");

    public_key_t *pk = public_key_create();
    private_key_t *sk = private_key_create();
    if (!pk || !sk) {
        printf("Setup failed (alloc)\n");
        return;
    }
    if (mceliece_keygen(pk, sk) != MCELIECE_SUCCESS) {
        printf("Setup failed (keygen)\n");
        public_key_free(pk); private_key_free(sk); return;
    }

    // Generate ground-truth error and ciphertext
    uint8_t *e = malloc(MCELIECE_N_BYTES);
    uint8_t *C = malloc(MCELIECE_MT_BYTES);
    uint8_t *v = malloc(MCELIECE_N_BYTES);
    if (!e || !C || !v) {
        printf("Alloc failed\n");
        free(e); free(C); free(v); public_key_free(pk); private_key_free(sk); return;
    }
    if (fixed_weight_vector(e, MCELIECE_N, MCELIECE_T) != MCELIECE_SUCCESS) {
        printf("Error vector generation failed\n");
        free(e); free(C); free(v); public_key_free(pk); private_key_free(sk); return;
    }
    encode_vector(e, &pk->T, C);

    // Build v=(C,0,...)
    memset(v, 0, MCELIECE_N_BYTES);
    int mt = MCELIECE_M * MCELIECE_T;
    for (int i = 0; i < mt; i++) {
        int bit = vector_get_bit(C, i);
        vector_set_bit(v, i, bit);
    }

    // Compute syndrome from true e
    gf_elem_t *s_true = malloc(sizeof(gf_elem_t) * 2 * MCELIECE_T);
    gf_elem_t *s_v = malloc(sizeof(gf_elem_t) * 2 * MCELIECE_T);
    if (!s_true || !s_v) {
        printf("Alloc failed (syndromes)\n");
        free(e); free(C); free(v); free(s_true); free(s_v);
        public_key_free(pk); private_key_free(sk); return;
    }
    compute_syndrome(e, &sk->g, sk->alpha, s_true);
    compute_syndrome(v, &sk->g, sk->alpha, s_v);

    // BM+Chien on s_true
    polynomial_t *sigma_true = polynomial_create(MCELIECE_T);
    polynomial_t *sigma_v = polynomial_create(MCELIECE_T);
    int *pos_true = NULL;
    int *pos_v = NULL;
    if (!sigma_true || !sigma_v) {
        printf("Alloc failed (polys)\n");
        goto cleanup;
    }
    berlekamp_massey(s_true, sigma_true);
    berlekamp_massey(s_v, sigma_v);
    pos_true = malloc(sizeof(int) * MCELIECE_T);
    pos_v = malloc(sizeof(int) * MCELIECE_T);
    int cnt_true = 0, cnt_v = 0;
    if (!pos_true || !pos_v) { printf("Alloc failed (pos)\n"); goto cleanup; }

    chien_search(sigma_true, sk->alpha, pos_true, &cnt_true);
    chien_search(sigma_v, sk->alpha, pos_v, &cnt_v);

    int wt_e = vector_weight(e, MCELIECE_N_BYTES);
    printf("Sigma_true deg=%d, Chien_true=%d, wt(e)=%d\n", sigma_true->degree, cnt_true, wt_e);
    printf("Sigma_v    deg=%d, Chien_v    =%d, wt(v)=%d\n", sigma_v->degree, cnt_v, vector_weight(v, MCELIECE_N_BYTES));

cleanup:
    free(pos_true); free(pos_v);
    polynomial_free(sigma_true);
    polynomial_free(sigma_v);
    free(s_true); free(s_v);
    free(e); free(C); free(v);
    public_key_free(pk); private_key_free(sk);
}

// Test fundamental GF, matrix, and vector operations
void test_basic_functions(void) {
    printf("\n=== Testing Basic Functions ===\n");
    
    // Test 1: GF arithmetic
    printf("1. Testing GF arithmetic...\n");
    gf_elem_t a = 123, b = 456;
    gf_elem_t sum = gf_add(a, b);
    gf_elem_t product = gf_mul(a, b);
    printf("   GF(%u) + GF(%u) = %u\n", a, b, sum);
    printf("   GF(%u) * GF(%u) = %u\n", a, b, product);
    
    // Test GF inverse
    if (a != 0) {
        gf_elem_t inv_a = gf_inv(a);
        gf_elem_t should_be_one = gf_mul(a, inv_a);
        printf("   GF(%u)^-1 = %u, verification: %u * %u = %u (should be 1)\n", 
               a, inv_a, a, inv_a, should_be_one);
    }
    
    // Test GF power
    gf_elem_t a_squared = gf_pow(a, 2);
    gf_elem_t a_squared_check = gf_mul(a, a);
    printf("   GF(%u)^2 = %u, verification: %u * %u = %u (should match)\n", 
           a, a_squared, a, a, a_squared_check);
    
    // Test 2: Vector operations
    printf("2. Testing vector operations...\n");
    uint8_t test_vector[16];
    memset(test_vector, 0, 16);
    
    // Set some bits
    vector_set_bit(test_vector, 5, 1);
    vector_set_bit(test_vector, 17, 1);
    vector_set_bit(test_vector, 33, 1);
    
    // Check bits
    printf("   Set bits at positions 5, 17, 33\n");
    printf("   Bit 5: %d, Bit 17: %d, Bit 33: %d\n", 
           vector_get_bit(test_vector, 5),
           vector_get_bit(test_vector, 17),
           vector_get_bit(test_vector, 33));
    printf("   Bit 6: %d, Bit 18: %d (should be 0)\n",
           vector_get_bit(test_vector, 6),
           vector_get_bit(test_vector, 18));
    
    // Test weight
    int weight = vector_weight(test_vector, 16);
    printf("   Vector weight: %d (should be 3)\n", weight);
    
    // Test 3: Matrix operations
    printf("3. Testing matrix operations...\n");
    matrix_t *test_matrix = matrix_create(4, 8);
    if (test_matrix) {
        // Set some bits
        matrix_set_bit(test_matrix, 0, 1, 1);
        matrix_set_bit(test_matrix, 1, 3, 1);
        matrix_set_bit(test_matrix, 2, 5, 1);
        
        // Check bits
        printf("   Set bits at (0,1), (1,3), (2,5)\n");
        printf("   Matrix[0,1]: %d, Matrix[1,3]: %d, Matrix[2,5]: %d\n",
               matrix_get_bit(test_matrix, 0, 1),
               matrix_get_bit(test_matrix, 1, 3),
               matrix_get_bit(test_matrix, 2, 5));
        printf("   Matrix[0,0]: %d, Matrix[1,2]: %d (should be 0)\n",
               matrix_get_bit(test_matrix, 0, 0),
               matrix_get_bit(test_matrix, 1, 2));
        
        // Test matrix-vector multiplication
        uint8_t test_vec[1];  // 8 bits
        memset(test_vec, 0, 1);
        vector_set_bit(test_vec, 1, 1);  // Set bit 1
        vector_set_bit(test_vec, 3, 1);  // Set bit 3
        vector_set_bit(test_vec, 5, 1);  // Set bit 5
        
        uint8_t result_vec[1]; // 4 bits
        matrix_vector_multiply(test_matrix, test_vec, result_vec);
        
        printf("   Matrix * vector test:\n");
        printf("   Input vector bits: 1,3,5 are set\n");
        printf("   Result bits: ");
        for (int i = 0; i < 4; i++) {
            if (vector_get_bit(result_vec, i)) {
                printf("%d ", i);
            }
        }
        printf("(should be 0,1,2 based on matrix setup)\n");
        
        matrix_free(test_matrix);
    }
    
    // Test 4: Polynomial operations
    printf("4. Testing polynomial operations...\n");
    polynomial_t *test_poly = polynomial_create(3);
    if (test_poly) {
        // Create polynomial: 1 + 2x + 3x^2
        polynomial_set_coeff(test_poly, 0, 1);
        polynomial_set_coeff(test_poly, 1, 2);
        polynomial_set_coeff(test_poly, 2, 3);
        
        printf("   Created polynomial: 1 + 2x + 3x^2\n");
        printf("   Degree: %d (should be 2)\n", test_poly->degree);
        
        // Evaluate at x = 1: should be 1 + 2 + 3 = 6 (in GF)
        gf_elem_t result = polynomial_eval(test_poly, 1);
        gf_elem_t expected = gf_add(gf_add(1, 2), 3);
        printf("   poly(1) = %u, expected = %u\n", result, expected);
        
        // Evaluate at x = 0: should be 1
        result = polynomial_eval(test_poly, 0);
        printf("   poly(0) = %u (should be 1)\n", result);
        
        polynomial_free(test_poly);
    }
    
    printf("=== Basic Function Tests Complete ===\n\n");
}