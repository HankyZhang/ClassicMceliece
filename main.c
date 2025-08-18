// main.c
#include "mceliece_types.h"
#include <stdio.h>
#include <time.h>
#include "mceliece_kem.h"
#include "kat_drbg.h"
#include "mceliece_gf.h"
#include "controlbits.h"
// 外部函数声明
extern void test_mceliece(void);
extern void run_all_tests(void);
extern mceliece_error_t mceliece_keygen(public_key_t *pk, private_key_t *sk);
extern mceliece_error_t mceliece_encap(const public_key_t *pk, uint8_t *ciphertext, uint8_t *session_key);
extern mceliece_error_t mceliece_decap(const uint8_t *ciphertext, const private_key_t *sk, uint8_t *session_key);


void print_usage(const char *prog_name) {
    printf("Usage: %s [command]\n", prog_name);
    printf("Commands:\n");
    printf("  test      - Run basic functionality tests\n");
    printf("  fulltest  - Run comprehensive test suite\n");
    printf("  basic     - Test fundamental GF/matrix/vector operations\n");
    printf("  bmchien   - Run BM+Chien targeted test\n");
    printf("  decapdbg  - Debug decapsulation pipeline (syndrome vs v)\n");
    printf("  stress    - Run 50-round stress test\n");
    printf("  tamper    - Tamper ciphertext test\n");
    printf("  seeded    - Deterministic seeded keygen test\n");
    printf("  roundtrip - Encode/Decode roundtrip test\n");
    printf("  tampswp   - Tamper sweep test\n");
    printf("  decapfull - Full decapsulation verification\n");
    printf("  kat <req> <rsp> - Run NIST KAT using req to produce rsp (DRBG mode)\n");
    printf("  katint <req> <int> - Produce .int file (encrypt/decrypt error positions)\n");
    printf("  cbtest           - Verify controlbits Benes routing on a random pi (sanity)\n");
    printf("  keygen    - Generate and display key pair\n");
    printf("  demo      - Run complete encryption/decryption demo\n");
    printf("  bench     - Run performance benchmark\n");
}

void print_parameters(void) {
    printf("Classic McEliece Parameters (mceliece%d%d%d):\n", MCELIECE_N, MCELIECE_N, MCELIECE_T);
    printf("  m = %d (log2 of field size)\n", MCELIECE_M);
    printf("  n = %d (code length)\n", MCELIECE_N);
    printf("  t = %d (error correction capability)\n", MCELIECE_T);
    printf("  k = %d (code dimension)\n", MCELIECE_K);
    printf("  q = %d (field size)\n", MCELIECE_Q);
    printf("\nKey sizes:\n");
    printf("  Public key: %zu bytes\n", (size_t)(MCELIECE_M * MCELIECE_T * MCELIECE_K_BYTES));
    printf("  Private key: ~%d bytes\n", MCELIECE_PRIVATEKEY_BYTES);
    printf("  Ciphertext: %d bytes\n", MCELIECE_MT_BYTES);
    printf("  Session key: %d bytes\n", MCELIECE_L_BYTES);
    printf("\n");
}

void demo_keygen(void) {
    printf("=== Key Generation Demo ===\n");
    print_parameters();

    printf("Generating key pair...\n");
    clock_t start = clock();

    public_key_t *pk = public_key_create();
    private_key_t *sk = private_key_create();

    if (!pk || !sk) {
        printf("Failed to allocate key structures\n");
        return;
    }

    mceliece_error_t ret = mceliece_keygen(pk, sk);

    clock_t end = clock();
    double time_spent = ((double)(end - start)) / CLOCKS_PER_SEC;

    if (ret == MCELIECE_SUCCESS) {
        printf("Key generation successful!\n");
        printf("Time taken: %.2f seconds\n", time_spent);

        // 显示部分私钥信息（用于验证）
        printf("\nPrivate key info:\n");
        printf("  Seed (delta): ");
        for (int i = 0; i < 8; i++) {  // 只显示前8字节
            printf("%02x", sk->delta[i]);
        }
        printf("...\n");

        printf("  Goppa polynomial degree: %d\n", sk->g.degree);
        printf("  First few coefficients: ");
        for (int i = 0; i <= 3 && i <= sk->g.degree; i++) {
            printf("g[%d]=%04x ", i, sk->g.coeffs[i]);
        }
        printf("\n");

        printf("\nPublic key matrix T dimensions: %dx%d\n", pk->T.rows, pk->T.cols);
    } else {
        printf("Key generation failed with error: %d\n", ret);
    }

    public_key_free(pk);
    private_key_free(sk);
}

void demo_complete(void) {
    printf("=== Complete Encryption/Decryption Demo ===\n");
    print_parameters();

    // 生成密钥
    printf("Step 1: Generating key pair...\n");
    public_key_t *pk = public_key_create();
    private_key_t *sk = private_key_create();

    if (!pk || !sk) {
        printf("Failed to allocate key structures\n");
        return;
    }

    clock_t start = clock();
    mceliece_error_t ret = mceliece_keygen(pk, sk);
    clock_t keygen_time = clock();

    if (ret != MCELIECE_SUCCESS) {
        printf("Key generation failed: %d\n", ret);
        public_key_free(pk);
        private_key_free(sk);
        return;
    }

    printf("Key generation successful! Time: %.3f ms\n",
           ((double)(keygen_time - start)) / CLOCKS_PER_SEC * 1000);

    // 封装
    printf("\nStep 2: Encapsulating session key...\n");
    uint8_t ciphertext[MCELIECE_MT_BYTES];
    uint8_t session_key1[MCELIECE_L_BYTES];

    start = clock();
    ret = mceliece_encap(pk, ciphertext, session_key1);
    clock_t encap_time = clock();

    if (ret != MCELIECE_SUCCESS) {
        printf("Encapsulation failed: %d\n", ret);
        public_key_free(pk);
        private_key_free(sk);
        return;
    }

    printf("Encapsulation successful! Time: %.3f ms\n",
           ((double)(encap_time - start)) / CLOCKS_PER_SEC * 1000);

    // 显示会话密钥
    printf("Session key: ");
    for (int i = 0; i < 16; i++) {  // 只显示前16字节
        printf("%02x", session_key1[i]);
    }
    printf("...\n");

    // 解封装
    printf("\nStep 3: Decapsulating session key...\n");
    uint8_t session_key2[MCELIECE_L_BYTES];

    start = clock();
    ret = mceliece_decap(ciphertext, sk, session_key2);
    clock_t decap_time = clock();

    if (ret != MCELIECE_SUCCESS) {
        printf("Decapsulation failed: %d\n", ret);
        public_key_free(pk);
        private_key_free(sk);
        return;
    }

    printf("Decapsulation successful! Time: %.3f ms\n",
           ((double)(decap_time - start)) / CLOCKS_PER_SEC * 1000);

    // 验证
    printf("\nStep 4: Verifying session keys...\n");
    int keys_match = 1;
    for (int i = 0; i < MCELIECE_L_BYTES; i++) {
        if (session_key1[i] != session_key2[i]) {
            keys_match = 0;
            break;
        }
    }

    if (keys_match) {
        printf("✓ Session keys match! Encryption/decryption successful.\n");
    } else {
        printf("✗ Session keys don't match! Something went wrong.\n");

        printf("Original:  ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", session_key1[i]);
        }
        printf("...\n");

        printf("Recovered: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", session_key2[i]);
        }
        printf("...\n");
    }

    public_key_free(pk);
    private_key_free(sk);
}

void benchmark(void) {
    printf("=== Performance Benchmark ===\n");
    print_parameters();

    const int num_trials = 5;
    double keygen_times[num_trials];
    double encap_times[num_trials];
    double decap_times[num_trials];

    printf("Running %d trials...\n\n", num_trials);

    for (int trial = 0; trial < num_trials; trial++) {
        printf("Trial %d/%d:\n", trial + 1, num_trials);

        public_key_t *pk = public_key_create();
        private_key_t *sk = private_key_create();

        if (!pk || !sk) {
            printf("Memory allocation failed\n");
            return;
        }

        // 密钥生成
        clock_t start = clock();
        mceliece_error_t ret = mceliece_keygen(pk, sk);
        clock_t end = clock();

        if (ret != MCELIECE_SUCCESS) {
            printf("  Key generation failed\n");
            public_key_free(pk);
            private_key_free(sk);
            continue;
        }

        keygen_times[trial] = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
        printf("  Keygen: %.2f ms\n", keygen_times[trial]);

        // 封装
        uint8_t ciphertext[MCELIECE_MT_BYTES];
        uint8_t session_key1[MCELIECE_L_BYTES];

        start = clock();
        ret = mceliece_encap(pk, ciphertext, session_key1);
        end = clock();

        if (ret != MCELIECE_SUCCESS) {
            printf("  Encapsulation failed\n");
            public_key_free(pk);
            private_key_free(sk);
            continue;
        }

        encap_times[trial] = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
        printf("  Encap:  %.2f ms\n", encap_times[trial]);

        // 解封装
        uint8_t session_key2[MCELIECE_L_BYTES];

        start = clock();
        ret = mceliece_decap(ciphertext, sk, session_key2);
        end = clock();

        if (ret != MCELIECE_SUCCESS) {
            printf("  Decapsulation failed\n");
            public_key_free(pk);
            private_key_free(sk);
            continue;
        }

        decap_times[trial] = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
        printf("  Decap:  %.2f ms\n", decap_times[trial]);

        public_key_free(pk);
        private_key_free(sk);
    }

    // 计算平均值
    double avg_keygen = 0, avg_encap = 0, avg_decap = 0;
    for (int i = 0; i < num_trials; i++) {
        avg_keygen += keygen_times[i];
        avg_encap += encap_times[i];
        avg_decap += decap_times[i];
    }
    avg_keygen /= num_trials;
    avg_encap /= num_trials;
    avg_decap /= num_trials;

    printf("\n=== Average Performance ===\n");
    printf("Key Generation: %.2f ms\n", avg_keygen);
    printf("Encapsulation:  %.2f ms\n", avg_encap);
    printf("Decapsulation:  %.2f ms\n", avg_decap);
    printf("Total:          %.2f ms\n", avg_keygen + avg_encap + avg_decap);
}

int main(int argc, char *argv[]) {
    gf_init();
    printf("Classic McEliece Implementation\n");
    printf("================================\n\n");

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];

    if (strcmp(command, "test") == 0) {
        test_mceliece();
    }
    else if (strcmp(command, "fulltest") == 0) {
        run_all_tests();
    }
    else if (strcmp(command, "basic") == 0) {
        test_basic_functions();
    }
    else if (strcmp(command, "keygen") == 0) {
        demo_keygen();
    }
    else if (strcmp(command, "demo") == 0) {
        demo_complete();
    }
    else if (strcmp(command, "kat") == 0) {
        if (argc < 4) {
            printf("Usage: %s kat <req> <rsp>\n", argv[0]);
            return 1;
        }
        // In KAT mode, the caller should initialize DRBG with seed per req lines inside run_kat_file
        run_kat_file(argv[2], argv[3]);
    }
    else if (strcmp(command, "katint") == 0) {
        if (argc < 4) {
            printf("Usage: %s katint <req> <int>\n", argv[0]);
            return 1;
        }
        run_kat_int(argv[2], argv[3]);
    }
    else if (strcmp(command, "cbtest") == 0) {
        long long w = MCELIECE_M;
        long long n = 1LL << w;
        int16_t *pi = (int16_t*)malloc(sizeof(int16_t) * (size_t)n);
        if (!pi) { printf("alloc fail\n"); return 1; }
        // simple random permutation using DRBG if inited, else identity
        for (long long i = 0; i < n; i++) pi[i] = (int16_t)i;
        if (kat_drbg_is_inited()) {
            for (long long i = n - 1; i > 0; i--) {
                uint8_t rb[2]; kat_drbg_randombytes(rb, 2);
                uint16_t r = (uint16_t)rb[0] | ((uint16_t)rb[1] << 8);
                long long j = r % (i + 1);
                int16_t tmp = pi[i]; pi[i] = pi[j]; pi[j] = tmp;
            }
        }
        size_t cb_len = (size_t)((((2 * w - 1) * n / 2) + 7) / 8);
        uint8_t *cb = (uint8_t*)malloc(cb_len);
        if (!cb) { free(pi); printf("alloc fail\n"); return 1; }
        memset(cb, 0, cb_len);
        cbits_from_perm_ns(cb, pi, w, n);
        int ok = controlbits_verify(cb, w, n, pi);
        printf("controlbits verify: %s\n", ok == 0 ? "PASS" : "FAIL");
        free(cb); free(pi);
    }
    else if (strcmp(command, "bench") == 0) {
        benchmark();
    }
    else if (strcmp(command, "bmchien") == 0) {
        test_bm_chien();
    }
    else if (strcmp(command, "decapdbg") == 0) {
        test_decap_pipeline();
    }
    else if (strcmp(command, "stress") == 0) {
        test_stress();
    }
    else if (strcmp(command, "tamper") == 0) {
        test_tamper();
    }
    else if (strcmp(command, "seeded") == 0) {
        test_seeded();
    }
    else if (strcmp(command, "roundtrip") == 0) {
        test_roundtrip();
    }
    else if (strcmp(command, "tampswp") == 0) {
        test_tamper_sweep();
    }
    else if (strcmp(command, "decapfull") == 0) {
        test_decap_full();
    }
    else {
        printf("Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}