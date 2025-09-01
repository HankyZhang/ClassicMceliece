#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>

// Our implementation includes
#include "mceliece_kem.h"
#include "kat_drbg.h"
#include "benchmark_timing.h"

// Reference implementation includes  
#include "mceliece6688128/operations.h"
#include "mceliece6688128/crypto_kem.h"
#include "mceliece6688128/params.h"

// Define reference API constants
#define REF_CRYPTO_PUBLICKEYBYTES  ((SYS_N - SYS_K)/8*SYS_K)
#define REF_CRYPTO_SECRETKEYBYTES  (40 + IRR_BYTES + COND_BYTES + SYS_N/8)
#define REF_CRYPTO_CIPHERTEXTBYTES SYND_BYTES
#define REF_CRYPTO_BYTES           32

// KAT test vector structure
typedef struct {
    int count;
    uint8_t seed[48];
    int valid;
} kat_test_vector_t;

// Hex string to binary conversion
static int hex2bin(const char *hex, uint8_t *out, size_t outlen) {
    size_t n = 0; 
    int nybble = -1;
    for (const char *p = hex; *p && n < outlen; p++) {
        if (isspace((unsigned char)*p)) continue;
        int v;
        if ('0' <= *p && *p <= '9') v = *p - '0';
        else if ('a' <= *p && *p <= 'f') v = *p - 'a' + 10;
        else if ('A' <= *p && *p <= 'F') v = *p - 'A' + 10;
        else break;
        if (nybble < 0) { 
            nybble = v; 
        } else { 
            out[n++] = (uint8_t)((nybble << 4) | v); 
            nybble = -1; 
        }
    }
    return (int)n;
}

// Parse KAT request file and extract test vectors
static int parse_kat_file(const char *kat_file, kat_test_vector_t **vectors, int *num_vectors) {
    FILE *f = fopen(kat_file, "r");
    if (!f) {
        printf("Error: Cannot open KAT file %s\n", kat_file);
        return -1;
    }
    
    // Count test vectors first
    int count = 0;
    char line[8192];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "count =", 7) == 0) {
            count++;
        }
    }
    
    if (count == 0) {
        printf("Error: No test vectors found in %s\n", kat_file);
        fclose(f);
        return -1;
    }
    
    // Allocate memory for vectors
    *vectors = (kat_test_vector_t*)malloc(count * sizeof(kat_test_vector_t));
    if (!*vectors) {
        printf("Error: Memory allocation failed\n");
        fclose(f);
        return -1;
    }
    
    // Parse vectors
    rewind(f);
    int vector_idx = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "count =", 7) == 0) {
            vector_idx++;
            (*vectors)[vector_idx].count = atoi(line + 7);
            (*vectors)[vector_idx].valid = 0; // Mark as invalid until we get seed
        } else if (strncmp(line, "seed =", 6) == 0 && vector_idx >= 0) {
            const char *hex = strchr(line, '=');
            if (hex) {
                hex++;
                while (*hex && isspace((unsigned char)*hex)) hex++;
                int got = hex2bin(hex, (*vectors)[vector_idx].seed, 48);
                if (got == 48) {
                    (*vectors)[vector_idx].valid = 1;
                }
            }
        }
    }
    
    fclose(f);
    *num_vectors = count;
    return 0;
}

// Benchmark our implementation with specific seed
static int benchmark_our_with_seed(const uint8_t seed[48], 
                                 benchmark_timer_t *keygen_timer,
                                 benchmark_timer_t *encap_timer, 
                                 benchmark_timer_t *decap_timer) {
    kat_drbg_init(seed);
    
    public_key_t *pk = public_key_create();
    private_key_t *sk = private_key_create();
    if (!pk || !sk) {
        if (pk) public_key_free(pk);
        if (sk) private_key_free(sk);
        return -1;
    }
    
    // Key generation
    BENCHMARK_START(*keygen_timer);
    mceliece_error_t ret = mceliece_keygen(pk, sk);
    BENCHMARK_END(*keygen_timer);
    
    if (ret != MCELIECE_SUCCESS) {
        public_key_free(pk);
        private_key_free(sk);
        return -1;
    }
    
    // Encapsulation
    uint8_t ciphertext[MCELIECE_MT_BYTES];
    uint8_t session_key1[MCELIECE_L_BYTES];
    
    BENCHMARK_START(*encap_timer);
    ret = mceliece_encap(pk, ciphertext, session_key1);
    BENCHMARK_END(*encap_timer);
    
    if (ret != MCELIECE_SUCCESS) {
        public_key_free(pk);
        private_key_free(sk);
        return -1;
    }
    
    // Decapsulation
    uint8_t session_key2[MCELIECE_L_BYTES];
    
    BENCHMARK_START(*decap_timer);
    ret = mceliece_decap(ciphertext, sk, session_key2);
    BENCHMARK_END(*decap_timer);
    
    public_key_free(pk);
    private_key_free(sk);
    
    if (ret != MCELIECE_SUCCESS) {
        return -1;
    }
    
    // Verify keys match
    return memcmp(session_key1, session_key2, MCELIECE_L_BYTES) == 0 ? 0 : -1;
}

// Benchmark reference implementation with specific seed
static int benchmark_ref_with_seed(const uint8_t seed[48],
                                 benchmark_timer_t *keygen_timer,
                                 benchmark_timer_t *encap_timer,
                                 benchmark_timer_t *decap_timer) {
    kat_drbg_init(seed);
    
    unsigned char pk[REF_CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[REF_CRYPTO_SECRETKEYBYTES];
    unsigned char ct[REF_CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss1[REF_CRYPTO_BYTES];
    unsigned char ss2[REF_CRYPTO_BYTES];
    
    // Key generation
    BENCHMARK_START(*keygen_timer);
    int ret = crypto_kem_keypair(pk, sk);
    BENCHMARK_END(*keygen_timer);
    
    if (ret != 0) return -1;
    
    // Encapsulation
    BENCHMARK_START(*encap_timer);
    ret = crypto_kem_enc(ct, ss1, pk);
    BENCHMARK_END(*encap_timer);
    
    if (ret != 0) return -1;
    
    // Decapsulation
    BENCHMARK_START(*decap_timer);
    ret = crypto_kem_dec(ss2, ct, sk);
    BENCHMARK_END(*decap_timer);
    
    if (ret != 0) return -1;
    
    // Verify keys match
    return memcmp(ss1, ss2, REF_CRYPTO_BYTES) == 0 ? 0 : -1;
}

// Run KAT-based benchmark comparison
int run_kat_benchmark(const char *kat_file, int max_vectors, const char *output_file) {
    printf("=== KAT-Based Benchmark Comparison ===\n");
    printf("KAT file: %s\n", kat_file);
    
    // Parse KAT file
    kat_test_vector_t *vectors = NULL;
    int num_vectors = 0;
    
    if (parse_kat_file(kat_file, &vectors, &num_vectors) != 0) {
        return -1;
    }
    
    // Limit number of vectors if requested
    if (max_vectors > 0 && max_vectors < num_vectors) {
        num_vectors = max_vectors;
    }
    
    printf("Total test vectors: %d\n\n", num_vectors);
    
    // Initialize benchmark results
    benchmark_results_t results;
    memset(&results, 0, sizeof(results));
    results.total_iterations = num_vectors;
    
    benchmark_init_stats(&results.keygen_our, "keygen_our");
    benchmark_init_stats(&results.encap_our, "encap_our");
    benchmark_init_stats(&results.decap_our, "decap_our");
    benchmark_init_stats(&results.keygen_ref, "keygen_ref");
    benchmark_init_stats(&results.encap_ref, "encap_ref");
    benchmark_init_stats(&results.decap_ref, "decap_ref");
    
    int our_successes = 0;
    int ref_successes = 0;
    
    // Run benchmarks on each test vector
    for (int i = 0; i < num_vectors; i++) {
        if (!vectors[i].valid) {
            printf("Vector %d (count=%d): INVALID SEED\n", i, vectors[i].count);
            continue;
        }
        
        printf("Vector %d (count=%d): ", i, vectors[i].count);
        fflush(stdout);
        
        // Test our implementation
        benchmark_timer_t our_keygen, our_encap, our_decap;
        int our_result = benchmark_our_with_seed(vectors[i].seed, &our_keygen, &our_encap, &our_decap);
        
        if (our_result == 0) {
            benchmark_add_sample(&results.keygen_our, our_keygen.elapsed_ms);
            benchmark_add_sample(&results.encap_our, our_encap.elapsed_ms);
            benchmark_add_sample(&results.decap_our, our_decap.elapsed_ms);
            results.total_our_time_ms += our_keygen.elapsed_ms + our_encap.elapsed_ms + our_decap.elapsed_ms;
            our_successes++;
            printf("OUR[OK] ");
        } else {
            printf("OUR[FAIL] ");
        }
        
        // Test reference implementation
        benchmark_timer_t ref_keygen, ref_encap, ref_decap;
        int ref_result = benchmark_ref_with_seed(vectors[i].seed, &ref_keygen, &ref_encap, &ref_decap);
        
        if (ref_result == 0) {
            benchmark_add_sample(&results.keygen_ref, ref_keygen.elapsed_ms);
            benchmark_add_sample(&results.encap_ref, ref_encap.elapsed_ms);
            benchmark_add_sample(&results.decap_ref, ref_decap.elapsed_ms);
            results.total_ref_time_ms += ref_keygen.elapsed_ms + ref_encap.elapsed_ms + ref_decap.elapsed_ms;
            ref_successes++;
            printf("REF[OK]\n");
        } else {
            printf("REF[FAIL]\n");
        }
    }
    
    // Print summary
    printf("\n=== SUMMARY ===\n");
    printf("Our implementation: %d/%d successful (%.1f%%)\n", 
           our_successes, num_vectors, 100.0 * our_successes / num_vectors);
    printf("Ref implementation: %d/%d successful (%.1f%%)\n", 
           ref_successes, num_vectors, 100.0 * ref_successes / num_vectors);
    
    // Finalize and print results
    benchmark_finalize_stats(&results.keygen_our);
    benchmark_finalize_stats(&results.encap_our);
    benchmark_finalize_stats(&results.decap_our);
    benchmark_finalize_stats(&results.keygen_ref);
    benchmark_finalize_stats(&results.encap_ref);
    benchmark_finalize_stats(&results.decap_ref);
    
    benchmark_print_comparison(&results);
    
    if (output_file) {
        benchmark_save_results(&results, output_file);
    }
    
    free(vectors);
    return 0;
}

void print_usage(const char *program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -f <file>    KAT file to use (default: mceliece6688128/kat_kem.req)\n");
    printf("  -n <num>     Maximum number of test vectors to use (default: all)\n");
    printf("  -o <file>    Output file for results (optional)\n");
    printf("  -h           Show this help message\n");
    printf("\nExample:\n");
    printf("  %s -f mceliece6688128/kat_kem.req -n 10 -o kat_results.csv\n", program_name);
}

int main(int argc, char *argv[]) {
    const char *kat_file = "mceliece6688128/kat_kem.req";
    int max_vectors = 0; // 0 means use all
    char *output_file = NULL;
    
    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "f:n:o:h")) != -1) {
        switch (opt) {
            case 'f':
                kat_file = optarg;
                break;
            case 'n':
                max_vectors = atoi(optarg);
                if (max_vectors <= 0) {
                    fprintf(stderr, "Error: Number of vectors must be positive\n");
                    return 1;
                }
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                fprintf(stderr, "Error: Unknown option\n");
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Initialize GF arithmetic
    extern void gf_init(void);
    gf_init();
    
    printf("Classic McEliece KAT-Based Performance Benchmark\n");
    printf("===============================================\n");
    printf("KAT file: %s\n", kat_file);
    if (max_vectors > 0) {
        printf("Max vectors: %d\n", max_vectors);
    }
    if (output_file) {
        printf("Output file: %s\n", output_file);
    }
    printf("\n");
    
    return run_kat_benchmark(kat_file, max_vectors, output_file);
}
