#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "mceliece_types.h"
#include "mceliece_kem.h"
#include "mceliece_gf.h"

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

int main(int argc, char** argv) {
    int iters = 100;
    if (argc >= 3 && strcmp(argv[1], "-n") == 0) {
        int n = atoi(argv[2]);
        if (n > 0 && n <= 1000) iters = n;
    }

    gf_init();

    double t_keygen_sum = 0, t_encap_sum = 0, t_decap_sum = 0;

    for (int r = 0; r < iters; r++) {
        public_key_t *pk = public_key_create();
        private_key_t *sk = private_key_create();
        if (!pk || !sk) { fprintf(stderr, "alloc failed\n"); return 1; }

        double t0 = now_ms();
        mceliece_error_t ret = mceliece_keygen(pk, sk);
        double t1 = now_ms();
        if (ret != MCELIECE_SUCCESS) { fprintf(stderr, "keygen failed\n"); return 1; }
        t_keygen_sum += (t1 - t0);

        uint8_t C[MCELIECE_MT_BYTES];
        uint8_t K1[MCELIECE_L_BYTES], K2[MCELIECE_L_BYTES];

        t0 = now_ms();
        ret = mceliece_encap(pk, C, K1);
        t1 = now_ms();
        if (ret != MCELIECE_SUCCESS) { fprintf(stderr, "encap failed\n"); return 1; }
        t_encap_sum += (t1 - t0);

        t0 = now_ms();
        ret = mceliece_decap(C, sk, K2);
        t1 = now_ms();
        if (ret != MCELIECE_SUCCESS) { fprintf(stderr, "decap failed\n"); return 1; }
        t_decap_sum += (t1 - t0);

        public_key_free(pk);
        private_key_free(sk);
    }

    printf("Normal-mode performance over %d runs (ms):\n", iters);
    printf("  keygen: %.3f avg\n", t_keygen_sum / iters);
    printf("  encap : %.3f avg\n", t_encap_sum / iters);
    printf("  decap : %.3f avg\n", t_decap_sum / iters);
    printf("  total : %.3f avg\n", (t_keygen_sum + t_encap_sum + t_decap_sum) / iters);
    return 0;
}


