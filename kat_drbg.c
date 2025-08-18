#include "kat_drbg.h"
// Switch to NIST AES-CTR-DRBG used by KAT harness (rng.c)
#include "rng.h"
#include <string.h>

static int g_inited = 0;

void kat_drbg_init(const uint8_t seed48[48]) {
    // entropy_input = 48 bytes; no personalization
    randombytes_init(seed48, NULL, 256);
    g_inited = 1;
}

void kat_drbg_randombytes(uint8_t *out, size_t len) {
    if (!g_inited) { memset(out, 0, len); return; }
    // KAT randombytes uses unsigned long long
    unsigned long long remaining = (unsigned long long)len;
    unsigned char *p = out;
    while (remaining) {
        unsigned long long chunk = remaining;
        // randombytes supports arbitrary; call once
        randombytes(p, chunk);
        p += chunk;
        remaining -= chunk;
    }
}

int kat_drbg_is_inited(void) { return g_inited; }


