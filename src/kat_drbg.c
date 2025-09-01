#include "kat_drbg.h"
// Use the same DRBG as NIST rng.c to match PQClean exactly
#include "rng.h"
#include <string.h>
#include "mceliece_shake.h"
#include <stdio.h>
#include <stdlib.h>

static int g_inited = 0;
// Keygen seed scheduler: 33-byte seed (seed[0] tag=64 + 32 bytes from DRBG)
static uint8_t kg_seed[33];
static int kg_inited = 0;

void kat_drbg_init(const uint8_t seed48[48]) {
    // Initialize the NIST DRBG exactly as reference does
    randombytes_init((unsigned char*)seed48, NULL, 256);
    g_inited = 1;
    // seed for keygen schedule: seed[0]=64, seed[1..32] = randombytes(32)
    kg_seed[0] = 64;
    randombytes(kg_seed + 1, 32);
    kg_inited = 1;
}

void kat_drbg_randombytes(uint8_t *out, size_t len) {
    if (!g_inited) { memset(out, 0, len); return; }
    randombytes(out, (unsigned long long)len);
}

int kat_drbg_is_inited(void) { return g_inited; }

// Expand r exactly like PQClean: r = SHAKE256(seed, 33, len); returns delta=seed[1..32]; then updates seed tail
void kat_expand_r(uint8_t *out, size_t len, uint8_t delta_out32[32]) {
    if (!kg_inited) { if (delta_out32) memset(delta_out32, 0, 32); if (out && len) memset(out, 0, len); return; }
    if (delta_out32) memcpy(delta_out32, kg_seed + 1, 32);
    shake256(kg_seed, 33, out, len);
    memcpy(kg_seed + 1, out + (len - 32), 32);
}

void kat_get_delta(uint8_t out32[32]) {
    if (!kg_inited) { if (out32) memset(out32, 0, 32); return; }
    memcpy(out32, kg_seed + 1, 32);
}


