#ifndef CLASSIC_MCELIECE_DEBUGLOG_H
#define CLASSIC_MCELIECE_DEBUGLOG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "mceliece_shake.h"

static inline int dbg_enabled_us(void) {
    const char *p = getenv("MCELIECE_DEBUG");
    return p && p[0] == '1';
}

static inline void dbg_hash_us(const char *label, const void *buf, size_t len) {
    if (!dbg_enabled_us()) return;
    unsigned char out[32];
    shake256((const uint8_t*)buf, len, out, sizeof out);
    printf("[us] %s: ", label);
    for (size_t i = 0; i < sizeof out; i++) printf("%02X", out[i]);
    printf("\n");
    fflush(stdout);
}

static inline void dbg_hex_us(const char *label, const void *buf, size_t len, size_t max_bytes) {
    if (!dbg_enabled_us()) return;
    printf("[us] %s: ", label);
    size_t n = len < max_bytes ? len : max_bytes;
    const unsigned char *p = (const unsigned char*)buf;
    for (size_t i = 0; i < n; i++) printf("%02X", p[i]);
    if (len > max_bytes) printf("...");
    printf("\n");
    fflush(stdout);
}

#endif // CLASSIC_MCELIECE_DEBUGLOG_H



