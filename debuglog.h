#ifndef DEBUGLOG_H
#define DEBUGLOG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static inline int dbg_enabled_us(void) {
    const char *env = getenv("MCELIECE_DEBUG");
    return env && env[0] == '1';
}

static inline void dbg_hex_us(const char *label, const void *buf, size_t len, size_t limit) {
    if (!dbg_enabled_us()) return;
    size_t n = len < limit ? len : limit;
    const uint8_t *p = (const uint8_t *)buf;
    printf("[DBG] %s (%zu/%zu): ", label, n, len);
    for (size_t i = 0; i < n; i++) printf("%02X", p[i]);
    if (n < len) printf("...");
    printf("\n");
    fflush(stdout);
}

#endif // DEBUGLOG_H


