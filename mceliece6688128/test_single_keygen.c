#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_kem.h"
#include "nist/rng.h"

int main() {
    unsigned char seed[48];
    unsigned char pk[crypto_kem_PUBLICKEYBYTES];
    unsigned char sk[crypto_kem_SECRETKEYBYTES];
    
    printf("=== Reference Implementation Single Keygen Test ===\n");
    
    // Use the same seed as the first KAT vector
    const char *hex_seed = "351025E30688D00982D0380C2B5EDA2C93002BFAFA09F958654C2965B5BB9A1E35578B8DDB7858443A3067AE4E7913F79EFC2A20AEF5";
    
    // Convert hex to bytes
    for (int i = 0; i < 48; i++) {
        sscanf(hex_seed + i*2, "%2hhx", &seed[i]);
    }
    
    printf("Using first KAT seed\n");
    
    // Initialize RNG with the seed
    randombytes_init(seed, NULL, 256);
    
    printf("Calling crypto_kem_keypair with attempt counting...\n");
    
    int result = crypto_kem_keypair(pk, sk);
    
    printf("Result: %d\n", result);
    if (result == 0) {
        printf("SUCCESS: Key generation completed\n");
    } else {
        printf("FAILED: crypto_kem_keypair returned %d\n", result);
    }
    
    return result;
}
