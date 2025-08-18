#include "rng.h"
#include <string.h>

/* Minimal AES-256-CTR DRBG used by NIST KAT (PQCgenKAT).
   This is a small, self-contained port adequate for matching
   byte-for-byte randomness consumption. */

/* AES-256 implementation (ECB encrypt) */
typedef struct {
    unsigned int rk[60];
    int nr;
} aes256_ctx;

static unsigned int rotr32(unsigned int x, int n) { return (x >> n) | (x << (32 - n)); }

/* S-box */
static const unsigned char sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static unsigned int rcon(int i){
    unsigned int c = 1;
    if (i==0) return 0;
    while (i != 1) { c = (c << 1) ^ ((c & 0x80)?0x1B:0); c &= 0xFF; i--; }
    return c;
}

static void sub_word(unsigned char w[4]){
    w[0]=sbox[w[0]]; w[1]=sbox[w[1]]; w[2]=sbox[w[2]]; w[3]=sbox[w[3]];
}

static void aes256_key_expand(aes256_ctx *ctx, const unsigned char key[32]){
    unsigned int temp;
    unsigned int *rk = ctx->rk;
    ctx->nr = 14;
    for (int i=0;i<8;i++) {
        rk[i] = ((unsigned int)key[4*i]<<24) | ((unsigned int)key[4*i+1]<<16) |
                ((unsigned int)key[4*i+2]<<8) | key[4*i+3];
    }
    for (int i=8;i<4*(ctx->nr+1);i++){
        temp = rk[i-1];
        if (i % 8 == 0) {
            temp = (temp << 8) | (temp >> 24);
            unsigned char t[4] = { (unsigned char)(temp>>24), (unsigned char)(temp>>16), (unsigned char)(temp>>8), (unsigned char)temp };
            sub_word(t);
            temp = ((unsigned int)t[0]<<24)|((unsigned int)t[1]<<16)|((unsigned int)t[2]<<8)|t[3];
            temp ^= ((unsigned int)rcon(i/8))<<24;
        } else if (i % 8 == 4) {
            unsigned char t[4] = { (unsigned char)(temp>>24), (unsigned char)(temp>>16), (unsigned char)(temp>>8), (unsigned char)temp };
            sub_word(t);
            temp = ((unsigned int)t[0]<<24)|((unsigned int)t[1]<<16)|((unsigned int)t[2]<<8)|t[3];
        }
        rk[i] = rk[i-8] ^ temp;
    }
}

static unsigned char xtime(unsigned char x){ return (unsigned char)((x<<1) ^ (((x>>7)&1)*0x1b)); }

static void aes256_encrypt_block(const aes256_ctx *ctx, const unsigned char in[16], unsigned char out[16]){
    unsigned char state[4][4];
    for (int i=0;i<16;i++) state[i%4][i/4] = in[i];
    const unsigned int *rk = ctx->rk;
    int nr = ctx->nr;
    #define GETU32(pt) (((unsigned int)(pt)[0] << 24) ^ ((unsigned int)(pt)[1] << 16) ^ ((unsigned int)(pt)[2] << 8) ^ ((unsigned int)(pt)[3]))
    #define PUTU32(ct, st) do{ (ct)[0]=(unsigned char)((st)>>24); (ct)[1]=(unsigned char)((st)>>16); (ct)[2]=(unsigned char)((st)>>8); (ct)[3]=(unsigned char)(st); }while(0)
    unsigned int round_key[4];
    for (int i=0;i<4;i++) round_key[i]=rk[i];
    for (int r=0;r<4;r++) for (int c=0;c<4;c++) state[r][c] ^= (unsigned char)(round_key[c] >> (24-8*r));
    for (int round=1; round<nr; round++){
        unsigned char tmp[4][4];
        for (int c=0;c<4;c++){
            tmp[0][c] = sbox[state[0][c]];
            tmp[1][c] = sbox[state[1][(c+1)&3]];
            tmp[2][c] = sbox[state[2][(c+2)&3]];
            tmp[3][c] = sbox[state[3][(c+3)&3]];
        }
        for (int c=0;c<4;c++){
            unsigned char a0=tmp[0][c], a1=tmp[1][c], a2=tmp[2][c], a3=tmp[3][c];
            unsigned char b0=xtime(a0)^a3^a2^xtime(a1)^a1;
            unsigned char b1=xtime(a1)^a0^a3^xtime(a2)^a2;
            unsigned char b2=xtime(a2)^a1^a0^xtime(a3)^a3;
            unsigned char b3=xtime(a3)^a2^a1^xtime(a0)^a0;
            state[0][c]=b0; state[1][c]=b1; state[2][c]=b2; state[3][c]=b3;
        }
        for (int i=0;i<4;i++) round_key[i]=rk[4*round+i];
        for (int r=0;r<4;r++) for (int c=0;c<4;c++) state[r][c] ^= (unsigned char)(round_key[c] >> (24-8*r));
    }
    unsigned char tmp[4][4];
    for (int c=0;c<4;c++){
        tmp[0][c] = sbox[state[0][c]];
        tmp[1][c] = sbox[state[1][(c+1)&3]];
        tmp[2][c] = sbox[state[2][(c+2)&3]];
        tmp[3][c] = sbox[state[3][(c+3)&3]];
    }
    for (int i=0;i<4;i++) round_key[i]=rk[4*nr+i];
    for (int r=0;r<4;r++) for (int c=0;c<4;c++) out[c*4+r] = tmp[r][c] ^ (unsigned char)(round_key[c] >> (24-8*r));
}

/* DRBG state */
static aes256_ctx ctx;
static unsigned char Key[32];
static unsigned char V[16];
static int reseed_counter = 0;

static void AES256_ECB(unsigned char *key, const unsigned char *in, unsigned char *out){
    aes256_ctx t; aes256_key_expand(&t, key); aes256_encrypt_block(&t, in, out);
}

static void DRBG_Update(const unsigned char *provided_data){
    unsigned char temp[48];
    for (int i=0;i<3;i++){
        for (int j=15;j>=0;j--){ if (++V[j]) break; }
        AES256_ECB(Key, V, temp + 16*i);
    }
    if (provided_data){ for (int i=0;i<48;i++) temp[i] ^= provided_data[i]; }
    memcpy(Key, temp, 32);
    memcpy(V, temp+32, 16);
}

void randombytes_init(const unsigned char *entropy_input,
                      const unsigned char *personalization_string,
                      int security_strength){
    (void)security_strength;
    unsigned char seed_material[48];
    memcpy(seed_material, entropy_input, 48);
    if (personalization_string){ for (int i=0;i<48;i++) seed_material[i] ^= personalization_string[i]; }
    memset(Key, 0, sizeof Key);
    memset(V, 0, sizeof V);
    DRBG_Update(seed_material);
    reseed_counter = 1;
}

void randombytes(unsigned char *x, unsigned long long xlen){
    unsigned char block[16];
    while (xlen > 0){
        for (int j=15;j>=0;j--){ if (++V[j]) break; }
        AES256_ECB(Key, V, block);
        unsigned long long use = xlen < 16 ? xlen : 16;
        memcpy(x, block, use);
        x += use; xlen -= use;
    }
    DRBG_Update(NULL);
    reseed_counter++;
}


