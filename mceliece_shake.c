#include "mceliece_types.h"
#include "mceliece_shake.h"
// Keccak-f[1600] 常量
#define KECCAK_ROUNDS 24
#define KECCAK_STATE_SIZE 25  // 25个64位字

// 轮常量
static const uint64_t keccak_round_constants[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// rho偏移量
static const unsigned int keccak_rho_offsets[25] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14, 27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

// pi置换
static const unsigned int keccak_pi_lane[25] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4, 15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

// 64位循环左移
static uint64_t rotl64(uint64_t x, int shift) {
    return (x << shift) | (x >> (64 - shift));
}

// Keccak-f[1600] 置换
static void keccak_f1600(uint64_t state[25]) {
    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        uint64_t C[5], D[5];
        
        // θ (Theta) step
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                state[y * 5 + x] ^= D[x];
            }
        }
        
        // ρ (Rho) and π (Pi) steps
        uint64_t current = state[1];
        for (int t = 0; t < 24; t++) {
            int index = keccak_pi_lane[t];
            uint64_t temp = state[index];
            state[index] = rotl64(current, keccak_rho_offsets[t]);
            current = temp;
        }
        
        // χ (Chi) step
        for (int y = 0; y < 5; y++) {
            uint64_t temp[5];
            for (int x = 0; x < 5; x++) {
                temp[x] = state[y * 5 + x];
            }
            for (int x = 0; x < 5; x++) {
                state[y * 5 + x] = temp[x] ^ (~temp[(x + 1) % 5] & temp[(x + 2) % 5]);
            }
        }
        
        // ι (Iota) step
        state[0] ^= keccak_round_constants[round];
    }
}

// SHAKE256 context is defined in mceliece_shake.h

// SHAKE256 初始化
void shake256_init(shake256_ctx *ctx) {
    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->buffer_pos = 0;
    ctx->squeezing = 0;
}

// SHAKE256 吸收数据
void shake256_absorb(shake256_ctx *ctx, const uint8_t *input, size_t len) {
    if (ctx->squeezing) return;  // 已经开始挤压，不能再吸收
    
    while (len > 0) {
        size_t remaining_in_buffer = 136 - (size_t)ctx->buffer_pos;
        size_t to_copy = (len < remaining_in_buffer) ? len : remaining_in_buffer;
        
        memcpy(ctx->buffer + ctx->buffer_pos, input, to_copy);
        ctx->buffer_pos += to_copy;
        input += to_copy;
        len -= to_copy;
        
        if (ctx->buffer_pos == 136) {
            // 缓冲区满，处理一个块
            // 使用一个指向缓冲区的指针，以提高清晰度
            const uint8_t *p_buffer = ctx->buffer;
            for (int i = 0; i < 17; i++, p_buffer += 8) { // 每次循环处理8个字节
                // 从 p_buffer 安全地加载一个小端序的 64 位字
                uint64_t word = (uint64_t)p_buffer[0] |
                               ((uint64_t)p_buffer[1] << 8) |
                               ((uint64_t)p_buffer[2] << 16) |
                               ((uint64_t)p_buffer[3] << 24) |
                               ((uint64_t)p_buffer[4] << 32) |
                               ((uint64_t)p_buffer[5] << 40) |
                               ((uint64_t)p_buffer[6] << 48) |
                               ((uint64_t)p_buffer[7] << 56);
                ctx->state[i] ^= word;
            }
            
            keccak_f1600(ctx->state);
            ctx->buffer_pos = 0;
        }
    }
}

// SHAKE256 finalize和开始挤压
void shake256_finalize(shake256_ctx *ctx) {
    if (ctx->squeezing) return;
    
    // 添加padding
    ctx->buffer[ctx->buffer_pos] = 0x1f;  // SHAKE256的domain separation
    for (int i = ctx->buffer_pos + 1; i < 135; i++) {
        ctx->buffer[i] = 0;
    }
    ctx->buffer[135] = 0x80;  // 最后一位设为1
    
    // 处理最后一个块
    const uint8_t *p_buffer = ctx->buffer;
    for (int i = 0; i < 17; i++, p_buffer += 8) {
        uint64_t word = (uint64_t)p_buffer[0] |
                       ((uint64_t)p_buffer[1] << 8) |
                       ((uint64_t)p_buffer[2] << 16) |
                       ((uint64_t)p_buffer[3] << 24) |
                       ((uint64_t)p_buffer[4] << 32) |
                       ((uint64_t)p_buffer[5] << 40) |
                       ((uint64_t)p_buffer[6] << 48) |
                       ((uint64_t)p_buffer[7] << 56);
        ctx->state[i] ^= word;
    }

    keccak_f1600(ctx->state);
    ctx->squeezing = 1;
    ctx->buffer_pos = 0;
}

// SHAKE256 挤压输出
void shake256_squeeze(shake256_ctx *ctx, uint8_t *output, size_t len) {
    if (!ctx->squeezing) {
        shake256_finalize(ctx);
    }

    while (len > 0) {
        if (ctx->buffer_pos == 0) {
            // 生成新的输出块
            for (int i = 0; i < 17; i++) {
                uint64_t word = ctx->state[i];
                for (int j = 0; j < 8; j++) {
                    ctx->buffer[i * 8 + j] = (word >> (8 * j)) & 0xff;
                }
            }
        }

        size_t remaining_in_buffer = 136 - (size_t)ctx->buffer_pos;
        size_t to_copy = (len < remaining_in_buffer) ? len : remaining_in_buffer;
        memcpy(output, ctx->buffer + ctx->buffer_pos, to_copy);

        ctx->buffer_pos += to_copy;
        output += to_copy;
        len -= to_copy;

        if (ctx->buffer_pos == 136) {
            keccak_f1600(ctx->state);
            ctx->buffer_pos = 0;
        }
    }
}

// 便捷函数：一次性计算SHAKE256
void shake256(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len) {
    shake256_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, input, input_len);
    shake256_squeeze(&ctx, output, output_len);
}

// Hash函数实现（用于Classic McEliece）
void mceliece_hash(uint8_t prefix, const uint8_t *input, size_t input_len, uint8_t *output) {
    shake256_ctx ctx;
    shake256_init(&ctx);

    // 先吸收前缀字节
    shake256_absorb(&ctx, &prefix, 1);

    // 再吸收输入数据
    shake256_absorb(&ctx, input, input_len);

    // 输出256位
    shake256_squeeze(&ctx, output, MCELIECE_L_BYTES);
}

// PRG函数实现（伪随机生成器）
void mceliece_prg(const uint8_t *seed, uint8_t *output, size_t output_len) {
    shake256_ctx ctx;
    shake256_init(&ctx);

    // 先吸收前缀字节64
    uint8_t prefix = 64;
    shake256_absorb(&ctx, &prefix, 1);

    // 再吸收种子
    shake256_absorb(&ctx, seed, MCELIECE_L_BYTES);

    // 生成所需长度的输出
    shake256_squeeze(&ctx, output, output_len);
}