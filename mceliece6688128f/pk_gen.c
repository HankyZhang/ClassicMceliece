/*
  This file is for public-key generation
*/

#include <stdint.h>          // 提供标准定宽整数类型（uint64_t 等）
#include <stdio.h>           // 这里没直接使用，但常见于调试或 I/O（可被优化器去掉）
#include <assert.h>          // 断言；本文件未直接使用
#include <string.h>          // 提供 memcpy 等内存操作

#include "controlbits.h"    // Benes 网络控制比特相关（置换网络的控制位）
#include "uint64_sort.h"    // 常数时间的 64 位整数排序（用于对置换对儿排序）
#include "pk_gen.h"         // 本模块导出的对外接口声明与参数
#include "params.h"         // 参数集（如 SYS_N, SYS_T, GFBITS, PK_NROWS 等）
#include "benes.h"          // Benes 网络（快速实现任意置换）
#include "root.h"           // 评估 Goppa 多项式在支持集上的值（g(L_i)）
#include "util.h"           // 工具函数（如 load8/store8, bitrev 等）
#include "crypto_declassify.h" // 侧信道防护相关：将密态信息“去机密化”以允许分支
#include "crypto_uint64.h"  // 常数时间比较，返回掩码（全 0 或全 1）

// —— 安全比较的“去机密化”包装：返回 (t == u) ? ~0ULL : 0ULL ——
static crypto_uint64 uint64_is_equal_declassify(uint64_t t,uint64_t u)
{
  crypto_uint64 mask = crypto_uint64_equal_mask(t,u); // 常数时间比较得到掩码
  crypto_declassify(&mask,sizeof mask);               // 显式标记为可用于分支（防止编译器优化泄漏）
  return mask;                                        // 返回全 1 或全 0 的 64 位掩码
}

// —— 安全检测“是否为 0”的“去机密化”包装：返回 (t == 0) ? ~0ULL : 0ULL ——
static crypto_uint64 uint64_is_zero_declassify(uint64_t t)
{
  crypto_uint64 mask = crypto_uint64_zero_mask(t);    // 常数时间计算零掩码
  crypto_declassify(&mask,sizeof mask);               // 去机密化，之后可以安全用于 if 判断
  return mask;
}

#define min(a, b) ((a < b) ? a : b) // 简单的最小值宏（本文件中未使用）

/* return number of trailing zeros of the non-zero input in */
static inline int ctz(uint64_t in)
{
	int i, b, m = 0, r = 0;                   // m 变为 1 后保持，r 统计尾随 0 个数

	for (i = 0; i < 64; i++)
	{
		b = (in >> i) & 1;                  // 取第 i 位
		m |= b;                             // 一旦遇到 1，m 保持为 1
		r += (m^1) & (b^1);                 // 仅在“尚未遇到 1 且当前位为 0”时累加
	}

	return r;                              // 返回末尾连续 0 的数量；若 in==0 则为 64
}

// —— 返回 (x == y) ? ~0ULL : 0ULL，用于常数时间条件选择 ——
static inline uint64_t same_mask(uint16_t x, uint16_t y)
{
        uint64_t mask;

        mask = x ^ y;                     // 不同则非 0，相同则为 0
        mask -= 1;                        // 相同: 0-1=0xFFFF..., 不同: 非 0 -1 的最高位不保证
        mask >>= 63;                      // 仅保留符号位（相同 -> 1，不同 -> 0）
        mask = -mask;                     // 相同-> 0xFFFF...，不同-> 0

        return mask;
}

// —— 关键过程：将某 32×64 子块做成“列主元”并据此全局换列 ——
// 输入：
//   mat    : 按字节打包的二进制矩阵，尺寸 PK_NROWS × (SYS_N/8)
//   pi     : 当前的列置换记录（长度至少 1<<GFBITS ）
//   pivots : 输出 64 位掩码，标记该 64 列块里选择到的 32 个主元位置
// 返回：0 成功，-1 表示该子块不满秩（失败）
static int mov_columns(uint8_t mat[][ SYS_N/8 ], int16_t * pi, uint64_t * pivots)
{
	int i, j, k, s, block_idx, row;                    // s 为当前主元列的 bit 位置（0..63）
	uint64_t buf[64], ctz_list[32], t, d, mask, one = 1; 
       
	row = PK_NROWS - 32;                               // 只处理最后 32 行（实现细节/参考实现约定）
	block_idx = row/8;                                  // 字节索引：这一行所在的“按 8 行分组”的列块索引

	// —— 提取一个 32×64 的子矩阵（每行连续 64 列，load8 一次取 64 个列比特）——

	for (i = 0; i < 32; i++)
		buf[i] = load8( &mat[ row + i ][ block_idx ] ); // 将 mat[row+i] 的 64 列窗口读为 64 位
        
	// —— 通过高斯消元（GF(2)）找出 32 个主元列的位置（存入 ctz_list）——
		
	*pivots = 0;                                        // 清空主元列掩码

	for (i = 0; i < 32; i++)
	{
		t = buf[i];
		for (j = i+1; j < 32; j++)
			t |= buf[j];                               // 计算从第 i 行起所有行的“列并”（是否某列存在 1）

		if (uint64_is_zero_declassify(t)) return -1; // 若全 0，秩不足，失败

		ctz_list[i] = s = ctz(t);                    // 取最低位 1 的位置作为主元列（0..63）
		*pivots |= one << ctz_list[i];               // 记录该列被用作主元

		// 确保第 i 行在该主元列上为 1：若不是 1，则用下面的某行异或补上
		for (j = i+1; j < 32; j++) { mask = (buf[i] >> s) & 1; mask -= 1;    buf[i] ^= buf[j] & mask; }
		// 清除第 i 行之下在主元列上的 1（形成上三角）
		for (j = i+1; j < 32; j++) { mask = (buf[j] >> s) & 1; mask = -mask; buf[j] ^= buf[i] & mask; }
	}
   
	// —— 根据主元列的位置，更新“列置换” pi，使主元列被换到本 64 列窗口的前 32 个位置 ——
  
	for (j = 0;   j < 32; j++)
	for (k = j+1; k < 64; k++)
	{
			d = pi[ row + j ] ^ pi[ row + k ];                 // 预构造交换用的差分
			d &= same_mask(k, ctz_list[j]);                   // 仅当 k 等于第 j 个主元列时才执行交换
			pi[ row + j ] ^= d;                               // 条件交换（常数时间掩码）
			pi[ row + k ] ^= d;
	}
   
	// —— 对整个矩阵 mat 执行实列换：把每一行的 bit[j] 与 bit[ctz_list[j]] 交换 ——

	for (i = 0; i < PK_NROWS; i++)
	{
		t = load8( &mat[ i ][ block_idx ] );              // 取该行该 64 列窗口
                	 
		for (j = 0; j < 32; j++)
		{
			d  = t >> j;                                  // 取位置 j 的比特
			d ^= t >> ctz_list[j];                        // 与主元位置比特异或，判断是否不同
			d &= 1;                                       // d=1 表示这两位不同，需要交换
        
			t ^= d << ctz_list[j];                        // 交换：按位翻转两个位置
			t ^= d << j;
		}
                
		store8( &mat[ i ][ block_idx ], t );            // 写回
	}

	return 0;                                          // 成功
}

/* input: secret key sk */
/* output: public key pk */
int pk_gen(unsigned char * pk, unsigned char * sk, uint32_t * perm, int16_t * pi, uint64_t * pivots)
{
	int i, j, k;                                       // 通用循环变量
	int row, c;                                        // 当前行与列字节索引

	uint64_t buf[ 1 << GFBITS ];                       // 用于对 (perm[i], i) 打包并排序

	unsigned char mat[ PK_NROWS ][ SYS_N/8 ];          // 生成的二进制矩阵（按字节存列块）
	unsigned char mask;                                // 单字节掩码，用于行运算
	unsigned char b;                                   // 打包每 8 个列比特为 1 字节

	gf g[ SYS_T+1 ]; // Goppa polynomial               // Goppa 多项式 g(x) 系数（次数 SYS_T，最高位设为 1）
	gf L[ SYS_N ]; // support                           // 支持集 L_i（GF(2^m) 上的 n 个不同元素）
	gf inv[ SYS_N ];                                    // 存储 g(L_i) 及其逆，后续生成矩阵时迭代使用

	// —— 读取秘密密钥中的 Goppa 多项式系数 ——

	g[ SYS_T ] = 1;                                     // 确保单项式最高次项系数为 1（monic）

	for (i = 0; i < SYS_T; i++) { g[i] = load_gf(sk); sk += 2; } // 从 sk 中逐个读取低阶系数（每个 16 位）

	// —— 利用 perm（Benes 网络产生的长度 2^m 的置换）构造支持集索引 ——
	for (i = 0; i < (1 << GFBITS); i++)
	{
		buf[i] = perm[i];                               // 高位放置 perm 值（排序主键）
		buf[i] <<= 31;                                  // 左移 31 位留出低位空间
		buf[i] |= i;                                    // 低位携带原索引 i（次键）
	}

	uint64_sort(buf, 1 << GFBITS);                    // 常数时间排序：按 perm 升序，再按 i 升序

	for (i = 1; i < (1 << GFBITS); i++)
		if (uint64_is_equal_declassify(buf[i-1] >> 31,buf[i] >> 31))
			return -1;                                // 若有重复 perm 值，说明不是置换（或冲突）→ 失败

	for (i = 0; i < (1 << GFBITS); i++) pi[i] = buf[i] & GFMASK; // 取回排序后的原索引（m 位掩码）
	for (i = 0; i < SYS_N;         i++) L[i] = bitrev(pi[i]);    // 对前 n 项做 bit-reverse 得到支持集元素索引

	// —— 在支持集上评估 g(L_i)，然后求逆，得到 1/g(L_i) ——

	root(inv, g, L);                                   // inv[i] ← g(L_i)（命名沿用参考实现）
					        
	for (i = 0; i < SYS_N; i++)
		inv[i] = gf_inv(inv[i]);                        // inv[i] ← 1 / g(L_i)

	// —— 清零生成矩阵缓存 ——
	for (i = 0; i < PK_NROWS; i++)
	for (j = 0; j < SYS_N/8; j++)
		mat[i][j] = 0;

	// —— 构建 (SYS_T * GFBITS) × SYS_N 的二进制矩阵 ——
	//   第 i 轮填充 i 从 0..SYS_T-1：每轮将 inv[j] 视作 L_j^i / g(L_j)，
	//   其 GF(2^m) 元素按 bit-planes（k=0..GFBITS-1）拆成二进制行。
	for (i = 0; i < SYS_T; i++)
	{
		for (j = 0; j < SYS_N; j+=8)                 // 每次处理 8 个列，将其第 k 位打包成一个字节
		for (k = 0; k < GFBITS;  k++)
		{
			b  = (inv[j+7] >> k) & 1; b <<= 1;        // 依次取 inv[j+7..j] 的第 k 个比特，拼成字节 b
			b |= (inv[j+6] >> k) & 1; b <<= 1;
			b |= (inv[j+5] >> k) & 1; b <<= 1;
			b |= (inv[j+4] >> k) & 1; b <<= 1;
			b |= (inv[j+3] >> k) & 1; b <<= 1;
			b |= (inv[j+2] >> k) & 1; b <<= 1;
			b |= (inv[j+1] >> k) & 1; b <<= 1;
			b |= (inv[j+0] >> k) & 1;

			mat[ i*GFBITS + k ][ j/8 ] = b;           // 写入第 (i*GFBITS+k) 行、第 j/8 个字节
		}

		for (j = 0; j < SYS_N; j++)
			inv[j] = gf_mul(inv[j], L[j]);            // 下一轮：inv[j] ← inv[j] * L[j]，实现 L_j^i/g(L_j) → L_j^{i+1}/g(L_j)

	}

	// —— 行消元，目标：把矩阵左侧前 PK_NROWS 列变成单位阵（系统化），
	//    剩余右侧 PK_ROW_BYTES 区段即为公钥（系统化生成矩阵的右半部分）。

	for (i = 0; i < (PK_NROWS + 7) / 8; i++)          // 按“字节列块”推进主元列
	for (j = 0; j < 8; j++)
	{
		row = i*8 + j;            

		if (row >= PK_NROWS)
			break;                                      // 越界保护（最后一个块可能不足 8 行）

		if (row == PK_NROWS - 32)
		{
			if (mov_columns(mat, pi, pivots))
				return -1;                            // 在倒数第 32 行前，先确保一个 32×64 子块满秩并完成换列
		}

		// —— 用下面的行，尝试把当前主元位（列 i、位 j）做成 1 ——
		for (k = row + 1; k < PK_NROWS; k++)
		{
			mask = mat[ row ][ i ] ^ mat[ k ][ i ];     // 比较该字节第 j 位是否不同
			mask >>= j;
			mask &= 1;                                  // 1 表示不同，需要异或以改变 row 的该位
			mask = -mask;                               // 扩展为 0x00 或 0xFF（按位掩码）

			for (c = 0; c < SYS_N/8; c++)
				mat[ row ][ c ] ^= mat[ k ][ c ] & mask; // 条件异或整行（GF(2) 加法）
		}

                if ( uint64_is_zero_declassify((mat[ row ][ i ] >> j) & 1) ) // 若主元位仍为 0，则无法系统化
		{
			return -1;                                 // 失败
		}

		// —— 清零该主元位所在列的其他行 ——
		for (k = 0; k < PK_NROWS; k++)
		{
			if (k != row)
			{
				mask = mat[ k ][ i ] >> j;              // 取第 j 位
				mask &= 1;
				mask = -mask;

				for (c = 0; c < SYS_N/8; c++)
					mat[ k ][ c ] ^= mat[ row ][ c ] & mask; // 有 1 的行用主元行异或清零
			}
		}
	}

	// —— 拷贝系统化矩阵的“右半部分”到公钥缓冲区 ——
	for (i = 0; i < PK_NROWS; i++)
		memcpy(pk + i*PK_ROW_BYTES, mat[i] + PK_NROWS/8, PK_ROW_BYTES); // 跳过左边单位阵部分

	return 0;                                          // 成功
}
