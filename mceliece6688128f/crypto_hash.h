/* Adapted to use project-local SHAKE256 implementation */
#include "../src/mceliece_shake.h"

/* PQClean expects SHAKE256(out, outlen, in, inlen) signature */
#define SHAKE256(out,outlen,in,inlen) \
  shake256((const unsigned char*)(in), (size_t)(inlen), (unsigned char*)(out), (size_t)(outlen))

#define crypto_hash_32b(out,in,inlen) \
  SHAKE256(out,32,in,inlen)

#define shake(out,outlen,in,inlen) \
  SHAKE256(out,outlen,in,inlen)

