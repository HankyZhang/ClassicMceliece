I'll open the reference KAT driver and the key reference functions to build an accurate call graph, then render it.
Ran tool
Ran tool
Ran tool
Ran tool
Ran tool

I traced the reference KAT path from the NIST driver through keypair/enc/dec. Here’s the Markdown call graph.

### Reference KAT call graph (PQClean-style)

- `mceliece6688128/nist/kat_kem.c: main`
  - `randombytes_init(entropy_input, NULL, 256)`
  - for each count:
    - `randombytes_init(seed[i], NULL, 256)`
    - `crypto_kem_keypair(pk, sk)` — in `mceliece6688128/operations.c`
      - local seed handling:
        - `shake(r, sizeof r, seed, 33)`
        - copy `seed+1` to `sk` delta; update seed tail from `r`
      - generate `irr`:
        - load `f` from `r` → `load_gf`
        - `genpoly_gen(irr, f)` — in `mceliece6688128/sk_gen.c`
          - fills matrix with `GF_mul`, does Gaussian elim with `gf_inv`, `gf_mul`
      - generate pk:
        - load `perm` from `r` → `load4`
        - `pk_gen(pk, skp - IRR_BYTES, perm, pi)` — in `mceliece6688128/pk_gen.c`
          - `uint64_sort(buf, 1<<GFBITS)`
          - `pi[i] = buf[i] & GFMASK`
          - `L[i] = bitrev(pi[i])`
          - `root(inv, g, L)` — in `mceliece6688128/root.c`
            - uses `gf_*` ops
          - for rows:
            - `inv[j] = gf_inv(inv[j])`
            - pack rows into `mat[]` from `inv`
            - per row multiply `inv[j] = gf_mul(inv[j], L[j])`
          - Gaussian elimination over `mat` to systematic form
          - copy right block to `pk`
        - `controlbitsfrompermutation(skp, pi, GFBITS, 1<<GFBITS)` — in `controlbits.c`
        - copy `s` from `r` tail to `sk`
        - `store8(sk + 32, 0xFFFFFFFF)` (pivot marker)
    - `crypto_kem_enc(ct, ss, pk)` — in `mceliece6688128/operations.c`
      - `encrypt(ct, pk, e)` — in `mceliece6688128/encrypt.c`
        - `gen_e(e)`:
          - `randombytes(buf.bytes, ...)`
          - parse to indices: `load_gf`
          - de-duplicate and pack bits
        - `syndrome(ct, pk, e)` — matrix-vector over pk rows
      - build `one_ec = 1 || e || ct`
      - `crypto_hash_32b(ss, one_ec, sizeof(one_ec))`
    - `crypto_kem_dec(ss1, ct, sk)` — in `mceliece6688128/operations.c`
      - `ret = decrypt(e, sk+40, ct)` — in `mceliece6688128/decrypt.c`
        - uses Goppa decode: Benes/permutation, syndrome, BM, Chien, etc. with `gf_*`, `benes`, `util`
      - construct `preimage = b || (b?e:s) || ct` where `b = (ret == 0)`
      - `crypto_hash_32b(ss1, preimage, sizeof(preimage))`

- Core dependencies invoked along the path:
  - `mceliece6688128/gf.c`: `gf_mul`, `gf_inv`, etc.
  - `mceliece6688128/benes.c`: Benes network for permutations (decode path)
  - `mceliece6688128/root.c`: evaluates `g(L)` for H construction
  - `mceliece6688128/controlbits.c`: `controlbitsfrompermutation`
  - `mceliece6688128/util.c`, `uint64_sort.h`, `crypto_hash.h`, `rng.c`