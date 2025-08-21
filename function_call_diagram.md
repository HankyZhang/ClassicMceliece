# Classic McEliece Function Call Diagram

## Overview
This diagram shows the function call hierarchy and relationships in the Classic McEliece KEM implementation.

## Main Entry Points

```
main()
├── print_usage()
├── print_parameters()
├── demo_keygen()
│   ├── public_key_create()
│   ├── private_key_create()
│   ├── mceliece_keygen()
│   ├── public_key_free()
│   └── private_key_free()
├── demo_complete()
│   ├── mceliece_keygen()
│   ├── mceliece_encap()
│   ├── mceliece_decap()
│   └── [verification logic]
├── benchmark()
│   ├── mceliece_keygen()
│   ├── mceliece_encap()
│   └── mceliece_decap()
├── run_kat_file()
│   ├── hex2bin()
│   ├── kat_drbg_init()
│   ├── mceliece_keygen()
│   ├── mceliece_encap()
│   └── mceliece_decap()
└── run_kat_int()
    ├── hex2bin()
    ├── kat_drbg_init()
    ├── mceliece_keygen()
    ├── gen_e_pqclean()
    ├── encode_vector()
    ├── decode_ciphertext()
    └── dump_positions()
```

## Core KEM Functions

### 1. Key Generation (`mceliece_keygen`)
```
mceliece_keygen(pk, sk)
├── kat_drbg_randombytes() [if KAT mode]
├── mceliece_prg() [if normal mode]
└── seeded_key_gen(delta, pk, sk)
    ├── mceliece_prg(sk->delta, E, prg_output_len_bytes)
    ├── generate_field_ordering()
    │   ├── mceliece_prg()
    │   └── [field element generation]
    ├── generate_irreducible_poly_final()
    │   ├── mceliece_prg()
    │   └── [polynomial generation]
    ├── matrix_create()
    ├── matrix_invert()
    ├── controlbitsfrompermutation()
    │   └── cbits_from_perm_ns()
    ├── mceliece_encap() [self-verification]
    └── mceliece_decap() [self-verification]
```

### 2. Encapsulation (`mceliece_encap`)
```
mceliece_encap(pk, ciphertext, session_key)
├── fixed_weight_vector() [if normal mode]
│   ├── mceliece_prg()
│   └── vector_set_bit()
├── gen_e_pqclean() [if KAT mode]
│   └── kat_drbg_randombytes()
├── encode_vector(error_vector, &pk->T, ciphertext)
│   ├── matrix_multiply()
│   └── [H = [I_mt | T] computation]
└── mceliece_hash()
    └── shake256()
```

### 3. Decapsulation (`mceliece_decap`)
```
mceliece_decap(ciphertext, sk, session_key)
├── decode_ciphertext(ciphertext, sk, error_vector, &success)
│   ├── compute_syndrome()
│   │   ├── vector_get_bit()
│   │   ├── polynomial_eval()
│   │   ├── gf_pow()
│   │   ├── gf_mul()
│   │   └── gf_div()
│   ├── berlekamp_massey()
│   │   ├── polynomial_create()
│   │   ├── polynomial_set_coeff()
│   │   ├── polynomial_copy()
│   │   ├── gf_add()
│   │   ├── gf_mul()
│   │   └── gf_div()
│   ├── chien_search()
│   │   ├── polynomial_eval()
│   │   └── vector_set_bit()
│   └── [error correction logic]
└── mceliece_hash()
    └── shake256()
```

## Supporting Functions

### Matrix Operations
```
matrix_create(rows, cols)
matrix_free(matrix)
matrix_multiply(A, B, C)
matrix_invert(A, A_inv)
matrix_transpose(A, A_T)
```

### Polynomial Operations
```
polynomial_create(max_degree)
polynomial_free(poly)
polynomial_set_coeff(poly, pos, coeff)
polynomial_get_coeff(poly, pos)
polynomial_eval(poly, x)
polynomial_copy(dest, src)
polynomial_add(a, b, result)
polynomial_mul(a, b, result)
polynomial_div(a, b, quotient, remainder)
```

### Finite Field Operations
```
gf_init()
gf_add(a, b)
gf_sub(a, b)
gf_mul(a, b)
gf_div(a, b)
gf_inv(a)
gf_pow(a, n)
```

### Vector Operations
```
vector_create(n_bits)
vector_free(vec)
vector_set_bit(vec, pos, value)
vector_get_bit(vec, pos)
vector_weight(vec, n_bits)
vector_xor(a, b, result, n_bits)
```

### Hash Functions
```
mceliece_hash(prefix, input, input_len, output)
├── shake256_init()
├── shake256_update()
└── shake256_final()
```

### Random Number Generation
```
mceliece_prg(seed, output, output_len)
├── shake256_init()
├── shake256_update()
└── shake256_final()

kat_drbg_init(seed48)
kat_drbg_randombytes(out, len)
kat_drbg_is_inited()
```

## Test Functions

### Basic Tests
```
test_mceliece()
├── mceliece_keygen()
├── mceliece_encap()
└── mceliece_decap()

test_basic_functions()
├── gf_add(), gf_mul(), gf_inv(), gf_pow()
├── vector_set_bit(), vector_get_bit(), vector_weight()
└── matrix_create(), matrix_multiply()

test_bm_chien()
├── compute_syndrome()
├── berlekamp_massey()
└── chien_search()
```

### Advanced Tests
```
test_stress()
├── [50 rounds of keygen/encap/decap]
└── [performance measurement]

test_tamper()
├── mceliece_keygen()
├── mceliece_encap()
├── [bit flipping in ciphertext]
└── mceliece_decap()

test_decap_pipeline()
├── compute_syndrome()
├── berlekamp_massey()
└── chien_search()
```

## Data Flow

### Key Generation Flow
```
Seed (delta) → PRG → E → [s, field_ordering, irreducible_poly, delta_prime]
                ↓
            Field Ordering → α₀, α₁, ..., α_{n-1}
                ↓
            Irreducible Poly → g(x)
                ↓
            Matrix Generation → T, U, U_inv, permutation
                ↓
            Control Bits → Benes network configuration
                ↓
            [Self-verification] → encap/decap test
```

### Encapsulation Flow
```
Public Key T → [Generate error vector e] → [Compute C = He] → [Hash(1, e, C)] → Session Key
                     ↓
              FixedWeight() or gen_e_pqclean()
                     ↓
              Encode(e, T) = He
                     ↓
              Hash(1, e, C)
```

### Decapsulation Flow
```
Ciphertext C → [Compute syndrome] → [BM algorithm] → [Chien search] → [Error correction] → Session Key
                     ↓
              compute_syndrome(C, g, α)
                     ↓
              berlekamp_massey(syndrome)
                     ↓
              chien_search(σ(x), α)
                     ↓
              [Error vector recovery]
                     ↓
              Hash(1, e, C)
```

## Error Handling

### Error Types
- `MCELIECE_SUCCESS`: Operation completed successfully
- `MCELIECE_ERROR_INVALID_PARAM`: Invalid parameters
- `MCELIECE_ERROR_MEMORY`: Memory allocation failure
- `MCELIECE_ERROR_KEYGEN_FAIL`: Key generation failed (retry)
- `MCELIECE_ERROR_DECODE_FAIL`: Decoding failed

### Retry Logic
- Key generation: Up to 400 attempts
- Encapsulation: Up to 10 attempts
- Decapsulation: Single attempt (with fallback to backup key)

## Performance Characteristics

### Time Complexity
- Key Generation: O(n³) due to matrix operations
- Encapsulation: O(mt × k) for matrix multiplication
- Decapsulation: O(t³) for Berlekamp-Massey + O(n) for Chien search

### Space Complexity
- Public Key: O(mt × k) bits
- Private Key: O(n + t² + mt²) bits
- Ciphertext: O(mt) bits
- Session Key: O(l) bits

## Security Considerations

### Randomness Sources
- Normal mode: System entropy (/dev/urandom)
- KAT mode: Deterministic DRBG with fixed seeds
- PRG: SHAKE256-based

### Side-Channel Protection
- Constant-time operations where possible
- Secure memory handling
- Deterministic execution paths





./mceliece test          *# Basic functionality tests*

./mceliece fulltest      *# Comprehensive test suite*

./mceliece basic         *# Test GF/matrix/vector operations*

./mceliece bmchien       *# BM+Chien targeted test*

./mceliece decapdbg      *# Debug decapsulation pipeline*

./mceliece stress        *# 50-round stress test*

./mceliece tamper        *# Tamper ciphertext test*

./mceliece seeded        *# Deterministic seeded keygen test*

./mceliece roundtrip     *# Encode/Decode roundtrip test*

./mceliece tampswp       *# Tamper sweep test*

./mceliece decapfull     *# Full decapsulation verification*

./mceliece cbtest        *# Controlbits Benes routing test*

./mceliece keygen        *# Generate and display key pair*

./mceliece demo          *# Complete encryption/decryption demo*

./mceliece bench 
