# Classic McEliece (mceliece6688128)

A working, readable implementation of Classic McEliece (parameter set mceliece6688128) with:
- Our implementation (clean, instrumentable C)
- Integrated reference components for cross-checking
- Deterministic KAT generation and an “internal KAT” that verifies decoding by showing error positions

This README shows how to build and run everything, including all available tests.

## Requirements
- clang or gcc (tested on macOS, clang)
- make (for reference/integration tests)

## Quick start (build CLI and run smoke tests)
```bash
# From repository root
clang -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
  -I. -Imceliece6688128/ -Imceliece6688128/subroutines/ \
  -o mceliece \
  main.c \
  mceliece_keygen.c mceliece_shake.c mceliece_gf.c mceliece_poly.c \
  mceliece_matrix_ops.c mceliece_genpoly.c reference_shake.c \
  mceliece_vector.c mceliece_decode.c mceliece_encode.c controlbits.c \
  kat_drbg.c rng.c mceliece_kem.c \
  mceliece6688128/gf.c mceliece6688128/benes.c mceliece6688128/controlbits.c \
  mceliece6688128/root.c mceliece6688128/util.c mceliece6688128/transpose.c \
  -lm

# See available commands
./mceliece | cat

# Round-trip test (encode+decode)
./mceliece roundtrip | cat

# Full decapsulation verification
./mceliece decapfull | cat
```

## CLI commands (our implementation)
Run `./mceliece` to see the menu. Common commands:
- `./mceliece basic`: basic GF, vector, matrix, and polynomial checks
- `./mceliece roundtrip`: generate e, compute C=H·e, decode, and compare with original e
- `./mceliece decapfull`: verify that decapsulation recovers e and that C == H·e_rec
- `./mceliece decapdbg`: prints BM/Chien stats and syndrome comparison for debugging
- `./mceliece bmchien`: focused BM+Chien test
- `./mceliece tamper`: flip bits in C and observe decap fallback behavior
- `./mceliece tampswp`: tamper sweep across k=1..16 bit flips
- `./mceliece seeded`: deterministic seeded keygen + roundtrip
- `./mceliece keygen`: generate and display a key pair summary
- `./mceliece demo`: end-to-end encapsulation/decapsulation demo
- `./mceliece bench`: simple performance benchmark
- `./mceliece cbtest`: verify Benes controlbits routing (sanity)
- `./mceliece kat <req> <rsp>`: produce KAT response file from request
- `./mceliece katint <req> <int>`: produce internal KAT file listing error positions

## Debug env vars
- `MCELIECE_DEBUG=1`: verbose decoding pipeline (syndrome, BM, Chien counts)
- `MCELIECE_VERIFY_CB=1`: extra verification after computing controlbits (slower)

Example:
```bash
env MCELIECE_DEBUG=1 ./mceliece roundtrip | cat
```

## KAT (Known Answer Tests)
Two flavors:

1) Produce a KAT response file (rsp) from a req file (deterministic DRBG):
```bash
# Wrapper
./run_kat | cat
# or directly via CLI
./mceliece kat mceliece6688128/kat_kem.req our_kat_output.rsp | cat
```
- Input: `mceliece6688128/kat_kem.req`
- Output: `our_kat_output.rsp` (contains `seed`, `pk`, `sk`, `ct`, `ss`)

2) Internal KAT (.int) that shows error positions for encrypt/decrypt:
```bash
./mceliece katint mceliece6688128/kat_kem.req our_test.int | cat
# our_test.int has lines: "encrypt e: positions ..." and "decrypt e: positions ..."
```

## Reference-integration tests
Build and run small programs that exercise our code + reference components.

### Reference integration comparison
```bash
make -f Makefile.reference_test
./test_reference_integration | cat
```

### Direct comparison and dataflow tracer (optional)
```bash
# Side-by-side numeric comparisons through keygen steps 1..5
make -f Makefile.direct_comparison
./direct_comparison_test | cat

# Dataflow tracer (reads kat_kem.req and logs a detailed pipeline)
make -f Makefile.direct_comparison TRACE_TARGET
./dataflow_trace | cat
```
Notes:
- These use reference sources for comparison only; production usage uses our clean pipeline.

## Reproducing typical workflows
- Roundtrip: `./mceliece roundtrip | cat`
- Full decap verification: `./mceliece decapfull | cat`
- Deterministic KAT rsp: `./run_kat | cat`
- KAT internal error-positions: `./mceliece katint mceliece6688128/kat_kem.req our_test.int | cat`
- Debug a decode: `env MCELIECE_DEBUG=1 ./mceliece decapdbg | cat`

## Troubleshooting
- If debug prints show `L vs alpha mismatch: YES`, ensure domain construction bit-reverses only the lower m bits (fixed in this repo).
- If a reference Makefile binary fails to link on your platform, prefer the main CLI tests above; Makefiles are primarily for reference integration.
- macOS users: use `clang` (Xcode toolchain) or Homebrew `llvm`. GNU `make` is sufficient.

## Repository structure (relevant parts)
- `mceliece_*.c/.h`: our implementation (GF, poly, matrix ops, keygen, encode/decode, KEM)
- `mceliece6688128/`: reference components (gf, benes, controlbits, etc.) for cross-checking
- `run_kat`, `run_kat.c`: driver to produce `our_kat_output.rsp`
- `Makefile.reference_test`, `Makefile.direct_comparison`: reference-integration builds

## License
This repository integrates reference sources strictly for testing and comparison. See headers for their respective licenses. Our implementation is provided for research and educational purposes.
