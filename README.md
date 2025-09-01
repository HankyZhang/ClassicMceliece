# Classic McEliece (Organized)

This repository contains a clean, minimal layout of a Classic McEliece KEM implementation, a deterministic KAT runner, and a call-runtime profiling tool.

## Repository layout

- `src/` – Complete implementation (self-contained, no external reference dependencies)
- `tests/kat/` – KAT runner and sample request data
  - `run_kat.c` – small driver that calls `run_kat_file()`
  - `data/kat_kem.req` – request file for KAT tests
- `tools/call_runtime/` – Call-graph runtime profiling tool
- `mceliece6688128/` – Reference tree retained for documentation only (GF headers and other sources remain; KAT artifacts removed)
- `iso-mceliece-20230419.pdf` – Parameter/spec reference
- `Classic McEliece Algorithm Explained in Detail.md` – Implementation notes

## Build

This repo is intentionally minimal and does not include a top-level build system anymore. You can build the two executables directly with clang or gcc:

### 1) Build the call-runtime tool

```bash
cc \
  -O2 -Wall -Wextra \
  -Isrc -Itools/call_runtime \
  tools/call_runtime/call_graph_benchmark.c \
  tools/call_runtime/function_profiler.c \
  tools/call_runtime/hierarchical_profiler.c \
  src/mceliece_gf.c src/mceliece_shake.c src/mceliece_poly.c \
  src/mceliece_matrix_ops.c src/mceliece_vector.c src/mceliece_keygen.c \
  src/mceliece_encode.c src/mceliece_decode.c src/mceliece_kem.c \
  src/mceliece_genpoly.c src/kat_drbg.c src/rng.c src/controlbits.c \
  -o call_graph_benchmark -lm
```

Run (examples):

```bash
./call_graph_benchmark -n 1
./call_graph_benchmark -n 3 -q
```

### 2) Build the KAT runner

```bash
cc \
  -O2 -Wall -Wextra \
  -Isrc \
  tests/kat/run_kat.c \
  src/mceliece_gf.c src/mceliece_shake.c src/mceliece_poly.c \
  src/mceliece_matrix_ops.c src/mceliece_vector.c src/mceliece_keygen.c \
  src/mceliece_encode.c src/mceliece_decode.c src/mceliece_kem.c \
  src/mceliece_genpoly.c src/kat_drbg.c src/rng.c src/controlbits.c \
  -o run_kat -lm
```

Run:

```bash
./run_kat
# Writes our_kat_output.rsp in the current directory
```

If you moved `tests/kat/data` elsewhere, pass explicit paths to `run_kat_file(req, rsp)` in `tests/kat/run_kat.c`.

## Deterministic KAT testing

- Source: `src/mceliece_kem.c` provides `run_kat_file(req, rsp)`.
- Provided request file: `tests/kat/data/kat_kem.req`.
- Output file: `our_kat_output.rsp`.

The DRBG in `src/kat_drbg.c` is initialized per-seed lines from the request, ensuring deterministic output.

## Implementation notes

- GF arithmetic: `src/mceliece_gf.c` implements GF(2^13) using a polynomial-basis (irreducible poly `x^13 + x^4 + x^3 + x + 1`).
- Hashing/PRG: `src/mceliece_shake.c` provides SHAKE256, `mceliece_prg`, and `mceliece_hash`.
- Core KEM API:
  - `mceliece_keygen`, `mceliece_encap`, `mceliece_decap` in `src/mceliece_kem.c`.
- Matrices/vectors and Goppa operations are in `src/mceliece_matrix_ops.c`, `src/mceliece_vector.c`, `src/mceliece_poly.c`, `src/mceliece_decode.c`, `src/mceliece_encode.c`, and `src/mceliece_genpoly.c`.

## Reproducing tests quickly

- Quick call-runtime profiling:
```bash
./call_graph_benchmark -n 1
```
- KAT generation:
```bash
./run_kat
ls -l our_kat_output.rsp
```

## Notes

- The reference folder `mceliece6688128/` is kept for context; KAT artifacts and `gf.c` were removed.
- If you prefer a Makefile or CMake again, you can reintroduce one using the compile lines above.

## Windows

### Option 1: WSL (recommended)

- Install WSL (Ubuntu), then run the same Linux commands from this README.
- Build examples:

```bash
cc -O2 -Wall -Wextra -Isrc -Itools/call_runtime \
  tools/call_runtime/call_graph_benchmark.c \
  tools/call_runtime/function_profiler.c \
  tools/call_runtime/hierarchical_profiler.c \
  src/*.c -o call_graph_benchmark -lm

cc -O2 -Wall -Wextra -Isrc \
  tests/kat/run_kat.c src/*.c -o run_kat -lm
```

### Option 2: MSYS2/MinGW-w64 (native Windows)

- Install MSYS2, open “MSYS2 MinGW x64” shell, then:

```bash
pacman -S --needed base-devel mingw-w64-x86_64-toolchain
gcc -O2 -Wall -Wextra -Isrc -Itools/call_runtime \
  tools/call_runtime/call_graph_benchmark.c \
  tools/call_runtime/function_profiler.c \
  tools/call_runtime/hierarchical_profiler.c \
  src/*.c -o call_graph_benchmark -lm
gcc -O2 -Wall -Wextra -Isrc \
  tests/kat/run_kat.c src/*.c -o run_kat -lm
```

### Option 3: Visual Studio (MSVC)

- Replace POSIX-specific pieces used by the runtime tool:
  - `tools/call_runtime/function_profiler.h`: implement `get_time_ms()` with QueryPerformanceCounter under `_WIN32`.
  - `tools/call_runtime/call_graph_benchmark.c`: replace `getopt`/`unistd.h` with a minimal argv parser or compile this tool under WSL/MSYS2.
- Create a VS project, add all files from `src/` and the three sources in `tools/call_runtime/`, and set include paths to `src` and `tools/call_runtime`.


