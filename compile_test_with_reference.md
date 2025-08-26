# Compiling the Reference Integration Test

## Overview
The enhanced `compare_steps_1_5.c` file now includes comprehensive testing against the actual reference implementation functions from the `mceliece6688128/` directory.

## Required Files from Reference Implementation
You need to link against these files from the `mceliece6688128/` directory:

### Core Reference Files:
- `mceliece6688128/sk_gen.c` - Contains `genpoly_gen()` function
- `mceliece6688128/pk_gen.c` - Contains `pk_gen()` function  
- `mceliece6688128/operations.c` - Contains key generation functions

### Supporting Reference Files:
- `mceliece6688128/gf.c` - Galois field operations
- `mceliece6688128/benes.c` - Benes network functions
- `mceliece6688128/controlbits.c` - Control bits generation
- `mceliece6688128/uint64_sort.c` - Sorting utilities
- `mceliece6688128/root.c` - Root finding
- `mceliece6688128/util.c` - Utility functions

## Compilation Example

```bash
# Compile the test with reference implementation
gcc -I. -Imceliece6688128/ -O2 -o test_reference_integration \
    compare_steps_1_5.c \
    reference_shake.c \
    mceliece_genpoly.c \
    mceliece_keygen.c \
    mceliece_shake.c \
    mceliece_gf.c \
    mceliece_poly.c \
    mceliece_matrix_ops.c \
    mceliece6688128/sk_gen.c \
    mceliece6688128/pk_gen.c \
    mceliece6688128/gf.c \
    mceliece6688128/benes.c \
    mceliece6688128/controlbits.c \
    mceliece6688128/uint64_sort.c \
    mceliece6688128/root.c \
    mceliece6688128/util.c \
    mceliece6688128/crypto_declassify.c \
    -lm
```

## What the Test Does

### Test 1: Direct genpoly_gen Comparison
- Extracts the same irreducible polynomial input data used by both implementations
- Calls the reference `genpoly_gen()` function directly with this data
- Calls our `generate_irreducible_poly_final()` function with the same data
- Compares the results coefficient by coefficient

### Test 2: Field Ordering Verification  
- Tests our `generate_field_ordering()` function
- Verifies no duplicate alpha values are generated
- Checks the field ordering properties

### Test 3: Integration with Reference pk_gen
- Uses our generated Goppa polynomial and field ordering data
- Formats the data according to reference implementation requirements
- Calls the reference `pk_gen()` function to verify compatibility
- This is the ultimate test - if `pk_gen()` succeeds, our data is correct

## Expected Results

If your implementation is correct, you should see:
- ✅ IRREDUCIBLE POLYNOMIAL EXACT MATCH with reference genpoly_gen!
- ✅ Field ordering has no duplicates - VERIFIED!  
- ✅ INTEGRATION TEST PASSED - reference pk_gen succeeded with our data!

## Troubleshooting

### Missing Function Errors
If you get "undefined reference" errors for reference functions, make sure you're linking against all the required reference implementation files.

### Header File Issues
Make sure your include paths are set correctly to find both your headers and the reference implementation headers.

### Parameter Mismatches
The reference implementation uses specific data types (`gf`, `uint16_t`) - the test code handles the conversion between your types and reference types.

## Alternative: Modify operations.c
Instead of separate compilation, you could also modify `mceliece6688128/operations.c` to add test functions that call your implementation functions and compare results directly.
