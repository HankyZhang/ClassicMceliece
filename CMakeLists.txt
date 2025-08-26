cmake_minimum_required(VERSION 3.20)
project(ClassicMceliece C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2")

# Source files
set(SOURCES
    main.c
    mceliece_gf.c
    mceliece_shake.c
    mceliece_poly.c
    mceliece_matrix_ops.c
    mceliece_vector.c
    mceliece_keygen.c
    mceliece_encode.c
    mceliece_decode.c
    mceliece_kem.c
    mceliece_genpoly.c
    kat_drbg.c
    rng.c
    controlbits.c
)

# Header files (for IDE)
set(HEADERS
    mceliece_types.h
    mceliece_gf.h
    mceliece_shake.h
    mceliece_poly.h
    mceliece_matrix_ops.h
    mceliece_vector.h
    mceliece_keygen.h
    mceliece_encode.h
    mceliece_decode.h
    mceliece_kem.h
    mceliece_genpoly.h
    kat_drbg.h
    rng.h
    controlbits.h
)

# Create the executable
add_executable(ClassicMceliece ${SOURCES} ${HEADERS})

# Include current directory for header files
target_include_directories(ClassicMceliece PRIVATE .)

# Math library on Unix systems
if(UNIX)
    target_link_libraries(ClassicMceliece m)
endif()

# Steps 1-5 Testing Targets

# Re-enable compare_steps_1_5 test target for KAT-style function-by-function checks
add_executable(compare_steps_1_5
    compare_steps_1_5.c
    mceliece_gf.c mceliece_shake.c reference_shake.c mceliece_poly.c mceliece_matrix_ops.c mceliece_vector.c mceliece_keygen.c mceliece_encode.c mceliece_decode.c mceliece_kem.c mceliece_genpoly.c kat_drbg.c rng.c controlbits.c
    # Reference implementation sources
    mceliece6688128/sk_gen.c
    mceliece6688128/pk_gen.c
    mceliece6688128/gf.c
    mceliece6688128/benes.c
    mceliece6688128/controlbits.c
    mceliece6688128/root.c
    mceliece6688128/util.c
    mceliece6688128/transpose.c
)

# Ensure reference sources are namespaced as ref_* and enable test comparisons
target_compile_definitions(compare_steps_1_5 PRIVATE "CRYPTO_NAMESPACE(x)=ref_##x" ENABLE_REFERENCE_TESTS=1)

target_include_directories(compare_steps_1_5 PRIVATE .)
# Reference headers
target_include_directories(compare_steps_1_5 PRIVATE mceliece6688128 mceliece6688128/subroutines)
if(UNIX)
    target_link_libraries(compare_steps_1_5 m)
endif()

