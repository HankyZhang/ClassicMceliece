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

# Early steps comparison test
add_executable(compare_early_steps compare_early_steps.c mceliece_gf.c mceliece_shake.c mceliece_poly.c mceliece_matrix_ops.c mceliece_vector.c mceliece_keygen.c mceliece_encode.c mceliece_decode.c mceliece_kem.c mceliece_genpoly.c kat_drbg.c rng.c controlbits.c)
target_include_directories(compare_early_steps PRIVATE .)
if(UNIX)
    target_link_libraries(compare_early_steps m)
endif()

# New SHAKE implementation test
add_executable(test_new_shake test_new_shake.c mceliece_shake.c)
target_include_directories(test_new_shake PRIVATE .)
if(UNIX)
    target_link_libraries(test_new_shake m)
endif()

# SHAKE implementation comparison test
add_executable(test_shake_comparison test_shake_comparison.c mceliece_shake.c reference_shake.c)
target_include_directories(test_shake_comparison PRIVATE .)
if(UNIX)
    target_link_libraries(test_shake_comparison m)
endif()

# Compare Steps 1-5 test
add_executable(compare_steps_1_5 compare_steps_1_5.c mceliece_gf.c mceliece_shake.c reference_shake.c mceliece_poly.c mceliece_matrix_ops.c mceliece_vector.c mceliece_keygen.c mceliece_encode.c mceliece_decode.c mceliece_kem.c mceliece_genpoly.c kat_drbg.c rng.c controlbits.c)
target_include_directories(compare_steps_1_5 PRIVATE .)
if(UNIX)
    target_link_libraries(compare_steps_1_5 m)
endif()

