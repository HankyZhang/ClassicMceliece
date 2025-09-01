#ifndef HIERARCHICAL_PROFILER_STUB_H
#define HIERARCHICAL_PROFILER_STUB_H

// Stubbed profiler header for core library builds.
// Defines no-op macros so core code can include profiling hooks without dependency.

#define PROFILE_START(name) do {} while (0)
#define PROFILE_END(name) do {} while (0)

#define PROFILE_RUN_KAT_FILE_START() do {} while (0)
#define PROFILE_RUN_KAT_FILE_END() do {} while (0)

#define PROFILE_MCELIECE_KEYGEN_START() do {} while (0)
#define PROFILE_MCELIECE_KEYGEN_END() do {} while (0)

#define PROFILE_SEEDED_KEY_GEN_START() do {} while (0)
#define PROFILE_SEEDED_KEY_GEN_END() do {} while (0)

#define PROFILE_KAT_EXPAND_R_START() do {} while (0)
#define PROFILE_KAT_EXPAND_R_END() do {} while (0)

#define PROFILE_GENERATE_IRREDUCIBLE_POLY_START() do {} while (0)
#define PROFILE_GENERATE_IRREDUCIBLE_POLY_END() do {} while (0)

#define PROFILE_GENPOLY_GEN_START() do {} while (0)
#define PROFILE_GENPOLY_GEN_END() do {} while (0)

#define PROFILE_GENERATE_FIELD_ORDERING_START() do {} while (0)
#define PROFILE_GENERATE_FIELD_ORDERING_END() do {} while (0)

#define PROFILE_QSORT_START() do {} while (0)
#define PROFILE_QSORT_END() do {} while (0)

#define PROFILE_BUILD_PARITY_CHECK_MATRIX_START() do {} while (0)
#define PROFILE_BUILD_PARITY_CHECK_MATRIX_END() do {} while (0)

#define PROFILE_REDUCE_TO_SYSTEMATIC_FORM_START() do {} while (0)
#define PROFILE_REDUCE_TO_SYSTEMATIC_FORM_END() do {} while (0)

#define PROFILE_CBITS_FROM_PERM_START() do {} while (0)
#define PROFILE_CBITS_FROM_PERM_END() do {} while (0)

#define PROFILE_MCELIECE_ENCAP_START() do {} while (0)
#define PROFILE_MCELIECE_ENCAP_END() do {} while (0)

#define PROFILE_GEN_E_PQCLEAN_START() do {} while (0)
#define PROFILE_GEN_E_PQCLEAN_END() do {} while (0)

#define PROFILE_ENCODE_VECTOR_START() do {} while (0)
#define PROFILE_ENCODE_VECTOR_END() do {} while (0)

#define PROFILE_SHAKE256_START() do {} while (0)
#define PROFILE_SHAKE256_END() do {} while (0)

#define PROFILE_MCELIECE_DECAP_START() do {} while (0)
#define PROFILE_MCELIECE_DECAP_END() do {} while (0)

#define PROFILE_DECODE_GOPPA_START() do {} while (0)
#define PROFILE_DECODE_GOPPA_END() do {} while (0)

#define PROFILE_COMPUTE_SYNDROME_START() do {} while (0)
#define PROFILE_COMPUTE_SYNDROME_END() do {} while (0)

#define PROFILE_BERLEKAMP_MASSEY_START() do {} while (0)
#define PROFILE_BERLEKAMP_MASSEY_END() do {} while (0)

#define PROFILE_CHIEN_SEARCH_START() do {} while (0)
#define PROFILE_CHIEN_SEARCH_END() do {} while (0)

#endif // HIERARCHICAL_PROFILER_STUB_H


