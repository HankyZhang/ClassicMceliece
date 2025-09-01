#ifndef HIERARCHICAL_PROFILER_H
#define HIERARCHICAL_PROFILER_H

#include "function_profiler.h"

// Enhanced profiler that tracks the exact call hierarchy from the call graphs

// Macro to automatically profile functions based on call graph
#define PROFILE_FUNC_AUTO() \
    profiler_function_enter(__FUNCTION__); \
    struct AutoProfiler { \
        const char* name; \
        AutoProfiler(const char* n) : name(n) {} \
        ~AutoProfiler() { profiler_function_exit(name); } \
    } _auto_prof(__FUNCTION__)

// Specific profiling macros for each call graph layer

// === OUR IMPLEMENTATION CALL GRAPH PROFILING ===

// Top level KAT functions
#define PROFILE_RUN_KAT_FILE_START() PROFILE_START("run_kat_file")
#define PROFILE_RUN_KAT_FILE_END() PROFILE_END("run_kat_file")

// Key generation hierarchy
#define PROFILE_MCELIECE_KEYGEN_START() PROFILE_START("mceliece_keygen")
#define PROFILE_MCELIECE_KEYGEN_END() PROFILE_END("mceliece_keygen")

#define PROFILE_SEEDED_KEY_GEN_START() PROFILE_START("seeded_key_gen")
#define PROFILE_SEEDED_KEY_GEN_END() PROFILE_END("seeded_key_gen")

#define PROFILE_KAT_EXPAND_R_START() PROFILE_START("kat_expand_r")
#define PROFILE_KAT_EXPAND_R_END() PROFILE_END("kat_expand_r")

#define PROFILE_GENERATE_IRREDUCIBLE_POLY_START() PROFILE_START("generate_irreducible_poly_final")
#define PROFILE_GENERATE_IRREDUCIBLE_POLY_END() PROFILE_END("generate_irreducible_poly_final")

#define PROFILE_GENPOLY_GEN_START() PROFILE_START("genpoly_gen")
#define PROFILE_GENPOLY_GEN_END() PROFILE_END("genpoly_gen")

#define PROFILE_GENERATE_FIELD_ORDERING_START() PROFILE_START("generate_field_ordering")
#define PROFILE_GENERATE_FIELD_ORDERING_END() PROFILE_END("generate_field_ordering")

#define PROFILE_QSORT_START() PROFILE_START("qsort")
#define PROFILE_QSORT_END() PROFILE_END("qsort")

#define PROFILE_BUILD_PARITY_CHECK_MATRIX_START() PROFILE_START("build_parity_check_matrix_reference_style")
#define PROFILE_BUILD_PARITY_CHECK_MATRIX_END() PROFILE_END("build_parity_check_matrix_reference_style")

#define PROFILE_REDUCE_TO_SYSTEMATIC_FORM_START() PROFILE_START("reduce_to_systematic_form_reference_style")
#define PROFILE_REDUCE_TO_SYSTEMATIC_FORM_END() PROFILE_END("reduce_to_systematic_form_reference_style")

#define PROFILE_CBITS_FROM_PERM_START() PROFILE_START("cbits_from_perm_ns")
#define PROFILE_CBITS_FROM_PERM_END() PROFILE_END("cbits_from_perm_ns")

// Encapsulation hierarchy
#define PROFILE_MCELIECE_ENCAP_START() PROFILE_START("mceliece_encap")
#define PROFILE_MCELIECE_ENCAP_END() PROFILE_END("mceliece_encap")

#define PROFILE_GEN_E_PQCLEAN_START() PROFILE_START("gen_e_pqclean")
#define PROFILE_GEN_E_PQCLEAN_END() PROFILE_END("gen_e_pqclean")

#define PROFILE_ENCODE_VECTOR_START() PROFILE_START("encode_vector")
#define PROFILE_ENCODE_VECTOR_END() PROFILE_END("encode_vector")

#define PROFILE_SHAKE256_START() PROFILE_START("shake256")
#define PROFILE_SHAKE256_END() PROFILE_END("shake256")

// Decapsulation hierarchy
#define PROFILE_MCELIECE_DECAP_START() PROFILE_START("mceliece_decap")
#define PROFILE_MCELIECE_DECAP_END() PROFILE_END("mceliece_decap")

#define PROFILE_DECODE_GOPPA_START() PROFILE_START("decode_goppa")
#define PROFILE_DECODE_GOPPA_END() PROFILE_END("decode_goppa")

#define PROFILE_COMPUTE_SYNDROME_START() PROFILE_START("compute_syndrome")
#define PROFILE_COMPUTE_SYNDROME_END() PROFILE_END("compute_syndrome")

#define PROFILE_BERLEKAMP_MASSEY_START() PROFILE_START("berlekamp_massey")
#define PROFILE_BERLEKAMP_MASSEY_END() PROFILE_END("berlekamp_massey")

#define PROFILE_CHIEN_SEARCH_START() PROFILE_START("chien_search")
#define PROFILE_CHIEN_SEARCH_END() PROFILE_END("chien_search")

// === REFERENCE IMPLEMENTATION CALL GRAPH PROFILING ===

// Reference key generation
#define PROFILE_REF_CRYPTO_KEM_KEYPAIR_START() PROFILE_START("ref_crypto_kem_keypair")
#define PROFILE_REF_CRYPTO_KEM_KEYPAIR_END() PROFILE_END("ref_crypto_kem_keypair")

#define PROFILE_REF_SHAKE_START() PROFILE_START("ref_shake")
#define PROFILE_REF_SHAKE_END() PROFILE_END("ref_shake")

#define PROFILE_REF_GENPOLY_GEN_START() PROFILE_START("ref_genpoly_gen")
#define PROFILE_REF_GENPOLY_GEN_END() PROFILE_END("ref_genpoly_gen")

#define PROFILE_REF_PK_GEN_START() PROFILE_START("ref_pk_gen")
#define PROFILE_REF_PK_GEN_END() PROFILE_END("ref_pk_gen")

#define PROFILE_REF_UINT64_SORT_START() PROFILE_START("ref_uint64_sort")
#define PROFILE_REF_UINT64_SORT_END() PROFILE_END("ref_uint64_sort")

#define PROFILE_REF_ROOT_START() PROFILE_START("ref_root")
#define PROFILE_REF_ROOT_END() PROFILE_END("ref_root")

#define PROFILE_REF_CONTROLBITS_START() PROFILE_START("ref_controlbitsfrompermutation")
#define PROFILE_REF_CONTROLBITS_END() PROFILE_END("ref_controlbitsfrompermutation")

// Reference encapsulation
#define PROFILE_REF_CRYPTO_KEM_ENC_START() PROFILE_START("ref_crypto_kem_enc")
#define PROFILE_REF_CRYPTO_KEM_ENC_END() PROFILE_END("ref_crypto_kem_enc")

#define PROFILE_REF_ENCRYPT_START() PROFILE_START("ref_encrypt")
#define PROFILE_REF_ENCRYPT_END() PROFILE_END("ref_encrypt")

#define PROFILE_REF_GEN_E_START() PROFILE_START("ref_gen_e")
#define PROFILE_REF_GEN_E_END() PROFILE_END("ref_gen_e")

#define PROFILE_REF_SYNDROME_START() PROFILE_START("ref_syndrome")
#define PROFILE_REF_SYNDROME_END() PROFILE_END("ref_syndrome")

#define PROFILE_REF_CRYPTO_HASH_START() PROFILE_START("ref_crypto_hash_32b")
#define PROFILE_REF_CRYPTO_HASH_END() PROFILE_END("ref_crypto_hash_32b")

// Reference decapsulation
#define PROFILE_REF_CRYPTO_KEM_DEC_START() PROFILE_START("ref_crypto_kem_dec")
#define PROFILE_REF_CRYPTO_KEM_DEC_END() PROFILE_END("ref_crypto_kem_dec")

#define PROFILE_REF_DECRYPT_START() PROFILE_START("ref_decrypt")
#define PROFILE_REF_DECRYPT_END() PROFILE_END("ref_decrypt")

// Helper function to print hierarchical report based on call graphs
void profiler_print_hierarchical_report(void);
void profiler_print_call_graph_comparison(void);

// Function to save call graph timing to detailed CSV
void profiler_save_call_graph_csv(const char* filename);

#endif // HIERARCHICAL_PROFILER_H
