#include "hierarchical_profiler.h"
#include <stdio.h>
#include <string.h>

// Structure to represent call graph hierarchy
typedef struct call_graph_node {
    const char* function_name;
    const char* phase;
    int depth;
    double time_ms;
    int call_count;
} call_graph_node_t;

// Call graph structure based on the provided call graphs
static call_graph_node_t our_call_graph[] = {
    // KAT Top Level
    {"run_kat_file", "kat", 0, 0, 0},
    
    // Key Generation Hierarchy
    {"mceliece_keygen", "keygen", 1, 0, 0},
    {"seeded_key_gen", "keygen", 2, 0, 0},
    {"kat_expand_r", "keygen", 3, 0, 0},
    {"generate_irreducible_poly_final", "keygen", 3, 0, 0},
    {"gf_init", "keygen", 4, 0, 0},
    {"genpoly_gen", "keygen", 4, 0, 0},
    {"polynomial_set_coeff", "keygen", 4, 0, 0},
    {"generate_field_ordering", "keygen", 3, 0, 0},
    {"qsort", "keygen", 4, 0, 0},
    {"bitrev_m_u16", "keygen", 4, 0, 0},
    {"build_parity_check_matrix_reference_style", "keygen", 3, 0, 0},
    {"reduce_to_systematic_form_reference_style", "keygen", 3, 0, 0},
    {"cbits_from_perm_ns", "keygen", 3, 0, 0},
    
    // Encapsulation Hierarchy
    {"mceliece_encap", "encap", 1, 0, 0},
    {"gen_e_pqclean", "encap", 2, 0, 0},
    {"kat_drbg_randombytes", "encap", 3, 0, 0},
    {"pqclean_load_gf_le", "encap", 3, 0, 0},
    {"encode_vector", "encap", 2, 0, 0},
    {"shake256", "encap", 2, 0, 0},
    
    // Decapsulation Hierarchy
    {"mceliece_decap", "decap", 1, 0, 0},
    {"build_v_vector", "decap", 2, 0, 0},
    {"support_from_cbits", "decap", 2, 0, 0},
    {"decode_goppa", "decap", 2, 0, 0},
    {"compute_syndrome", "decap", 3, 0, 0},
    {"berlekamp_massey", "decap", 3, 0, 0},
    {"chien_search", "decap", 3, 0, 0},
    {"shake256", "decap", 2, 0, 0},
};

static call_graph_node_t ref_call_graph[] = {
    // Reference Key Generation
    {"ref_crypto_kem_keypair", "ref_keygen", 0, 0, 0},
    {"ref_shake", "ref_keygen", 1, 0, 0},
    {"ref_genpoly_gen", "ref_keygen", 1, 0, 0},
    {"ref_pk_gen", "ref_keygen", 1, 0, 0},
    {"ref_uint64_sort", "ref_keygen", 2, 0, 0},
    {"ref_root", "ref_keygen", 2, 0, 0},
    {"ref_controlbitsfrompermutation", "ref_keygen", 1, 0, 0},
    
    // Reference Encapsulation
    {"ref_crypto_kem_enc", "ref_encap", 0, 0, 0},
    {"ref_encrypt", "ref_encap", 1, 0, 0},
    {"ref_gen_e", "ref_encap", 2, 0, 0},
    {"ref_syndrome", "ref_encap", 2, 0, 0},
    {"ref_crypto_hash_32b", "ref_encap", 1, 0, 0},
    
    // Reference Decapsulation
    {"ref_crypto_kem_dec", "ref_decap", 0, 0, 0},
    {"ref_decrypt", "ref_decap", 1, 0, 0},
    {"ref_crypto_hash_32b", "ref_decap", 1, 0, 0},
};

static const int our_call_graph_size = sizeof(our_call_graph) / sizeof(our_call_graph[0]);
static const int ref_call_graph_size = sizeof(ref_call_graph) / sizeof(ref_call_graph[0]);

// Update call graph data with actual timing results
static void update_call_graph_timing(call_graph_node_t* graph, int size) {
    for (int i = 0; i < size; i++) {
        // Find corresponding function in profiler data
        for (int j = 0; j < g_profiler.call_count; j++) {
            if (strcmp(graph[i].function_name, g_profiler.calls[j].function_name) == 0) {
                graph[i].time_ms = g_profiler.calls[j].duration_ms;
                graph[i].call_count = 1;
                break;
            }
        }
    }
}

void profiler_print_hierarchical_report(void) {
    printf("\n🌳 HIERARCHICAL CALL GRAPH ANALYSIS\n");
    printf("============================================================\n");
    
    // Update timing data
    update_call_graph_timing(our_call_graph, our_call_graph_size);
    
    const char* current_phase = "";
    
    for (int i = 0; i < our_call_graph_size; i++) {
        call_graph_node_t* node = &our_call_graph[i];
        
        // Print phase header if changed
        if (strcmp(current_phase, node->phase) != 0) {
            current_phase = node->phase;
            printf("\n📋 %s PHASE:\n", current_phase);
            printf("----------------------------------------\n");
        }
        
        // Print indentation based on call depth
        for (int d = 0; d < node->depth; d++) {
            printf("  ");
        }
        
        // Print function with timing
        if (node->time_ms > 0) {
            printf("├─ %-35s %8.3f ms", node->function_name, node->time_ms);
            
            // Add timing indicators
            if (node->time_ms > 1000.0) {
                printf(" 🐌");
            } else if (node->time_ms > 100.0) {
                printf(" ⚠️");
            } else if (node->time_ms < 1.0) {
                printf(" ⚡");
            }
        } else {
            printf("├─ %-35s %8s", node->function_name, "not timed");
        }
        printf("\n");
    }
}

void profiler_print_call_graph_comparison(void) {
    printf("\n⚖️  CALL GRAPH COMPARISON (Our vs Reference)\n");
    printf("======================================================================\n");
    
    // Update timing data
    update_call_graph_timing(our_call_graph, our_call_graph_size);
    update_call_graph_timing(ref_call_graph, ref_call_graph_size);
    
    // Group by phases and compare
    const char* phases[][2] = {
        {"keygen", "ref_keygen"},
        {"encap", "ref_encap"},
        {"decap", "ref_decap"}
    };
    
    for (int p = 0; p < 3; p++) {
        const char* our_phase = phases[p][0];
        const char* ref_phase = phases[p][1];
        
        printf("\n🔍 %s PHASE COMPARISON:\n", our_phase);
        printf("--------------------------------------------------\n");
        
        // Find matching functions
        printf("%-35s | %-12s | %-12s | %s\n", "Function", "Our (ms)", "Ref (ms)", "Ratio");
        printf("---------------------------------------------------------------------------\n");
        
        // Print our functions
        for (int i = 0; i < our_call_graph_size; i++) {
            if (strcmp(our_call_graph[i].phase, our_phase) == 0 && our_call_graph[i].time_ms > 0) {
                printf("%-35s | %8.3f    | %8s    | %s\n", 
                       our_call_graph[i].function_name,
                       our_call_graph[i].time_ms,
                       "---",
                       "our only");
            }
        }
        
        // Print reference functions
        for (int i = 0; i < ref_call_graph_size; i++) {
            if (strcmp(ref_call_graph[i].phase, ref_phase) == 0 && ref_call_graph[i].time_ms > 0) {
                printf("%-35s | %8s    | %8.3f    | %s\n", 
                       ref_call_graph[i].function_name,
                       "---",
                       ref_call_graph[i].time_ms,
                       "ref only");
            }
        }
    }
}

void profiler_save_call_graph_csv(const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) {
        printf("Error: Could not open %s for writing\n", filename);
        return;
    }
    
    fprintf(f, "# Classic McEliece Call Graph Analysis\n");
    fprintf(f, "implementation,function_name,phase,depth,time_ms,call_count\n");
    
    // Update timing data
    update_call_graph_timing(our_call_graph, our_call_graph_size);
    update_call_graph_timing(ref_call_graph, ref_call_graph_size);
    
    // Write our implementation data
    for (int i = 0; i < our_call_graph_size; i++) {
        call_graph_node_t* node = &our_call_graph[i];
        fprintf(f, "our,%s,%s,%d,%.6f,%d\n",
                node->function_name,
                node->phase,
                node->depth,
                node->time_ms,
                node->call_count);
    }
    
    // Write reference implementation data
    for (int i = 0; i < ref_call_graph_size; i++) {
        call_graph_node_t* node = &ref_call_graph[i];
        fprintf(f, "reference,%s,%s,%d,%.6f,%d\n",
                node->function_name,
                node->phase,
                node->depth,
                node->time_ms,
                node->call_count);
    }
    
    fclose(f);
    printf("📁 Call graph analysis saved to %s\n", filename);
}
