#include "function_profiler.h"
#include <string.h>
#include <stdlib.h>

// Global profiler instance
profiler_t g_profiler = {0};

void profiler_init(void) {
    memset(&g_profiler, 0, sizeof(g_profiler));
    g_profiler.enabled = 1;
    g_profiler.session_start_time_ms = get_time_ms();
}

void profiler_start_session(const char* category) {
    if (!g_profiler.enabled) return;
    
    g_profiler.current_category = category;
    g_profiler.session_start_time_ms = get_time_ms();
    g_profiler.current_depth = 0;
    
    printf("🔍 Starting %s profiling session...\n", category);
}

void profiler_end_session(void) {
    if (!g_profiler.enabled) return;
    
    double session_duration = get_time_ms() - g_profiler.session_start_time_ms;
    printf("✅ %s session completed in %.3f ms\n", 
           g_profiler.current_category ? g_profiler.current_category : "unknown", 
           session_duration);
}

void profiler_enable(void) {
    g_profiler.enabled = 1;
}

void profiler_disable(void) {
    g_profiler.enabled = 0;
}

void profiler_function_enter(const char* function_name) {
    if (!g_profiler.enabled || g_profiler.call_count >= MAX_FUNCTION_CALLS) return;
    
    function_call_t* call = &g_profiler.calls[g_profiler.call_count];
    call->function_name = function_name;
    call->category = g_profiler.current_category;
    call->start_time_ms = get_time_ms();
    call->call_order = g_profiler.call_count;
    call->depth = g_profiler.current_depth;
    call->duration_ms = 0; // Will be set on exit
    
    g_profiler.current_depth++;
    g_profiler.call_count++;
}

void profiler_function_exit(const char* function_name) {
    if (!g_profiler.enabled || g_profiler.call_count == 0) return;
    
    double exit_time = get_time_ms();
    g_profiler.current_depth--;
    
    // Find the most recent call to this function
    for (int i = g_profiler.call_count - 1; i >= 0; i--) {
        function_call_t* call = &g_profiler.calls[i];
        if (strcmp(call->function_name, function_name) == 0 && call->duration_ms == 0) {
            call->duration_ms = exit_time - call->start_time_ms;
            break;
        }
    }
}

void profiler_print_report(void) {
    if (!g_profiler.enabled) {
        printf("Profiler is disabled\n");
        return;
    }
    
    printf("\n============================================================\n");
    printf("DETAILED FUNCTION PROFILING REPORT\n");
    printf("============================================================\n");
    printf("Total functions traced: %d\n\n", g_profiler.call_count);
    
    const char* current_category = "";
    for (int i = 0; i < g_profiler.call_count; i++) {
        function_call_t* call = &g_profiler.calls[i];
        
        // Print category header if changed
        if (call->category && strcmp(current_category, call->category) != 0) {
            current_category = call->category;
            printf("\n📋 %s PHASE:\n", current_category);
            printf("----------------------------------------\n");
        }
        
        // Print indentation based on call depth
        for (int d = 0; d < call->depth; d++) {
            printf("  ");
        }
        
        // Print function timing
        printf("%3d. %-30s %8.3f ms", 
               call->call_order + 1,
               call->function_name, 
               call->duration_ms);
        
        // Add timing indicators
        if (call->duration_ms > 1000.0) {
            printf(" 🐌 (slow)");
        } else if (call->duration_ms > 100.0) {
            printf(" ⚠️  (moderate)");
        } else if (call->duration_ms < 1.0) {
            printf(" ⚡ (fast)");
        }
        
        printf("\n");
    }
    
    printf("\n");
}

void profiler_print_summary(void) {
    if (!g_profiler.enabled || g_profiler.call_count == 0) return;
    
    printf("\n📊 PROFILING SUMMARY\n");
    printf("==============================\n");
    
    // Group by category
    const char* categories[] = {"keygen", "encap", "decap", NULL};
    
    for (int cat = 0; categories[cat]; cat++) {
        const char* category = categories[cat];
        double total_time = 0;
        int count = 0;
        double max_time = 0;
        const char* slowest_function = "";
        
        for (int i = 0; i < g_profiler.call_count; i++) {
            function_call_t* call = &g_profiler.calls[i];
            if (call->category && strcmp(call->category, category) == 0) {
                total_time += call->duration_ms;
                count++;
                if (call->duration_ms > max_time) {
                    max_time = call->duration_ms;
                    slowest_function = call->function_name;
                }
            }
        }
        
        if (count > 0) {
            printf("%s: %.3f ms (%d calls)\n", category, total_time, count);
            printf("  Slowest: %s (%.3f ms)\n", slowest_function, max_time);
        }
    }
    
    // Overall stats
    double total_session_time = 0;
    for (int i = 0; i < g_profiler.call_count; i++) {
        total_session_time += g_profiler.calls[i].duration_ms;
    }
    
    printf("\nTotal measured time: %.3f ms\n", total_session_time);
    printf("Functions called: %d\n", g_profiler.call_count);
    printf("Average per function: %.3f ms\n", 
           g_profiler.call_count > 0 ? total_session_time / g_profiler.call_count : 0);
}

void profiler_save_csv(const char* filename) {
    if (!g_profiler.enabled) return;
    
    FILE* f = fopen(filename, "w");
    if (!f) {
        printf("Error: Could not open %s for writing\n", filename);
        return;
    }
    
    fprintf(f, "order,function_name,category,duration_ms,depth,start_time_ms\n");
    
    for (int i = 0; i < g_profiler.call_count; i++) {
        function_call_t* call = &g_profiler.calls[i];
        fprintf(f, "%d,%s,%s,%.6f,%d,%.6f\n",
                call->call_order,
                call->function_name,
                call->category ? call->category : "unknown",
                call->duration_ms,
                call->depth,
                call->start_time_ms);
    }
    
    fclose(f);
    printf("📁 Detailed profiling data saved to %s\n", filename);
}
