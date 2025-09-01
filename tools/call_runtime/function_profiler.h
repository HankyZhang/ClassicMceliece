#ifndef FUNCTION_PROFILER_H
#define FUNCTION_PROFILER_H

#include <stdint.h>
#include <time.h>
#include <stdio.h>

// Maximum number of function calls to track
#define MAX_FUNCTION_CALLS 1000

// Function call record
typedef struct {
    const char* function_name;
    const char* category;      // "keygen", "encap", "decap"
    double start_time_ms;
    double duration_ms;
    int call_order;
    int depth;                 // Call stack depth for indentation
} function_call_t;

// Profiler state
typedef struct {
    function_call_t calls[MAX_FUNCTION_CALLS];
    int call_count;
    int current_depth;
    double session_start_time_ms;
    const char* current_category;
    int enabled;
} profiler_t;

// Global profiler instance
extern profiler_t g_profiler;

// Timing helper
static inline double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

// Profiler control
void profiler_init(void);
void profiler_start_session(const char* category);
void profiler_end_session(void);
void profiler_enable(void);
void profiler_disable(void);

// Function timing
void profiler_function_enter(const char* function_name);
void profiler_function_exit(const char* function_name);

// Reporting
void profiler_print_report(void);
void profiler_print_summary(void);
void profiler_save_csv(const char* filename);

// Macros for easy instrumentation
#define PROFILE_FUNCTION() \
    profiler_function_enter(__FUNCTION__); \
    struct ProfilerScope { \
        const char* name; \
        ProfilerScope(const char* n) : name(n) {} \
        ~ProfilerScope() { profiler_function_exit(name); } \
    } _prof_scope(__FUNCTION__)

// C-style profiling macros
#define PROFILE_START(name) profiler_function_enter(name)
#define PROFILE_END(name) profiler_function_exit(name)

// Category helpers
#define PROFILE_KEYGEN_START() profiler_start_session("keygen")
#define PROFILE_ENCAP_START() profiler_start_session("encap")
#define PROFILE_DECAP_START() profiler_start_session("decap")
#define PROFILE_SESSION_END() profiler_end_session()

#endif // FUNCTION_PROFILER_H
