#!/bin/bash

# Classic McEliece Benchmark Runner
# This script builds and runs comprehensive benchmarks comparing our implementation
# with the reference implementation.

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to display usage
usage() {
    echo "Usage: $0 [OPTION]"
    echo "Run Classic McEliece benchmarks comparing our implementation vs reference"
    echo ""
    echo "Options:"
    echo "  -q, --quick      Run quick benchmark (3 synthetic + 2 KAT iterations)"
    echo "  -k, --kat        Run KAT-based benchmark (5 KAT test vectors)"
    echo "  -s, --synthetic  Run synthetic benchmark (10 iterations)"
    echo "  -p, --performance Run performance benchmark (25 iterations)"
    echo "  -e, --extended   Run extended benchmark (100 iterations)"
    echo "  -a, --all        Run complete benchmark suite"
    echo "  -c, --clean      Clean build artifacts and results"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --quick          # Quick test for development"
    echo "  $0 --kat            # Compare with official KAT vectors"
    echo "  $0 --performance    # Detailed performance analysis"
    echo "  $0 --all            # Complete benchmark suite"
}

# Function to check if required files exist
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if KAT file exists
    if [ ! -f "mceliece6688128/kat_kem.req" ]; then
        print_error "KAT file mceliece6688128/kat_kem.req not found"
        print_error "Please ensure you're running from the project root"
        exit 1
    fi
    
    # Check if source files exist
    local required_files=(
        "mceliece_kem.c"
        "benchmark_timing.c"
        "benchmark_comparison.c"
        "kat_benchmark.c"
        "mceliece6688128/operations.c"
    )
    
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            print_error "Required file $file not found"
            exit 1
        fi
    done
    
    print_success "Prerequisites check passed"
}

# Function to build the benchmark tools
build_tools() {
    print_status "Building benchmark tools..."
    
    if make -f Makefile.benchmark all; then
        print_success "Build completed successfully"
    else
        print_error "Build failed"
        exit 1
    fi
}

# Function to run quick benchmark
run_quick() {
    print_status "Running quick benchmark..."
    make -f Makefile.benchmark run_quick
    print_success "Quick benchmark completed"
}

# Function to run KAT benchmark  
run_kat() {
    print_status "Running KAT-based benchmark..."
    make -f Makefile.benchmark run_kat_benchmark
    print_success "KAT benchmark completed"
}

# Function to run synthetic benchmark
run_synthetic() {
    print_status "Running synthetic benchmark..."
    make -f Makefile.benchmark run_synthetic
    print_success "Synthetic benchmark completed"
}

# Function to run performance benchmark
run_performance() {
    print_status "Running performance benchmark..."
    make -f Makefile.benchmark run_performance
    print_success "Performance benchmark completed"
}

# Function to run extended benchmark
run_extended() {
    print_status "Running extended benchmark..."
    make -f Makefile.benchmark run_extended
    print_success "Extended benchmark completed"
}

# Function to run all benchmarks
run_all() {
    print_status "Running complete benchmark suite..."
    make -f Makefile.benchmark run_all_benchmarks
    print_success "Complete benchmark suite completed"
    
    print_status "Generating summary..."
    echo ""
    echo "==================== BENCHMARK SUMMARY ===================="
    echo "The following result files were generated:"
    ls -la *.csv 2>/dev/null || echo "No CSV files found"
    echo ""
    echo "To analyze results:"
    echo "  - Open CSV files in spreadsheet software"
    echo "  - Compare 'our' vs 'ref' implementation timings"
    echo "  - Look for performance ratios in console output"
    echo "============================================================"
}

# Function to clean build artifacts
clean_all() {
    print_status "Cleaning build artifacts and results..."
    make -f Makefile.benchmark clean
    print_success "Clean completed"
}

# Function to show results summary
show_summary() {
    echo ""
    echo "==================== RECENT RESULTS ===================="
    if ls *.csv &>/dev/null; then
        for file in *.csv; do
            echo "📊 $file ($(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "unknown") bytes)"
        done
    else
        echo "No result files found. Run a benchmark first."
    fi
    echo "========================================================"
}

# Main execution
main() {
    echo "🚀 Classic McEliece Benchmark Runner"
    echo "===================================="
    echo ""
    
    # Check prerequisites
    check_prerequisites
    
    # Parse command line arguments
    case "${1:-}" in
        -q|--quick)
            build_tools
            run_quick
            show_summary
            ;;
        -k|--kat)
            build_tools
            run_kat
            show_summary
            ;;
        -s|--synthetic)
            build_tools
            run_synthetic
            show_summary
            ;;
        -p|--performance)
            build_tools
            run_performance
            show_summary
            ;;
        -e|--extended)
            build_tools
            run_extended
            show_summary
            ;;
        -a|--all)
            build_tools
            run_all
            show_summary
            ;;
        -c|--clean)
            clean_all
            ;;
        -h|--help|"")
            usage
            ;;
        *)
            print_error "Unknown option: $1"
            echo ""
            usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
