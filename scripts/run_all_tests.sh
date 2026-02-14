#!/bin/bash
# run_all_tests.sh - Comprehensive test runner for nexus-sfu
#
# This script runs all tests in the proper order with appropriate flags.
# It follows TigerStyle principles: explicit, bounded, and traceable.
#
# Usage:
#   ./scripts/run_all_tests.sh          # Run all tests
#   ./scripts/run_all_tests.sh --quick  # Quick mode (skip slow tests)
#   ./scripts/run_all_tests.sh --ci     # CI mode (with coverage)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
QUICK_MODE=false
CI_MODE=false

for arg in "$@"; do
    case $arg in
        --quick)
            QUICK_MODE=true
            shift
            ;;
        --ci)
            CI_MODE=true
            shift
            ;;
        *)
            ;;
    esac
done

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Nexus-SFU Comprehensive Test Suite${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Track results
PASSED=0
FAILED=0
SKIPPED=0

run_test() {
    local name="$1"
    local cmd="$2"
    
    echo -e "${YELLOW}Running: ${name}${NC}"
    
    if eval "$cmd"; then
        echo -e "${GREEN}✓ ${name} passed${NC}"
        ((PASSED++))
    else
        echo -e "${RED}✗ ${name} failed${NC}"
        ((FAILED++))
        if [ "$CI_MODE" = true ]; then
            # In CI mode, continue running tests even on failure
            return 0
        fi
    fi
    echo ""
}

# =============================================================================
# Phase 1: Unit Tests
# =============================================================================

echo -e "${BLUE}--- Phase 1: Unit Tests ---${NC}"
echo ""

run_test "ICE Module Unit Tests" "cargo test --lib ice:: -- --test-threads=1"
run_test "DTLS Module Unit Tests" "cargo test --lib dtls:: -- --test-threads=1"
run_test "SRTP Module Unit Tests" "cargo test --lib srtp:: -- --test-threads=1"
run_test "SDP Module Unit Tests" "cargo test --lib sdp:: -- --test-threads=1"

# =============================================================================
# Phase 2: Integration Tests
# =============================================================================

echo -e "${BLUE}--- Phase 2: Integration Tests ---${NC}"
echo ""

run_test "ICE/DTLS/SRTP Flow" "cargo test --test ice_dtls_srtp_flow -- --test-threads=1"
run_test "Offer/Answer Exchange" "cargo test --test offer_answer_exchange -- --test-threads=1"
run_test "Session Cleanup" "cargo test --test session_cleanup -- --test-threads=1"

# =============================================================================
# Phase 3: Stress Tests (Skip in quick mode)
# =============================================================================

if [ "$QUICK_MODE" = false ]; then
    echo -e "${BLUE}--- Phase 3: Stress Tests ---${NC}"
    echo ""
    
    run_test "Resource Limits" "cargo test --test resource_limits -- --test-threads=1"
    run_test "Replay Window Exhaustion" "cargo test --test replay_window_exhaustion -- --test-threads=1"
    run_test "Concurrent Sessions" "cargo test --test concurrent_sessions -- --test-threads=1"
else
    echo -e "${YELLOW}--- Phase 3: Stress Tests (SKIPPED - quick mode) ---${NC}"
    ((SKIPPED+=3))
    echo ""
fi

# =============================================================================
# Phase 4: Validation Tests
# =============================================================================

echo -e "${BLUE}--- Phase 4: Validation Tests ---${NC}"
echo ""

run_test "RFC Compliance" "cargo test --test rfc_compliance -- --test-threads=1"
run_test "TigerStyle Assertions" "cargo test --test tigerstyle_assertions -- --test-threads=1"

# =============================================================================
# Phase 5: Property Tests (Skip in quick mode)
# =============================================================================

if [ "$QUICK_MODE" = false ]; then
    echo -e "${BLUE}--- Phase 5: Property Tests ---${NC}"
    echo ""
    
    run_test "SDP Property Tests" "cargo test --lib sdp::parser::tests::property_tests -- --test-threads=1"
    run_test "SRTP Property Tests" "cargo test --lib srtp::context::tests::property_tests -- --test-threads=1"
    run_test "ICE Property Tests" "cargo test --lib ice::agent::tests::property_tests -- --test-threads=1"
    run_test "DTLS Property Tests" "cargo test --lib dtls::session::tests::property_tests -- --test-threads=1"
else
    echo -e "${YELLOW}--- Phase 5: Property Tests (SKIPPED - quick mode) ---${NC}"
    ((SKIPPED+=4))
    echo ""
fi

# =============================================================================
# Phase 6: Documentation Tests
# =============================================================================

echo -e "${BLUE}--- Phase 6: Documentation Tests ---${NC}"
echo ""

run_test "Doc Tests" "cargo test --doc"

# =============================================================================
# Summary
# =============================================================================

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Test Summary${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "  ${GREEN}Passed:${NC}  $PASSED"
echo -e "  ${RED}Failed:${NC}  $FAILED"
echo -e "  ${YELLOW}Skipped:${NC} $SKIPPED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
