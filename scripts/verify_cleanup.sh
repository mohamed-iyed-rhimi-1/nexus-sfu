#!/bin/bash
set -e

echo "=== Nexus SFU Cleanup Verification ==="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0

# Function to check for deprecated code usage
check_deprecated() {
    local pattern=$1
    local description=$2
    local exclude=$3
    
    echo -n "Checking for $description... "
    
    if [ -n "$exclude" ]; then
        if rg "$pattern" --type rust --glob "!$exclude" > /dev/null 2>&1; then
            echo -e "${RED}FAIL${NC}"
            echo "  Found deprecated usage:"
            rg "$pattern" --type rust --glob "!$exclude" | head -5
            ERRORS=$((ERRORS + 1))
        else
            echo -e "${GREEN}OK${NC}"
        fi
    else
        if rg "$pattern" --type rust > /dev/null 2>&1; then
            echo -e "${RED}FAIL${NC}"
            echo "  Found deprecated usage:"
            rg "$pattern" --type rust | head -5
            ERRORS=$((ERRORS + 1))
        else
            echo -e "${GREEN}OK${NC}"
        fi
    fi
}

# 1. Check for deprecated RoomManager usage
echo "1. Checking for deprecated RoomManager usage..."
check_deprecated "RoomManager" "RoomManager usage" "src/room/mod.rs"
check_deprecated "use crate::room::RoomManager" "RoomManager imports" "src/room/mod.rs"

# 2. Check for deprecated SignalingServer usage
echo ""
echo "2. Checking for deprecated SignalingServer usage..."
check_deprecated "SignalingServer" "SignalingServer usage" "src/signal/mod.rs"

# 3. Check for JSON serialization
echo ""
echo "3. Checking for JSON serialization..."
check_deprecated "serde_json" "serde_json usage" ""
check_deprecated "to_json|from_json" "JSON methods" ""

# 4. Verify new architecture components
echo ""
echo "5. Verifying new architecture components..."

echo -n "  ActorManager in Sfu... "
if rg "ActorManager" src/sfu.rs > /dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"
    ERRORS=$((ERRORS + 1))
fi

echo -n "  DistributedState in Sfu... "
if rg "DistributedState" src/sfu.rs > /dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"
    ERRORS=$((ERRORS + 1))
fi

# 5. Check for loss-based BWE
echo ""
echo "5. Checking for loss-based BWE..."
if [ -f "crates/nexus-bwe/src/loss.rs" ]; then
    echo -e "${RED}FAIL${NC}"
    echo "  loss.rs still exists"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}OK${NC}"
fi

# 6. Run tests
echo ""
echo "6. Running test suite..."
if cargo test --all-features --quiet 2>&1 | grep -q "test result: ok"; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}WARNING${NC} - Some tests may have failed"
fi

# 7. Check for dead code (if cargo-udeps is installed)
echo ""
echo "7. Checking for unused dependencies..."
if command -v cargo-udeps &> /dev/null; then
    if cargo +nightly udeps --quiet 2>&1 | grep -q "unused"; then
        echo -e "${YELLOW}WARNING${NC} - Found unused dependencies"
    else
        echo -e "${GREEN}OK${NC}"
    fi
else
    echo -e "${YELLOW}SKIP${NC} - cargo-udeps not installed"
fi

# 8. Check for dead code (if cargo-machete is installed)
echo ""
echo "8. Checking for dead code..."
if command -v cargo-machete &> /dev/null; then
    if cargo machete 2>&1 | grep -q "unused"; then
        echo -e "${YELLOW}WARNING${NC} - Found dead code"
    else
        echo -e "${GREEN}OK${NC}"
    fi
else
    echo -e "${YELLOW}SKIP${NC} - cargo-machete not installed"
fi

# 9. Build both binaries
echo ""
echo "9. Building binaries..."
echo -n "  nexus-sfu... "
if cargo build --release --bin nexus-sfu --quiet 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Summary
echo ""
echo "=== Verification Complete ==="
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}All checks passed!${NC}"
    exit 0
else
    echo -e "${RED}$ERRORS check(s) failed${NC}"
    exit 1
fi
