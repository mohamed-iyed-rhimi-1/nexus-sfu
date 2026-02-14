#!/bin/bash
set -e

echo "=== Verifying No Dead Code ==="

# Install cargo tools if not present
if ! command -v cargo-udeps &> /dev/null; then
    echo "Installing cargo-udeps..."
    cargo install cargo-udeps
fi

if ! command -v cargo-machete &> /dev/null; then
    echo "Installing cargo-machete..."
    cargo install cargo-machete
fi

# Check for unused dependencies
echo "Checking for unused dependencies..."
cargo +nightly udeps --all-targets

# Check for unused code
echo "Checking for unused code..."
cargo machete

# Check for deprecated usage
echo "Checking for deprecated code..."
if rg "RoomManager|SignalingServer|LossBasedBwe" --type rust --glob '!*.md' --glob '!CLEANUP*'; then
    echo "ERROR: Found deprecated code usage"
    exit 1
fi

# Check for TODO/FIXME
echo "Checking for TODO/FIXME..."
if rg "TODO|FIXME" --type rust --glob '!*.md'; then
    echo "WARNING: Found TODO/FIXME comments"
fi

echo "=== Verification Complete ==="
