#!/bin/bash
set -e

echo "=== Building All Binaries ==="

# Clean build
cargo clean

# Build main SFU binary
echo "Building nexus-sfu..."
cargo build --release --bin nexus-sfu

# Build with all features
echo "Building with all features..."
cargo build --release --all-features

# Run tests
echo "Running unit tests..."
cargo test --lib

echo "Running integration tests..."
cargo test --test '*'

echo "Running doc tests..."
cargo test --doc

# Run benchmarks (compile only, don't execute)
echo "Compiling benchmarks..."
cargo bench --no-run

echo "=== Build and Test Complete ==="

# Print binary sizes
echo "=== Binary Sizes ==="
ls -lh target/release/nexus-sfu