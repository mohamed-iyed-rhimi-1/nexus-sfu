#!/bin/bash
# Nexus SFU Development Runner
# This script starts the SFU and serves the web client for browser testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🚀 Nexus SFU Development Environment"
echo "======================================"
echo ""

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo "❌ Error: cargo not found. Please install Rust."
    exit 1
fi

# Build the SFU
echo "📦 Building Nexus SFU..."
cd "$PROJECT_DIR"
cargo build --release 2>&1 | tail -5

echo ""
echo "✅ Build complete!"
echo ""

# Start the web client server in background
echo "🌐 Starting web client server on http://127.0.0.1:3000"
cd "$PROJECT_DIR/web-client"

# Use Python's built-in HTTP server (available on macOS)
if command -v python3 &> /dev/null; then
    python3 -m http.server 3000 &
    WEB_PID=$!
elif command -v python &> /dev/null; then
    python -m SimpleHTTPServer 3000 &
    WEB_PID=$!
else
    echo "⚠️  Warning: Python not found. Please serve web-client/ manually."
    WEB_PID=""
fi

cd "$PROJECT_DIR"

# Cleanup function
cleanup() {
    echo ""
    echo "🛑 Shutting down..."
    if [ -n "$WEB_PID" ]; then
        kill $WEB_PID 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM

echo ""
echo "======================================"
echo "📋 Quick Start Guide"
echo "======================================"
echo ""
echo "1. Open your browser to: http://localhost:3000"
echo "   ⚠️  Use 'localhost' not '127.0.0.1' for camera access!"
echo ""
echo "2. Click 'Connect' to connect to the SFU"
echo "3. Click 'Publish Camera' to start streaming"
echo ""
echo "Signaling:"
echo "  - QUIC (primary):       quic://localhost:8443"
echo "  - WebSocket (fallback): ws://localhost:8080"
echo ""
echo "Other endpoints:"
echo "  - API Server:    http://localhost:8081"
echo "  - Metrics:       http://localhost:9090/metrics"
echo ""
echo "Note: QUIC requires TLS certificates. In dev mode without certs,"
echo "      the SFU falls back to WebSocket automatically."
echo ""
echo "======================================"
echo ""

# Start the SFU
echo "🎬 Starting Nexus SFU..."
echo ""
NEXUS_CONFIG_PATH="$PROJECT_DIR/config/development.toml" ./target/release/nexus-sfu

# Cleanup on exit
cleanup
