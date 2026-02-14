# =============================================================================
# Build Stage - Compile Rust binary with all optimizations
# =============================================================================
FROM rust:1.83.0-bookworm AS builder

# Install build dependencies explicitly (TigerStyle: no defaults)
# liburing-dev: io_uring support for Linux
# capnproto: Cap'n Proto schema compiler
# protobuf-compiler: Protocol Buffers compiler (if needed)
# pkg-config: Build configuration helper
RUN apt-get update && \
    apt-get install -y \
        liburing-dev=2.3-3 \
        capnproto=0.10.2-1 \
        protobuf-compiler=3.21.12-3 \
        pkg-config=1.8.1-1 \
    && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy dependency manifests first for layer caching
# TigerStyle: minimize scope - only copy what's needed for dependency resolution
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY build.rs ./
COPY crates/nexus-state/Cargo.toml ./crates/nexus-state/
COPY crates/nexus-actor/Cargo.toml ./crates/nexus-actor/
COPY crates/nexus-signal/Cargo.toml ./crates/nexus-signal/
COPY crates/nexus-metrics/Cargo.toml ./crates/nexus-metrics/

# Copy Cap'n Proto schemas (required by build.rs)
COPY proto/ ./proto/

# Create dummy source files to cache dependencies
# TigerStyle: explicit bounds - exactly 4 crates + main
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    mkdir -p crates/nexus-state/src && \
    echo "pub fn dummy() {}" > crates/nexus-state/src/lib.rs && \
    mkdir -p crates/nexus-actor/src && \
    echo "pub fn dummy() {}" > crates/nexus-actor/src/lib.rs && \
    mkdir -p crates/nexus-signal/src && \
    echo "pub fn dummy() {}" > crates/nexus-signal/src/lib.rs && \
    mkdir -p crates/nexus-metrics/src && \
    echo "pub fn dummy() {}" > crates/nexus-metrics/src/lib.rs

# Build dependencies only (cached layer)
# TigerStyle: explicit flags, no defaults
RUN cargo build \
    --release \
    --locked \
    --target-dir /build/target

# Remove dummy source files
# TigerStyle: clean state before real build
RUN rm -rf src crates/*/src

# Copy actual source code
COPY src/ ./src/
COPY crates/ ./crates/

# Build actual binary with maximum optimizations
# Profile settings from Cargo.toml:
# - opt-level = 3 (maximum optimization)
# - lto = "fat" (full link-time optimization)
# - codegen-units = 1 (single codegen unit for best optimization)
# - panic = "abort" (smaller binary, faster panics)
# - strip = true (remove debug symbols)
RUN cargo build \
    --release \
    --locked \
    --target-dir /build/target

# Strip binary explicitly (defense in depth, even though Cargo.toml has strip=true)
# TigerStyle: assert what we expect
RUN strip /build/target/release/nexus-sfu && \
    test -f /build/target/release/nexus-sfu

# Verify binary size is reasonable (<30MB for stripped binary)
# TigerStyle: assert bounds on everything
RUN BINARY_SIZE=$(stat -c%s /build/target/release/nexus-sfu) && \
    echo "Binary size: $BINARY_SIZE bytes" && \
    test "$BINARY_SIZE" -lt 31457280

# =============================================================================
# Runtime Stage - Minimal distroless image
# =============================================================================
FROM gcr.io/distroless/cc-debian12:nonroot

# Metadata labels (OCI standard)
LABEL org.opencontainers.image.title="Nexus SFU"
LABEL org.opencontainers.image.description="High-performance WebRTC Selective Forwarding Unit"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.authors="Nexus Team"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy binary from builder
# TigerStyle: explicit source and destination
COPY --from=builder \
    --chown=nonroot:nonroot \
    /build/target/release/nexus-sfu \
    /usr/local/bin/nexus-sfu

# Copy default configuration
# TigerStyle: configuration is code, version it
COPY --chown=nonroot:nonroot \
    config/production.toml \
    /etc/nexus-sfu/config.toml

# Note: TLS certificates are NOT bundled in the image for security reasons
# They must be mounted at runtime via volume mount to /etc/nexus-sfu/tls/
# See README.md for mounting instructions

# Expose ports with explicit protocol
# TigerStyle: document why each port exists
# 10000/udp: Media (RTP/RTCP) traffic
EXPOSE 10000/udp
# 443/udp: QUIC signaling (0-RTT support)
EXPOSE 443/udp
# 443/tcp: QUIC signaling fallback
EXPOSE 443/tcp
# 8080/tcp: WebSocket signaling fallback
EXPOSE 8080/tcp
# 9090/tcp: Prometheus metrics endpoint
EXPOSE 9090/tcp

# Health check configuration
# TigerStyle: explicit intervals and timeouts
# Check /health endpoint every 10 seconds
# Timeout after 3 seconds
# Start checking after 5 seconds (startup grace period)
# Fail after 3 consecutive failures
HEALTHCHECK \
    --interval=10s \
    --timeout=3s \
    --start-period=5s \
    --retries=3 \
    CMD ["/busybox/wget", "-q", "-O", "-", "http://127.0.0.1:3000/health"]

# Note: distroless/cc includes busybox for health checks
# The health endpoint returns 200 OK when healthy, non-200 when unhealthy

# Run as non-root user (distroless nonroot user)
# UID 65532, GID 65532
USER nonroot:nonroot

# Set working directory
WORKDIR /app

# Entry point and default command
# TigerStyle: explicit configuration path
ENTRYPOINT ["/usr/local/bin/nexus-sfu"]
CMD ["--config", "/etc/nexus-sfu/config.toml"]
