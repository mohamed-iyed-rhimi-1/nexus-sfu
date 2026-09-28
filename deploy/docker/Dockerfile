# syntax=docker/dockerfile:1
# =============================================================================
# Build Stage - Compile Rust binary with all optimizations
# =============================================================================
FROM rust:1.83.0-bookworm AS builder

# Install build dependencies explicitly (TigerStyle: no defaults)
# liburing-dev: io_uring support for Linux
# capnproto: Cap'n Proto schema compiler
# pkg-config: Build configuration helper
# Not pinned to exact Debian revisions: bookworm replaces them with security
# updates (and capnproto 0.10.2-1 never existed in bookworm), which broke the
# build. The base image tag pins the Debian release.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        liburing-dev \
        capnproto \
        pkg-config \
    && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy the workspace. Cargo validates every declared target (benches,
# examples) when loading the manifest, so those directories are needed even
# though only the binary is built. `.cargo/` carries the target rustflags
# that enable ARMv8 AES/PMULL for SRTP on arm64.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo/ ./.cargo/
COPY src/ ./src/
COPY crates/ ./crates/
COPY benches/ ./benches/
COPY examples/ ./examples/

# Build the binary with the release profile from Cargo.toml
# (opt-level 3, fat LTO, codegen-units 1, panic = abort, strip).
# Cache mounts keep the registry and build artifacts between image builds.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/cache \
    cargo build --release --locked --bin nexus-sfu --target-dir /build/cache && \
    mkdir -p /build/target/release && \
    cp /build/cache/release/nexus-sfu /build/target/release/nexus-sfu

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
# Mount them at runtime as /etc/nexus/tls/cert.pem and key.pem (the paths in
# production.toml), or point NEXUS_TLS_CERT_PATH / NEXUS_TLS_KEY_PATH at them.
# Startup fails if they are configured but missing: signaling never falls
# back to unencrypted WebSocket.

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
# 8081/tcp: REST API, including /health and /ready probes
EXPOSE 8081/tcp

# Health: probe from outside the container. distroless/cc has no shell or
# HTTP client (busybox is only in the :debug variant), so an in-image
# HEALTHCHECK cannot run. Use the API endpoints on port 8081:
#   liveness:  GET http://<pod>:8081/health
#   readiness: GET http://<pod>:8081/ready
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
