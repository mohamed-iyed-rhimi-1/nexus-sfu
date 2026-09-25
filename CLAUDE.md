# CLAUDE.md - Nexus SFU

## Project Overview

Nexus SFU is a high-performance WebRTC Selective Forwarding Unit written in Rust. It forwards media packets between participants in real-time video/audio sessions with zero-allocation hot paths, CRDT-based distributed state (no Redis/Postgres), and optional XDP kernel bypass.

**Status:** v0.1.0 - incomplete, under active development. Performance benchmarks not yet validated.
**License:** AGPL-3.0-only (binary), Apache-2.0 (library crates)

## Tech Stack

- **Language:** Rust 1.83.0 (edition 2021) - pinned in `rust-toolchain.toml`
- **Async runtime:** Tokio 1.44 (multi-threaded, full features)
- **HTTP:** Axum 0.7
- **Serialization:** Cap'n Proto 0.19 (signaling), Protobuf/prost 0.13 (API), serde_json (WebSocket)
- **Crypto:** ring 0.17, OpenSSL (vendored), rustls 0.22
- **Client SDK:** TypeScript 5.3.3, bundled with tsup (dual ESM/CJS)

## Build & Run

### Prerequisites

- Rust 1.83+ (install via `rustup`)
- Cap'n Proto compiler: `capnp`
- Protocol Buffers compiler: `protoc`
- Linux only: `liburing-dev` for io_uring support

### Commands

```bash
# Build
cargo build --release
cargo build --release --features xdp    # Linux only, with kernel bypass

# Run
cargo run -- --config config/development.toml    # Development
./target/release/nexus-sfu --config config/production.toml  # Production

# Test
cargo test --workspace                   # All tests
cargo bench --workspace                  # Benchmarks
cargo run -p nexus-dst -- run scenarios/basic.toml   # Deterministic simulation
cargo run -p nexus-loadtest -- webinar --viewers 100 --sfu-url ws://localhost:7880

# Lint
cargo fmt --all --check
cargo clippy --workspace -- -D warnings

# SDK (TypeScript)
cd sdk && npm run build                  # Build SDK
cd sdk && npm run dev                    # Watch mode
```

### Docker

```bash
cd deploy/docker && ./build.sh && ./run.sh
```

## Architecture

### Control Plane vs Data Plane

**Data plane (hot path)** - zero allocation, pinned CPU core:
```
UDP recv -> classify (1 byte) -> RTP/RTCP (inline) -> SRTP decrypt -> SSRC route -> worker forward -> batch send (sendmmsg)
```

**Control plane** - Tokio async:
- Signaling (QUIC primary on :4433, WebSocket fallback on :8080)
- Session orchestrator (`tokio::select!` loop) with 4 modules:
  - `RoomManager` - room CRUD, join/leave
  - `NegotiationManager` - SDP offer/answer, ICE gathering, track registration
  - `SubscriptionManager` - subscribe/unsubscribe, viewport filtering
  - `ConnectionMonitor` - STUN/DTLS, ICE pacing, consent checks
- REST API (Axum on :8081 with JWT auth)

### Workspace Structure

```
nexus-sfu/
  src/               # Binary crate - main SFU orchestrator (~22K LoC)
    main.rs          # Entry point, CLI args, startup sequence
    sfu.rs           # Top-level Sfu struct, component initialization
    config/          # TOML config loading, validation, hot-reload
    forward/         # Hot-path packet forwarding (processor, router, selective)
    orchestrator/    # Control plane (room, connection, negotiation, subscription)
    signal/          # Signaling server coordination
    worker/          # Worker pool, sharding, SPSC channels
    transport/       # Transport abstraction (io_uring, kqueue, recvmmsg)
    state/           # Forward table, distributed state integration
  crates/
    nexus-core/      # Shared types, config primitives
    nexus-transport/ # UDP, ICE, DTLS, SRTP, arena allocator (largest crate ~1.2M)
    nexus-media/     # RTP/RTCP parsing (SIMD: NEON/SSE/AVX), codec detection
    nexus-webrtc/    # WebRTC state machine, SDP negotiation, packet demux
    nexus-state/     # CRDTs (Orswot, LWWReg, GCounter), SWIM gossip
    nexus-actor/     # Actor-per-track with supervision, migration, registry
    nexus-signal/    # QUIC 0-RTT signaling + WebSocket fallback
    nexus-bwe/       # GCC bandwidth estimation, REMB, probing
    nexus-api/       # REST API with JWT auth
    nexus-metrics/   # Prometheus metrics, per-worker stats
    nexus-recorder/  # Track recording to disk
    nexus-dst/       # Deterministic simulation testing
    nexus-loadtest/  # Load testing framework
  sdk/               # TypeScript client SDK (@nexus-sfu/sdk)
    src/client.ts    # NexusClient - WebRTC + signaling
    src/signaling.ts # WebSocket transport with reconnection
    src/messages.ts  # Message type definitions
    src/errors.ts    # NexusError class
  proto/             # Schema definitions
    signaling.capnp  # Real-time signaling (Cap'n Proto)
    api.proto        # REST API (Protocol Buffers)
  config/            # TOML config files (development, production, loadtest)
  tests/             # Integration, stress, unit, validation tests
  benches/           # Criterion benchmarks (forwarding, packet_processing, crdt_sync)
  deploy/            # Docker + Grafana dashboard
  bpf/               # eBPF/XDP kernel bypass (Linux)
  scripts/           # Dev utilities (run, build, verify scripts)
```

### Key Features

```
io_uring       - Default on Linux, kernel async I/O
xdp            - Optional Linux kernel bypass (10M+ pps)
capnp          - Cap'n Proto signaling codec
production     - Compile-time production guards
sim            - Deterministic simulation mode (no-op I/O, clock abstraction)
```

## Code Style & Conventions

### TigerStyle (strictly enforced)

- **No dynamic allocation** on hot paths after initialization
- **Fixed upper bounds** on all loops - no unbounded iteration
- **Comprehensive assertions** - both positive and negative space
- **Functions fit on one screen** (~60 lines max)
- **No `unsafe`** unless absolutely necessary and documented
- **`#![deny(warnings)]`** enforced in all crates

### Error Handling

- Hot path: `Option<T>` for recoverable, drop packet on failure, never panic
- Control path: `Result<T, SfuError>` with typed error hierarchy
- Startup: panic (fail fast) on invalid configuration
- Actor failures: supervised with restart policies

### Concurrency

- Lock-free SPSC channels between packet loop and workers
- `DashMap` for SSRC routing (concurrent hash map)
- `AtomicBool`/`AtomicU64` for hot/cold subscriber state
- `arc-swap` for atomic Arc updates
- `parking_lot` mutexes only on control path
- **Never add locks or allocations to the packet forwarding hot path**

## Configuration

Config files in `config/` (TOML format). Precedence: CLI args > env vars (`NEXUS_*`) > config file > defaults.

- `config/development.toml` - 2 workers, 32MB arena, DEBUG logging, no CPU affinity
- `config/production.toml` - auto workers, 1GB arena, CPU pinning, RT priority
- `config/loadtest.toml` - tuned for load testing

Hot-reloadable: logging, metrics, room timeouts, BWE settings.
Requires restart: memory, workers, transport.

## Testing

- **Unit tests:** `tests/unit/` - NACK, REMB, simulcast
- **Integration:** `tests/integration/` - actor system, e2e signaling, ICE/DTLS/SRTP, SDP exchange
- **Stress:** `tests/stress/` - concurrent sessions, replay window, resource limits
- **Validation:** `tests/validation/` - RFC compliance, TigerStyle assertions
- **Property-based:** proptest for SPSC channel correctness
- **Benchmarks:** Criterion in `benches/` - forwarding throughput, packet parsing, CRDT sync
- **DST:** `nexus-dst` crate - deterministic simulation with fault injection

## PR Checklist

- `cargo test --workspace` passes
- `cargo clippy --workspace -- -D warnings` has no warnings
- `cargo fmt --check` passes
- New code has assertions for preconditions and postconditions
- Hot path changes include benchmark results
- No allocations or locks added to the packet forwarding hot path

## Ports (defaults)

| Port | Protocol | Purpose |
|------|----------|---------|
| 7880 | UDP | Media (RTP/RTCP) |
| 7881 | TCP | WebSocket signaling |
| 4433 | UDP | QUIC signaling |
| 8081 | TCP | REST API |
| 9090 | TCP | Prometheus metrics |
