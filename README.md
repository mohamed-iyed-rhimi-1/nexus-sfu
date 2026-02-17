<p align="center">
  <h1 align="center">Nexus SFU</h1>
  <p align="center">High-performance WebRTC Selective Forwarding Unit written in Rust.</p>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#testing">Testing</a> •
  <a href="#deployment">Deployment</a> •
  <a href="#contributing">Contributing</a>
</p>

---

> **⚠️ This project is incomplete and under active development. Performance benchmarks have not been validated yet. Use at your own risk.**

## Why Nexus?

Most SFUs are written in Go or C++ and rely on garbage collection or manual memory management. Nexus takes a different approach:

- **No GC pauses** — Rust's ownership model gives deterministic latency
- **No external state** — CRDTs replace Redis; nodes self-coordinate via gossip
- **No kernel overhead** — optional XDP/AF_XDP bypasses the kernel network stack entirely
- **No god objects** — the packet loop does one thing (forward packets), the orchestrator does another (manage sessions)

The result is an SFU that can forward 500K+ packets/sec/core in userspace and 10M+ with XDP, with P99 latency under 5ms.

## Features

- **Zero-alloc hot path** — arena allocator with partitioned packet slots, SPSC lock-free channels
- **Worker sharding** — consistent hashing distributes tracks across CPU cores
- **XDP/AF_XDP** — kernel bypass on Linux for 10x+ packet throughput
- **SIMD RTP parsing** — NEON (ARM) and SSE/AVX (x86) accelerated header parsing
- **Hot/cold subscribers** — active subscribers iterated first, inactive demoted
- **Viewport filtering** — only forward tracks visible in subscriber's viewport
- **Simulcast** — layer selection with hysteresis to prevent oscillation
- **Actor-per-track** — independent failure domains, cross-node migration
- **CRDT state** — no Redis, no Postgres, self-coordinating cluster
- **QUIC signaling** — 0-RTT resumption, connection migration, multiplexed streams
- **GCC bandwidth estimation** — delay + loss based, with REMB and probing
- **Deterministic simulation testing** — reproducible fault injection

## Architecture

```
UDP recv → classify (1 byte) → RTP/RTCP (inline) → SRTP decrypt → SSRC route → worker forward
                              → STUN/DTLS (channel) → ConnectionMonitor → orchestrator
```

The packet loop runs on a pinned core with zero allocations. It receives packets, decrypts RTP/RTCP inline, and routes by SSRC to sharded workers. STUN/DTLS packets (< 1% of traffic) are channeled to the orchestrator.

The orchestrator runs a `tokio::select!` loop with 4 modules:

| Module | Responsibility |
|--------|---------------|
| `RoomManager` | Room CRUD, join/leave, participant notifications |
| `NegotiationManager` | Transport creation, SDP offer/answer, ICE gathering, track registration |
| `SubscriptionManager` | Subscribe/unsubscribe, viewport filtering, media activation |
| `ConnectionMonitor` | STUN/DTLS processing, ICE pacing, DTLS retransmit, consent checks |

### Workspace Crates

| Crate | Purpose |
|-------|---------|
| `nexus-core` | Shared types, config, error definitions |
| `nexus-transport` | UDP, ICE, DTLS, SRTP, arena allocator, ring buffers, io_uring |
| `nexus-media` | RTP/RTCP parsing (SIMD), codec detection (H264/VP8/VP9/AV1/Opus), simulcast |
| `nexus-webrtc` | WebRTC session state machine, SDP negotiation, packet demux |
| `nexus-state` | CRDTs (Orswot, LWWReg, GCounter), SWIM gossip, distributed state |
| `nexus-actor` | Actor-per-track model with migration, supervision, registry |
| `nexus-bwe` | GCC bandwidth estimation (delay + loss), REMB, probing, speaker detection |
| `nexus-signal` | QUIC signaling (0-RTT, session resumption) + WebSocket fallback |
| `nexus-api` | REST API with JWT auth |
| `nexus-metrics` | Prometheus metrics, per-worker stats, tracing |
| `nexus-recorder` | Track recording to disk |
| `nexus-dst` | Deterministic simulation testing with fault injection |
| `nexus-loadtest` | Load testing framework with headless WebRTC clients |

## Quick Start

### Prerequisites

- Rust 1.83+ (see `rust-toolchain.toml`)
- Cap'n Proto compiler (`capnp`)
- Protocol Buffers compiler (`protoc`)
- Linux with `liburing-dev` for io_uring support (optional)

### Build

```bash
cargo build --release
```

With XDP support (Linux only):

```bash
cargo build --release --features xdp
```

### Run

```bash
# Development (with hot reload logging)
cargo run -- --config config/development.toml

# Production
./target/release/nexus-sfu --config config/production.toml
```

## Configuration

Configuration files live in `config/`:

| File | Purpose |
|------|---------|
| `development.toml` | Local development with verbose logging |
| `production.toml` | Production defaults |
| `loadtest.toml` | Tuned for load testing scenarios |

Key configuration sections:

```toml
[transport]
media_addr = "0.0.0.0:7880"
signaling_addr = "0.0.0.0:7881"

[room]
max_participants = 1000

[memory]
arena_size_mb = 64

[worker]
count = 0  # 0 = auto-detect CPU cores

[bwe]
initial_bitrate_bps = 1_000_000
max_bitrate_bps = 10_000_000
```

## Testing

```bash
# Unit + integration tests
cargo test --workspace

# Deterministic simulation (reproducible, with fault injection)
cargo run -p nexus-dst -- run scenarios/basic.toml

# Load test
cargo run -p nexus-loadtest -- webinar --viewers 100 --sfu-url ws://localhost:7880

# Benchmarks
cargo bench --workspace
```

## Deployment

### Docker

```bash
cd deploy/docker
./build.sh
./run.sh
```

### Monitoring

Nexus exports Prometheus metrics on the configured metrics endpoint. A Grafana dashboard is included at `deploy/grafana/dashboard.json`.

## Performance Targets

| Metric | Target |
|--------|--------|
| Participants per room | 500–1000 |
| P50 forwarding latency | < 1ms |
| P99 forwarding latency | < 5ms |
| Packets/sec/core (userspace) | 500K+ |
| Packets/sec/core (XDP) | 10M+ |
| Memory per participant | < 100KB |

## Contributing

Contributions are welcome. Please read the guidelines below before submitting a PR.

### Code Style

All code follows [TigerStyle](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md) and NASA's Power of 10 Rules adapted for Rust:

- No dynamic allocation after initialization on hot paths
- Fixed upper bounds on all loops
- Comprehensive assertions (positive and negative space)
- Functions fit on one screen (~60 lines)
- No `unsafe` unless absolutely necessary and documented
- `#![deny(warnings)]` everywhere

### PR Checklist

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace` has no warnings
- [ ] `cargo fmt --check` passes
- [ ] New code has assertions for preconditions and postconditions
- [ ] Hot path changes include benchmark results

## License

This project is licensed under [AGPL-3.0](LICENSE).
