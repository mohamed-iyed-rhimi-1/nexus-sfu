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
- **No god objects** — the packet loop does one thing (forward packets), the orchestrator does another (manage sessions)

The goal is an SFU that forwards 500K+ packets/sec/core in userspace with P99 latency under 5ms; see `architecture.md` for what is measured today.

## Features

- **Zero-alloc hot path** — arena allocator with partitioned packet slots, SPSC lock-free channels
- **Worker sharding** — consistent hashing distributes tracks across CPU cores
- **SIMD RTP parsing** — NEON (ARM) and SSE/AVX (x86) accelerated header parsing
- **Simulcast** — layer selection with hysteresis to prevent oscillation
- **Actor-per-track** — independent failure domains, cross-node migration
- **CRDT state** — no Redis, no Postgres, self-coordinating cluster
- **WebSocket signaling** — JSON messages, WSS with TLS
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
| `nexus-bwe` | GCC bandwidth estimation (delay + loss), REMB, probing, speaker detection |
| `nexus-signal` | WebSocket signaling (a QUIC module exists but is not started) |
| `nexus-api` | REST API with JWT auth |
| `nexus-metrics` | Prometheus metrics, per-worker stats, tracing |
| `nexus-loadtest` | Load testing framework with headless WebRTC clients |

## Quick Start

### Prerequisites

- Rust 1.83+ (see `rust-toolchain.toml`)
- Cap'n Proto compiler (`capnp`)
- Linux with `liburing-dev` for io_uring support (optional)

### Build

```bash
cargo build --release
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
media_bind_addr = "0.0.0.0:10000"     # UDP media (RTP/RTCP, STUN, DTLS)
signaling_bind_addr = "0.0.0.0:8080"  # WebSocket signaling
announced_ips = ["203.0.113.7"]       # ICE host candidates; see below

[room]
max_participants_per_room = 1000

[memory]
arena_size_mb = 64

[worker]
num_workers = 0  # 0 = auto-detect CPU cores

[bwe]
initial_bandwidth_bps = 1_000_000
max_bandwidth_bps = 10_000_000
```

Precedence: command-line arguments > environment variables > config file > defaults.

| Environment variable | Sets |
|----------------------|------|
| `NEXUS_CONFIG_PATH` | Config file (same as `--config`) |
| `NEXUS_ANNOUNCED_IPS` | `transport.announced_ips`, comma-separated |
| `NEXUS_JWT_SECRET` | `security.jwt_secret` and `api.jwt_secret` (at least 32 characters) |
| `NEXUS_TLS_CERT_PATH`, `NEXUS_TLS_KEY_PATH` | Signaling TLS certificate and key (PEM) |
| `NEXUS_WORKER_COUNT` | `worker.num_workers` |
| `NEXUS_ARENA_SIZE_MB` | `memory.arena_size_mb` |
| `NEXUS_LOG_LEVEL` | `logging.level` |
| `NEXUS_METRICS_ADDR` | `metrics.bind_addr` |

### Announced addresses

Clients connect to the ICE host candidates the SFU advertises: each address in
`transport.announced_ips`, with the port the media socket is bound to. If the list is
empty, the SFU uses the bind IP when it is a specific address; with a wildcard bind
(`0.0.0.0`), it advertises the host's interface addresses and logs a warning naming them.
Behind NAT, in a container or on a cloud VM, set `NEXUS_ANNOUNCED_IPS` to the public
address clients can reach.

## Testing

```bash
# Unit + integration tests
cargo test --workspace

# Load test
cargo run -p nexus-loadtest -- webinar --viewers 100 --sfu-url ws://localhost:8080

# Benchmarks
cargo bench --workspace
```

## Deployment

### Docker

```bash
cd deploy/docker
./build.sh
NEXUS_ANNOUNCED_IPS=<host public IP> ./run.sh
```

Inside a container the SFU only sees the container's own addresses, so remote clients
need `NEXUS_ANNOUNCED_IPS` set to the host's address. The candidate carries the
container's media port (10000), so publish it on the same host port (`MEDIA_PORT=10000`,
the default).

### TLS

Signaling needs a certificate. Mount it as `/etc/nexus/tls/cert.pem` and `key.pem` (the paths in `config/production.toml`), or set `NEXUS_TLS_CERT_PATH` and `NEXUS_TLS_KEY_PATH`. If the paths are set but the files can't be loaded, the SFU refuses to start rather than falling back to unencrypted WebSocket. Leaving both paths empty gives plain WebSocket, for local development only.

### Host tuning (Linux)

The SFU asks for 16 MB UDP socket buffers. Linux caps them at `net.core.rmem_max` / `wmem_max`, about 208 KB by default, and a small receive buffer drops packets during bursts even when the CPU is idle. The SFU logs a warning at startup when this happens. Raise the limits on the host (containers share the host's setting):

```bash
sudo sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216
# persist across reboots
echo -e "net.core.rmem_max=16777216\nnet.core.wmem_max=16777216" | sudo tee /etc/sysctl.d/99-nexus-sfu.conf
```

Worker threads are pinned to CPU cores when `worker.cpu_affinity = true` (production config) and left to the scheduler when it is `false`.

### Monitoring

Nexus exports Prometheus metrics on the configured metrics endpoint. A Grafana dashboard is included at `deploy/grafana/dashboard.json`.

## Performance Targets

| Metric | Target |
|--------|--------|
| Participants per room | 500–1000 |
| P50 forwarding latency | < 1ms |
| P99 forwarding latency | < 5ms |
| Packets/sec/core (userspace) | 500K+ |
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
