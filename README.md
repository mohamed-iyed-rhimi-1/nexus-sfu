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

> **⚠️ This project is incomplete and under active development.** The new data plane runs with one shard; throughput and multi-core targets are not measured yet (see `architecture.md` Part 5 for what is). Use at your own risk.

## Why Nexus?

Most SFUs are written in Go or C++ and rely on garbage collection or manual memory management. Nexus takes a different approach:

- **No GC pauses** — Rust's ownership model gives deterministic latency
- **No external state** — room and track state lives in CRDTs in the process, no Redis (single node in v1)
- **No god objects** — the data plane does one thing (forward packets), the orchestrator does another (manage sessions)

The goal is an SFU that forwards 500K+ packets/sec/core in userspace with P99 latency under 5ms; see `architecture.md` for what is measured today.

## Features

- **Zero-alloc hot path** — the shard forwards with no heap allocation, lock or clock read per packet (checked in CI)
- **Sharded data plane** — one thread and one socket per shard, `recvmmsg`/`sendmmsg`; several shards start (`dataplane.shards`), but every session is placed on shard 0 until Phase 2.4
- **In-process state** — CRDTs, no Redis, no Postgres; single node (gossip is off and not yet authenticated)
- **WebSocket signaling** — JSON messages, WSS with TLS
- **Keyframes and lip sync** — PLI on subscribe, PLI/FIR forwarding with throttling, Sender Report translation

Not yet: placing sessions on several shards (Phase 2.4; until then all go to shard 0, capped at `max_webrtc_sessions / shards`), NACK and TWCC feedback (Phase 3), simulcast and bandwidth estimation (after v1). `nexus-bwe` exists but is not wired in.

## Architecture

```
recvmmsg → classify → STUN (ICE-lite, answered in the shard)
                    → DTLS → event → orchestrator (handshake) → SendDatagram command
                    → SRTP/SRTCP → decrypt → route → rewrite (SSRC, seq, ts, PT, extensions)
                                 → encrypt per subscriber → sendmmsg
```

The data plane (`nexus-dataplane`) runs shards: one thread and one socket each, driven only by commands from the orchestrator and reporting events back. The shard answers STUN itself, decrypts and forwards media with zero allocations per packet, translates Sender Reports and forwards keyframe requests. DTLS datagrams go to the orchestrator, which runs the handshake and installs the SRTP keys.

The orchestrator (`src/orchestrator/`) runs a `tokio::select!` loop over signaling messages, data-plane events and timers:

| Module | Responsibility |
|--------|---------------|
| `room` | Room CRUD, join/leave, participant notifications |
| `negotiation` | SDP offer/answer (the SFU always offers), track registration |
| `subscription` | Subscribe/unsubscribe (viewport messages are acknowledged, no effect in v1) |
| `connection`, `dtls` | DTLS handshakes on the shard's DTLS datagrams, consent and timeouts |
| `plane` | Commands to the shards, sessions, SSRC allocation |

### Workspace Crates

| Crate | Purpose |
|-------|---------|
| `nexus-core` | Shared types, config, error definitions |
| `nexus-dataplane` | The data plane: shards, commands and events, SRTP in/out, rewrite, fan-out, socket I/O |
| `nexus-transport` | SRTP, STUN, candidates, the OpenSSL DTLS engine, socket setup |
| `nexus-media` | RTP/RTCP parsing and the header-extension table (codec detection and simulcast helpers are not on the live path) |
| `nexus-webrtc` | SDP parsing, printing and offer/answer negotiation |
| `nexus-state` | CRDTs (Orswot, LWWReg, GCounter): the single-node room registry; SWIM gossip (off by default) |
| `nexus-bwe` | GCC bandwidth estimation, REMB, probing (not on the live path yet) |
| `nexus-signal` | WebSocket signaling (a QUIC module exists but is not started) |
| `nexus-api` | REST API with JWT auth |
| `nexus-metrics` | Prometheus metrics (per-shard stats), tracing |
| `nexus-loadtest` | Load testing framework with headless WebRTC clients |

## Quick Start

### Prerequisites

- Rust 1.83+ (see `rust-toolchain.toml`)
- Cap'n Proto compiler (`capnp`)

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

[dataplane]
shards = 1              # one thread and one media port per shard (1..=16)
busy_poll_rounds = 0    # idle iterations before a shard parks (256 in production)
cpu_affinity = false    # pin shard i to core i

```

Precedence: command-line arguments > environment variables > config file > defaults.

| Environment variable | Sets |
|----------------------|------|
| `NEXUS_CONFIG_PATH` | Config file (same as `--config`) |
| `NEXUS_ANNOUNCED_IPS` | `transport.announced_ips`, comma-separated |
| `NEXUS_JWT_SECRET` | `security.jwt_secret` and `api.jwt_secret` (at least 32 characters) |
| `NEXUS_TLS_CERT_PATH`, `NEXUS_TLS_KEY_PATH` | Signaling TLS certificate and key (PEM) |
| `NEXUS_SHARDS` | `dataplane.shards` |
| `NEXUS_LOG_LEVEL` | `logging.level` |
| `NEXUS_METRICS_ADDR` | `metrics.bind_addr` (reserved; metrics are served on the API port) |

### Announced addresses

Clients connect to the ICE host candidates the SFU advertises: each address in
`transport.announced_ips`, with the port the media socket is bound to. If the list is
empty, the SFU uses the bind IP when it is a specific address; with a wildcard bind
(`0.0.0.0`), it advertises the host's interface addresses and logs a warning naming them.
Behind NAT, in a container or on a cloud VM, set `NEXUS_ANNOUNCED_IPS` to the public
address clients can reach.

## Testing

```bash
# Unit, integration and end-to-end tests
cargo test --workspace
cargo test --test e2e              # in-process SFU + webrtc-rs clients (8 tests)

# Everything CI runs (macOS + Linux arm64 in Docker; `all` adds x86_64 and the image)
scripts/ci-local.sh

# SDK
cd sdk && npm ci && npm run build && npm test

# Load test
cargo run -p nexus-loadtest -- webinar --viewers 100 --sfu-url ws://localhost:8080

# Benchmarks
cargo bench --bench real_path      # ingress and per-subscriber egress cost
cargo bench --bench memory         # session state per participant (CI budget: 25 KB)
cargo bench --bench srtp_backends
cargo bench --bench udp_floor      # Linux only
```

A browser test page on the SDK is in [`examples/web/`](examples/web/README.md); it needs a
token: `NEXUS_JWT_SECRET=<32+ chars> cargo run -p nexus-loadtest -- token --sub alice --room demo`
(the token may create or join only the rooms it names).

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

Shard threads are pinned to CPU cores when `dataplane.cpu_affinity = true` (production config) and left to the scheduler when it is `false`.

### Monitoring

Nexus exports Prometheus metrics at `/metrics` on the REST API port (8081 by default). A Grafana dashboard is included at `deploy/grafana/dashboard.json`.

## Performance Targets

| Metric | Target |
|--------|--------|
| Participants per room | 500–1000 |
| P50 forwarding latency | < 1ms |
| P99 forwarding latency | < 5ms |
| Packets/sec/core (userspace) | 500K+ |
| Memory per participant (session state) | ≤ 25 KB (checked in CI) |

Measured so far (one shard): `architecture.md` Part 5.

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
