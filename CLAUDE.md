# CLAUDE.md - Nexus SFU

## Project Overview

Nexus SFU is a WebRTC Selective Forwarding Unit written in Rust. It forwards media packets
between participants in real-time video/audio sessions.

**Status:** v0.1.0 — incomplete. The data plane is being redesigned; performance and memory
targets are not met yet.
**License:** AGPL-3.0-only (binary), Apache-2.0 (library crates)

## Start here

| Document | What it is |
|----------|-----------|
| `architecture.md` | What the code does **today**: live path, what is broken, dead code, measured baseline |
| `docs/dataplane-design.md` | The data-plane redesign: decisions (D1-D10), targets, phases |
| `docs/plans/phase-N.md` | The plan for the current phase, with a **Status** section and session log |
| `docs/design/*.md` | Detailed designs, written before the phase that needs them |
| `docs/architecture-vision.md` | The original design, for reference only; much of it is not implemented or cannot work |

**Current phase: 0** (`docs/plans/phase-0.md`).

Working on a phase:
1. Read the phase plan's Status section first; pick the next part that is not done.
2. Keep to the design's decisions. If one has to change, propose a revision to
   `docs/dataplane-design.md` (revision log) instead of silently diverging.
3. Before ending a session, update the plan's Status table and add a session-log line
   (what was done, what is left), so the next session can continue from the documents.

Do not trust comments or the vision document about what runs: many describe code that is
never called. Check `architecture.md` Part 2, or trace from `src/main.rs`.

## Tech Stack

- **Language:** Rust 1.83.0 (edition 2021) - pinned in `rust-toolchain.toml`
- **Async runtime:** Tokio 1.44 (control plane only)
- **HTTP:** Axum 0.7
- **Signaling:** WebSocket + JSON (the only transport the SDK and loadtest use)
- **Crypto:** OpenSSL (vendored) for DTLS; RustCrypto (aes, ctr, hmac, sha1, aes-gcm) for SRTP; rustls for TLS
- **Client SDK:** TypeScript 5.3.3, bundled with tsup (dual ESM/CJS)

## Build & Run

### Prerequisites

- Rust 1.83+ (install via `rustup`); cargo lives in `~/.cargo/bin`
- Cap'n Proto compiler: `capnp`
- Protocol Buffers compiler: `protoc`

### Commands

```bash
# Build
cargo build --release

# Run
cargo run -- --config config/development.toml    # Development (needs certs/dev-{cert,key}.pem)
./target/release/nexus-sfu --config config/production.toml

# Test
cargo test --workspace                   # All tests (only in-crate tests and top-level tests/*.rs compile)
cargo bench --bench real_path            # Real ingress/egress path cost
cargo bench --bench memory               # Heap per participant; NEXUS_MEM_BUDGET_KB=<n> makes it a check

# Lint
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings

# SDK (TypeScript)
cd sdk && npm run build
```

On macOS, check Linux in Docker: a `rust:1.83.0-bookworm` container with `capnproto` and
`protobuf-compiler` installed, the repo mounted, and named volumes for `target/` and the
cargo registry. Many paths differ on Linux (io_uring, `recvmmsg`, core pinning,
`panic = "abort"` in release), and CI is the only other Linux environment.

### Docker

```bash
cd deploy/docker && ./build.sh && ./run.sh     # run.sh: TLS_CERT/TLS_KEY, NEXUS_JWT_SECRET, *_PORT overrides
```

## Architecture (today)

See `architecture.md` for the full picture. The essentials:

- **Ingress:** one busy loop on the main thread (`Sfu::run_packet_loop`, `src/sfu.rs`)
  receives, classifies, decrypts (under a per-session mutex) and routes every packet.
- **Workers:** pinned threads (`src/worker/pool.rs`) own tracks; per subscriber they copy,
  rewrite, SRTP-encrypt and `sendmmsg`.
- **Control plane:** Tokio. WebSocket signaling → `SessionOrchestrator`
  (`src/orchestrator/`: room, negotiation, subscription, connection) which also runs DTLS
  handshakes and ICE timers. REST API on Axum with JWT.

The redesign replaces ingress and workers with per-session shards
(`docs/dataplane-design.md`).

### Workspace Structure

```
src/                 Binary crate: main.rs, sfu.rs (packet loop), orchestrator/, worker/,
                     forward/ (router.rs is live), config/, signal/, transport/
crates/
  nexus-core/        Shared types, config primitives
  nexus-transport/   UDP, io_uring, ICE, DTLS (OpenSSL), SRTP, arena, ring buffer
  nexus-media/       RTP/RTCP parsing, codec detection
  nexus-webrtc/      WebRTC session state machine, SDP, packet demux
  nexus-signal/      WebSocket signaling (QUIC module is a stub)
  nexus-bwe/         GCC, REMB (not fed by the live path)
  nexus-api/         REST API with JWT
  nexus-metrics/     Prometheus metrics
  nexus-state/       CRDTs, SWIM gossip
  nexus-actor/       Actor system; only config limits and migration types are used
  nexus-recorder/    Unused (removed in Phase 0)
  nexus-dst/         Deterministic simulation; does not exercise the server
  nexus-loadtest/    Load generator with webrtc-rs clients
sdk/                 TypeScript client SDK
benches/             real_path, memory (trusted); forwarding, packet_processing, crdt_sync
deploy/              Docker, Grafana dashboard
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
- Startup: fail fast on invalid configuration (`main` returns `ExitCode::FAILURE`)

### Concurrency

- **Never add locks or allocations to the packet forwarding hot path.** The current path
  has both (see `architecture.md` 1.2); the redesign removes them. Do not add more.
- `parking_lot` mutexes only on control path

## Configuration

Config files in `config/` (TOML). Precedence: CLI args > env vars (`NEXUS_*`) > config file > defaults.

- `config/development.toml` - 2 workers, small arena, DEBUG logging, no CPU affinity
- `config/production.toml` - auto workers, 1 GB arena, CPU pinning; needs `NEXUS_JWT_SECRET` and TLS files at `/etc/nexus/tls/`
- `config/loadtest.toml` - tuned for load testing

If TLS paths are set but the files do not load, the SFU refuses to start.

## Testing

- Unit tests live in each crate (`#[cfg(test)]`).
- `tests/` subdirectories (`integration/`, `stress/`, `unit/`, `validation/`) are **not
  compiled** by cargo and are stale; they are deleted in Phase 0. Only top-level
  `tests/*.rs` files are compiled.
- End-to-end tests with real WebRTC clients: `tests/e2e.rs` (added in Phase 0).
- Benchmarks: `real_path` and `memory` measure the live path; CI runs them as a smoke test
  and enforces a memory budget.

## PR Checklist

- `cargo test --workspace` passes
- `cargo clippy --workspace --all-targets -- -D warnings` has no warnings
- `cargo fmt --all --check` passes
- New code has assertions for preconditions and postconditions
- Hot path changes include `real_path` benchmark results
- Phase work updates the phase plan's Status section

## Ports (defaults in `config/development.toml` / `config/production.toml`)

| Port (dev / prod) | Protocol | Purpose |
|-------------------|----------|---------|
| 10000 / 10000 | UDP | Media (RTP/RTCP, STUN, DTLS) |
| 8080 / 443 | TCP | WebSocket signaling (WSS when TLS is configured) |
| 8443 / 443 | UDP | QUIC signaling (stub) |
| 8081 / 8081 | TCP | REST API, `/health`, `/ready` |
| 9090 / 9090 | TCP | Prometheus metrics |
