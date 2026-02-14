# Nexus SFU

High-performance WebRTC Selective Forwarding Unit built in Rust.

Nexus uses an actor-per-track architecture where each media track is an independent actor that can live anywhere and migrate dynamically based on subscriber locations. State is replicated via CRDTs with no external database dependency.

## Prerequisites

- Rust 1.75+ (stable)
- OpenSSL development headers (for TLS)
- Linux: `libbpf-dev` and `clang` if using XDP kernel bypass

## Quick Start

```bash
# Run with default configuration (development mode)
cargo run

# Run with a specific config file
cargo run -- --config config/development.toml

# Or via environment variable
NEXUS_CONFIG_PATH=config/development.toml cargo run
```

## CLI Options

```
nexus-sfu [OPTIONS]

  -h, --help              Print help
  -v, --version           Print version
  -c, --config <PATH>     Path to TOML configuration file
  --media-addr <ADDR>     Media (RTP/RTCP) bind address [default: 0.0.0.0:10000]
  --signal-addr <ADDR>    Signaling (WebSocket) bind address [default: 0.0.0.0:8080]
  --workers <NUM>         Number of worker threads [default: auto-detect]
  --log-level <LEVEL>     trace, debug, info, warn, error [default: info]
  --log-file <PATH>       Optional log file path
```

## Configuration

Configuration follows this precedence: CLI flags > environment variables > config file > defaults.

Three config profiles are provided:

| Profile | File | Use case |
|---------|------|----------|
| Default | `config/default.toml` | General development, auto-detect workers |
| Development | `config/development.toml` | Local testing, minimal resources |
| Production | `config/production.toml` | Deployed environments, tuned for performance |

See `config/README.md` for the full configuration reference.

### Key Environment Variables

```bash
NEXUS_CONFIG_PATH       # Path to TOML config file
NEXUS_JWT_SECRET        # JWT signing secret (required in production)
NEXUS_TLS_CERT_PATH     # TLS certificate path
NEXUS_TLS_KEY_PATH      # TLS private key path
NEXUS_WORKER_COUNT      # Override worker count
NEXUS_ARENA_SIZE_MB     # Override arena size
NEXUS_LOG_LEVEL         # Override log level
```

## Project Structure

```
nexus-sfu/
├── src/                    # SFU binary entry point and core logic
├── crates/
│   ├── nexus-core/         # Shared types and traits
│   ├── nexus-media/        # RTP/RTCP parsing, codecs, simulcast
│   ├── nexus-transport/    # UDP, ICE, DTLS, SRTP, arena, ring buffer
│   ├── nexus-state/        # CRDT-based distributed state, gossip
│   ├── nexus-actor/        # Actor system (track, participant, room)
│   ├── nexus-signal/       # QUIC + WebSocket signaling
│   ├── nexus-bwe/          # Bandwidth estimation (GCC)
│   ├── nexus-metrics/      # Prometheus metrics
│   ├── nexus-api/          # HTTP REST API
│   └── nexus-webrtc/       # WebRTC transport and SDP
├── config/                 # TOML configuration profiles
├── certs/                  # Development TLS certificates
├── benches/                # Criterion benchmarks
└── bpf/                    # XDP/BPF kernel bypass (Linux)
```

## Benchmarks

```bash
cargo bench --bench forwarding
cargo bench --bench packet_processing
cargo bench --bench crdt_sync
```

## License

Apache-2.0
