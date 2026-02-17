# Contributing to Nexus SFU

## Getting Started

1. Fork the repository
2. Clone your fork
3. Install prerequisites: Rust 1.83+, `capnp`, `protoc`, `liburing-dev` (Linux)
4. Run `cargo test --workspace` to verify your setup

## Development Workflow

```bash
# Run all checks before submitting
cargo fmt --all --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Code Style

All code follows [TigerStyle](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md) and NASA's Power of 10 Rules:

- No dynamic allocation after initialization on hot paths
- Fixed upper bounds on all loops
- Comprehensive assertions (positive and negative space)
- Functions fit on one screen (~60 lines)
- No `unsafe` unless absolutely necessary and documented
- `#![deny(warnings)]` everywhere

## PR Guidelines

- Keep PRs focused on a single change
- Include tests for new functionality
- Hot path changes must include benchmark results
- Update documentation if behavior changes

## Architecture

Before making changes, understand the separation:

- **Packet loop** (`sfu.rs`): zero-alloc, pinned core, inline RTP/RTCP processing
- **Orchestrator** (`orchestrator/`): tokio async, session management, signaling
- **Library crates** (`crates/`): reusable components with their own test suites

Do not add allocations or locks to the packet loop hot path.
