# Nexus SFU Architecture

This document describes the architecture **as it exists in the code today**, what is
**planned but not built**, and what in the original design **needs redesign** because it
cannot work as specified. The original design document is preserved in
[`docs/architecture-vision.md`](docs/architecture-vision.md).

Status legend:

| Mark | Meaning |
|------|---------|
| ✅ Implemented | Runs in the binary started by `src/main.rs` |
| 🟡 Partial | Code exists but is not wired in, or only part of it is on the live path |
| ⬜ Planned | Described in the vision, no implementation |
| ❌ Needs redesign | The design as written is incompatible with WebRTC or with other requirements |

Line references are as of v0.1.0 and will drift; prefer the file paths.

---

## Part 1 — Implemented

### 1.1 Process layout

One binary, one node. `main.rs` (`#[tokio::main]`) starts:

```
tokio runtime (multi-thread)
├── Signaling server         QUIC (quinn, Cap'n Proto) + WebSocket fallback (serde_json)
├── SessionOrchestrator      tokio::select! loop: Room / Negotiation / Subscription / ConnectionMonitor
├── REST API                 Axum + JWT
├── Metrics                  Prometheus
├── SWIM gossip              probe cycle + CRDT delta sync (nexus-state)
└── Ingress packet loop      Sfu::run_packet_loop — a single async task

std threads
└── Worker pool              N workers (num_cpus by default), optionally CPU-pinned + SCHED_FIFO
```

### 1.2 Media data path (actual)

```
media UDP socket
  │  recvmmsg (Linux) / recv_from per packet (macOS, Linux without io_uring)
  ▼
Ingress task (ONE tokio task for the whole process, not pinned)      src/sfu.rs  run_packet_loop
  ├── classify first byte (STUN / DTLS / RTP / RTCP)
  ├── STUN, DTLS  ──► mpsc channel ──► orchestrator (cold path)
  └── RTP / RTCP
        ├── session lookup (ArcSwap map + DashMap + session Mutex)   nexus-webrtc transport.rs
        ├── SRTP unprotect (RustCrypto AES-CM/HMAC-SHA1 or AES-GCM)
        ├── SSRC → (track, worker) lookup (DashMap)                  src/forward/router.rs
        ├── copy into arena slot                                     nexus-transport arena.rs
        └── crossbeam bounded MPMC try_send ──► worker               src/worker/pool.rs
                                                     │
Worker thread (pinned, spin-polling)                 ▼
  ├── per-track state (TrackActorState in a HashMap)
  ├── retransmission ring (RingBuffer<2048>, holds arena slots)
  ├── simulcast layer selection, TWCC recording, NACK / PLI handling
  └── per subscriber:
        ├── allocate slot + copy payload
        ├── inject MID / RID header extensions
        ├── rewrite seq / timestamp / PT / SSRC
        ├── SRTP protect with the subscriber's own keys
        └── BatchSender.queue ──► sendmmsg (flush at 64 packets or 1 ms)
```

Key facts about this path:

- **Receiving is single-threaded.** Receive, SRTP decrypt and routing for all
  publishers run in one task (`src/sfu.rs` `run_packet_loop`), so adding cores does not
  raise the ingress limit.
- **Fan-out is copy + encrypt per subscriber.** Each subscriber has its own DTLS-SRTP keys,
  so every forwarded packet is copied and re-encrypted (`src/worker/pool.rs`
  `forward_to_subscribers_static`).
- **Worker handoff is crossbeam MPMC**, not the SPSC channel in `src/worker/spsc.rs`.
- **Retransmission** is served from the per-track ring buffer on the worker. It is not
  correct yet: NACKs carry the subscriber's rewritten sequence numbers, but the ring is
  looked up by its own push counter; the cached packet is re-sent without the subscriber's
  seq / timestamp / SSRC rewrite; and the NACK sender SSRC is matched against the internal
  subscriber id.

### 1.3 Control plane

| Component | Status | Location |
|-----------|--------|----------|
| Session orchestrator (room, negotiation, subscription, connection monitor) | ✅ | `src/orchestrator/` |
| SDP offer/answer, ICE (host candidates, consent), DTLS via OpenSSL | ✅ | `crates/nexus-webrtc`, `crates/nexus-transport/src/{ice,dtls}` |
| DTLS peer certificate checked against the SDP `a=fingerprint` (RFC 8122); media blocked until it matches | ✅ | `WebRtcSession::set_remote_fingerprint` |
| SRTP / SRTCP (AES-CM-HMAC-SHA1-80, AES-GCM) | ✅ | `crates/nexus-transport/src/srtp` |
| QUIC signaling with Cap'n Proto | ✅ | `crates/nexus-signal/src/quic` |
| WebSocket signaling with JSON (used by the TypeScript SDK) | ✅ | `crates/nexus-signal/src/websocket` |
| REST API with JWT | ✅ | `crates/nexus-api` |
| Prometheus metrics + Grafana dashboard | ✅ | `crates/nexus-metrics`, `deploy/grafana` |
| GCC bandwidth estimation, REMB, probing | ✅ | `crates/nexus-bwe` |
| Config loading, validation, hot-reload | ✅ | `src/config/` |
| TypeScript client SDK | ✅ | `sdk/` |
| Docker image | ✅ | `deploy/docker` |

### 1.4 Distributed state

| Component | Status | Notes |
|-----------|--------|-------|
| CRDTs: ORSWOT, LWWReg, GCounter | ✅ | `crates/nexus-state/src/crdt`. Guarded by `std::sync::RwLock` |
| SWIM membership + gossip | ✅ | Started in `src/sfu.rs` (`SwimProtocol::new`, `run_probe_cycle`) |
| No Redis / no database | ✅ | |
| Subscription graph in CRDT | 🟡 | ORSWOT capacity is 10,000 entries; `add_subscription` errors are discarded (`src/orchestrator/subscription.rs`), so large rooms silently lose entries |
| Cross-node relay (cascade) | 🟡 | `src/relay/` exists and relay events are gossiped, but `set_relay_manager` is never called, so no packets are relayed |

### 1.5 Memory model (actual)

- Global `PacketArena` of 1500-byte slots (1 GB in `config/production.toml`), plus a
  per-worker arena in `src/worker/pool.rs`.
- Slot free list is a lock-free stack. **Each slot also heap-allocates its refcount**
  (`Box<AtomicU32>` in `PacketSlot::new`), so there is one malloc/free per slot.
- Per track: `RingBuffer<2048>` keeping up to 2,048 packets for retransmission (~3 MB of
  arena per track once full).
- Per track: subscriber `Vec` pre-reserved for 100 subscribers (~450 KB), each entry with
  its own `SrtpContext`.
- Per session: OpenSSL context, key and certificate, DTLS buffers, a pure-Rust
  `DtlsSession` fallback and the ICE agent, all kept for the life of the session.

---

## Part 2 — Planned, not built

These appear in the vision document but have no implementation, or only unreachable code.

| Item | Status | What exists today |
|------|--------|-------------------|
| Multi-threaded ingress (each pinned worker owns a socket, e.g. `SO_REUSEPORT`) | ⬜ | Single ingress task |
| io_uring multishot recv with registered buffers | 🟡 | `init_multishot_recv` exists in `crates/nexus-transport/src/io_uring.rs` but is never called; the multishot path also has a source-address bug (`MSG_PEEK` on the next packet) |
| UDP GRO / GSO | 🟡 | `crates/nexus-transport/src/{gro,gso}.rs` exist, not used by the live path |
| SPSC ingress → worker channels | 🟡 | `src/worker/spsc.rs` exists, not used |
| Lock-free copy-on-write subscriber set (`ArcSwap<SubscriberSet>`) | ⬜ | Plain `Vec<ActorSubscriber>` |
| Actor-per-track runtime (`nexus-actor` supervision) | 🟡 | `spawn_track` / `spawn_participant` are only called from tests; live per-track state is `TrackActorState` in the worker pool |
| Track migration by subscriber location | 🟡 | `WorkerPool::migrate_track` exists, nothing calls it |
| Consistent-hash track assignment, work stealing | ⬜ | |
| Cross-node forwarding | 🟡 | See 1.4 |
| QUIC 0-RTT resume | ⬜ | |
| gRPC API | ⬜ | REST only |
| Edge layer (anycast, PoPs) | ⬜ | Single node binary |
| Kubernetes manifests, HPA, autoscaler, Terraform | ⬜ | `deploy/` has only `docker/` and `grafana/` |
| Stateless workers / spot-instance tolerance | ⬜ | All session state (ICE, DTLS, SRTP, rings) lives in one process; losing a node drops its calls |
| DPDK | ⬜ | |
| `src/forward/{multicast,selective,processor}.rs` | 🟡 | Present, not on the live path |

---

## Part 3 — Needs redesign

These parts of the vision cannot work as written, whatever the implementation effort.

### 3.1 Zero-copy fan-out conflicts with per-subscriber SRTP

The vision's `forward_packet` pushes `clone_shallow()` of one buffer to every subscriber
(~200 ns per packet). In WebRTC every subscriber negotiates its own DTLS-SRTP keys, and the
SFU also rewrites SSRC / sequence / timestamp and header extensions per subscriber. Each
outgoing packet therefore needs its own buffer and its own encryption.

Redesign direction:
- Accept one copy + one encrypt per subscriber-packet as the base cost and budget for it.
- Reduce the constant: cache the AES key schedule and HMAC state per SRTP context
  (currently rebuilt per packet), prefer AES-GCM, and use GSO for sends.
- Share an SRTP context per subscriber rather than per subscribed track.

### 3.2 XDP / eBPF forwarding of RTP

`bpf/xdp_sfu.c` rewrites IP/port and redirects the publisher's packet. That forwards the
publisher's SRTP ciphertext, which subscribers cannot decrypt, and the map holds one
destination per SSRC, so it cannot fan out. The "90% of packets in XDP" model is not
possible for WebRTC media.

Additional state: `XdpPacketLoop` (`src/sfu.rs`) is never constructed, AF_XDP ring
operations in `src/transport/af_xdp.rs` are placeholders, and nothing loads the BPF
program.

Redesign direction: use AF_XDP only as a faster **userspace** socket (zero-copy RX/TX
rings), with SRTP still done in userspace; or drop XDP from scope.

### 3.3 "Zero locks, zero allocation" hot path

The design principle is sound, but the live path currently takes DashMap shard locks, a
session `Mutex` (twice per packet), a `RwLock` over the whole `WorkerPool`, and allocates
per packet (`to_vec` on receive, `Vec`s per `recvmmsg` poll, `get_srtp_key_material()`,
the arena refcount `Box`, `BatchSender`'s per-destination `Vec`s). Meeting the principle
requires restructuring ownership, not local tweaks: session and SRTP state owned by the
thread that receives the packet, and pre-allocated batch buffers.

### 3.4 Memory per participant

The vision targets < 100 KB per participant. Measured heap today is ~1.5 MB for an
audio+video publisher, plus ~6 MB of arena held by retransmission rings. Reaching the
target requires changing design choices, not only tuning:
- size retransmission buffers by time (hundreds of ms), not 2,048 packets;
- do not pre-reserve subscriber capacity;
- free the DTLS fallback and ICE agent once connected; share one OpenSSL context;
- one SRTP context per subscriber, not per subscribed track.

Also note that with a 1 GB arena and 2,048-packet rings, a node holds about 349 tracks
(~174 audio+video publishers), which contradicts the capacity and cost figures in the
vision.

### 3.5 Distributed subscription state

A subscription graph stored as a single ORSWOT grows as O(participants²) per room
(~250K entries for a 500-person room) and is capped at 10,000 entries. It needs
per-room or per-track partitioning, and insert failures must be surfaced.

---

## Performance targets

There is one set of targets: the table in [`README.md`](README.md#performance-targets).
The figures in `docs/architecture-vision.md` (1M+ pps, 800K pps, P99 < 15 ms) and the
500 KB figure in `src/lib.rs` are superseded.

**None of the targets are validated yet.** The real-path numbers below come from
`benches/real_path.rs` and `benches/memory.rs`. Numbers are Linux (Docker, arm64, Apple M2
Pro host), single core, loopback sockets. They exclude the kernel receive syscall and the
NIC transmit path, so a real deployment will be somewhat slower.

Browsers negotiate `SRTP_AES128_CM_HMAC_SHA1_80` today: the SFU lists it first in
`use_srtp` (crates/nexus-transport/src/dtls/openssl_backend.rs).

Egress, per forwarded packet (real `MediaWorker`, per-subscriber SRTP, `sendmmsg`):

| Media | SRTP profile | Per packet | Packets/sec/core |
|-------|--------------|-----------|------------------|
| Audio (100 B) | AES-CM + HMAC-SHA1 | ~1.3 µs | ~770K |
| Audio (100 B) | AES-GCM | ~1.25 µs | ~800K |
| Video (1100 B) | AES-CM + HMAC-SHA1 | ~2.0 µs | ~500K |
| Video (1100 B) | AES-GCM | ~3.2 µs | ~310K |

Ingress, per published packet (session lookup, SRTP decrypt, routing, handoff). This runs
on one thread for the whole process, so it is a server-wide limit, not per core:

| Media | AES-CM + HMAC-SHA1 | AES-GCM |
|-------|--------------------|---------|
| Audio | ~2.1 µs (~475K/s) | ~2.4 µs (~420K/s) |
| Video | ~2.8 µs (~360K/s) | ~4.2 µs (~240K/s) |

SRTP on arm64 uses the ARMv8 AES and SHA-1 instructions (`.cargo/config.toml`, and the
`sha1` `asm` feature in crates/nexus-transport/Cargo.toml). Cipher key schedules and
keyed HMAC state are built once per context, not per packet.

What dominates now:
- **AES-GCM on Linux arm64 is still slow** (~2.3 µs for 1.1 KB, ~0.5 GB/s): the
  RustCrypto GHASH only reaches hardware speed when PMULL is enabled at compile time,
  which slows the CM profile. A GCM implementation with runtime-dispatched assembly
  (e.g. `ring`, already a dependency) would fix both; then prefer GCM in `use_srtp`.
- **Ingress has ~1.6 µs of non-crypto overhead per packet:** locks, lookups, the per-packet
  key-material `Vec`, the 7 KB buffer memset and the copies.

Memory per audio+video publisher: **~1.5 MB heap** (session ~100 KB, DTLS handshake
~265 KB, ~580 KB per track, mostly the pre-reserved subscriber list) **plus ~6 MB of
arena** held by two 2048-packet retransmission rings. Each subscription beyond the
reservation costs ~4.4 KB.

Known gaps in measurement:
- No benchmark covers kernel receive or a real NIC; profile the running binary with `perf`.
- No latency (P50/P99) measurement under load.
- "Packets/sec" must state whether it counts ingress (published) or egress (forwarded)
  packets; with fan-out these differ by the subscriber count.
