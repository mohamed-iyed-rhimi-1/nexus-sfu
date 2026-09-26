# Nexus SFU Architecture

This document describes the architecture **as it exists in the code today**: what runs,
what is broken on the live path, what is planned but not built, and what in the original
design cannot work as specified.

- The original design: [`docs/architecture-vision.md`](docs/architecture-vision.md).
- The replacement data plane: [`docs/dataplane-design.md`](docs/dataplane-design.md), with
  the phase plans in [`docs/plans/`](docs/plans/).

Status legend:

| Mark | Meaning |
|------|---------|
| ✅ Implemented | Runs in the binary started by `src/main.rs` and works |
| 🟡 Partial | Code exists but is not wired in, or runs but does not work (see Part 2) |
| ⬜ Planned | Described in the vision, no implementation |
| ❌ Needs redesign | The design as written is incompatible with WebRTC or with other requirements |

Findings are as of commit `062e668` (v0.1.0), updated for Phase 0 (live bug fixes, dead
code removed, end-to-end harness, measurements). Line references will drift; prefer the
file paths.

---

## Part 1 — What runs

### 1.1 Process layout

One binary, one node. `main.rs` (`#[tokio::main]`) loads config, initialises tracing and
calls `nexus_sfu::server::start` (`src/server.rs`), which the end-to-end tests call too:

```
std threads
├── nexus-ingress            Sfu::run_packet_loop on its own current-thread runtime —
│                            busy loop, all media ingress for the process
├── Worker pool              N workers (num_cpus by default), CPU-pinned if worker.cpu_affinity,
│                            SCHED_FIFO if worker.realtime_priority
└── Gossip                   SWIM probe cycle + CRDT sync (nexus-state), bound to a random port

tokio runtime (multi-thread)
├── Signaling server         WebSocket + JSON (used by SDK and loadtest); QUIC is not started
├── SessionOrchestrator      tokio::select! loop: Room / Negotiation / Subscription / ConnectionMonitor
│                            also runs every DTLS handshake and ICE/consent timer
└── REST API                 Axum + JWT, /health, /ready, /metrics (Prometheus)
```

`main.rs` waits for SIGTERM/SIGINT and calls `ServerHandle::shutdown`: stop the ingress
loop, notify clients, drain, stop the worker pool, gossip and control-plane tasks.

### 1.2 Media data path

```
media UDP socket (one for the process)
  │  recvmmsg (Linux; io_uring is tried first but its multishot receive is never armed)
  │  kqueue + recv_from per packet (macOS)
  ▼
Ingress loop (main thread)                                          src/sfu.rs  step_once
  ├── classify first byte (RFC 7983)
  ├── STUN, DTLS  ──► to_vec ──► tokio mpsc ──► orchestrator (cold path)
  └── RTP / RTCP
        ├── session: ArcSwap addr map → DashMap → session Mutex     nexus-webrtc transport.rs
        ├── SRTP unprotect inside the lock (3 copies + memset)
        ├── SsrcRouter DashMap lookup                               src/forward/router.rs
        ├── send_publisher_srtcp_if_needed: 2nd session Mutex,
        │   key extraction (Vec alloc), SipHash, static DashMap      src/sfu.rs  (every packet)
        ├── arena alloc (CAS + Box) and copy                        nexus-transport arena.rs
        └── RwLock<WorkerPool> read → HashMap → crossbeam try_send  src/worker/pool.rs
                                                     │
Worker thread (pinned, spin-polling)                 ▼
  ├── per-track state (TrackActorState in a HashMap, 4 lookups per packet)
  ├── retransmission ring (RingBuffer<2048> of arena slots, audio included)
  └── per subscriber:
        ├── arena alloc (CAS + Box) + copy
        ├── inject MID / RID extensions, rewrite seq / timestamp / PT
        ├── SRTP protect with that (subscriber, track)'s own context
        └── BatchSender (HashMap<SocketAddr, Vec>) ──► sendmmsg at 64 packets or 1 ms
```

Key facts:

- **Ingress is one thread for the whole process**, and it sleeps with `std::thread::sleep`
  inside async code when idle (`src/spin.rs`). Adding cores does not raise the ingress limit.
- **Fan-out is copy + encrypt per subscriber**, because every subscriber has its own
  DTLS-SRTP keys (`forward_to_subscribers_static`).
- **Worker handoff is crossbeam MPMC.** The SPSC mesh in `src/worker/spsc.rs` is created
  and drained but has no production sender.
- **Per-packet cost on the ingress thread:** 2 session mutex locks, 4 DashMap reads,
  1 RwLock, 2 ArcSwap loads, about 2 heap allocations per packet plus 5 per batch.
- **Workers never touch sessions.** Everything reaches them as `WorkerMessage`s; subscriber
  addresses and SRTP contexts are copied in once and never updated.

### 1.3 Control plane

| Component | Status | Location |
|-----------|--------|----------|
| Session orchestrator (room, negotiation, subscription, connection monitor) | ✅ | `src/orchestrator/` |
| SDP offer/answer (SFU always offers) | ✅ | `crates/nexus-webrtc/src/sdp`, `src/orchestrator/negotiation.rs` |
| ICE: host candidates from `transport.announced_ips` (or the bind IP / interfaces) with the bound port, consent checks, full ICE (controlling) | ✅ | `src/orchestrator/candidates.rs`, `negotiation.rs` |
| DTLS via OpenSSL, peer certificate checked against SDP `a=fingerprint` (RFC 8122); role from the answer's `a=setup`; retransmission via OpenSSL's timer | ✅ | `openssl_backend.rs` `handle_timeout`, `session.rs` `poll_dtls_retransmit` |
| SRTP / SRTCP (AES-CM-HMAC-SHA1-80, AES-GCM) | ✅ | `crates/nexus-transport/src/srtp` |
| WebSocket signaling with JSON (SDK, loadtest) | ✅ | `crates/nexus-signal/src/websocket` |
| TLS for signaling, refuses to start if configured TLS fails | ✅ | `WebSocketServer::new` |
| QUIC signaling with Cap'n Proto | 🟡 | Echo stub in `nexus-signal`, not started (see 2.1) |
| REST API with JWT, `/health`, `/ready` | ✅ | `crates/nexus-api` |
| Prometheus metrics + Grafana dashboard | ✅ | `crates/nexus-metrics`, `deploy/grafana` |
| GCC bandwidth estimation, REMB | 🟡 | Runs, never receives input, see 2.1 |
| Config loading, validation, hot-reload | ✅ | `src/config/` |
| TypeScript client SDK (WebSocket + JSON only) | ✅ | `sdk/` |
| Docker image, `deploy/docker/run.sh` | ✅ | `deploy/docker` |

### 1.4 Distributed state

| Component | Status | Notes |
|-----------|--------|-------|
| CRDTs: ORSWOT, LWWReg, GCounter | ✅ | `crates/nexus-state/src/crdt`. Guarded by `std::sync::RwLock` |
| SWIM membership + gossip | 🟡 | Thread runs, but binds `0.0.0.0:0` (a random port), so other nodes cannot use it as a seed |
| No Redis / no database | ✅ | |
| Subscription graph in CRDT | 🟡 | ORSWOT capacity is 10,000 entries; `add_subscription` errors are discarded, so large rooms silently lose entries |
| Cross-node relay (cascade) | ⬜ | Removed in Phase 0 (it never relayed a packet); non-goal of the redesign |

### 1.5 Memory model

- Global `PacketArena` of 1500-byte slots of `memory.arena_size_mb`, plus per-worker arenas
  of `arena_size_mb / num_workers`: about 2× the configured size is mapped.
  `arena_size_mb / num_workers` panics when there are more workers than megabytes.
- Each slot heap-allocates its refcount (`Box<AtomicU32>` in `PacketSlot::new`).
- Per track: `RingBuffer<2048>` holding up to 2,048 ingest slots (≈ 3 MB once full), for
  audio as well as video.
- Per track: subscriber `Vec` pre-reserved for 100 subscribers (≈ 220 KB or more).
- Per subscriber per track: an `SrtpContext` and a `seq_map: [u16; 1024]` that is written
  but never read.
- Per session: OpenSSL context, key and certificate, DTLS buffers, an unused pure-Rust
  `DtlsSession` and the ICE agent, all kept for the life of the session.

---

## Part 2 — What is broken or unused on the live path

### 2.1 Features that do not work

| Feature | Why | Where |
|---------|-----|-------|
| **NACK retransmission** | Subscriber matched by `s.id == sender_ssrc` (participant id vs RTCP SSRC); ring looked up by its push counter, not RTP seq; `seq_map` never read; retransmits skip the rewrite; upstream NACK uses the subscriber's seq space; `nack` is never offered to publishers. | `pool.rs` `retransmit_from_ring_buffer`, `handle_rtcp_nack`; `negotiator.rs` |
| **Simulcast** | Each simulcast SSRC becomes its own track; layer messages are never sent; no `a=rid`/`a=simulcast` offered. | `pool.rs`, `negotiation.rs` |
| **Bandwidth estimation** | Worker GCC inputs are never sent; TWCC ext id stays 0; REMB always advertises the 1 Mbps constant. | `pool.rs` `BandwidthCoordinator`; `negotiation.rs` |
| **Keyframe on join** | No PLI when a subscriber is added; FIR ignored. PLI forwarding from subscribers works. | `pool.rs` `add_subscriber`; `sfu.rs` RTCP dispatch |
| **MID per subscriber** | One MID value per track (last subscriber wins); injection skips packets already carrying MID id 1. | `pool.rs` `SetTrackMid`, `inject_mid_extension` |
| **Address changes** | Subscriber destination fixed at subscribe time; NAT rebinding and ICE restart never reach workers. | `subscription.rs`; `pool.rs` `add_subscriber` |
| **QUIC signaling** | Not started. The module accepts connections and echoes the offer back as the answer; it never talks to the orchestrator. | `crates/nexus-signal/src/quic/streams.rs` |

Fixed in Phase 0: connecting from another machine (`transport.announced_ips` /
`NEXUS_ANNOUNCED_IPS`, candidates carry the bound port) and DTLS retransmission (OpenSSL's
timer is driven; the answer's `a=setup:passive` makes the SFU the DTLS client). Both are
covered by `tests/e2e.rs`.

### 2.2 Security risks

- **SRTCP toward publishers: one context per track, one key per publisher.** Each published
  track still has its own SRTCP context built from the publisher's key (`SetPublisherSrtcp`),
  each starting its SRTCP index at 0. Until Phase 0 this reused keystream: REMB and TWCC used
  sender SSRC 1 and forwarded PLI/NACK kept the subscriber's SSRC, so two tracks could emit
  the same (key, SSRC, index). Phase 0 closes it on the legacy path: every RTCP packet to a
  publisher carries its track's own random `rtcp_sender_ssrc` and is protected with that
  track's context, a repeated key keeps the existing context, and the ingress key cache
  forgets removed tracks. The structural fix (one context per session) is Phase 1.
- **SRTP keystream reuse on re-subscribe (open).** Each subscription gets a fresh
  `SrtpContext` from the subscriber session's key, with the publisher's SSRC (not
  rewritten) and a sequence counter starting at 0. `Unsubscribe` then `Subscribe` for the
  same track on the same session repeats the (key, SSRC, packet index) sequence: keystream
  reuse on media with AES-CM, nonce reuse with AES-GCM. Any client can trigger it. Not
  fixed on this data plane (nothing is deployed and Phase 1 replaces it); the new data plane
  removes it by construction (one outbound context per session), checked by a Phase 1 e2e
  test.
- **Subscriber SR contexts** share the same weakness: the per-subscription context also
  protects the SRs sent to that subscriber, so they restart at SRTCP index 0 on
  re-subscribe. Covered by the same fix.

### 2.3 Code not reachable from `main.rs`

Phase 0 removed about 17,000 lines of unreachable code and 5,600 lines of tests that were
never compiled: the XDP packet loop, `src/forward/{multicast,selective,processor}.rs`,
AF_XDP, `bpf/`, the relay, `nexus-recorder`, TURN, `SignalingHandler`,
`src/track_registry.rs`, QUIC and `ActorManager` from startup, and
`tests/{integration,stress,unit,validation,common}`. What remains unreachable:

| Code | Note |
|------|------|
| `nexus-actor` runtime | Not started. Config validation uses its limits and the worker its migration types; goes with the worker pool in Phase 6 |
| `nexus-signal` QUIC module | Not started; `[quic]` config kept, marked unused |
| `src/worker/spsc.rs`, migration drivers | Created but no production sender / caller (Part 3) |

`nexus-dst` builds and runs, but models the actor system and does not exercise the server.

---

## Part 3 — Planned, not built

| Item | Status | What exists today |
|------|--------|-------------------|
| Multi-threaded ingress | ⬜ | Single ingress loop; see the redesign |
| io_uring multishot recv with registered buffers | 🟡 | `init_multishot_recv` exists, never called |
| UDP GRO / GSO | 🟡 | `crates/nexus-transport/src/{gro,gso}.rs`, not on the live path |
| SPSC ingress → worker channels | 🟡 | `src/worker/spsc.rs`, no production sender |
| Actor-per-track runtime (`nexus-actor` supervision) | 🟡 | See 2.3 |
| Track migration, consistent hashing, work stealing | 🟡 | `migrate_track` has no caller; assignment is FNV-1a modulo |
| Cross-node forwarding | ⬜ | Relay code removed in Phase 0 (1.4) |
| QUIC 0-RTT signaling | 🟡 | See 2.1 |
| gRPC API | ⬜ | REST only |
| Edge layer (anycast, PoPs), Kubernetes manifests, autoscaler, Terraform | ⬜ | `deploy/` has `docker/` and `grafana/` |
| Stateless workers / spot-instance tolerance | ⬜ | All session state lives in one process |
| DPDK | ⬜ | |

---

## Part 4 — Needs redesign

These parts of the vision cannot work as written. The replacement data plane is
[`docs/dataplane-design.md`](docs/dataplane-design.md).

### 4.1 Zero-copy fan-out conflicts with per-subscriber SRTP

The vision's `forward_packet` pushes `clone_shallow()` of one buffer to every subscriber.
In WebRTC every subscriber has its own DTLS-SRTP keys, and the SFU rewrites SSRC, sequence,
timestamp and header extensions per subscriber. Each outgoing packet needs its own buffer
and its own encryption; the redesign budgets for that cost instead of avoiding it.

### 4.2 XDP / eBPF forwarding of RTP

`bpf/xdp_sfu.c` (removed in Phase 0) rewrote IP/port and redirected the publisher's
packet. That forwards the publisher's SRTP ciphertext, which subscribers cannot decrypt, and
the map held one destination per SSRC, so it could not fan out. AF_XDP remains possible as a faster userspace
socket, with SRTP still in userspace.

### 4.3 "Zero locks, zero allocation" hot path

Sound as a principle; unreachable with the current ownership (1.2). It requires session and
SRTP state owned by the thread that receives the packet.

### 4.4 Memory per participant

Measured ≈ 1.5 MB heap plus ≈ 6 MB arena per audio+video publisher (Part 5), against a
100 KB target. The redesign restates the target: 100 KB fixed per participant, with video
retransmission history (≈ 310 KB per second of 2.5 Mbps video) reported separately.

### 4.5 Distributed subscription state

A subscription graph in one ORSWOT grows as O(participants²) per room (≈ 250K entries for
500 people) and is capped at 10,000 entries. It needs per-room or per-track partitioning,
and insert failures must be surfaced. Out of scope for the data-plane redesign.

---

## Part 5 — Performance baseline

There is one set of targets: the table in [`README.md`](README.md#performance-targets),
restated with measurement methods in the redesign. **None are met or validated yet.**

Measured at commit `062e668` on Linux arm64 (Docker Desktop VM, 6 vCPUs, Apple M2 Pro host)
with `cargo bench --bench real_path` and `--bench memory`. Criterion medians; runs vary by
±10% (more on single-subscriber cases), so the 100-subscriber rows are used. Loopback
sockets; no NIC.

**Per-packet cost**

| Stage | AES-CM-HMAC-SHA1-80 | AES-GCM |
|-------|--------------------:|--------:|
| SRTP protect, 1,200-byte video | 0.73 µs | 2.04 µs |
| SRTP protect, 160-byte audio | 0.21 µs | 0.40 µs |
| Ingress, video (socket buffer → worker queue) | 2.47 µs | 3.78 µs |
| Ingress, audio | 1.91 µs | 2.08 µs |
| Egress per subscriber, video (100 subscribers, incl. `sendmmsg`) | 2.19 µs | 3.13 µs |
| Egress per subscriber, audio (100 subscribers) | 1.22 µs | 1.25 µs |

- **Egress:** ≈ 455K video subscriber-packets/s per worker core with AES-CM (≈ 320K with GCM).
- **Ingress:** one thread for the process, ≈ 400K incoming video packets/s at most, shared
  with STUN, DTLS and RTCP.
- **Combined:** a video packet fanned out to 10 subscribers costs ≈ 24 µs of CPU, ≈ 2.4 µs
  per subscriber-packet; beyond that, the ingress thread is the limit.
- Browsers negotiate AES-CM today (listed first in `use_srtp`). AES-GCM is slow with the
  RustCrypto backend; the redesign picks the backend by benchmark.

**Memory** (heap via counting allocator; arena slots separately)

| Item | Rust allocator | All malloc (incl. OpenSSL) |
|------|---------------:|---------------------------:|
| Session created | 69 KB | 102 KB |
| Session after DTLS handshake | 127 KB | 268 KB |
| Published track (worker state) | 578 KB | — |
| Subscriber 1-100 on a track | 0 (pre-reserved in the track) | — |
| Subscriber 101-200 | 4.4 KB | — |
| Retransmit ring, full | 3,000 KB of arena | — |
| **A+V publisher, no subscriptions** | **1,526 KB** + 6,000 KB arena | — |
| **+ subscribed to 10 A+V publishers** | **1,615 KB** + 6,000 KB arena | — |

**SRTP backends** (Phase 0.4, `cargo bench --bench srtp_backends`). Median ns per packet,
20-byte RTP header + payload; every backend's output is checked byte-for-byte against
`SrtpContext` before timing.

Linux arm64 (Docker VM, 6 vCPUs, Apple M2 Pro host, idle machine):

| Profile | Backend | protect 160 B | protect 1,200 B | unprotect 160 B | unprotect 1,200 B |
|---------|---------|--------------:|----------------:|----------------:|------------------:|
| AES-CM-HMAC-SHA1-80 | RustCrypto `SrtpContext` (current) | 238 | 763 | 247 | 773 |
| AES-CM-HMAC-SHA1-80 | OpenSSL CTR + OpenSSL HMAC¹ | 391 | 839 | 346 | 810 |
| AES-CM-HMAC-SHA1-80 | OpenSSL CTR + ring HMAC² | 924 | 3,596 | 936 | 3,277 |
| AES-128-GCM | RustCrypto `SrtpContext` (current) | 440 | 2,279 | 495 | 2,226 |
| AES-128-GCM | OpenSSL EVP | 131 | 290 | 126 | 266 |
| AES-128-GCM | ring `LessSafeKey` | 103 | 238 | 107 | 258 |

macOS arm64 (Apple M2 Pro, native):

| Profile | Backend | protect 160 B | protect 1,200 B | unprotect 160 B | unprotect 1,200 B |
|---------|---------|--------------:|----------------:|----------------:|------------------:|
| AES-CM-HMAC-SHA1-80 | RustCrypto `SrtpContext` (current) | 273 | 1,000 | 281 | 1,013 |
| AES-CM-HMAC-SHA1-80 | OpenSSL CTR + OpenSSL HMAC¹ | 483 | 1,139 | 488 | 1,149 |
| AES-CM-HMAC-SHA1-80 | OpenSSL CTR + ring HMAC² | 1,117 | 4,297 | 1,126 | 4,314 |
| AES-128-GCM | RustCrypto `SrtpContext` (current) | 156 | 809 | 218 | 871 |
| AES-128-GCM | OpenSSL EVP | 167 | 301 | 164 | 306 |
| AES-128-GCM | ring `LessSafeKey` | 99 | 282 | 101 | 297 |

¹ Copies two digest contexts per packet (the `openssl` crate has no reusable keyed HMAC); an
upper bound. ² ring's SHA-1 has no hardware acceleration.

The RFC 7714 vectors added with this bench found two AES-GCM interop bugs, fixed in Phase 0:
the AEAD KDF put the label in salt byte 6 instead of 7 (wrong RTP salt and RTCP keys), and
SRTCP put E+index before the tag instead of after it. AES-GCM therefore never worked with
browsers; it went unnoticed because AES-CM is offered first.

**Kernel UDP floor** (`cargo bench --bench udp_floor`, Linux arm64, same VM): raw
`sendmmsg`/`recvmmsg` of 1,200-byte datagrams in batches of 64 over loopback, no SFU code.

| Operation | ns per datagram |
|-----------|----------------:|
| `sendmmsg`, 1 destination | 665 |
| `sendmmsg`, 10 destinations | 895 |
| `sendmmsg`, 100 destinations | 1,058 |
| `recvmmsg` | 418 |

Loopback delivers each datagram to the receiving socket inside the sender's system call, so
these include receive-side work a NIC transmit would not; treat them as an upper bound for
the send floor on this machine. Not measured: x86_64 (needs the CI runner) and a real NIC.

Known gaps: no benchmark covers kernel receive, a real NIC, or latency (P50/P99) under
load. "Packets/sec" always needs to say ingress (published) or egress (forwarded).
