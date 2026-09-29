# Nexus SFU Architecture

This document describes the architecture **as it exists in the code today**: what runs,
what is missing or unused on the live path, what is planned but not built, and what in the
original design cannot work as specified.

- The original design: [`docs/architecture-vision.md`](docs/architecture-vision.md) (reference
  only; most of it describes code that no longer exists).
- The replacement data plane: [`docs/dataplane-design.md`](docs/dataplane-design.md), with
  the phase plans in [`docs/plans/`](docs/plans/).

Status legend:

| Mark | Meaning |
|------|---------|
| ✅ Implemented | Runs in the binary started by `src/main.rs` and works |
| 🟡 Partial | Code exists but is not wired in, or runs but does not work (see Part 2) |
| ⬜ Planned | Described in the design or vision, no implementation |
| ❌ Needs redesign | The design as written is incompatible with WebRTC or with other requirements |

Findings are as of Phase 1 (the new data plane with one shard, commit `fa8a6a9`), traced from
`src/main.rs`. The old data plane (ingress loop, worker pool, SSRC router, packet arena,
`nexus-actor`) is deleted. The full rewrite of this document is part of the v1 release
(`dataplane-design.md` §5). Line references drift; prefer the file paths and symbol names.

---

## Part 1 — What runs

### 1.1 Process layout

One binary, one node. `main.rs` (`#[tokio::main]`) loads config (CLI > env > file >
defaults, then `NexusConfig::validate`), initialises tracing and calls
`nexus_sfu::server::start` (`src/server.rs`), which the end-to-end tests call too:

```
std threads
├── nexus-shard-0           ShardThread::run: the data plane (one shard in Phase 1), its own
│                           UDP socket; pinned and SCHED_FIFO only if configured
├── nexus-gossip            SWIM gossip: only if cluster.gossip_enabled (default off)
└── config watcher          notify; only with a config path (see 2.1: nothing reads reloads)

tokio runtime (multi-thread)
├── Signaling server        WebSocket + JSON, one task per connection; QUIC is not started
├── SessionOrchestrator     select! over signaling, data-plane events and timers; runs every
│                           DTLS handshake; sends commands to the shard
└── REST API                Axum + JWT: /health, /ready, /metrics, GET/POST /rooms, GET/DELETE /rooms/:id
```

There is no separate metrics server: `/metrics` is served by the REST API, and
`metrics.bind_addr` is only reserved so media ports avoid it. `/metrics` reads the shard's
published counters at render time (`DataplaneHandle::stats`); no copy task runs.

`main.rs` waits for SIGTERM/SIGINT (and notices a dead shard, `ServerHandle::is_finished`),
then calls `ServerHandle::shutdown`:

1. `/ready` returns 503;
2. `ServerShutdown` to every WebSocket client, then `drain_timeout_ms`;
3. the shared shutdown flag: the accept loop, the orchestrator (next 50 ms tick) and the API
   task exit; they are awaited for at most 5 s;
4. `dataplane.shutdown()` (stop flag, wake, join; the shard publishes its final stats), then
   the gossip thread, if any.

The orchestrator stops before the shard, so no `CloseSession` is sent at shutdown.

### 1.2 Media data path

```
shard UDP socket (one per shard)                    crates/nexus-dataplane/src/shard/
  │  Linux: recvmmsg / sendmmsg, batches of 64 / 256, UDP_GRO refused     io/linux.rs
  │  macOS: recv_from / send_to per datagram ("correct, not fast")          io/portable.rs
  ▼
Shard::iterate(now)                                                          mod.rs
  ├── classify first byte (RFC 7983): STUN / DTLS / RTP / RTCP / drop          ingress.rs
  ├── STUN: bounded scan (≤ 32 attributes), MESSAGE-INTEGRITY + FINGERPRINT,   ice.rs
  │         response written in place; ICE-lite address selection
  │         (nomination, rebind after 2 s silence, 100 ms switch throttle)
  ├── DTLS: from the selected address, before SRTP is verified, within the
  │         per-session (32/s) and shard (1,024/s) budgets
  │         ──► Event::DtlsDatagram ──► orchestrator (handshake)
  ├── RTP:  SrtpInbound unprotect in place ──► SSRC → track (learned by `mid`)
  │         └── fan_out: per subscription
  │               ├── rewrite: PT, seq / ts offsets, SSRC, extension ids     rewrite.rs
  │               ├── SrtpOutbound protect (one context per subscriber session)
  │               └── commit (state advances only if the packet is queued)
  ├── RTCP: SR ──► SR + SDES CNAME per subscription (translated timestamps)   rtcp.rs
  │         PLI / FIR ──► one PLI to the publisher per 500 ms
  │         everything else counted as rtcp_ignored
  ├── pending address switches, flush (sendmmsg)
  ├── commands (≤ 64 per iteration), flush
  └── housekeeping, once per second                                          housekeeping.rs
        (budgets, idle SRTP state, consent timeout 30 s, stats publish)
```

Key facts:

- **One clock read per iteration** (`Instant::now` in `ShardThread::run`, passed down), no
  locks and **0 heap allocations per packet** on the steady-state path, AES-GCM and AES-CM
  (`crates/nexus-dataplane/tests/alloc.rs`). Allocations remain on the DTLS path (each
  `DtlsDatagram` is a boxed copy) and in command handling (slab and map growth).
- **State is owned by the shard thread:** sessions, published tracks and subscriptions in
  generational slabs (`slab.rs`), looked up through pre-sized `FxHashMap`s (`by_addr`,
  `by_ufrag`, ids); packets in a fixed `BufferPool` of 2,048-byte buffers (`pool.rs`).
- **SRTP:** one `SrtpInbound` and one `SrtpOutbound` per session (`nexus-transport`
  `srtp/direction.rs`). Each subscription sends under its own SSRC, `out_ssrc_base` plus a
  strictly increasing offset that is never reused, so an unsubscribe/resubscribe can never
  repeat an (SSRC, packet index) pair. AES-GCM runs on ring, AES-CM on RustCrypto.
- **Keyframes:** a PLI to the publisher on `Subscribe` (when SRTP is installed) and on
  `InstallSrtp` for existing subscriptions; subscriber PLI/FIR are forwarded, throttled to
  one per 500 ms per track.
- **Interface to the control plane** (`command.rs`, `handle.rs`): commands (`CreateSession`,
  `SendDatagram`, `InstallSrtp`, `AddTrack`, `RemoveTrack`, `Subscribe`, `Unsubscribe`,
  `CloseSession`) through a bounded `ArrayQueue` per shard (4,096; a full queue is an error to
  the sender, never a silent drop); events (`DtlsDatagram`, `AddressSelected`,
  `PeerSrtpVerified`, `ConsentLost`, `CommandRejected`) through one `tokio::mpsc` (8,192),
  sent with `try_send`. When it is full, events are retained (up to 256) except
  `DtlsDatagram`, which is dropped (peers retransmit).
- **Idle:** the shard busy-polls `busy_poll_rounds` times (default 0), then parks in
  `mio::Poll` on the socket and a waker; a command producer wakes it only if it is parked
  (`shard/park.rs`).
- **Limits per session:** 10 published tracks, 31 subscriptions, one layer per track.

### 1.3 Control plane

| Component | Status | Location |
|-----------|--------|----------|
| Session orchestrator: one `select!` loop over signaling, data-plane events (≤ 256 at a time), the DTLS timer (200 ms) and the sweep (1 s) | ✅ | `src/orchestrator/mod.rs` |
| Commands, sessions, SRTP install, closing (`Plane`); a full command queue closes that participant with `Overloaded` | ✅ | `plane.rs` |
| Data-plane events: DTLS input, `AddressSelected` (may start the handshake as client), `PeerSrtpVerified` (frees the OpenSSL `SSL`), `ConsentLost`; ICE (30 s) and DTLS (10 s) timeouts | ✅ | `connection.rs`, `transports.rs` |
| DTLS via OpenSSL, one certificate for the process; role fixed by whichever comes first, a ClientHello or the answer's `a=setup`; output split into ≤ 1,200-byte datagrams; peer fingerprint (SHA-256) checked against the SDP; `SRTP_AEAD_AES_128_GCM` offered first, then `SRTP_AES128_CM_SHA1_80` | ✅ | `dtls.rs`, `crates/nexus-transport/src/dtls/openssl_backend.rs` |
| ICE-lite: random credentials per session, host candidates from `transport.announced_ips` (or the bind IP / interfaces) with the bound port; the SFU starts no checks and sends no consent requests (consent is the shard's 30 s receive timeout); remote candidates are ignored | ✅ | `transports.rs`, `candidates.rs`, `negotiation.rs` |
| SDP offer/answer: the SFU always offers, one BUNDLE session per participant; VP8/96 and Opus/111 only; `nack pli` and `ccm fir` on video; declined m-lines stay as inactive placeholders; simulcast groups refused | ✅ | `negotiation.rs`, `sdp_params.rs`, `crates/nexus-webrtc` (SDP only) |
| Tracks and subscriptions: registry, `Published` to the publisher, ≤ 10 tracks per request, subscriptions confined to the subscriber's room; `Viewport` / `SetContent` acknowledged with no effect | ✅ | `tracks.rs`, `subscription.rs` |
| Rooms: create, join, leave on `DistributedState`; ≤ 10,000 rooms, 4 per creating connection, released when empty | ✅ | `room.rs` |
| WebSocket signaling with JSON (SDK, loadtest); 256 KB message and 1 MB frame caps, rate limit | ✅ | `crates/nexus-signal/src/websocket` |
| TLS for signaling; refuses to start if configured TLS fails | ✅ | `WebSocketServer::new` |
| REST API with JWT, `/health`, `/ready`, `/metrics`; room routes limited to the token's `rooms` | ✅ | `crates/nexus-api` |
| Room authorization: the JWT's `rooms` claim (names, `"*"` for all) gates `Create`/`Join` and the REST room routes (`FORBIDDEN` / 403); no claim, no room | ✅ | `nexus_api::auth::RoomGrant`, `src/orchestrator/room.rs` |
| Prometheus metrics: `nexus_shard_*` per shard; Grafana dashboard | ✅ | `crates/nexus-metrics`, `deploy/grafana` |
| Config loading and validation (unknown sections and fields refused) | ✅ | `src/config/` |
| Config hot-reload | 🟡 | Runs, but nothing reads the reloaded config (2.1) |
| QUIC signaling | 🟡 | Not started (2.3) |
| GCC bandwidth estimation, REMB | 🟡 | Not called (2.3) |
| TypeScript client SDK (WebSocket + JSON), example page | ✅ | `sdk/`, `examples/web/` |
| Dev token: `nexus-loadtest token --sub <name> --room <room>` | ✅ | `crates/nexus-loadtest` |
| Docker image, `deploy/docker/run.sh` | ✅ | `deploy/docker` |

### 1.4 Distributed state

| Component | Status | Notes |
|-----------|--------|-------|
| `DistributedState`: rooms, participants, tracks, subscriptions as CRDTs (ORSWOT, LWWReg, GCounter) behind `std::sync::RwLock` | ✅ | `crates/nexus-state`. On one node it is the orchestrator's and REST's registry; one room-id allocator (`create_room_auto`) for both |
| SWIM membership + gossip | 🟡 | Off unless `cluster.gossip_enabled` (then bound to `cluster.gossip_bind_addr`, never a wildcard). **Unauthenticated**; clustering is a v1 non-goal (`dataplane-design.md` §2). The receive path does not panic on any input |
| Room participant sets | ✅ | Grow on demand up to the room's limit (0 B of heap for an empty room). Removal records (tombstones) recycle, oldest first: safe on one node only |
| No Redis / no database | ✅ | |
| Cross-node relay (cascade) | ⬜ | Non-goal of the redesign |

### 1.5 Memory model

- **Per shard, fixed at start:** the `BufferPool` (`pool_buffers` × 2,048 B, 1,024 buffers by
  default), the command queue, maps pre-sized for `max_sessions` (1,000 by default), and the
  receive and send batches.
- **Per participant:** a session slot with fixed arrays (10 tracks, 31 subscriptions),
  `SrtpInbound` + `SrtpOutbound` (7,728 B), published-track and subscription slots, and the
  control plane's transport entry and registry records. The OpenSSL `SSL` object and the
  engine's buffers are freed once the peer's SRTP is verified (`free_ssl`).
- **No retransmission history** (NACK is Phase 3).
- Numbers: Part 5.

---

## Part 2 — What is missing, broken or unused

### 2.1 Not built or not working

| Feature | State | Where / when |
|---------|-------|--------------|
| **NACK retransmission, RTX** | Not offered to publishers; subscriber NACKs are counted and dropped (`rtcp_ignored`); no history | Phase 3 (NACK); RTX after v1 |
| **RR and TWCC toward publishers** | Not sent, so browsers keep their start bitrate | Phase 3 |
| **Simulcast** | `MAX_LAYERS` = 1; `a=ssrc-group:SIM` refused in the answer | After v1 |
| **Bandwidth estimation** | Not called (`nexus-bwe`, 2.3); `[bwe]` config is not read | After v1 |
| **Multiple shards** | `dataplane.shards` 1..=16 starts one thread per shard, connected by the cross-shard mesh (Phase 2.3); only `SingleShard` placement exists, so every session is on shard 0, capped at `max_webrtc_sessions / shards` while the other shards idle (a startup warning says so), and only its candidates are advertised | Phase 2.4 (`Placement` is the hook) |
| **ICE restart / network switch** | No ICE restart; a changed address is followed only by the rebind rule (2 s silence), so a client whose new path needs a new candidate pair loses the call | After v1 |
| **Codecs** | VP8 and Opus only | After v1 |
| **QUIC signaling** | Not started (2.3) | Non-goal |
| **Config hot-reload** | The watcher writes a config that nothing reads (`_runtime_config` in `main.rs`) | — |
| **Unread config** | `[bwe]`, `[quic]`, `[room]`, `[ice_servers]`; `[metrics]` except its port reservation | — |
| **Metrics that stay zero** | `nexus_sfu_*` and `nexus_crdt_*` are exported, but nothing feeds `SfuMetrics` / `CrdtMetrics` since the old path was deleted; the Grafana panels on them read zero | After v1 |

### 2.2 Security

Fixed in Phase 1 (by construction, one outbound SRTP context per session; tested by
`resubscribe_no_srtp_index_reuse` and `sender_report_translation` in `tests/e2e.rs`):

- **SRTP keystream reuse on re-subscribe.** The old path built a fresh context per
  subscription from the same key, so `Unsubscribe` + `Subscribe` repeated (key, SSRC,
  packet index). Each subscription now sends under a new SSRC from a strictly increasing,
  never reused offset, in the session's single outbound context.
- **SRTCP per-track contexts toward publishers and subscriber SRs.** Both now go through the
  session's single context and SRTCP index.
- **Room authorization** (Phase 1.9a). The JWT's `rooms` claim names the rooms its holder
  may create, join or manage over REST (`"*"`: every room, including unnamed ones); others
  are refused with `FORBIDDEN` (REST: 403). A token without the claim authenticates but
  reaches no room. `FORBIDDEN` on `Join` differs from `ROOM_NOT_FOUND`, so room ids can
  still be probed for existence (owner's decision).
- **No panic on network input** (Phase 1 exit criterion 6): every path a datagram or a
  signaling message reaches was swept, with proptests on the shard's STUN handling, the
  signaling messages and the gossip decoders (`docs/plans/phase-1.md`, "Before 1.9").

Open (known, accepted for now; details in `docs/plans/phase-1.md` "Risks" and "Before 1.9"):

- **ICE-lite on-path injection.** STUN authenticates the request, not its source address; an
  on-path attacker can move a session to its own address until the peer's next nomination.
  Media stays encrypted.
- **Gossip is unauthenticated** (off by default).
- **Signaling resource limits:** the TLS accept and WebSocket upgrade have no timeout, so
  half-open connections can hold the connection slots; `Disconnected` is sent with
  `try_send` and can be lost when the orchestrator's queue is full (that participant's state
  leaks); rooms created over REST are released only by `DELETE /rooms/:id`, never automatically when
  empty.
- **`MemBio` grows without a limit** if OpenSSL stops reading after an alert (bounded in rate
  by the shard's DTLS budget and in time by the 10 s handshake timeout).

### 2.3 Code not reachable from `main.rs`

| Code | Note |
|------|------|
| `nexus-bwe` (GCC, REMB, probing) | Only re-exported from `src/lib.rs`; no caller |
| `nexus-signal` QUIC module | Not started; `[quic]` config kept, unread |
| `nexus-transport` `gro.rs`, `gso.rs` | Unused; the shard reads `UDP_GRO` only to refuse it |
| `nexus-transport` `SrtpContext` | Tests and benches only; the shard uses `SrtpInbound` / `SrtpOutbound` |
| `nexus-media` `simulcast.rs`, `codec/`, `RtpHeader::parse_simd` | The shard uses the scalar `RtpHeader::parse`, the RTCP parsers and the extension table only |
| `TracingMetrics`, `HOT_PATH_METRICS`, `LatencyGuard` | Created or used in tests only |
| Gossip `drain_relay_events` (`nexus-state` `gossip/protocol.rs`) | Called in tests only; with gossip on, its relay queue fills |
| `src/signal/mod.rs` constants | `MAX_MESSAGE_QUEUE_SIZE`, `DEFAULT_PING_INTERVAL_MS`, `DEFAULT_CONNECTION_TIMEOUT_MS`, `CONSENT_FRESHNESS_INTERVAL_MS` have no users |

---

## Part 3 — Planned, not built

| Item | Status | What exists today |
|------|--------|-------------------|
| Multiple shards on multiple cores, port per shard, cross-shard queues | 🟡 | Phase 2. Shards start on their own threads and ports, connected by the cross-shard queues (2.3); placement is still `SingleShard` (2.4), so sessions all go to shard 0, capped at `max_webrtc_sessions / shards` |
| Throughput and scaling bench (`benches/dataplane.rs`) | ⬜ | Phase 2. `real_path` measures ingress and per-subscriber egress separately |
| NACK, RR, TWCC feedback | ⬜ | Phase 3 (`docs/design/loss-recovery.md`, to be written) |
| Simulcast, bandwidth estimation, single-port mode, RTX | ⬜ | After v1 |
| UDP GRO / GSO | 🟡 | Modules exist, unused (2.3); GRO is refused on the shard socket |
| io_uring / AF_XDP | ⬜ | Evaluated after v1 (`dataplane-design.md` §3.12) |
| Clustering (authenticated gossip, cross-node state) | ⬜ | Non-goal for v1 |
| gRPC API | ⬜ | REST only |
| Edge layer (anycast, PoPs), Kubernetes manifests, autoscaler, Terraform | ⬜ | `deploy/` has `docker/` and `grafana/` |
| DPDK | ⬜ | |

---

## Part 4 — Needs redesign

These parts of the vision cannot work as written. The replacement data plane is
[`docs/dataplane-design.md`](docs/dataplane-design.md); 4.1, 4.3 and 4.4 are what Phase 1
built (a per-subscriber encrypt within a measured budget, state owned by the shard thread,
17.5 KB of session state per participant).

### 4.1 Zero-copy fan-out conflicts with per-subscriber SRTP

The vision's `forward_packet` pushes `clone_shallow()` of one buffer to every subscriber.
In WebRTC every subscriber has its own DTLS-SRTP keys, and the SFU rewrites SSRC, sequence,
timestamp and header extensions per subscriber. Each outgoing packet needs its own buffer
and its own encryption; the redesign budgets for that cost instead of avoiding it.

### 4.2 XDP / eBPF forwarding of RTP

`bpf/xdp_sfu.c` (removed in Phase 0) rewrote IP/port and redirected the publisher's
packet. That forwards the publisher's SRTP ciphertext, which subscribers cannot decrypt, and
the map held one destination per SSRC, so it could not fan out. AF_XDP remains possible as a
faster userspace socket, with SRTP still in userspace.

### 4.3 "Zero locks, zero allocation" hot path

Sound as a principle; unreachable with the old ownership (shared session maps and mutexes).
It requires session and SRTP state owned by the thread that receives the packet, which is
what the shard does.

### 4.4 Memory per participant

The old path measured ≈ 1.5 MB heap plus ≈ 6 MB arena per audio+video publisher (Part 5
baseline), against a 100 KB target. The redesign restates the target: 100 KB fixed per
participant, with video retransmission history reported separately, and a 25 KB budget for
session state checked in CI.

### 4.5 Distributed subscription state

A subscription graph in one ORSWOT grows as O(participants²) per room (≈ 250K entries for
500 people). It needs per-room or per-track partitioning, and insert failures must be
surfaced. Out of scope for the data-plane redesign (clustering is a v1 non-goal).

---

## Part 5 — Performance

There is one set of targets: the table in [`README.md`](README.md#performance-targets),
restated with measurement methods in `dataplane-design.md` §2.

- **Met in Phase 1:** 0 heap allocations per packet (AES-GCM and AES-CM); session state
  ≤ 25 KB per participant, checked in CI (17.5 KB).
- **Not measured yet:** the ≥ 500K subscriber-packets/s per core target end to end (needs
  `benches/dataplane.rs`, Phase 2), scaling across shards, latency (p50/p99) under load,
  x86_64 on real hardware, a real NIC.

"Packets/sec" always needs to say ingress (published) or egress (forwarded).

### 5.1 Phase 1 (one shard)

**Per-packet cost** (`cargo bench --bench real_path`, Criterion medians, Phase 1.7a;
`udp_floor` in the same container session). Ingress starts at the socket (receive included);
egress is per subscriber and includes the send.

| | macOS arm64 (M2 Pro, `PortableIo`) | Linux arm64 container (6 vCPU, `LinuxIo`) |
|---|---|---|
| Ingress, GCM audio / video | 1.52 / 1.71 µs | 0.67 / 0.80 µs |
| Ingress, CM audio / video | 1.55 / 2.20 µs | 0.71 / 1.24 µs |
| Egress, GCM video, per subscriber at 1 / 10 / 100 / 500 | 7.61 / 7.98 / 7.34 / 7.51 µs | 2.14 / 1.30 / 1.07 / 0.94 µs |
| Egress, CM video, per subscriber at 1 / 10 / 100 / 500 | 8.57 / 8.34 / 7.74 / 7.88 µs | 3.15 / 1.74 / 1.52 / 1.35 µs |
| Egress, GCM audio, per subscriber at 100 | 7.05 µs | 0.75 µs |
| `udp_floor` `sendmmsg`, 1,200 B, to 1 / 10 / 100 destinations | (Linux only) | 0.51 / 0.82 / 0.69 µs |
| **Egress video ÷ floor** at 10 / 100 subscribers, GCM | | **1.58× / 1.55×** |
| **Egress video ÷ floor** at 10 / 100 subscribers, CM | | **2.12× / 2.20×** |
| SRTP protect, GCM audio / video | 112 / 259 ns | 150 / 295 ns |
| SRTP protect, CM audio / video | 158 / 675 ns | 193 / 716 ns |

- Only ratios within one session are meaningful: a later run in a busier VM measured the
  floor at 1.57 µs per datagram.
- macOS egress is one `send_to` per datagram (correct, not fast; production is Linux).
- Not comparable with the Phase 0 ingress row below, which started from a slice with no
  receive. Phase 0 egress at 100 subscribers was 3.13 µs (GCM) / 2.19 µs (CM) per
  subscriber on Linux arm64; Phase 1 is 1.07 / 1.52 µs.
- Browsers negotiate AES-GCM (offered first): Chrome 153 did in every Phase 1 check.

**SRTP** (`cargo bench --bench srtp_backends`, macOS arm64, ns for protect 160 / 1,200 B,
unprotect 160 / 1,200 B): the shard's `SrtpCipher` with GCM on ring 102 / 282 / 107 / 297
(ring alone 99 / 282 / 101 / 297).

**Memory** (`cargo bench --bench memory`, counting allocator, macOS arm64 at `fa8a6a9`; the
Rust numbers are identical on Linux arm64). Scenario: an audio + video publisher subscribed to 10 tracks.

| Per participant | Value |
|---|---|
| **Session state, checked in CI (budget 25 KB)** | **17.5 KB** |
| of which: data plane / control plane (11-room run) + pre-sized map entries | 13.0 / 4.3 KB + 248 B |
| Structural (`size_of`): session 664 B, SRTP in + out ≈ 7.9 KB, 2 tracks × 384 B, 10 subscriptions × 120 B | ≈ 10.2 KB |
| Signaling connection, reported apart: WebSocket / TLS | 49.3 / 56.9 KB |
| OpenSSL per session after the handshake, before / after `free_ssl` | 151.6 / 3.8 KB (macOS); 124.8 / 1.9 KB (Linux) |
| Transient, control plane, while handling one subscribe (12 m-lines) | 420 KB above resting |

Fixed costs are reported apart: the shard ≈ 8.9 MB in the bench (6 MB of it the bench's
in-memory I/O capture), the orchestrator ≈ 9.3 MB of pre-sized state; a room adds ≈ 0.1 KB.

**Shard loop** (`crates/nexus-dataplane/tests/loopback.rs`, Linux arm64 container / macOS): wake round trip median
1.0 ms / 0.3 ms; shutdown 0.45 / 0.37 ms; idle CPU 0.2 / 0.1 ms per second.

**End to end** (`cargo test --test e2e`, 8 tests with webrtc-rs clients): ≈ 47 s macOS,
48 s Linux arm64, 51 s Linux x86_64 (emulated). Resume after an address change 2.1-2.3 s
(the 2 s silence rule), SR translation error 2-5 ms, a burst of subscriber PLIs → one PLI.

### 5.2 Phase 0 baseline (old data plane, `062e668`)

Measured on Linux arm64 (Docker Desktop VM, 6 vCPUs, Apple M2 Pro host)
with `cargo bench --bench real_path` and `--bench memory`. Criterion medians; runs vary by
±10% (more on single-subscriber cases), so the 100-subscriber rows are used. Loopback
sockets; no NIC. Kept for comparison; the old path is deleted.

**Per-packet cost** (old path)

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
- Browsers negotiated AES-CM then (listed first in `use_srtp`). AES-GCM was slow with the
  RustCrypto backend; Phase 1 moved it to ring and offers it first.

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
| AES-CM-HMAC-SHA1-80 | RustCrypto `SrtpContext` (Phase 0) | 238 | 763 | 247 | 773 |
| AES-CM-HMAC-SHA1-80 | OpenSSL CTR + OpenSSL HMAC¹ | 391 | 839 | 346 | 810 |
| AES-CM-HMAC-SHA1-80 | OpenSSL CTR + ring HMAC² | 924 | 3,596 | 936 | 3,277 |
| AES-128-GCM | RustCrypto `SrtpContext` (Phase 0) | 440 | 2,279 | 495 | 2,226 |
| AES-128-GCM | OpenSSL EVP | 131 | 290 | 126 | 266 |
| AES-128-GCM | ring `LessSafeKey` | 103 | 238 | 107 | 258 |

macOS arm64 (Apple M2 Pro, native):

| Profile | Backend | protect 160 B | protect 1,200 B | unprotect 160 B | unprotect 1,200 B |
|---------|---------|--------------:|----------------:|----------------:|------------------:|
| AES-CM-HMAC-SHA1-80 | RustCrypto `SrtpContext` (Phase 0) | 273 | 1,000 | 281 | 1,013 |
| AES-CM-HMAC-SHA1-80 | OpenSSL CTR + OpenSSL HMAC¹ | 483 | 1,139 | 488 | 1,149 |
| AES-CM-HMAC-SHA1-80 | OpenSSL CTR + ring HMAC² | 1,117 | 4,297 | 1,126 | 4,314 |
| AES-128-GCM | RustCrypto `SrtpContext` (Phase 0) | 156 | 809 | 218 | 871 |
| AES-128-GCM | OpenSSL EVP | 167 | 301 | 164 | 306 |
| AES-128-GCM | ring `LessSafeKey` | 99 | 282 | 101 | 297 |

¹ Copies two digest contexts per packet (the `openssl` crate has no reusable keyed HMAC); an
upper bound. ² ring's SHA-1 has no hardware acceleration.

The RFC 7714 vectors added with this bench found two AES-GCM interop bugs, fixed in Phase 0:
the AEAD KDF put the label in salt byte 6 instead of 7 (wrong RTP salt and RTCP keys), and
SRTCP put E+index before the tag instead of after it. AES-GCM therefore never worked with
browsers; it went unnoticed because AES-CM was offered first.

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
