# Data plane redesign

**Status:** proposal, 2026-09-25. **Scope:** everything a media packet touches after the
UDP socket, plus the ICE/DTLS pieces it depends on. The control plane (signaling,
orchestrator, SDP, REST API) stays and is adapted, not rewritten.

This document holds the **decisions, targets and phase boundaries**. It changes only by an
entry in the revision log (§8). Everything else lives elsewhere:

| Document | Holds |
|----------|-------|
| [`architecture.md`](../architecture.md) | What exists today: live path, broken features, dead code, baseline numbers |
| [`docs/plans/phase-N.md`](plans/) | The working plan for one phase, written when that phase starts |
| [`docs/design/*.md`](design/) | Detailed designs, each written before the phase that needs it (§5) |
| [`architecture-vision.md`](architecture-vision.md) | The original design, for reference |

---

## 0. Decisions at a glance

| # | Decision | Instead of (today) |
|---|----------|--------------------|
| D1 | **Shard by session.** Each shard is one pinned OS thread that owns a set of WebRTC sessions end to end: socket, ICE consent, SRTP in and out, RTP rewrite, RTCP. | One ingest loop on the main thread decrypts everything, workers own tracks. |
| D2 | **One UDP port per shard.** A session's ICE candidate advertises its shard's port, so the kernel delivers its packets straight to the owning thread. | One socket, one reader. |
| D3 | **Cross-shard fan-out by handle.** The publisher's shard decrypts once and passes a refcounted plaintext buffer to each shard that has subscribers; that shard encrypts per subscriber. One hop per (packet, shard), not per subscriber. | Every packet hops from ingest thread to a track worker. |
| D4 | **No shared mutable state on the packet path.** Control plane talks to shards with bounded command/event queues. No DashMap, Mutex, RwLock or ArcSwap per packet. | 2 session mutex locks, 4 DashMap reads, 1 RwLock, 2 ArcSwap loads per packet. |
| D5 | **One SRTP context per session per direction**, holding per-SSRC state. | One context per (subscriber, track) and per publisher track, sharing a key. |
| D6 | **NACK, keyframe requests and SR translation are part of the core path and of v1** (SR translation, PLI/FIR forwarding and PLI on subscribe in Phase 1; NACK in Phase 3), each covered by end-to-end tests. | Present in code, not working. |
| D7 | **Crypto backend chosen by benchmark**, OpenSSL EVP as the expected winner (already vendored for DTLS). Prefer AES-GCM when the benchmark confirms it. | RustCrypto, AES-CM preferred. |
| D8 | **Memory is sized to traffic, not to maxima.** Buffers sized by packet, NACK history by time window, no pre-reserved subscriber arrays, OpenSSL state freed after the handshake. | Fixed 1500-byte slots, 2048-slot ring per track (audio too), 100 subscribers reserved per track. |
| D9 | **Linux is the production target** (`recvmmsg`/`sendmmsg`, busy-poll with `epoll` fallback). A portable `std::net` shard keeps macOS development working. io_uring and AF_XDP are later, benchmark-gated options. | io_uring default (multishot never armed), XDP/eBPF path that cannot work for SRTP. |
| D10 | **New crate `nexus-dataplane` replaces the old data plane outright** (`src/worker/`, `src/forward/`, the packet loop in `src/sfu.rs`). No parallel engines and no switch: the project has no deployments to protect, so the new path lands when it passes the end-to-end tests and the old code is deleted in the same phase (Phase 1). Fixes to the old path are not made. | — |

---

## 1. Why

The current data plane cannot reach its goals by local fixes. The details, with file
references, are in [`architecture.md`](../architecture.md); in short:

- **Ownership:** all ingress runs on one thread that decrypts every packet under a
  per-session mutex, and workers hold copies of session state that are never updated
  (architecture.md 1.2).
- **Correctness:** remote clients cannot connect, and NACK, simulcast, bandwidth estimation,
  keyframe-on-join and per-subscriber MID do not work (2.1).
- **Security:** SRTCP keystream can repeat across a publisher's tracks (2.2).
- **Memory:** ≈ 1.5 MB heap + 6 MB arena per audio+video publisher (Part 5).
- **Size:** about 17,000 lines of unreachable code and 5,600 lines of uncompiled tests (2.3).

---

## 2. Goals, non-goals, targets

### Goals

1. Media works between browsers on different networks, including loss (NACK), joins
   (keyframe) and lip sync (SR translation).
2. Per-core throughput that scales with cores, with no cross-core locks on the packet path.
3. Memory that follows traffic, with a budget checked in CI.
4. Every data-plane feature covered by an end-to-end test with real WebRTC clients.

### v1 scope

The aim is to ship the new data plane as soon as it is correct, not to build every feature
first. v1 is the release that replaces the old data plane.

| In v1 | After v1 |
|-------|----------|
| Per-session shards on multiple cores, port per shard (§3.1-3.3) | Simulcast (§3.7). **Open decision:** moving it into v1 adds one phase between Phases 3 and the release |
| SRTP one context per session per direction; AES-GCM on ring, offered first after a browser check (§3.4) | SFU-side bandwidth estimation toward subscribers, automatic layer selection (§3.8) |
| RTP rewrite, header extension mapping, SR translation for lip sync (§3.5, §3.6) | Single-port mode (§3.1) |
| NACK retransmission, PLI/FIR forwarding, keyframe on join, RR to publishers (§3.6) | RTX (RFC 4588) |
| TWCC feedback toward publishers, so browsers set their publish bitrate (§3.8) | More than ≈ 15 audio + video publishers visible per participant |
| Announced IP, consent, NAT rebinding (§3.9) | io_uring / AF_XDP evaluation (§3.12) |
| End-to-end tests: two-party, multi-party, loss, late join, rejoin, unsubscribe/resubscribe, address change | Automated browser tests (Playwright) |
| Room authorization: the token names the rooms its holder may create or join, and `Create`/`Join` check it (today tokens carry no room claim, so any authenticated user can join any room by id) | |

Without simulcast every subscriber receives the publisher's full-quality stream: fine for
small meetings, poor for large rooms or weak connections. A session is limited to ≈ 30
m-lines by dynamic payload types, so a participant sees at most ≈ 15 audio + video
publishers; accepted for v1.

### Non-goals

- Multi-node media relay, recording, XDP/eBPF forwarding, QUIC signaling. They stay out of
  the binary until they have their own design; code is kept in git history, not in the tree.
- TURN server, TCP media candidates.
- SVC (VP9/AV1 layer dropping); a later extension of §3.7.

### Targets and how they are measured

| Metric | Target | Measured by |
|--------|--------|-------------|
| Forwarded packets per core | **≥ 500,000 subscriber-packets/s per shard** for 1,200-byte video, AES-GCM, end to end (receive, decrypt, fan-out, encrypt, `sendmmsg`), with the ingress cost amortised over 10 subscribers | New `benches/dataplane.rs` (§6), Linux arm64 and x86_64 |
| Scaling | ≥ 0.8 × linear from 1 to 4 shards | Same bench, `--shards 1,2,4` |
| Added latency | p99 < 200 µs inside the SFU at 50% of target load | Timestamp at receive vs `sendmmsg` return |
| Memory per participant | **≤ 100 KB fixed** (session, SRTP, ICE, per-subscription state), plus **NACK history reported separately**: bitrate × window, ≈ 300 KB for a 2.5 Mbps video track with the default 1 s window | `benches/memory.rs`, budget enforced in CI |
| Allocation | 0 heap allocations per packet on the steady-state path | Counting allocator in the bench |

The 100 KB target in the README cannot include video retransmission history: one second
of 2.5 Mbps video is ≈ 310 KB by itself. The target is restated this way rather than met
by keeping no history.

**Is 500K/core reachable?** 500K/s is a budget of 2 µs per subscriber-packet, all of it:
one ≈ 1,200-byte copy, a header rewrite, one encryption, and the kernel's share of
`sendmmsg`. Today (architecture.md Part 5) a video subscriber-packet costs ≈ 2.2 µs with AES-CM, of which
encryption is only ≈ 0.73 µs; the rest is allocation, hashing, copies and the send. AES-GCM
costs 2.0 µs for encryption alone with the current RustCrypto backend, so GCM needs a
faster backend (§3.4) before it can be preferred.

The floor nobody can remove is the kernel's per-datagram UDP send cost, since every
subscriber is a different destination and GSO does not apply. Phase 0 measures it
directly (raw `sendmmsg` of 1,200-byte datagrams to many destinations, no SFU code). If
kernel send plus encryption leaves less than ≈ 0.5 µs for the SFU's own work, the target is
revised in this document rather than quietly missed.

---

## 3. Design

### 3.1 Shards, threads and sockets (D1, D2, D9)

```
                       control plane (tokio)
      signaling ─ orchestrator ─ DTLS handshakes ─ REST/metrics
                 │ commands (bounded)       ▲ events (bounded)
   ┌─────────────┼──────────────────────────┼──────────────────┐
   ▼             ▼                          │                  ▼
 shard 0       shard 1        …        shard N-1       (pinned OS threads)
 udp :P0       udp :P1                 udp :PN-1
 sessions      sessions                sessions
   ▲  └──── cross-shard media queues (SPSC, one per ordered pair) ────┘
```

- A **shard** is a `std::thread`, optionally pinned (`worker.cpu_affinity`) and SCHED_FIFO
  (`worker.realtime_priority`). It runs a loop: receive batch → process → flush sends →
  drain cross-shard queues → drain commands → timers. No tokio inside a shard.
- Each shard binds its own UDP socket on `media_port_base + shard_index`. The orchestrator
  picks the shard when it creates a session and advertises that port in the ICE candidate.
  Consequence: operators open a port range (`N` ports) instead of one port.
- **Placement:** room-affine with spill. The orchestrator puts a room's participants on the
  shard that already hosts the room until that shard passes a load threshold (sessions or
  measured packets/s), then spills to the least-loaded shard. A small room then runs on one
  core with no cross-shard traffic; a large one spreads.
- **Candidates:** a new `transport.announced_ip` (list, IPv4 and IPv6) is advertised instead
  of the bind address. With it unset the SFU enumerates interface addresses (the unused
  `ice/gather.rs` already does this) and refuses `0.0.0.0`. Shipped in Phase 0 on the
  current code.
- **Idle behaviour:** busy-poll a configurable number of empty receive rounds, then block in
  `epoll_wait` with a timeout equal to the next timer. No `thread::sleep` loops.
- **Single-port mode** (one socket, a dispatcher thread that only demultiplexes by address
  and hands raw datagrams to shards) is the fallback for deployments that can expose only
  one UDP port. Not in the first phases; the shard interface does not depend on which mode
  feeds it.

### 3.2 Ownership and the control-plane interface (D4)

A shard exclusively owns, for each of its sessions: remote address(es), ICE credentials
needed to answer consent checks, inbound and outbound SRTP contexts, published tracks and
subscriptions. Nothing on the packet path is read from another thread.

| Stays in the control plane | Moves to the shard |
|----------------------------|--------------------|
| Signaling, SDP offer/answer, room membership | ICE consent (answering and sending binding checks), NAT rebinding |
| DTLS handshake (OpenSSL, CPU-heavy, rare) | SRTP/SRTCP protect and unprotect |
| Placement decisions, subscription policy | SSRC → track routing for its publishers |
| Metrics aggregation | Per-shard counters, published by atomic snapshot |

**Commands** (control → shard, bounded, drained once per loop, never blocking the shard):
`CreateSession`, `SendDatagram` (DTLS records), `InstallSrtp`, `AddTrack` (keyed by `mid`),
`RemoveTrack`, `Subscribe`, `Unsubscribe`, `CloseSession`.

**Events** (shard → control): `DtlsDatagram`, `AddressSelected` (nomination or rebinding),
`PeerSrtpVerified` (first authenticated SRTP/SRTCP; the control plane then frees the DTLS
state), `ConsentLost`, `CommandRejected`. Stats are read from per-shard atomics.

The full types are in `docs/design/dataplane-v1.md` §5.

DTLS stays on the control plane: the shard forwards DTLS datagrams as events and sends the
datagrams it is given. Handshakes take milliseconds of CPU and would add jitter to every
session on a media core. After the handshake the control plane exports the SRTP keys,
sends `InstallSrtp`, and **drops the OpenSSL `SSL` object** (§3.11).

Command handling and the placement API are the only places the orchestrator changes shape;
`negotiation.rs` and `subscription.rs` switch from `WorkerMessage`/`SsrcRouter` to these
commands.

### 3.3 Packet path and buffers (D3, D8)

**Ingress (publisher's shard):**
`recvmmsg` into shard-owned buffers → classify (first byte, RFC 7983) → session by source
address (shard-local `HashMap` with a fast hasher; unknown addresses go through STUN/ufrag)
→ SRTP unprotect in place → SSRC → track → NACK history append (video) → fan-out.

**Fan-out:** the track's subscriber set is split by shard.
- Local subscribers: processed immediately from the same buffer.
- Each remote shard with subscribers: one handle pushed on the SPSC queue to that shard.

**Egress (per subscriber, on the subscriber's shard):** copy into a send buffer → rewrite
header (§3.5) → SRTP protect → queue for `sendmmsg`. Flush at the end of every loop
iteration, not on a 1 ms timer.

**Buffers:**
- Each shard owns a pool of fixed 2,048-byte buffers. The pool is sized at startup and never
  grows. Reference counts are owner-local (a plain array on the owning shard, changed only
  by the owner as handles go out and come back), so no atomics and no `Box` per buffer.
- A buffer handed to another shard is returned to its owner through that pair's return
  queue, so frees never touch another shard's free list (no cross-thread CAS stack, no ABA).
- Send buffers are recycled after `sendmmsg` returns.
- Queues are bounded. When full, the packet is dropped and counted; a shard never waits.

### 3.4 SRTP (D5, D7)

- Two contexts per session: inbound (unprotect everything from that peer) and outbound
  (protect everything to it), each with per-SSRC state (ROC, replay window, SRTCP index).
  All RTCP the SFU originates for a peer, including REMB/PLI/NACK toward publishers, goes
  through that peer's outbound context with a distinct SFU sender SSRC per session. This
  removes the nonce-reuse risk (architecture.md 2.2) by construction.
- Memory: the key schedule and HMAC state are built once per context (as done in `6667f4b`).
  Per-SSRC state is a small fixed array, not a `HashMap`.
- **Backend:** Phase 0 benchmarks RustCrypto (current), OpenSSL EVP (`aes-128-ctr`,
  `aes-128-gcm`, HMAC-SHA1) and `ring` (GCM only) on 160-byte audio and 1,200-byte video,
  Linux arm64 and x86_64. The winner per profile sits behind the existing `SrtpCipher`
  interface, so the SRTP module and its RFC tests are kept.
- **Profile order:** if AES-GCM is faster, offer `SRTP_AEAD_AES_128_GCM` first in DTLS
  (`openssl_backend.rs:268-277`). Browsers support both.

### 3.5 RTP rewrite and header extensions

Per subscription, the subscriber's shard keeps:

- **Sequence numbers:** an offset from publisher seq to subscriber seq, adjusted at layer
  switches and when packets are intentionally dropped, plus a 512-entry ring of
  (subscriber seq → publisher seq) for the NACK path. Replaces the write-only `seq_map`.
- **Timestamps:** an offset rebased at layer switches (a single first-packet offset cannot
  survive a switch between simulcast layers).
- **SSRC:** rewritten to the SSRC announced to that subscriber in SDP. Always, so switching
  simulcast layers is invisible to the receiver.
- **Payload type:** mapped from the publisher's PT to the subscriber's negotiated PT.
- **Header extensions:** a per-subscription table mapping publisher extension id →
  subscriber extension id, built from both SDPs. Extensions the subscriber did not
  negotiate are removed. `mid` is written per subscriber. `transport-cc` is written by the
  SFU with a per-subscriber-session counter (needed for §3.8).

The rewrite is done in place in the send buffer. Removing or resizing extensions uses a
bounded rewrite of the header only; the payload is not moved more than once.

### 3.6 RTCP (D6)

| Packet | From | Handling |
|--------|------|----------|
| **NACK** | Subscriber | Map each subscriber seq to publisher seq through the subscription's ring → look up the track's NACK history → if present, rewrite for that subscriber and resend (in-band, original SSRC) → if missing, collect and send one NACK upstream in publisher seq space, rate-limited per track. |
| **PLI / FIR** | Subscriber | Forward to the publisher as PLI, at most one per track per 500 ms. |
| **REMB / TWCC** | Subscriber | Input to that subscriber's estimator (§3.8). Not forwarded. |
| **SR** | Publisher | Stored per track (NTP ↔ RTP mapping). Subscribers get an SR built from it with rewritten SSRC and timestamps, so lip sync works. |
| **RR** | Subscriber | Loss and jitter for the subscriber's estimator and stats. Not forwarded. |
| **SDES/BYE** | Any | BYE ends the track or subscription; SDES ignored. |

SFU-originated:
- **PLI** to the publisher when a subscriber is added, when it switches layers, and when
  decoding would otherwise resume on a delta frame.
- **RR** to publishers (loss, jitter, last SR) so their congestion control has input.

**NACK history:** per video track, a byte ring holding the last `nack_window_ms`
(default 1,000 ms, capped at 512 packets) of **decrypted** packets at their real length,
indexed by publisher seq through a 512-entry offset table. Audio keeps no history unless
the publisher negotiated NACK for it. Memory is bitrate × window, not slots × 1,500.

**Negotiation:** offer `a=rtcp-fb:<pt> nack`, `nack pli`, `ccm fir` and `goog-remb`/`transport-cc`
to publishers and subscribers. RTX (RFC 4588) is a later step; in-band retransmission
works with current browsers.

### 3.7 Simulcast (after v1)

- A published video track has up to 3 layers, identified by `a=rid`/`a=simulcast` or SSRC
  groups; RTX SSRCs are recognised as such and never become tracks.
- Each subscription has a target layer (from the subscriber's request, capped by its
  estimator) and a current layer. A switch happens only on a keyframe of the target layer
  (codec keyframe detection for VP8, VP9, H.264, AV1 from `nexus-media`); the SFU sends
  PLI for the target layer when a switch is pending.
- Seq and timestamp offsets are adjusted at the switch (§3.5) so the subscriber sees one
  continuous stream.

### 3.8 Bandwidth estimation

**Toward publishers (v1, Phase 3).** The SFU offers transport-cc on publish m-lines, records
arrival times per publisher session and sends TWCC feedback about every 100 ms. The
browser's own estimator then sets the publish bitrate; without any feedback it stays near
its start value (≈ 300 kbps in Chrome). Details in `docs/design/dataplane-v1.md` §12.4 and
`loss-recovery.md`.

**Toward subscribers (after v1).**
- SFU writes `transport-cc` sequence numbers per subscriber session, receives TWCC feedback,
  and runs the existing GCC from `nexus-bwe` per subscriber session on its shard.
- The estimate drives simulcast layer selection across that subscriber's video
  subscriptions (the allocation logic in `nexus-bwe` is reused).
- Pacing: not in this redesign; fan-out sends are already spread by packet arrival.

### 3.9 ICE, DTLS and addresses

- **ICE role: ICE-lite** (decided in `docs/design/dataplane-v1.md` §8). The SFU announces
  `a=ice-lite`, answers binding requests and sends none; the browser is controlling and runs
  consent checks. No timer wheel for ICE on the shard.
- **Liveness:** no authenticated packet (STUN, SRTP, SRTCP) from the selected address for
  30 s ends the session (`ConsentLost`).
- **Nomination and NAT rebinding:** an authenticated binding request with `USE-CANDIDATE`
  selects its address. One without it, from a new address, moves the session only if the
  selected address has been silent for `rebind_silence` (2 s); otherwise it is another pair
  being checked and is only answered. Handled on the shard, no command round-trip; media
  resumes within about the silence plus the client's check interval.
- **DTLS retransmission:** the control plane drives OpenSSL's DTLS timer
  (`DTLS_CTRL_GET_TIMEOUT` / `DTLS_CTRL_HANDLE_TIMEOUT`) for handshaking sessions. Done in
  Phase 0; this code stays.

### 3.10 Signaling scope

WebSocket + JSON is the only signaling transport the SDK and loadtest use. QUIC signaling
is removed from startup until it is connected to the orchestrator; the crate stays.

### 3.11 Memory budget

Per participant publishing audio + video and subscribed to 10 others (5 A+V pairs):

| Item | Budget | Today (measured / estimated) |
|------|-------:|------------------------------|
| Session: addresses, ICE creds, counters | 1 KB | — |
| SRTP inbound + outbound contexts | ≈ 5 KB | one context per (subscriber, track) |
| DTLS after handshake | 0 (SSL object freed) | ≈ 136 KB OpenSSL + session state |
| Published track state × 2 | 2 × 0.5 KB | ≈ 578 KB per track (incl. 100 reserved subscribers) |
| Subscription state × 10 (rewrite, NACK seq ring, ext map) | 10 × 1.5 KB | ≥ 2.2 KB each plus SRTP context |
| **Fixed total** | **≈ 25 KB** | **≈ 1.5 MB heap** |
| NACK history, video, 1 s at 2.5 Mbps | ≈ 310 KB | 3 MB per track (audio too), arena |

Shard-level fixed memory (buffer pool, queues) is configured and reported separately.

### 3.12 Platform

- Linux: `recvmmsg`/`sendmmsg`, `SO_RCVBUF`/`SO_SNDBUF` checks (already warn), optional GSO
  where a batch has several packets to one destination (retransmit bursts, one subscriber
  with many tracks).
- macOS: a portable shard using non-blocking `std::net::UdpSocket` and `kqueue`; correct, not
  fast. CI runs the end-to-end tests on both.
- io_uring and AF_XDP (as a faster userspace socket, not XDP forwarding) are evaluated after
  v1 against the `recvmmsg` numbers and adopted only if they win.

---

## 4. Reuse, rewrite, delete

| Component | Fate |
|-----------|------|
| `nexus-media` (RTP/RTCP parsing, codec keyframe detection) | **Reuse** |
| `nexus-transport`: SRTP (`srtp/`), DTLS OpenSSL backend, STUN/ICE message code, `socket_config` | **Reuse**; SRTP gets the backend from §3.4 |
| `nexus-transport`: `arena`, `ring_buffer`, `batch`, `io_uring`, `media_transport` | **Replace** by `nexus-dataplane` buffers and I/O |
| `nexus-webrtc`: SDP | **Reuse** and extend (rid/simulcast, rtcp-fb, extmap) |
| `nexus-webrtc`: `WebRtcTransport` session map, `process_packet` | **Split**: DTLS/ICE negotiation stays in control plane, packet handling moves to shards |
| `nexus-bwe` GCC and allocation | **Reuse** after v1 (§3.8) |
| `src/orchestrator`, `nexus-signal` (WS), `nexus-api`, `nexus-metrics`, config | **Keep**, adapted to the command interface |
| `src/worker/`, `src/forward/`, the packet loop in `src/sfu.rs`, `nexus-actor` | **Delete** in Phase 1, when the new path lands |
| Dead code (architecture.md 2.3) | **Deleted** in Phase 0 (recoverable from git) |
| `nexus-state` gossip thread | **Keep off by default** (`cluster.enabled`); it serves no media purpose today |
| `benches/real_path.rs`, `benches/memory.rs` | **Port** to the new API, keep the same scenarios so numbers stay comparable |
| `tests/*/` (uncompiled) | **Delete**; coverage replaced by §6 |

---

## 5. Plan

Each phase ends with its exit criteria met on macOS and Linux (arm64 locally, x86_64 in CI
once it runs). There is one data plane at a time: Phase 1 replaces the old one.

| Phase | Content | Exit criteria |
|-------|---------|---------------|
| **0. Ground work** (done) | Live bug fixes, dead code removed, end-to-end harness, SRTP backends and kernel send floor measured | Met, except x86_64 numbers (CI) |
| **1. New data plane, one shard** | `nexus-dataplane` with one shard and its own socket; sessions with SRTP in/out (one context per direction, ring for GCM); fan-out; rewrite (seq/ts/ssrc/pt/extensions); SR translation; PLI/FIR forwarding and PLI on subscribe; ICE-lite, liveness and NAT rebinding; orchestrator moved to the command interface (§3.2). The old path, `nexus-actor` and the replaced `nexus-transport` modules are deleted; `real_path`/`memory` benches ported | E2E: the Phase 0 tests plus 10 clients A+V, address change mid-call, unsubscribe → resubscribe with no repeated (SSRC, packet index) on the wire, SR translation, and keyframe requests (PLI on subscribe, forwarding, throttling); 0 allocations per packet; §3.11 fixed memory budget in CI; manual Chrome and Firefox call with AES-GCM offered first |
| **2. Multiple shards** | Port per shard, placement, cross-shard queues and buffer return | E2E with participants on different shards; §2 throughput and scaling targets on `benches/dataplane.rs` |
| **3. Loss, joins, publisher bitrate** | NACK history and retransmit, upstream NACK, RR to publishers, TWCC feedback toward publishers (§3.8) | E2E with 5% injected loss: packets recovered, no sustained freeze; a late joiner gets a keyframe within 1 s; publishers receive transport-cc feedback covering every packet; browser check: publish bitrate climbs well above the start value |
| **Release v1** | `architecture.md` rewritten for the new path, README targets updated with measured numbers, version tag | All of the above green; manual browser check (Chrome, Firefox, Safari) |

After v1, in order of value: simulcast, bandwidth estimation, single-port mode, RTX.

**Detailed designs** are written, reviewed and committed before the phase that needs them.
The sections above are the constraints they must satisfy; where a detailed design has to
break one, it proposes a revision to this document instead.

| Design note | Before phase | Covers |
|-------------|--------------|--------|
| `docs/design/dataplane-v1.md` | 1 | Shard loop, command/event types, buffer pool and ownership, timers, ICE-lite decision, macOS shard, per-subscription rewrite state, header extension mapping, SR translation, and the cross-shard interfaces Phase 2 builds on (placement, queues, buffer return, port range config) |
| `docs/design/loss-recovery.md` | 3 | NACK history, retransmit, upstream NACK, RR, TWCC feedback toward publishers (constraints in `dataplane-v1.md` §12.4 and §18) |
| `docs/design/simulcast.md`, `docs/design/congestion-control.md` | after v1 | Written when those phases start |

Each phase has a plan in `docs/plans/phase-N.md` with tasks, files, tests and a status
section updated at the end of every working session.

---

## 6. Testing and benchmarks

- **End-to-end harness** (`tests/e2e.rs`, built in Phase 0): starts the SFU in-process on
  ephemeral ports, drives `webrtc-rs` clients from `nexus-loadtest` through WebSocket
  signaling, and asserts on what clients receive: exactly the peer's streams, packet rate,
  sequence continuity, timestamps. Loss is injected on a client's own socket
  (`nexus_loadtest::lossy`), so it runs without root and on macOS. Each phase adds its exit
  checks here.
- **Benchmarks:**
  - `benches/dataplane.rs`: shard throughput with N subscribers, 1 to 4 shards, reports
    subscriber-packets/s/core and allocations per packet.
  - `benches/memory.rs`: ported; CI budget becomes the §3.11 fixed total.
  - SRTP backend comparison: kept as a bench group.
- **CI:** E2E and bench smoke on every push (already in `ci.yml`), plus a nightly timed run
  on a dedicated runner if one becomes available (shared runners are too noisy for gating
  on throughput).
- **Deterministic simulation:** `nexus-dst` today does not exercise the server. Once shards
  exist, a shard can run against an in-memory socket and clock, which is the natural place
  to plug DST in. Out of scope until after v1.

---

## 7. Risks and open questions

- **Port range.** Port-per-shard needs `N` UDP ports reachable. Kubernetes and some
  firewalls make that awkward; single-port mode (§3.1) is the answer and may need to move
  earlier.
- **Crypto ceiling.** If no backend gets 1,200-byte encryption under ≈ 1 µs on commodity
  cores, 500K/core is not reachable and the target changes (§2).
- **Hot rooms.** A room of 1,000 viewers of one publisher puts all ingress for that track on
  one shard; fan-out spreads across shards by handle. The hop cost per remote shard is
  small, but a single publisher's decrypt stays on one core. Acceptable: ingress per track
  is at most a few thousand packets/s.
- **ICE-lite.** Decided (`dataplane-v1.md` §8); an SFU behind NAT needs a forwarded,
  announced address, as before. Checked with browsers early in Phase 1.
- **One core until Phase 2.** After Phase 1 the SFU runs on a single shard. Acceptable
  because nothing is deployed; the release waits for Phase 2.
- **No safety net of a working old path.** With direct replacement, `main` has no working
  SFU between the start of Phase 1 work and its end if the work is merged early. Phase 1 is
  developed on a branch and merged only when its exit criteria pass.
- **Browser coverage.** `webrtc-rs` clients prove protocol correctness, not browser
  behaviour. A manual Chrome/Firefox/Safari check is part of each phase's exit until an
  automated browser test (Playwright) is added.

---

## 8. Revisions

| Date | Change |
|------|--------|
| 2026-09-25 | First version. Findings and baseline moved to `architecture.md`. |
| 2026-09-26 | Phase 0.4, partial (macOS arm64 only; Linux runs and the `sendmmsg` floor still to do, so §2's 500K/core target is **not yet confirmed or revised**). Provisional backend per profile (§3.4, D7): AES-128-GCM → ring (≈ 0.28 µs per 1,200-byte packet vs 0.81 µs RustCrypto; OpenSSL EVP 0.30 µs), AES-CM-HMAC-SHA1-80 → keep RustCrypto (no alternative was faster). Profile order in `use_srtp` unchanged (AES-CM first) until AES-GCM, now RFC 7714-correct after two interop fixes, is checked against a browser. With GCM at ≈ 0.3 µs, the 2 µs budget holds if kernel send stays ≤ ≈ 1.2 µs per datagram (the §2 rule). |
| 2026-09-26 | Phase 0.4, Linux arm64 (architecture.md Part 5). **Backends (D7):** AES-128-GCM → ring (0.24 µs per 1,200-byte packet; OpenSSL EVP 0.29 µs; RustCrypto 2.2 µs); AES-CM-HMAC-SHA1-80 → keep RustCrypto (0.77 µs, fastest tested). **Target (§2):** kernel `sendmmsg` to 100 destinations costs 1.06 µs per datagram (loopback upper bound). With GCM on ring, send + encrypt = 1.30 µs, leaving ≈ 0.7 µs of the 2 µs budget for the SFU's own work: **500K subscriber-packets/s per core is confirmed as the target, for AES-GCM**. With AES-CM (1.83 µs) the ceiling is ≈ 450K/core, so reaching the target requires offering GCM first in `use_srtp`, which waits for a browser interop check of the fixed GCM code (Phase 1 exit). x86_64 not measured yet. |
| 2026-09-26 | Ship-first revision: the project has no deployments, so the old data plane is replaced directly instead of run beside the new one (D10), fixes to the old path stop (Phase 0 part 0.1d dropped; its bug is covered by a Phase 1 test), phases 4-6 become "after v1", and the six design notes become one (`dataplane-v1.md`) plus `loss-recovery.md`. v1 scope in §2; simulcast is after v1 unless decided otherwise. |
| 2026-09-26 | `docs/design/dataplane-v1.md` approved. Its revisions applied: **R1** PLI/FIR forwarding and PLI on subscribe move to Phase 1 (D6, §5); **R2** ICE-lite, no consent-check timer (§3.9); **R3** command/event lists (§3.2); **R4** owner-local buffer refcounts (§3.3); **R5** SRTP ≈ 5 KB and track state 0.5 KB in the budget, total unchanged (§3.11); **R6** SR and PLI e2e tests in the Phase 1 exit; **R7** rebinding rule (§3.9); **R8** TWCC feedback toward publishers in v1, Phase 3 (§2, §3.8, §5); **R9** ≈ 15 A+V publishers per participant accepted for v1 (§2). |
| 2026-09-27 | v1 scope (§2) gains **room authorization**, found in the Phase 1.5b review: JWTs carry no room claim, so any authenticated user can join any room whose id it guesses (ids are sequential) and subscribe to its tracks. Not assigned to a phase yet; it touches the token format (`nexus-api`), signaling (`Create`/`Join`) and the SDK/dev-token tooling (Phase 1.8). |
