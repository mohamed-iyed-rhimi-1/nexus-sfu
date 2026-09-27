# Data plane v1: detailed design (Phase 1)

**Status:** approved 2026-09-26 (with the owner's decisions R8 and R9). **Constraints:** [`docs/dataplane-design.md`](../dataplane-design.md)
(D1-D10, §2 v1 scope, §3, §5). **Current code:** [`architecture.md`](../../architecture.md).

This note is the design Phase 1 is planned from. It covers the shard, its interface to the
control plane, session state, SRTP, ICE, buffers, RTP/RTCP rewriting, the interfaces Phase 2
builds on, the order in which the old path is deleted, and how each Phase 1 exit criterion is
tested. Where it has to change a decision or a number in `dataplane-design.md`, it says so in
§1 rather than diverging silently.

Code references were checked against commit `523a72b`.

---

## 1. Decisions made here and proposed revisions

### Decided in this note

| Topic | Decision | Section |
|-------|----------|---------|
| ICE role | **ICE-lite.** The SFU answers binding requests and sends none. Liveness is the absence of authenticated traffic for 30 s | §8 |
| Shard event loop | One loop for Linux and macOS on `mio` (epoll / kqueue) with a `mio::Waker`; only the datagram I/O differs (`recvmmsg`/`sendmmsg` vs `recv_from`/`send_to`) | §3 |
| Timers | No timer wheel in Phase 1. A 1 s housekeeping sweep covers liveness and stats; per-packet limits (PLI throttle, rebinding) are timestamp checks | §3.4 |
| Outbound SSRC | Every subscription gets an SFU-chosen SSRC, unique for the life of the subscriber's session and announced in SDP. The shard refuses SSRCs that are reused or out of order | §9.3 |
| Track identity | One track per publish m-line (`mid`), not per SSRC. SSRCs are attributes of the track; unknown SSRCs are learned from the `mid` header extension | §7.2 |
| Header extensions | The SFU is always the offerer, so it offers one fixed extension-ID table on every m-line. Mapping tables are still built from both answers | §11.2 |
| DTLS | One certificate per process instead of one per session. The shard forwards DTLS datagrams until the peer's first authenticated SRTP/SRTCP packet, when the control plane frees the `SSL` object | §6.3 |
| Subscription activation | A subscription is created on the shard when the **answer** is processed, not when DTLS completes. The shard starts forwarding (and asks for a keyframe) when the subscriber's outbound SRTP exists | §6.2 |
| Browser page | Phase 1 adds a minimal static page, `examples/web/`, for the manual Chrome/Firefox check | §17 |
| `nexus-dst` | Deleted in Phase 1 with `nexus-actor`, its last user | §16 |
| TWCC toward publishers | **In v1 (Phase 3)**: transport-cc offered on publish m-lines, the shard sends transport-wide feedback so the browser's own estimator sets the publish bitrate. Without any feedback a publisher stays near its start bitrate (≈ 300 kbps in Chrome). Decided with the project owner | §12.4 |
| Per-participant subscription limit | **Accepted for v1:** ≈ 30 m-lines per session, so at most ≈ 15 audio + video publishers visible per participant. Decided with the project owner | §6.5, §19 |

### Proposed revisions to `dataplane-design.md`

Applied to `dataplane-design.md` as one revision entry (§8, 2026-09-26).

| # | Where | Change | Why |
|---|-------|--------|-----|
| R1 | D6, §3.6, §5 | **PLI/FIR forwarding and PLI on subscribe move from Phase 3 to Phase 1.** Phase 3 keeps NACK, upstream NACK, RR to publishers and the late-join e2e test. Phase 1 exit adds a PLI e2e test (§17.6) | The Phase 1 browser check is meaningless without them: a subscriber that joins after the publisher's first keyframe shows black video until the next one. Decided with the project owner |
| R2 | §3.9, §7 | **ICE-lite decided** (§8). The "timer wheel for consent checks" in §3.9 is dropped, because the SFU sends no checks | Simpler shard, no outbound STUN, nomination is the browser's job |
| R3 | §3.2 | Command and event lists replaced by §5 of this note: `ForwardDtls` becomes `SendDatagram`; `AddPublishedTrack` becomes `AddTrack` keyed by `mid`; `SetLayer` waits for simulcast; `AddressChanged` becomes `AddressSelected` (covers the first selection); `PeerSrtpVerified` is added; `TrackStarted` and `KeyframeNeeded` are not needed in v1 | Found while tracing the handshake and PLI paths |
| R4 | §3.3 | The buffer refcount is **owner-local** (a plain array on the owning shard, changed only by the owner as handles go out and come back), not an atomic in the buffer header | Same ownership rule (frees never touch another shard), no atomics |
| R5 | §3.11 | SRTP line: 2 KB → **≈ 5 KB** per participant (key schedules for 4 ciphers plus fixed per-SSRC tables). Published-track line: 2 × 2 KB → 2 × 0.5 KB. **Fixed total unchanged at 25 KB**; CI enforces the total, not the lines | Estimate in §15 |
| R6 | §5 Phase 1 exit | Adds: SR translation e2e test (§17.5) and PLI e2e test (§17.6). D6 already requires each feature to have an e2e test; the Phase 1 row did not list them | Consistency with D6 |
| R7 | §3.9 | NAT rebinding: an authenticated binding request from a new address moves the session only after the selected address has been silent for `rebind_silence` (2 s) or when it carries `USE-CANDIDATE` (§8.3, §8.4) | Full agents keep checking other pairs; switching on every valid request would flap |
| R8 | §2 v1 scope, §3.8, §5 Phase 3 | **TWCC feedback toward publishers moves into v1 (Phase 3).** The SFU offers transport-cc to publishers, records arrivals and sends feedback; the browser runs its own estimator. SFU-side estimation toward subscribers (GCC per subscriber, layer selection) stays after v1 | Owner's decision: without feedback, publish bitrate stays near the browser's start value |
| R9 | §2 v1 scope, §7 | **Per-participant limit accepted for v1:** ≈ 30 m-lines per session (≈ 15 A+V publishers visible), set by dynamic payload types. Lifting it is later SDP work | Owner's decision |

Nothing here breaks D1-D10.

---

## 2. Crate layout

New crate `crates/nexus-dataplane` (library, Apache-2.0 like the other library crates).
Dependencies: `nexus-transport` (SRTP, STUN), `nexus-media` (RTP/RTCP parsing), `mio`
(already in `Cargo.lock` through tokio), `crossbeam-queue` (already locked), `libc`,
`rustc-hash` (already locked), `ring` (already a `nexus-transport` dependency). No tokio.

```
crates/nexus-dataplane/src/
  lib.rs           Dataplane::start(config) -> (DataplaneHandle, Vec<ShardInfo>)
  config.rs        DataplaneConfig (from [dataplane] + [transport], §14)
  ids.rs           SessionId, TrackId, SubscriptionId, ShardId, internal slab indices
  command.rs       Command, Event (§5)
  handle.rs        DataplaneHandle: send commands, receive events, read stats
  placement.rs     Placement trait, SingleShard (Phase 1), RoomAffine (Phase 2)
  shard/
    mod.rs         Shard: state tables, run loop (§3)
    io.rs          DatagramIo trait; LinuxIo (recvmmsg/sendmmsg), PortableIo, MemIo (tests)
    park.rs        park/wake protocol around mio::Poll + mio::Waker
    stats.rs       ShardStats (atomics, published once per second)
  session.rs       Session, SessionTable (§7)
  ice.rs           ICE-lite binding-request handler, no allocation (§8)
  track.rs         PublishedTrack, fan-out list
  subscription.rs  Subscription, RewriteState, ExtMap, PtMap (§11)
  rewrite.rs       RTP header rewrite into a send buffer
  rtcp.rs          inbound RTCP dispatch, SR translation, PLI build (§12)
  pool.rs          BufferPool, BufRef (§10)
tests/
  shard.rs         shard driven through MemIo with scripted peers
  alloc.rs         counting global allocator: 0 allocations per packet (§17.7)
```

SRTP stays in `nexus-transport::srtp` (design §4 "reuse"); the per-direction contexts are
added there (§9) so the RFC vector tests keep covering them.

---

## 3. The shard

### 3.1 Thread

`Dataplane::start` binds one UDP socket per shard (§13.3), then spawns one `std::thread`
per shard, named `nexus-shard-{i}`. It is pinned when `dataplane.cpu_affinity` is set and
runs SCHED_FIFO when `dataplane.realtime_priority` is set; both helpers move from
`src/worker/pool.rs`. Both are Linux only and are ignored on macOS with one `warn!`. Tokio
never runs on a shard thread.

### 3.2 Loop

Every step has a fixed upper bound, so one iteration's worst case is known.

```text
loop {
    now = Instant::now()                        // once per iteration; passed down, never re-read
    n = io.recv_batch(&mut rx)                  // ≤ RECV_BATCH = 64 datagrams, non-blocking
    for d in rx[..n] { handle_datagram(d, now) }// may flush tx early when it fills
    drain_cross_shard(now)                      // Phase 2: ≤ XS_BUDGET handles per peer shard
    io.flush(&mut tx)                           // sendmmsg; a short write drops the rest, counted
    drain_commands(now)                         // ≤ 64 commands
    push_pending_events()                       // ≤ 256 retained events (§5.4)
    if now >= next_housekeeping { housekeeping(now) }   // every 1 s (§3.4)
    if stop_requested { break }
    maybe_park(now, n)                          // §3.3
}
```

The order follows design §3.1: receive, process, flush sends, cross-shard queues, commands,
timers. Sends are flushed once per iteration, not on a timer. `tx` holds up to
`SEND_BATCH = 256` datagrams; a fan-out that fills it flushes in the middle of the batch.

### 3.3 Busy-poll and parking

The socket is registered with a `mio::Poll` (epoll on Linux, kqueue on macOS) for
readability, together with a `mio::Waker` (eventfd on Linux, `EVFILT_USER` on macOS).

- An iteration is **idle** when `recv_batch` returned 0 and no command or cross-shard handle
  was drained. `idle_rounds` counts consecutive idle iterations.
- While `idle_rounds ≤ dataplane.busy_poll_rounds`, the loop continues without blocking.
  The defaults are 0 in `development.toml` and the test config, and 256 in
  `production.toml`; Phase 2 tunes the value with `benches/dataplane.rs`.
- After that, the shard parks: `mio::Poll::poll(timeout = next_housekeeping - now)`.
  - mio is edge-triggered, so the shard parks only when the last receive call returned
    `WouldBlock`. A batch that came back full does not count as empty.
- **No lost wake-ups:**
  - The shard sets `parked.store(true, SeqCst)`, then checks the command queue (and the
    cross-shard queues in Phase 2) once more before calling `poll`. If anything is
    pending, it clears the flag and runs the loop.
  - A producer pushes first, then calls `if parked.swap(false, SeqCst) { waker.wake() }`.
  - A busy shard therefore costs producers no syscall.
- No `thread::sleep` anywhere.

### 3.4 Timers and clock

Phase 1 needs only one periodic job. `housekeeping(now)` runs once per second and:

- Sweeps all sessions (at most `max_sessions_per_shard`, ≈ 20 ns each). It emits
  `ConsentLost` for sessions with no authenticated traffic for `consent_timeout` (30 s),
  and evicts idle inbound SSRC entries (§9.2).
- Copies the shard-local counters into `ShardStats` atomics. The hot path increments plain
  `u64` fields, with no atomics per packet.

Per-packet time limits are timestamp comparisons against `now`: PLI throttle (§12.3) and
rebinding silence (§8.4). Phase 3 adds RR (1 s, fits the sweep) and NACK timers; if those
need finer granularity, `loss-recovery.md` introduces a wheel.

All code below the loop takes `now: Instant` as an argument and never reads the clock
itself. Tests drive time explicitly, which is also what deterministic simulation needs
later (design §6).

### 3.5 I/O backends

```rust
pub trait DatagramIo {
    /// Receive up to rx.capacity() datagrams into pool buffers. Ok(0) with
    /// would_block = true means the socket is drained.
    fn recv_batch(&mut self, rx: &mut RecvBatch, pool: &mut BufferPool) -> io::Result<RecvResult>;
    /// Send every queued datagram; returns how many the kernel took. Never blocks.
    fn flush(&mut self, tx: &mut SendBatch, pool: &mut BufferPool) -> usize;
}
```

| Backend | Receive | Send | Used by |
|---------|---------|------|---------|
| `LinuxIo` | `recvmmsg` into pool buffers; the `mmsghdr`/`iovec`/`sockaddr_storage` arrays are allocated once. Truncated datagrams (`MSG_TRUNC`) are dropped | `sendmmsg`; `EAGAIN` or a short count drops the rest (counted) | Linux |
| `PortableIo` | `recv_from` loop, ≤ 64 datagrams, until `WouldBlock` | `send_to` per datagram | macOS (correct, not fast: design §3.12) |
| `MemIo` | datagrams queued by the test | captured into a `Vec` by the test | unit tests, `tests/alloc.rs`, later DST |

The syscall code is based on `benches/udp_floor.rs`, which already does allocation-free
`sendmmsg`/`recvmmsg`, not on `nexus-transport/src/udp.rs`, which allocates per packet.
`socket_config.rs` (buffer sizes and their checks) is kept and used at bind time.

### 3.6 Shutdown

`DataplaneHandle::shutdown()` sets each shard's stop flag, wakes it, and joins the threads.
A shard exits after the current iteration and flushes its send batch. Sessions are not
closed one by one; the process is ending. `ServerHandle` keeps the join handles.

### 3.7 Panics

A shard must not panic on network input. Release builds use `panic = "abort"`, so one bad
packet would end the process. Parse and crypto failures return `None` and drop the packet.
`assert!` is only for invariants of the shard's own state.

Two existing panics on this path are fixed as part of §9:

- `context.rs:307` asserts on `packet_len` before its graceful check.
- The GCM AAD copy into a 128-byte stack buffer (`crypto.rs:270`, `:354`) panics on long
  headers.

---

## 4. Identifiers

| Type | Allocated by | Scope | Notes |
|------|--------------|-------|-------|
| `SessionId(u64)` | orchestrator counter | process | One per participant transport; replaces `TransportId`. Never 0 |
| `TrackId(u64)` | orchestrator counter | process | Replaces `WorkerPool::assign_track`. Same value as today's signaling `track_id` |
| `SubscriptionId(u64)` | orchestrator counter | process | One per (subscriber session, track, m-line use) |
| `ShardId(u8)` | `Dataplane::start` | process | `MAX_SHARDS = 64` |
| `SessionIdx`, `TrackIdx`, `SubIdx` (`u32`) | shard | shard | Indices into shard slabs (§7.1). Used on the hot path; the `*Id → *Idx` maps are only used by command handling |

---

## 5. Control-plane interface

### 5.1 Commands (control → shard)

```rust
pub enum Command {
    CreateSession { id: SessionId, ice: IceParams, out_ssrc_base: u32 },
    SendDatagram  { id: SessionId, bytes: Box<[u8]> },                  // DTLS records
    InstallSrtp   { id: SessionId, profile: ProtectionProfile,
                    local: KeyMaterial, remote: KeyMaterial },         // local = our write key
    AddTrack      { id: SessionId, track: TrackId, spec: Box<TrackSpec> },
    RemoveTrack   { track: TrackId },
    Subscribe     { id: SessionId, sub: SubscriptionId, track: TrackId, spec: Box<SubSpec> },
    Unsubscribe   { sub: SubscriptionId },
    CloseSession  { id: SessionId },
}

pub struct IceParams { local_ufrag: [u8; 16], local_pwd: [u8; 32] }   // fixed size, no String

pub struct TrackSpec {
    kind: MediaKind, mid: MidValue,            // MidValue: [u8; 16] + len
    ssrc: Option<u32>,                         // from a=ssrc; None: learn from the mid extension
    codec: CodecParams { pt: u8, clock_rate: u32, codec: MediaCodec },
    ext: ExtIds,                               // publisher's negotiated ids by extension (§11.2)
    cname: CnameValue,                         // used in translated SRs
}

pub struct SubSpec {
    out_ssrc: u32, mid: MidValue,
    pt_map: PtMap,                             // publisher PT -> subscriber PT (§11.3)
    ext_map: ExtMap,                           // publisher ext id -> subscriber ext id (§11.2)
    source: TrackRef,                          // { shard, track }; Phase 1: always this shard
}
```

Large payloads are boxed so `Command` stays small. Allocation is fine here: this is the
control path, and the box is freed on the shard.

### 5.2 Events (shard → control)

```rust
pub enum Event {
    DtlsDatagram     { id: SessionId, bytes: Box<[u8]> },  // until PeerSrtpVerified (§6.3)
    AddressSelected  { id: SessionId, addr: SocketAddr, reason: SelectReason },
                                                          // Nominated | Rebound
    PeerSrtpVerified { id: SessionId },                   // first authenticated SRTP/SRTCP
    ConsentLost      { id: SessionId },
    CommandRejected  { id: Option<SessionId>, reason: RejectReason },  // limits, unknown ids
}
```

### 5.3 Queues and ordering

- **Commands:** one `crossbeam_queue::ArrayQueue<Command>` per shard, capacity 4,096, with
  the waker protocol of §3.3.
  - Pushes to a shard arrive in order. The orchestrator is the only producer, running on
    one tokio task.
  - A full queue makes the orchestrator operation fail: it sends `Error` to the client and
    closes the session. Commands are never dropped silently, because the two sides'
    states would diverge.
- **Events:** one bounded `tokio::sync::mpsc` channel (capacity 8,192) shared by all
  shards. Shards call the synchronous `try_send`.
  - When the channel is full, a `DtlsDatagram` is dropped and counted; the peer
    retransmits.
  - Other events wait in a shard-local queue of 256 and are retried every iteration. If
    that also fills, the event is dropped and counted; the orchestrator's timeouts (§6.4)
    recover.
- Commands for different shards are not ordered with respect to each other. Phase 2's
  protocol accepts this (§13.4).

### 5.4 Stats

`ShardStats` is a struct of `AtomicU64`, one per shard. The shard writes it once per
second; anything may read it.

- Counters:
  - `rx_datagrams`, `rx_bytes`, `tx_datagrams`, `tx_bytes`
  - `drop_unknown_addr`, `drop_srtp_auth`, `drop_srtp_replay`, `drop_no_route`
  - `drop_send_full`, `drop_pool_empty`, `drop_event_full`
- Gauges: `sessions`, `tracks`, `subscriptions`, `loop_iterations`, `parks`.
- `nexus-metrics` exports these instead of the worker metrics, and `MetricsCollector` is
  sized by shard count.

---

## 6. Session lifecycle

### 6.1 Publisher

```text
Publish          orchestrator: SessionId, placement -> shard, ICE ufrag/pwd, DTLS SSL object (shared cert)
                 -> CreateSession ; offer (a=ice-lite, recvonly m-lines, fixed extmap table, rtcp-fb)
                 candidates trickled: that shard's addresses
Answer           role from a=setup, fingerprint pinned (as today)
                 per publish m-line -> AddTrack{ mid, ssrc (a=ssrc), pt, ext ids }
browser checks   shard answers STUN; USE-CANDIDATE -> address selected -> AddressSelected
DTLS             browser active (usual): ClientHello -> DtlsDatagram -> OpenSSL -> SendDatagram ...
                 SFU active (answer said passive): AddressSelected triggers start_handshake
                 complete + fingerprint ok -> InstallSrtp -> SessionEvent::Established (logs)
media            shard: unprotect -> track -> fan-out ; first packet -> PeerSrtpVerified -> SSL freed
```

### 6.2 Subscriber

```text
Subscribe        orchestrator: m-line (reuse inactive or append), SubscriptionId, out SSRC from the
                 session's allocator (§9.3) ; offer: sendonly m-line announcing out SSRC
Answer           per answered subscribe m-line -> Subscribe{ out_ssrc, mid, pt_map, ext_map }
shard            subscription added to the track's fan-out list ; if the subscriber already has
                 outbound SRTP: request keyframe (§12.3) ; else when InstallSrtp arrives: keyframe
                 for each of its subscriptions
Unsubscribe      Unsubscribe{sub} ; the out SSRC is retired, never reused in this session
```

Subscriptions go to the shard at answer time. Today they wait for `SessionEvent::Established`
(`handle_session_established`) or for "settled established transport" after a
renegotiation. Both waits go away: the shard skips subscriptions whose session has no
outbound SRTP or no address yet. This removes the `pending_mid_map` state machine and the
race it guards.

### 6.3 DTLS and freeing OpenSSL state

- **One certificate per process.** An ECDSA P-256 key and self-signed certificate are
  created at startup, and one `SslContext` holds them. Each session gets only an `Ssl`.
  - Today `OpenSslDtlsEngine::new` (`openssl_backend.rs:177`) generates a key and
    certificate per session, on the orchestrator's only task.
  - `OpenSslDtlsEngine` gets a constructor that takes the shared context.
  - The fingerprint in every offer is the process certificate's.
- DTLS state lives in the orchestrator's new `Transports` table (§6.5). The shard only moves
  datagrams: `DtlsDatagram` events in, `SendDatagram` commands out. DTLS retransmission
  (`handle_timeout`, Phase 0) keeps running on the 200 ms tick.
- **When to free the `SSL` object.** The design wants 0 bytes of DTLS state after the
  handshake. Freeing it on handshake completion is wrong: if the SFU's last flight is
  lost, the peer retransmits its Finished and must get the SFU's flight again. The first
  authenticated SRTP or SRTCP packet from the peer proves the peer finished, so:
  1. The shard sends `PeerSrtpVerified` once, on the first packet that passes SRTP auth.
  2. The orchestrator frees the `Ssl` object.
  3. From then on the shard drops DTLS datagrams for that session without an event, so a
     peer cannot make the shard allocate per packet.
- A second `InstallSrtp` for a session is rejected (`CommandRejected`). Neither DTLS
  renegotiation nor ICE restart is supported in v1; neither is today.

### 6.4 Timeouts and teardown

| Condition | Detected by | Result |
|-----------|-------------|--------|
| No `AddressSelected` within 30 s of the first offer | orchestrator, 1 s sweep | `CloseSession`, `SessionEvent::Disconnected{IceFailed}` |
| DTLS not complete within the existing handshake timeout | orchestrator, 200 ms tick | same, `DtlsFailed` (new `DisconnectReason` variant) |
| No authenticated traffic for 30 s | shard sweep, `ConsentLost` | same, `ConsentExpired` |
| `Leave`, WS disconnect | orchestrator | `CloseSession`; the shard removes the session's tracks (and every subscription to them), its subscriptions and its address/ufrag entries |

`cleanup_idle` (30 s tick) and `poll_consent` (5 s, which today always sends binding
indications because `remote_ice_ufrag` is never set) are deleted.

### 6.5 Orchestrator changes, file by file

**New `src/orchestrator/transports.rs`** replaces `Arc<WebRtcTransport>`. It holds a
`HashMap<SessionId, TransportEntry>`:

- Fields: `shard`, `ice: IceParams`, `dtls: Option<DtlsHandshake>`, `state`,
  `out_ssrc: SsrcAllocator` (§9.3), `created_at`, `address_selected: bool`.
- `DtlsHandshake` wraps the per-session `Ssl`, the role and the pinned remote fingerprint.
  It keeps the logic of `check_dtls_completion` / `initialize_srtp` (`session.rs:1479`,
  `:1645`), without the key copy into the pure-Rust `DtlsSession`.

**`negotiation.rs`**

| Today | Phase 1 |
|-------|---------|
| Fields `webrtc_transport`, `ssrc_router`, `worker_pool` | `dataplane: DataplaneHandle`, `placement: Box<dyn Placement>`, `shard_candidates: Vec<Arc<[SocketAddr]>>`, `tracks: TrackRegistry` (TrackId → publisher session, shard, kind, codec, mid, cname) |
| `create_transport`: `webrtc_transport.create_session(DtlsParameters::new(Server))` | allocate `SessionId`, `placement.place(room)`, generate ICE ufrag (16 chars) / pwd (32 chars), create `DtlsHandshake`, push `CreateSession` |
| Offer without `a=ice-lite` | session-level `a=ice-lite` (`SessionDescription::ice_lite`, printer already supports it) |
| `start_ice_gathering` trickles the global candidates; completion calls `start_connectivity_checks` | trickles the session's shard's candidates; no connectivity checks |
| `handle_candidate` adds remote candidates and starts checks | accepts and ignores remote candidates (ICE-lite needs none) |
| `handle_answer`: remote ICE creds into the session | not needed; dropped |
| `register_tracks_from_sdp`: one track per SSRC (`take(8)`), global duplicate-SSRC check in `SsrcRouter`, `pool.assign_track`, `SetTrackTwccExtId` | one track per publish m-line: `TrackId` from the counter; SSRC = first `a=ssrc` not listed as secondary in an `a=ssrc-group` (FID/SIM); PT and extmap ids from the answer, cname `nexus-{publisher participant}` (the publisher's own CNAME is not used); push `AddTrack`. Duplicate SSRCs are only an error within one session (SSRC lookup is per session on the shard) |
| After answer: `SetTrackMid` per pending mid | per answered subscribe m-line: build `SubSpec` from both answers (§11), push `Subscribe` |
| `send_ordered_offer`: `OfferMline::Track { ssrc: publisher's }`, `extmaps: &[]`, msid `nexus-stream-{ssrc}` | `ssrc`: the subscription's out SSRC; extmaps from the fixed table (§11.2); msid stream id `nexus-{publisher participant}` and cname `nexus-{publisher participant}` for all of a publisher's tracks (today every track is its own stream, so browsers cannot lip-sync audio with video) |
| Publish m-lines without rtcp-fb | `nack pli`, `ccm fir` on publish m-lines (R1). `RecycledMline` gets an `rtcp_fbs` field; today recycled m-lines cannot carry any |
| `cleanup_participant`: `ssrc_router.remove_by_track`, `pool.remove_track`, `remove_session` | `CloseSession` (the shard removes the tracks); `TrackRegistry` and `DistributedState` entries removed |
| `get_srtp_key_material`, `selected_remote_addr`, `settled_established_transport`, `take_pending_mid_map` | deleted |

**`subscription.rs`**

| Today | Phase 1 |
|-------|---------|
| `worker_pool` field; `subscriber_id` truncated to `u32` | removed; the truncation note goes with it |
| `handle_unsubscribe`: `pool.remove_subscriber` if active | `Unsubscribe{sub}`; the m-line goes inactive as today |
| `handle_session_established`: builds an `SrtpContext` per (subscriber, track) and calls `add_subscriber` | deleted. `SubState::Active` is set when the answer is processed and the `Subscribe` command is pushed (§6.2) |
| `handle_viewport`: `pool.update_viewport` | no data-plane effect in v1 (layer selection comes with simulcast); still replies `ViewportUpdated` |
| `handle_set_content`: `pool.set_content_type` | stored in `TrackRegistry` / `DistributedState`; no data-plane effect in v1 |
| `cleanup_participant`: `remove_subscriber` per track | `DistributedState` only; `CloseSession` removes the shard state |

**`connection.rs`** keeps the name `ConnectionMonitor`, but its job changes to handshakes
and shard events.

| Today | Phase 1 |
|-------|---------|
| `process_incoming(ColdPathPacket)` → `webrtc_transport.process_packet`; replies through `PacketSender` | `handle_event(Event)`: `DtlsDatagram` → `DtlsHandshake::process` → `SendDatagram`; `AddressSelected` → start the handshake if the SFU is client; `PeerSrtpVerified` → free `Ssl`; `ConsentLost` → `Disconnected` |
| `poll_ice` (50 ms) | deleted |
| `poll_dtls` (200 ms) | kept: `handle_timeout` for handshaking sessions; also the handshake and ICE-connect timeouts (§6.4) |
| `poll_consent` (5 s), `cleanup_idle` (30 s) | deleted (§6.4) |
| `PacketSender` (dup'd media fd) | deleted: every datagram leaves through its shard |
| `check_established` | set when `InstallSrtp` is pushed |

**`mod.rs`:** the constructor takes `DataplaneHandle`, `Vec<ShardInfo>` and the placement
instead of `WebRtcTransport`, `SsrcRouter` and `WorkerPool`. In `select!`,
`connection_rx: Receiver<ColdPathPacket>` becomes the dataplane `Receiver<Event>`; the ICE,
consent and cleanup intervals go; a 1 s sweep is added. `Unpublish` sends `RemoveTrack`
instead of `ssrc_router().remove_by_track`. `events.rs` loses `ColdPathPacket`.

**`candidates.rs`:** `resolve(announced_ips, bound_addr)` is unchanged and called once per
shard.

**`src/server.rs`:** starts `Dataplane` instead of `Sfu` and the ingress thread.
`DistributedState`, the gossip thread, `MetricsCollector` and the shutdown notification,
which live in `Sfu::new` / `Sfu::shutdown` today, move into `server.rs`. `ServerHandle`:

- `media_addr` becomes `media_addrs: Vec<SocketAddr>`, one per shard.
- `packet_loop` becomes the dataplane handle, which joins the shards on shutdown.

**`nexus-webrtc` SDP:**

- `SessionDescription::media` becomes a `Vec<MediaDescription>` bounded by
  `MAX_MEDIA_SECTIONS = 32`. Today it is `[Option<MediaDescription>; 8]`, the compile-time
  assertion claims 8 is "per WebRTC spec", and each entry has large inline arrays. A 10-client
  call needs 20 m-lines per session.
  - 32 is the practical limit: the negotiator gives each new sendonly m-line an unused PT
    from 96-127 (`negotiator.rs`, `used_pts`), so about 30 m-lines per session is the
    ceiling anyway. The subscription limit per session is enforced with an error.
  - The `.min(8)` / `.min(16)` loops in `negotiation.rs` go.
- `OfferMline::Track` gets `stream_id` and `cname`; `RecycledMline` gets `rtcp_fbs`.
- `openssl_backend.rs` `set_tlsext_use_srtp` (≈ line 280): `SRTP_AEAD_AES_128_GCM` first
  (Phase 1 exit criterion, design revision 2026-09-26).

---

## 7. Session state on a shard

### 7.1 Tables

Slabs (`Vec<Option<T>>` plus a free list) for sessions, tracks and subscriptions:

- They grow only in command handling (control path, allocation allowed). Nothing is
  reserved per session up front (D8).
- References between them are slab indices. Removal is eager (§6.4), so no index dangles.
  A generation counter is checked in debug builds.

```rust
struct Session {
    id: SessionId,
    addr: Option<SocketAddr>,          // selected address; None until nominated
    last_auth_rx: Instant,             // last authenticated packet (STUN, SRTP, SRTCP)
    ice: IceParams,                    // 48 B
    srtp_in: Option<SrtpInbound>,      // §9
    srtp_out: Option<SrtpOutbound>,
    srtp_verified: bool,               // PeerSrtpVerified sent; DTLS now dropped
    rtcp_ssrc: u32,                    // SFU's sender SSRC for RTCP it originates to this peer
    out_ssrc_base: u32, last_out_ssrc_offset: u32,   // §9.3
    published: SmallArray<(u32 /*ssrc*/, TrackIdx), 10>,   // SSRC -> track, linear scan
    unbound: SmallArray<TrackIdx, 10>, // tracks whose SSRC is not known yet (§7.2)
    subs: Vec<SubIdx>,                 // this session's subscriptions (grows on command)
    counters: SessionCounters,
}

struct PublishedTrack {
    id: TrackId, session: SessionIdx, spec: TrackSpec,
    layers: [Layer; MAX_LAYERS],       // MAX_LAYERS = 1 in v1 (§11.5); Layer { ssrc, last_sr }
    subscribers: Vec<SubIdx>,          // local fan-out list (grows on command, D8)
    remote_shards: ShardMask,          // Phase 2 (§13.4); always empty in Phase 1
    last_pli: Option<Instant>,
}

struct Subscription {
    id: SubscriptionId, session: SessionIdx, track: TrackIdx,
    rewrite: RewriteState,             // §11.1
    ext_map: ExtMap, pt_map: PtMap, mid: MidValue,
    sent_packets: u32, sent_octets: u32,   // for translated SRs
}
```

Lookups on the hot path:

- **Address → session:** `HashMap<SocketAddr, SessionIdx>` with `rustc-hash`. Only
  addresses that passed STUN authentication are inserted, so unauthenticated senders
  cannot grow the map or choose its keys.
- **Ufrag → session:** `HashMap<[u8; 16], SessionIdx>`, for STUN from unknown addresses.
- **SSRC → track:** linear scan of the session's `published` array (≤ 10).
- **Subscriber SSRC → subscription** (inbound RTCP): linear scan of the session's `subs`
  (≤ 30).

### 7.2 SSRC learning

Browsers put `a=ssrc` in their answers, and the orchestrator passes it in `TrackSpec`.

If a packet arrives with an SSRC the session does not know, and the session has unbound
tracks, the shard reads the `mid` extension (publisher's id from `TrackSpec::ext`). If it
matches an unbound track's mid, the SSRC is bound to that track. This is RFC 8843 §9.2
demultiplexing, and simulcast will need it for `rid`. The work per unknown SSRC is bounded
by 10 tracks.

An SSRC that matches nothing is dropped and counted (`drop_no_route`). RTX SSRCs never
appear in v1, because RTX is not offered.

---

## 8. ICE: ICE-lite

### 8.1 Decision

**The SFU is an ICE-lite agent** (RFC 8445 §2.5): `a=ice-lite` in every offer, host
candidates only, no checks sent, and the browser is always controlling.

- Every client already has to reach the SFU's announced address; the SFU never needs to
  reach a client address it has not heard from. The full agent in `nexus-transport/src/ice`
  (agent, checklist, 3,971 lines) buys nothing for an SFU with a public address.
- The shard only answers binding requests: no candidate pairs, no pacing timer, no role
  conflicts, no outbound STUN.
- The consent-check code that never worked (`poll_consent` sends indications) goes away
  instead of being fixed.
- Checked in webrtc-rs 0.10.1 (`peer_connection/mod.rs:1547`): a full agent facing a lite
  remote becomes controlling, so the e2e clients work without change. Chrome and Firefox
  support lite remotes (mediasoup, for example, is ICE-lite). A quick browser call right
  after the switch (Part 1.5, §16) confirms it, well before the final manual check.
- **Cost:** an SFU behind NAT without a port-forwarded announced address does not work.
  That is already the case today; §3.1's `announced_ip` is the answer.

### 8.2 Binding requests (on the shard, no allocation)

A new function in `nexus-dataplane/src/ice.rs`, built from existing `nexus-transport`
pieces (≈ 60 lines):

1. `StunMessage::parse`. It does not allocate, but returns a ≈ 2 KB struct by value; if
   the benchmark shows that cost, a slimmer scan copies the offset logic of
   `parse_with_integrity` (`server.rs:220-265`).
2. Binding request only; other STUN classes are dropped.
3. `USERNAME` = `local_ufrag:remote_ufrag` → ufrag map → session. The remote part is not
   checked: requests can arrive before the answer is processed, and MESSAGE-INTEGRITY
   already proves the sender knows the password.
4. `verify_message_integrity` with the session's local password (`integrity.rs:100`);
   `verify_fingerprint`.
5. Build the success response with `XOR-MAPPED-ADDRESS` (`attributes.rs:464`) and
   `sign_message` (`integrity.rs:365`) into a pool send buffer; queue it to the source
   address.
6. Apply §8.3 / §8.4 and update `last_auth_rx`.

`StunServer::handle_request` is not reused: it allocates (`username.to_string()`) and
writes into its own buffer.

### 8.3 Nomination

An authenticated request with `USE-CANDIDATE` from address A:

- If A is not the selected address, select A: update `addr`, add A to the address map
  (keep the old entry until the next housekeeping sweep so in-flight packets still
  authenticate), and emit `AddressSelected{Nominated}`.
- The latest nomination wins, which also covers a browser that renominates.

Requests without `USE-CANDIDATE` before any nomination are answered but select nothing.

### 8.4 NAT rebinding

An authenticated request **without** `USE-CANDIDATE` from address B ≠ selected:

- If the selected address has sent nothing authenticated for `rebind_silence`
  (default 2 s), select B and emit `AddressSelected{Rebound}`.
- Otherwise B is another candidate pair being checked: answer only.

The rule is needed because full agents keep checking other pairs at a low rate; switching
on every valid request would flap between interfaces.

Media therefore resumes within about `rebind_silence` plus the client's check interval
(webrtc-rs sends a keepalive binding request every 2 s; browsers check the selected pair
every few seconds). No command round-trip is involved (design §3.9).

SRTP from an unknown address never moves the session, even when it authenticates. Only
STUN does, as the design says.

### 8.5 Liveness

- An ICE-lite agent sends no consent checks. RFC 7675 consent is the full agent's job, and
  the browser does it.
- The shard treats any authenticated packet (binding request, SRTP, SRTCP) from the selected
  address as proof of life, via `last_auth_rx`.
- No such packet for `consent_timeout` (30 s) → `ConsentLost`.

---

## 9. SRTP

### 9.1 Contexts per direction (D5)

Added to `nexus-transport/src/srtp/` as `direction.rs`:

```rust
pub struct SrtpInbound  { cipher: SrtpCipher, ssrcs: SsrcTable<SsrcIn, 16> }
pub struct SrtpOutbound { cipher: SrtpCipher, ssrcs: SsrcTable<SsrcOut, 32> }

struct SsrcIn  { ssrc: u32, roc: u32, highest_seq: u16, rtp_replay: ReplayProtection,
                 rtcp_replay: ReplayProtection, last_seen_s: u32 }
struct SsrcOut { ssrc: u32, roc: u32, highest_seq: u16, sent: ReplayProtection /* §9.3 */,
                 srtcp_index: u32 }

impl SrtpInbound {
    pub fn unprotect_rtp(&mut self, buf: &mut [u8], len: usize, now_s: u32) -> Option<usize>;
    pub fn unprotect_rtcp(&mut self, buf: &mut [u8], len: usize, now_s: u32) -> Option<usize>;
}
impl SrtpOutbound {
    pub fn protect_rtp(&mut self, buf: &mut [u8], len: usize) -> Option<usize>;
    pub fn protect_rtcp(&mut self, buf: &mut [u8], len: usize) -> Option<usize>;
    pub fn retire(&mut self, ssrc: u32);   // subscription ended; frees the slot
}
```

- **Fixed tables, no `HashMap`.** Today `SrtpContext` allocates a `HashMap` entry on the
  first packet of each SSRC (`context.rs:121`).
  - Inbound, 16 slots: the peer's media SSRCs (≤ 10) plus the SSRCs it sends RTCP from as
    a receiver. A full table evicts the entry idle longest (> 30 s, in the sweep);
    otherwise the packet is dropped.
  - Outbound, 32 slots: one per subscription (≤ 30) plus `rtcp_ssrc`.
- **Cipher:** the existing `SrtpCipher` enum (`crypto.rs:934`), whose calls take the packet
  index from the caller. Its `AesGcm` variant is reimplemented on `ring`: the
  `RingGcmBackend` from `benches/srtp_backends.rs:344-389`, with SRTCP added (nonce per
  RFC 7714 §9.1 as in `crypto.rs:178`, AAD = header ‖ E+index). `AesCmHmac` stays
  RustCrypto (D7, revision 2026-09-26).
  - The RFC 3711 / RFC 7714 vector tests (`rfc_vectors.rs`) and the byte-for-byte check
    against `SrtpContext` in the bench keep covering both.
  - With `ring`, the AAD is a slice of the packet, so the 128-byte AAD copy and its panic
    disappear.
- **ROC and replay logic** come out of `context.rs` as functions that both `SrtpContext` and
  the new types call, so the RFC 3711 index estimate stays in one place.
- `SrtpContext` stays for now: the SRTP benches compare against it. Once nothing else uses
  it, it goes in the Phase 1 cleanup (§16, C5).

### 9.2 Keys

`InstallSrtp` carries both directions' `KeyMaterial`. The orchestrator picks them by DTLS
role, as `initialize_srtp` does today (server: inbound = client write key). The shard
builds `SrtpInbound` from the remote key and `SrtpOutbound` from the local key. It does
this in command handling, where allocation is allowed; the key schedule is built once per
context.

### 9.3 Outbound SSRCs and the re-subscribe bug

The open bug (architecture.md 2.2): an unsubscribe followed by a subscribe repeats
(key, SSRC, index). Two mechanisms rule it out, and a test (§17.4) checks the wire.

1. **An SSRC is never reused within a session.**
   - The orchestrator allocates out SSRCs as `base + n`, with `base` random per session
     (sent in `CreateSession`) and `n` strictly increasing. Values that are 0 or equal to
     one of the peer's own SSRCs are skipped, which is a bounded loop.
   - The shard accepts a `Subscribe` only if `out_ssrc - base > last_out_ssrc_offset`
     (wrapping arithmetic, `n < 2^31`), then records the offset. Reuse is refused by
     construction, even if the orchestrator has a bug.
   - The session's outbound key lives exactly as long as the session. A rejoin is a new
     session with a new DTLS handshake and a new key.
2. **The outbound context never sends the same index twice.**
   - Each `SsrcOut` keeps a 64-packet window of sent indices (the `ReplayProtection` type,
     reused on the send side). `protect_rtp` refuses an index already sent or older than
     the window, and the packet is dropped and counted.
   - Reordered packets (lower seq, not yet sent) still pass.
   - Phase 3 retransmission must not re-protect a packet with the same index and a
     different header (§18).

SFU-originated RTCP to a peer (PLI in Phase 1, RR in Phase 3) uses the session's
`rtcp_ssrc`. Translated SRs use the subscription's out SSRC. Each (key, sender SSRC) pair
therefore has exactly one SRTCP index counter, which removes architecture.md 2.2's SRTCP
issue by construction.

### 9.4 Profile

`use_srtp` offers `SRTP_AEAD_AES_128_GCM` first (§6.5). AES-CM stays supported for
browsers that do not pick GCM. 500K/core needs GCM (design revision 2026-09-26); the manual
browser check (§17.9) confirms which profile Chrome and Firefox choose.

---

## 10. Packet path and buffers

### 10.1 Ingress, per datagram

```text
classify byte 0 (RFC 7983): 0-3 STUN | 20-63 DTLS | 128-191 RTP/RTCP (RTCP if byte1 & 0x7F in 64..=95, RFC 5761)
STUN      §8.2
DTLS      session by addr; if !srtp_verified: Event::DtlsDatagram (copy) else drop
RTP       session by addr (else drop) -> srtp_in (else drop) -> unprotect in place (else drop)
          -> last_auth_rx = now ; first time: PeerSrtpVerified
          -> RtpHeader::parse -> SSRC -> track (§7.2) -> fan-out (§10.2)
RTCP      session by addr -> unprotect -> compound iterate (≤ 16 blocks) -> §12
```

`demux.rs` classification is not reused as is: its RTCP range is 72..=79, and its validation
functions allocate on invalid input. The classification is five comparisons, written in
`shard/mod.rs`.

### 10.2 Fan-out and egress (Phase 1: all local)

For each `sub` in `track.subscribers`, skipping subscribers whose session has no
`srtp_out` or no `addr`:

1. `pool.take()` a send buffer; if the pool is empty, drop and count.
2. `rewrite(pkt, sub, buf)` (§11.4); `None` means drop.
3. `srtp_out.protect_rtp(buf, len)`; `None` means drop.
4. Update `sub.sent_packets` and `sent_octets`.
5. `tx.push(buf, len, addr)`; flush first if `tx` is full.

The ingress buffer goes back to the pool once the datagram is processed. In Phase 2 it
goes back when the last cross-shard handle is returned (§13.4).

### 10.3 Buffer pool

- **One pool per shard:** `dataplane.pool_buffers` buffers of 2,048 bytes in one
  allocation made at startup, never grown. The default is 1,024 (2 MB per shard), reported
  separately from per-participant memory (design §3.11).
- Phase 1 needs at most `RECV_BATCH` (64) receive buffers plus `SEND_BATCH` (256) send
  buffers at a time. Phase 2 sizes the rest for cross-shard queues.
- **Free list:** a `Vec<u32>` stack of indices. `take()` and `put()` are O(1) and never
  allocate.
- **Buffer size:** 2,048 bytes leave room for a 1,500-byte datagram, header growth from the
  rewrite (a `mid` element is at most 4 + 17 bytes plus padding) and the SRTP/SRTCP
  trailer (≤ 20 bytes).
- **`BufRef { shard: ShardId, index: u32 }`** is the handle type from Phase 1 on. Phase 2
  adds the owner-local refcount and cross-shard reads (§13.4).

### 10.4 Allocation rule

After a session, its tracks and subscriptions exist and each SSRC has been seen once, the
receive → decrypt → fan-out → rewrite → encrypt → send path allocates nothing. §17.7 tests
this.

Allocations allowed on the shard are in command handling (slab growth, fan-out `Vec`
growth, boxed command payloads being freed) and in `DtlsDatagram` events. The latter
happen only until `PeerSrtpVerified`.

---

## 11. RTP rewrite

### 11.1 Per-subscription rewrite state

```rust
struct RewriteState {
    out_ssrc: u32,          // announced in the subscriber's SDP; never changes (§9.3)
    seq_offset: u16,        // sub_seq = pub_seq + seq_offset (wrapping)
    ts_offset: u32,         // sub_ts  = pub_ts  + ts_offset  (wrapping)
    started: bool,          // offsets set by the first forwarded packet
    last_out_seq: u16, last_out_ts: u32, last_out_at: Instant,  // highest forwarded; for rebasing
    layer: u8,              // current source layer; always 0 in v1 (§11.5)
}
```

- **First packet:** `seq_offset` and `ts_offset` are chosen so the subscriber's stream
  starts at a random sequence number and timestamp (RFC 3550 §5.1). Later packets use the
  same offsets, so reordering and gaps pass through unchanged.
- **Deliberate drops:** Phase 1 drops no packet on purpose except one whose PT is not in
  `pt_map`, which only a negotiation error causes. It does not adjust `seq_offset` for
  that; the subscriber sees a gap.
  - Adjusting for deliberate drops (padding-only probes, layer switches) needs a record of
    the dropped seqs so that reordered packets still map correctly. That comes with
    simulcast and bandwidth estimation, which are the features that drop packets on purpose.
- **NACK ring:** the 512-entry ring from subscriber seq to publisher seq (design §3.5) is
  Phase 3 (`loss-recovery.md`). With a constant offset it is only needed once offsets can
  change, but it belongs with the NACK path.

### 11.2 Header extensions

Because the SFU always offers (publishers and subscribers alike), it chooses every ID. It
offers one fixed table on every m-line, each extension only for the kinds it applies to.
`nexus-dataplane` and the negotiator share it as a constant:

| ID | URI | Kinds | v1 handling |
|---:|-----|-------|-------------|
| 1 | `urn:ietf:params:rtp-hdrext:sdes:mid` | A, V | Read on ingress (SSRC learning); stripped from the publisher packet and written per subscriber with the subscriber's mid |
| 2 | `urn:ietf:params:rtp-hdrext:ssrc-audio-level` | A | Forwarded (ID mapped) |
| 3 | `urn:3gpp:video-orientation` | V | Forwarded |
| 4 | `http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01` | A, V | **Publish m-lines: offered from Phase 3** (R8), read on ingress for TWCC feedback (§12.4) and stripped, never forwarded. Subscribe m-lines: not offered in v1; written by the SFU per subscriber session once §3.8 lands |
| 5 | `http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time` | V | Reserved, not offered (forwarding the publisher's value would mislead the subscriber's estimator) |
| 10 | `urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id` | V | Reserved for simulcast |
| 11 | `urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id` | V | Reserved for simulcast + RTX |

The IDs are fixed, and JSEP answerers keep the offerer's IDs. The mapping is still **built
from the two answers, not assumed**:

- `ExtIds` (publisher, in `TrackSpec`): the ID the publisher's answer accepted for each
  table entry, or 0 if it declined.
- `ExtMap` (per subscription, `[u8; 15]`): index = publisher's one-byte ID (1-14), value =
  the subscriber's ID for the same URI, or 0 to drop.
  - Built by the orchestrator as publisher `id → URI` (from the publisher's answer),
    then `URI → id` from the subscriber's answer for that m-line.
  - `mid` is special: the publisher's `mid` element is always dropped, and the subscriber's
    is written if its answer accepted `mid`.
- This costs 15 bytes and keeps working if an answer ever renumbers or declines, or when
  bandwidth estimation adds SFU-written extensions.

**Output form:** the rewrite always writes the one-byte form (`0xBEDE`). Every ID in the
table is ≤ 14. Input in the two-byte form (`0x100X`, used when a sender mixes forms) is
parsed; elements longer than 16 bytes or with IDs > 14 cannot be in the table and are
dropped.

### 11.3 Payload types

`PtMap` has a fixed array of up to 2 `(publisher_pt, subscriber_pt)` pairs: the codec in
v1, and RTX's PT after v1. The subscriber's PT can differ from the publisher's because the
negotiator remaps new sendonly m-lines to unused PTs for BUNDLE uniqueness (`used_pts` in
`create_ordered_offer`).

The orchestrator matches the codec by name and clock rate in the subscriber's answer. A PT
not in the map means the packet is dropped (counted).

Codecs in v1 are unchanged: Opus and VP8 (`publish_codec`). H.264 needs fmtp
(`profile-level-id`) matching between publisher and subscriber and is not in v1 scope.

### 11.4 The rewrite

`rewrite(src: &[u8] /* decrypted */, sub: &mut Subscription, dst: &mut [u8]) -> Option<usize>`
is one pass that never moves the payload more than once:

1. Parse the source header (`RtpHeader::parse`, no allocation): CC, X, extension block,
   payload offset.
2. Write the fixed 12 bytes into `dst`: V/P/X/CC, M, mapped PT, `seq + seq_offset`,
   `ts + ts_offset`, `out_ssrc`. Copy the CSRCs (the SFU does not mix; normally none).
3. Extensions: write `0xBEDE` and a placeholder length. For each source element (at most 16),
   write the element with its mapped ID if `ext_map[id] != 0`. Then write the `mid`
   element, pad to 32 bits and fill in the length. If no element was written, clear X.
4. `copy_from_slice` the payload (including any RTP padding, keeping P).
5. Return the length; the caller protects in place.

Bounded work: ≤ 16 elements, header ≤ 12 + 60 + 4 + 16 × 17 bytes.

### 11.5 Keeping simulcast easy

Simulcast is after v1 (design §3.7). These choices keep it an addition rather than a
rewrite:

- **Out SSRC per subscription, always rewritten.** A layer switch changes the source, not
  what the subscriber sees.
- **Explicit offsets plus `last_out_*` fields.** A switch rebases:
  - `seq_offset = last_out_seq + 1 - first_new_pub_seq`
  - `ts_offset = last_out_ts + elapsed × clock_rate - first_new_pub_ts`
  No "first packet" offset is baked in.
- **`PublishedTrack::layers: [Layer; MAX_LAYERS]`** with `MAX_LAYERS = 1` in v1.
  - The SSRC → track lookup already returns (track, layer).
  - The subscription has `layer`; simulcast adds `target_layer`.
  - SRs are stored per layer, and a subscription only translates SRs of its current layer
    (§12.2).
- **Keyframe requests** go through `request_keyframe(track, layer)` (§12.3).
- **Keyframe detection** exists: `nexus_media::codec::is_keyframe` (VP8, VP9, H.264, AV1).
- **Extension IDs** 10 and 11 are reserved for `rid` / `repaired-rid`, and SSRC learning
  from the `mid` extension (§7.2) is the same mechanism `rid` needs.
- **Phase 2's cross-shard message** carries the layer (§13.4).
- **`PtMap`** has room for the RTX pair.

---

## 12. RTCP (Phase 1)

### 12.1 Inbound

Iterate the compound packet (`nexus_media::rtcp::demux_compound`, zero-copy, ≤ 16 entries).

| Block | From | Phase 1 handling |
|-------|------|------------------|
| SR | publisher | Store `(ntp, rtp, at)` on the track's layer for the sender SSRC; translate to each started subscription (§12.2) |
| PLI | subscriber | media SSRC → subscription (by out SSRC in the session's `subs`) → `request_keyframe(track, layer)` |
| FIR | subscriber | same as PLI (design §3.6: forwarded as PLI). Parsed in place; `FirPacket::parse` allocates a `Vec` and is not used |
| RR, REMB, TWCC, NACK, SDES, BYE, XR | any | ignored in Phase 1, counted. NACK and RR come in Phase 3, REMB/TWCC after v1. BYE is ignored because signaling (`Unpublish`, `Leave`) is authoritative |

`nexus-media` parsers that return `Vec` (RR, NACK, FIR, REMB) are not used on the shard.
Phase 3 adds allocation-free versions where needed.

### 12.2 SR translation (lip sync)

When a publisher's SR for layer L of track T arrives, for each subscription of T that is on
layer L and `started`, the shard builds a compound RTCP packet in a pool buffer:

- **SR** (RFC 3550 §6.4.1):
  - sender SSRC = `out_ssrc`
  - NTP = the publisher's NTP
  - RTP = the publisher's RTP + `ts_offset`
  - packet count = `sent_packets`, octet count = `sent_octets`
  - no report blocks
- **SDES** with CNAME = the publisher's cname (`TrackSpec::cname`). The packet is always
  compound, so it does not depend on `rtcp-rsize` being negotiated.

It is protected with the subscriber's `srtp_out` (per-SSRC SRTCP index of `out_ssrc`) and
queued. Translating on arrival costs no timer and keeps the NTP/RTP pair exact. Publishers
send SRs about once a second, which is also the subscriber's SR rate.

Lip sync needs this plus a shared msid stream and cname for all of a publisher's tracks
(§6.5); today each track is its own stream.

### 12.3 Keyframe requests (R1)

`request_keyframe(track, layer)`:

- If `now - track.last_pli < 500 ms`, it does nothing.
- Otherwise it builds a PLI (sender SSRC = the publisher session's `rtcp_ssrc`, media
  SSRC = the layer's SSRC), protects it with the **publisher's** `srtp_out` and queues it
  to the publisher's address.

Callers:

- a subscriber's PLI or FIR;
- a new subscription whose session has outbound SRTP;
- `InstallSrtp` on a session that already has subscriptions.

Across shards (Phase 2), a subscriber's shard sends `KeyframeRequest{track, layer}` to the
publisher's shard (§13.4).

### 12.4 TWCC feedback toward publishers (Phase 3, R8)

Specified in `loss-recovery.md`; the constraints fixed here:

- Offered only on publish m-lines, together with `a=rtcp-fb:<pt> transport-cc`, and only once
  feedback is implemented (Phase 3). Offering it earlier would switch the browser to
  transport-cc estimation with no feedback.
- The transport-wide sequence counter is per publisher **session** (one per peer, across
  its audio and video), so the arrival record belongs to `Session`, not to a track: a
  fixed ring of (transport seq, arrival time), ≈ 256 entries, no allocation.
- Feedback is sent about every 100 ms per publishing session, with the session's
  `rtcp_ssrc` as sender SSRC and the publisher's `srtp_out` (one SRTCP index counter per
  (key, sender SSRC), §9.3). The 1 s sweep is too coarse: the loop checks a per-session
  due time on the packet path, or `loss-recovery.md` introduces a timer wheel (§3.4).
- The builder must not allocate; the worker's `generate_and_send_twcc` and
  `nexus-bwe/src/feedback.rs` are starting points, not reused as is (they allocate).
- Tests: an e2e test in Phase 3 checks that a webrtc-rs publisher receives transport-cc
  feedback about every 100 ms covering every transport sequence number it sent (webrtc-rs
  sends synthetic media at a fixed rate, so it cannot show the rate rising). The manual
  browser check confirms the publish bitrate climbs well above ≈ 300 kbps
  (`chrome://webrtc-internals`, outbound video bitrate / available send bandwidth).

---

## 13. Interfaces for Phase 2

Phase 1 runs one shard, but the following are in place so Phase 2 adds code instead of
changing shapes.

### 13.1 Built in Phase 1

- `ShardId` in `TrackRef`, `BufRef` and `ShardInfo`.
- The placement trait (§13.2) with `SingleShard`.
- Port-range config and per-shard candidates (§13.3). Validation rejects `shards > 1`
  until Phase 2.
- `PublishedTrack::remote_shards` (always empty) and `SubSpec::source: TrackRef` (always
  local).

### 13.2 Placement

```rust
pub struct ShardLoad { pub sessions: u32, pub rx_pps: u32 }   // from ShardStats
pub trait Placement: Send {
    /// Shard for a new session. `room` is None for a participant not in a room.
    fn place(&mut self, room: Option<RoomId>, loads: &[ShardLoad]) -> ShardId;
    fn session_closed(&mut self, room: Option<RoomId>, shard: ShardId);
}
```

- Called in `create_transport`. A session stays on its shard for life; there is no
  migration.
- Phase 1: `SingleShard` always returns 0.
- Phase 2: `RoomAffine { max_sessions, max_pps }`. The room's current shard is used while it
  is under both thresholds; otherwise the least-loaded shard (design §3.1).

### 13.3 Ports and candidates

- `transport.media_bind_addr` is the **base**: shard *i* binds `ip:(port + i)`. Port 0 means
  each shard binds its own ephemeral port (tests).
- Validation: `port + shards - 1 ≤ 65535`, and none of the ports is the signaling, API or
  metrics port.
- `Dataplane::start` returns `ShardInfo { id, local_addr }` per shard. The orchestrator runs
  `candidates::resolve(announced_ips, local_addr)` per shard: the announced IPs are shared,
  the port is the shard's.
- `deploy/docker/run.sh` publishes the range (`-p ${MEDIA_PORT}-${MEDIA_PORT+N-1}:…/udp`) in
  Phase 2. With one shard it is unchanged.

### 13.4 Cross-shard queues and buffer ownership (Phase 2)

**Queues:** one bounded SPSC ring per ordered shard pair (i → j) for media messages, and
one per pair (j → i) for returned buffers. They are created by `Dataplane::start` as an
N × N mesh; each shard gets its producer and consumer ends. `src/worker/spsc.rs` and its
proptest (deleted in Phase 1, kept in git) are the starting point, made generic over a
`Copy` item.

```rust
enum XsMsg {                                       // Copy, ≤ 32 bytes
    Rtp { buf: BufRef, len: u16, track: TrackId, layer: u8 },
    SenderReport { track: TrackId, layer: u8, ntp: u64, rtp: u32 },
    KeyframeRequest { track: TrackId, layer: u8 },   // subscriber shard -> publisher shard
}
```

**Subscribing across shards:**

- The orchestrator sends `Subscribe{source: TrackRef{shard: A, ..}}` to the subscriber's
  shard B.
- It sends `AddRemoteShard{track, shard: B}` to A when B gets its first subscription to
  that track, and `RemoveRemoteShard` when B's last one ends. The orchestrator counts
  subscriptions per (track, shard).
- **Unordered commands are safe.** Media that reaches B before B's `Subscribe` is dropped
  (no local subscriber for that track). Media after the last `Unsubscribe` is dropped the
  same way.

**Buffer ownership (the only `unsafe` in the design, confined to `pool.rs`):**

1. Each shard's pool region is one allocation, shared read-only with the other shards as
   `Arc<PoolRegion>`. Only the owner writes to it.
2. Owner-local `refs: Box<[u16]>`, one per buffer, read and written only by the owner.
3. Handing out: after local fan-out, for each remote shard in `track.remote_shards`, push
   `XsMsg::Rtp{buf}`. Each successful push increments `refs[buf]`; a full queue drops for
   that shard and is counted.
   - If `refs[buf] == 0` after the loop, the buffer is freed immediately.
4. Receiving shard: pop (Acquire) → read `region.slice(buf, len)` → fan out to its local
   subscribers (each copies into its own send buffer, §10.2) → push the `BufRef` onto the
   return ring (Release).
5. The owner drains its return rings every iteration: `refs[buf] -= 1`, and at 0 → `put()`.
6. **Safety argument:**
   - The owner writes a buffer only while `refs == 0` and it is not in flight.
   - The media ring's Release/Acquire orders the owner's writes before the reader's reads.
   - The return ring's Release/Acquire orders the reader's reads before the owner's reuse.
   - Tests: `loom` model of one pair plus a stress test.
7. **Return rings can never be full:** at most `capacity(i→j) + XS_BUDGET` of i's buffers
   can be outstanding on j, so the return ring's capacity is set to that. A full return
   ring would leak a buffer; it is an `assert!`.

SRs and keyframe requests travel on the same media ring without a buffer.

---

## 14. Configuration

| Today | Phase 1 |
|-------|---------|
| `worker.num_workers`, `--workers`, `NEXUS_WORKER_COUNT` | `dataplane.shards` (default 1; must be 1 in Phase 1), `--shards`, `NEXUS_SHARDS` |
| `worker.cpu_affinity`, `realtime_priority`, `realtime_priority_level` | same fields under `[dataplane]` |
| `memory.arena_size_mb`, `memory.ring_buffer_size`, `NEXUS_ARENA_SIZE_MB` | removed; `dataplane.pool_buffers` (default 1,024) |
| — | `dataplane.busy_poll_rounds` (0 dev/test, 256 production), `dataplane.consent_timeout_ms` (30,000), `dataplane.rebind_silence_ms` (2,000) |
| `transport.media_bind_addr` | base address of the port range (§13.3) |
| `transport.max_webrtc_sessions` | kept; `max_sessions_per_shard = ceil(max / shards)` |
| `transport.batch_size`, `batch_flush_interval_us`, `stun_servers`, all `actor.*` | removed (validated but never read today) |
| `nexus-actor` limits in `config/mod.rs:157-181` | the orchestrator's own constants (they already exist as `MAX_ROOMS`, `MAX_PARTICIPANTS_PER_ROOM` in `room.rs`) |
| Cargo feature `io_uring` (default) | removed with `io_uring.rs` |

The config files in `config/`, the e2e harness config (`harness.rs:57`) and the README
config section are updated in the same step.

---

## 15. Memory estimate (§3.11 check)

Per participant publishing audio + video and subscribed to 10 tracks (5 A+V pairs).

| Item | Estimate | Notes |
|------|---------:|-------|
| `Session` (addresses, ICE, index arrays, counters) | 0.5 KB | |
| `SrtpInbound` | 2.3 KB | 2 ciphers (RTP, RTCP) ≈ 1 KB + 16 × 80 B |
| `SrtpOutbound` | 2.3 KB | 2 ciphers ≈ 1 KB + 32 × 40 B |
| Published tracks × 2 | 1 KB | struct + fan-out `Vec` |
| Subscriptions × 10 | 1.5 KB | ≈ 150 B each (rewrite 24 B, ext map 15 B, PT map, mid, counters) |
| Control plane: negotiation, subscription, transport entry (`Ssl` freed), track registry | 3-4 KB | mostly `NegotiationState` strings and `Vec`s |
| **Fixed total, Phase 1** | **≈ 11 KB** | budget 25 KB |
| Phase 3: NACK seq ring for 5 video subscriptions | + 5 KB | 512 × u16 each |
| Phase 3: TWCC arrival ring for the publishing session | + 2 KB | ≈ 256 × (u16, u32) plus state |

The SRTP line is over the design's 2 KB split and the track line is under it (R5); the
total is what CI enforces.

The memory bench (§17.8) measures the data-plane state through commands and the
control-plane state through the orchestrator's managers. The WebSocket connection's
buffers are signaling, not session state, and are reported separately.

---

## 16. Order of work and deletion

All of Phase 1 happens on a `phase-1` branch, merged into `main` when every exit
criterion passes (design §7). Every commit on the branch builds, passes clippy and
`cargo test --workspace`, so the branch can be bisected. The steps below are the suggested
parts of `docs/plans/phase-1.md`.

**Add, with the old path still live and green:**

| Part | Content | Checkpoint |
|------|---------|------------|
| 1.1 SRTP per direction | `direction.rs`, ring GCM in `SrtpCipher` (with SRTCP), ROC/replay functions shared, the two panics fixed | RFC vectors, bench byte-for-byte check, `srtp_backends` numbers unchanged |
| 1.2 Shard core on `MemIo` | `nexus-dataplane`: ids, commands/events, tables, ICE-lite handler, rewrite, RTCP (SR, PLI), pool, `Shard::iterate` | `tests/shard.rs` with scripted peers (STUN, SRTP via `SrtpContext` as the peer's implementation); `tests/alloc.rs` at 0 |
| 1.3 Shard thread and I/O | `LinuxIo`, `PortableIo`, park/wake, stats, `DataplaneHandle`, `Dataplane::start` | loopback test: two in-process peers through a real socket, macOS and Linux |
| 1.4 SDP groundwork | `media: Vec`, `MAX_MEDIA_SECTIONS = 32`, `RecycledMline::rtcp_fbs`, `OfferMline::Track{stream_id, cname}`, extension table constant, shared DTLS certificate | old path e2e still green |

**Switch (one commit):**

| Part | Content | Checkpoint |
|------|---------|------------|
| 1.5 Orchestrator on commands | §6.5: `transports.rs`, negotiation/subscription/connection/mod, `server.rs` starts the dataplane, ICE-lite offer, GCM first, config `[dataplane]`. The old path is no longer started but still compiles | Phase 0 e2e tests green on the new path (`two_party_audio_video` now compares against the SSRCs announced in each client's offer, not the publisher's). Quick Chrome and Firefox call (§17.9 steps 1-2) to confirm ICE-lite and GCM with browsers early; there is no page yet, so this uses a scratch page or the SDK in a console |

**Delete, one commit each, green after each:**

| Step | Removed | Also |
|------|---------|------|
| C1 | Packet loop and `Sfu` (`src/sfu.rs`), `SRTCP_SENT_CACHE`, `tests/pps_pipeline.rs`, the `sim` feature, `src/spin.rs`, `src/clock.rs` (if unused) | the pieces moved to `server.rs` in 1.5 stay |
| C2 | `benches/real_path.rs` and `benches/memory.rs` ported to `nexus-dataplane` (same scenarios, §17.8); `benches/forwarding.rs` deleted (it measures `SsrcRouter`) | CI bench-smoke uses the ported benches |
| C3 | `src/worker/`, `src/forward/`, `src/transport/` re-exports, `lib.rs` re-exports, `WorkerError` uses in `error.rs`, `proto.rs` and its `protoc` step in `build.rs` | CLAUDE.md prerequisites lose `protoc` if nothing else needs it |
| C4 | `nexus-actor`, `nexus-dst` (decided: DST returns after v1 on shards), their workspace entries, `config/mod.rs:157-181` limits, `config/tests.rs:333-338`, `lib.rs:70-75` | |
| C5 | `nexus-transport`: `arena`, `ring_buffer`, `batch`, `udp`, `media_transport`, `io_uring` and their proptests; the `io_uring` feature. ICE `agent.rs`, `checklist.rs` (unreachable with ICE-lite); `StunServer` if unused. Pure-Rust DTLS (`dtls/session.rs`, `handshake.rs`, `record.rs`) where nothing live imports it; `SrtpContext` if only benches use it (move it to the bench) | `gro.rs`, `gso.rs`, `socket_config.rs`, `stun/`, `candidate.rs`, `gather.rs` interface enumeration stay |
| C6 | `nexus-webrtc`: `webrtc/transport.rs`, `webrtc/session.rs`, `webrtc/demux.rs` (validation allocates; classification lives in the shard) | SDP stays |
| C7 | Config fields of §14, README, `deploy/docker/run.sh`, `config/*.toml` | |

**Finish:**

| Part | Content |
|------|---------|
| 1.6 New e2e tests and harness changes | §17.2-§17.6 |
| 1.7 Benches, budget, CI | 0-allocation and memory checks in CI (`NEXUS_MEM_BUDGET_KB=25`, was 1700); a macOS job running `cargo test --test e2e` (design §3.12 asks for both, and CI has only Linux today) |
| 1.8 Browser page and manual check | `examples/web/`, §17.9 |
| 1.9 Documents | `architecture.md` Parts 1-2 for the new path (the full rewrite is at release), CLAUDE.md "Architecture (today)" and commands, design revisions R1-R6, the plan's status |

Part 1.6 and C1-C7 are independent after 1.5 and can be interleaved; the browser page (1.8) can be written any time and makes the early check in 1.5 easier.

---

## 17. Testing the Phase 1 exit criteria

### 17.1 Phase 0 tests on the new path

`tests/e2e.rs` keeps `two_party_audio_video`, `candidate_is_announced_address` and
`dtls_survives_lost_first_flight`. Two changes:

- SSRCs are rewritten, so "receives exactly the peer's SSRCs" becomes "receives exactly
  the SSRCs its offer announced for the peer's tracks". The client records the offer's
  `tracks` (mid → track) and the `a=ssrc` per mid.
- To prove the media came from the right publisher, the synthetic payloads carry the
  publisher's SSRC and a frame counter in their first 8 bytes (`nexus-loadtest` `media.rs`),
  and the subscriber checks them.

### 17.2 Ten clients, audio + video

`ten_clients_audio_video`: 10 `HeadlessClient`s in one room, each publishing A+V and
subscribing to all others (18 tracks each, 20 m-lines per session). After 5 s of media,
each client receives exactly 18 streams, from the 9 right publishers (payload marker), each
at ≥ 10 packets/s with ≤ 1% missing and timestamps advancing.

Runtime target < 30 s. `subscribe_to_all` may need several `Subscribe` messages: today's
per-request cap is 10 (`MAX_TRACKS_PER_PARTICIPANT` in `subscription.rs`).

### 17.3 Address change mid-call

`address_change_mid_call`: A and B in a call. After 3 s, A's socket is rebound to a new
local port. That needs harness work: `LossyUdpConn` gets a `rebind()` that swaps its inner
socket (`ArcSwap<UdpSocket>`), so the webrtc-rs agent keeps its candidate while packets
leave from a new port, which is exactly what a NAT rebinding looks like to the SFU.

Asserts:

- B's stream of A's media and A's stream of B's media both resume within 5 s of the rebind
  (§8.4: 2 s silence plus a 2 s keepalive).
- After that, both continue with ≤ 1% loss.
- The shard reported `AddressSelected{Rebound}` for A's session (read through a test hook
  on the events).

### 17.4 Unsubscribe → resubscribe, no repeated (SSRC, packet index)

`resubscribe_no_srtp_index_reuse`: A publishes. B subscribes, receives for 1 s,
unsubscribes, and repeats this three times.

Harness work:

- `HeadlessClient` gets `unsubscribe(track_ids)`. Today its signaling handle is private to
  the background task; it becomes a command channel into that task.
- `LossyUdpConn` gets a tap that records, for every inbound datagram:
  - SRTP (byte 0 in 128-191, not RTCP): (SSRC, seq);
  - SRTCP: (sender SSRC, E+index from the trailer).

Asserts:

- No (SSRC, seq) pair repeats. The test runs well under 65,536 packets per SSRC, so seq
  stands in for the packet index.
- No (SSRC, SRTCP index) pair repeats.
- Each resubscription arrives on a new SSRC.
- Media is received after each resubscribe.

This test fails on the old path, whose re-subscribe reuses the context.

Unit tests in `nexus-dataplane` cover the mechanisms directly:

- the shard refuses a reused or out-of-order out SSRC;
- `SrtpOutbound` refuses an index it already sent.

### 17.5 SR translation (R6)

`sender_report_translation`: A publishes A+V (webrtc-rs sends SRs through its default
interceptors), and B subscribes. Harness work: `on_track` starts a `receiver.read_rtcp()`
task that records SRs per SSRC; today `_receiver` is ignored (`client.rs:413`).

Asserts, per track:

- B gets SRs (≥ 2 within 5 s).
- Sender SSRC = the SSRC B receives that track's media on.
- The SR's RTP timestamp is consistent with the media: extrapolated from the latest
  received packet's timestamp, using the clock rate and the NTP difference to its arrival,
  it agrees within 20 ms.
- Audio and video SRs carry the same CNAME.

The exact arithmetic (offset applied, counts, compound layout, SRTCP with the out SSRC) is
a `nexus-dataplane` unit test that parses the packet the shard builds.

### 17.6 Keyframe requests (R1)

`keyframe_requests`. Harness work: the publisher reads `sender.read_rtcp()` and records
PLI/FIR per SSRC.

Asserts:

1. When B subscribes, A receives a PLI for its video SSRC within 1 s.
2. B sends a PLI (webrtc-rs `write_rtcp`) → A receives it within 500 ms.
3. B sends 5 PLIs within 100 ms → A receives exactly 1 in the following 400 ms.

The late-join test with a real keyframe (within 1 s) stays in Phase 3; the webrtc-rs
clients send synthetic VP8 and do not produce keyframes on request.

### 17.7 Zero allocations per packet

`crates/nexus-dataplane/tests/alloc.rs` is its own test binary with a counting
`#[global_allocator]`.

1. Build a shard on `MemIo`: 11 sessions (1 publisher, 10 subscribers), SRTP installed
   (AES-GCM, and a second run with AES-CM), 10 subscriptions to the video track and 10 to
   audio.
2. Warm up with 100 packets per SSRC.
3. Push 10,000 RTP packets and 100 SRs and PLIs through `iterate`, capturing the output.
4. Assert that the allocation count did not change and that the output is 10 × the
   input.

The ported `real_path` bench prints allocations per packet as well.

### 17.8 Fixed memory budget in CI

`benches/memory.rs`, ported, keeps its scenario names:

- **Data plane:** a shard on `MemIo` with sessions, tracks and subscriptions created through
  commands (synthetic keys, no handshake), measured with the counting allocator.
- **Control plane:** the orchestrator managers driven through their message handlers with a
  fake signaling channel, and the transport entry after `Ssl` is freed.
- Reports "A+V publisher, no subscriptions" and "+ subscribed to 10 tracks", and the sum
  is checked against `NEXUS_MEM_BUDGET_KB=25` in CI.
- Also reports the `Ssl` object's size during the handshake and 0 after it is freed.

### 17.9 Manual Chrome and Firefox call, AES-GCM offered first

`examples/web/` is a static page using the SDK's ESM build. It takes the signaling URL and
room from the query string, joins, publishes camera and microphone, subscribes to everyone
and shows the videos. Any static server can serve it; the SFU does not.

Procedure, recorded in the Phase 1 plan with browser versions:

1. Chrome and Firefox on two machines on different networks (or one on a phone hotspot),
   SFU with `NEXUS_ANNOUNCED_IPS` set.
2. Both see and hear each other. `chrome://webrtc-internals` and `about:webrtc` show the
   ICE-lite remote, and which SRTP cipher was negotiated (expected
   `AEAD_AES_128_GCM`).
3. A third tab joins late and shows video within about 1 s (PLI on subscribe).
4. Lip sync looks right (translated SRs + shared msid).
5. Unpublish/republish and leave/rejoin work.
6. Switching one laptop between Wi-Fi and wired: the call recovers. Browsers usually do an
   ICE restart here, which v1 does not support; if that is what happens, it is recorded as
   a known limitation, not a failure. The e2e test covers pure NAT rebinding.

---

## 18. Constraints handed to later designs

- **`loss-recovery.md` (Phase 3):**
  - **AES-GCM retransmission.** A retransmitted packet reuses its (SSRC, index). Under GCM,
    protecting it again with any header difference (a new transport-cc value, a different
    extension set) is nonce reuse with different AAD and exposes the GHASH key.
    Retransmissions must be byte-identical (keep the protected packet, or re-protect
    exactly the same bytes), or use RTX. `SrtpOutbound`'s sent-index window (§9.3) refuses
    the resend unless the retransmit path bypasses it explicitly for byte-identical copies.
  - The subscriber seq → publisher seq ring (§11.1), RR to publishers (1 s, fits the
    sweep), upstream NACK with the publisher session's `rtcp_ssrc`.
  - TWCC feedback toward publishers (§12.4, R8): arrival ring per publisher session,
    ≈ 100 ms feedback timer, allocation-free builder, e2e check of feedback coverage, browser
    check of the publish bitrate.
- **Simulcast (after v1):** §11.5, plus deliberate drops with seq bookkeeping (§11.1).
- **Bandwidth estimation (after v1):** extension ID 4 reserved; the transport-cc counter
  belongs to the subscriber `Session` (one per session, not per subscription).
- **DST (after v1):** `MemIo` plus `now: Instant` arguments are the seams; the shard has no
  other source of time or I/O.

---

## 19. Risks

| Risk | Mitigation |
|------|------------|
| A browser behaves differently with an ICE-lite SFU | Low (ICE-lite SFUs are common); checked with Chrome and Firefox at the switch (Part 1.5), not only at the end |
| webrtc-rs handles an SSRC change on a reused m-line (resubscribe) differently from browsers | §17.4 runs on webrtc-rs; the manual check does unpublish/republish in browsers |
| `StunMessage::parse` is costly (2 KB struct by value) | Only STUN pays it (≈ 1 request per session every few seconds); a slimmer scan if the bench shows it |
| The event channel fills during a mass join (DTLS datagrams) | DTLS datagrams are dropped and retransmitted by the peer; state events are retained (§5.3); counters show it |
| 20+ m-lines per session exhaust dynamic PTs in larger rooms | **Accepted for v1 (R9):** limit enforced with an error at ≈ 30 m-lines (≈ 15 A+V publishers per participant); lifting it (reusing a PT across bundled m-lines of the same codec) is later SDP work |
| Phase 1 takes long and `main` still runs the old path | Accepted by design §7: nothing is deployed, and the branch merges only when the exit criteria pass |
