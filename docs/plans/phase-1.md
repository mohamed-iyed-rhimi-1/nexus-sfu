# Phase 1 — New data plane, one shard

**State: not started** (plan written 2026-09-26).

**Design:** [`docs/design/dataplane-v1.md`](../design/dataplane-v1.md) (approved; §16 gives the
parts and order, §17 the tests), within [`docs/dataplane-design.md`](../dataplane-design.md)
§5, Phase 1.
**Current state:** [`architecture.md`](../../architecture.md).
**Branch:** `phase-1` (from `4fabfc6`). Merged into `main` only when every exit criterion
passes (design §7). `main` was fast-forwarded to `v0.1.0` at `4fabfc6` and is the trunk from
now on; `v0.1.0` is no longer used. Every commit on the branch builds, passes `cargo clippy --workspace
--all-targets -- -D warnings`, `cargo fmt --all --check` and `cargo test --workspace`, so the
branch can be bisected.

Phase 1 replaces the old data plane (ingress loop, worker pool, SSRC router) with
`nexus-dataplane` running **one shard**, moves the orchestrator to the command/event
interface, and deletes the old path. Multiple shards are Phase 2; NACK, RR and TWCC toward
publishers are Phase 3.

Section references like "note §9.3" point into the design note.

## Exit criteria

1. **E2E on the new path**, in CI on Linux (x86_64, arm64) and macOS:
   - the Phase 0 tests (`two_party_audio_video`, `candidate_is_announced_address`,
     `dtls_survives_lost_first_flight`), adapted for SSRC rewriting (note §17.1);
   - `ten_clients_audio_video` (note §17.2);
   - `address_change_mid_call` (note §17.3);
   - `resubscribe_no_srtp_index_reuse`: no repeated (SSRC, packet index) on the wire
     (note §17.4);
   - `sender_report_translation` (note §17.5);
   - `keyframe_requests`: PLI on subscribe, forwarding, throttling (note §17.6).
2. **0 heap allocations per packet** on the steady-state path, AES-GCM and AES-CM
   (`crates/nexus-dataplane/tests/alloc.rs`, note §17.7).
3. **Fixed memory per participant ≤ 25 KB** (design §3.11), enforced in CI by the ported
   `benches/memory.rs` (note §17.8).
4. **Manual Chrome and Firefox call** with AES-GCM offered first, recorded in this plan with
   browser versions and the negotiated cipher (note §17.9).
5. **Old path deleted:** `src/worker/`, `src/forward/`, the packet loop and `Sfu`,
   `nexus-actor`, `nexus-dst`, the replaced `nexus-transport` and `nexus-webrtc` modules
   (note §16 C1-C7). `real_path` and `memory` benches ported with the same scenarios.
6. `architecture.md` Parts 1-2 and CLAUDE.md describe the new path.

## Parts

Each part is sized for one working session and ends at a green checkpoint. Order (note §16):

- **Add**, with the old path still live: 1.1 → 1.2a → 1.2b → 1.3 → 1.4 → 1.5a. 1.1 and 1.4
  are independent of the rest and can move earlier or later.
- **Switch** (one commit): 1.5b.
- **After the switch**, in any interleaving: deletion steps C1-C7 and parts 1.6a, 1.6b, 1.7,
  except that C2 comes after 1.7, and C3 after C1 and C2 (it deletes what they used).
  The browser page (1.8) can be written any time; having it by 1.5b makes the early browser
  check easier. 1.9 is last.

---

### 1.1 SRTP per direction

**Goal:** the per-session SRTP contexts of note §9, in `nexus-transport`, with the backends
decided in Phase 0 (GCM on `ring`, AES-CM on RustCrypto).

**Files:** `crates/nexus-transport/src/srtp/{direction.rs (new), crypto.rs, context.rs,
replay.rs, mod.rs, rfc_vectors.rs}`, `crates/nexus-transport/Cargo.toml`, root `Cargo.toml`
(dev profile), `benches/srtp_backends.rs`.

**Change:**
- `SrtpCipher::AesGcm` reimplemented on `ring` (`LessSafeKey`, `seal_in_place_separate_tag`
  / `open_in_place`), from `RingGcmBackend` in `benches/srtp_backends.rs:344-389`. Add SRTCP:
  nonce as in `crypto.rs:178` (RFC 7714 §9.1), AAD = 8-byte header ‖ E+index, tag, then
  E+index after the tag (the Phase 0 fix). AES-256-GCM is not offered; drop it or keep it on
  RustCrypto, whichever is less code.
- Move the RFC 3711 index/ROC estimate and the replay check out of `SrtpContext` into free
  functions (`context.rs`), called by both `SrtpContext` and the new types.
- `direction.rs`: `SrtpInbound` (16 SSRC slots: ROC, highest seq, RTP and RTCP replay
  windows, `last_seen_s`) and `SrtpOutbound` (32 slots: ROC, highest seq, **sent-index
  window**, SRTCP index), fixed arrays with linear scan, API of note §9.1. Inbound eviction
  of the entry idle longest (> 30 s) when full; otherwise drop. `SrtpOutbound::retire(ssrc)`.
  All failures return `None`; no `assert!` on packet contents.
- Fix the two panics: `context.rs:307` (assert before the graceful length check) and the
  128-byte AAD copy (`crypto.rs:270`, `:354`), which disappears with `ring`.
- `[profile.dev.package.ring] opt-level = 3` next to the existing `aes`/`ctr` entries, or
  debug builds (e2e) run unoptimised GCM.

**Code notes (checked 2026-09-26):**
- `ring = "0.17"` is already a `nexus-transport` dependency, never imported.
- `SrtpContext` stays: besides the old worker and benches, `rfc_vectors.rs` and
  `crates/nexus-transport/tests/{srtp_interop,srtp_100sub,srtp_forwarding}.rs` use it. It is
  the reference implementation the new types are checked against. (Note §16 C5 said "if only
  benches use it"; they don't, so it stays through Phase 1.)
- The old path keeps working: it builds its contexts through `SrtpContext`, which now uses
  the ring GCM cipher. The e2e tests negotiate AES-CM until 1.5b, so the GCM change is
  covered by the vectors and the bench check, not by e2e, until then.

**Tests:**
- RFC 3711 B.2 and RFC 7714 §16 vectors pass through `SrtpInbound`/`SrtpOutbound` (RTP and
  RTCP, both profiles).
- Round trip against `SrtpContext` byte for byte, including a ROC rollover (start seq
  65,500) and reordering across the rollover.
- `SrtpOutbound` refuses an index it already sent and one older than the window; accepts a
  reordered, not-yet-sent index.
- Inbound: replayed packet refused, 17th SSRC with all slots fresh refused, evicts after
  30 s idle.
- Short and malformed packets (0-12 bytes, header length beyond the packet, CSRC count
  beyond the packet, 200-byte extension header) return `None`, never panic.
- `benches/srtp_backends.rs` byte-for-byte `verify()` still passes.

**Checkpoint:** tests above green; `cargo bench --bench srtp_backends` numbers within noise
of architecture.md Part 5 (ring GCM ≈ 0.28 µs / 1,200 B on macOS).

---

### 1.2a Shard core: tables, commands, ICE-lite, forwarding

**Goal:** `nexus-dataplane` with a shard that can be driven entirely through `MemIo` and
explicit `now`: sessions are created by commands, answer STUN, install SRTP, and forward RTP
from a publisher to subscribers with seq/ts/SSRC/PT rewritten. No header extensions yet.

**Files:** new `crates/nexus-dataplane/` (`Cargo.toml` Apache-2.0, `#![deny(warnings)]`,
workspace member), `src/{lib.rs, ids.rs, command.rs, config.rs, session.rs, ice.rs,
track.rs, subscription.rs, rewrite.rs, pool.rs, shard/mod.rs, shard/io.rs (MemIo only)}`,
`tests/shard.rs`.

**Change:**
- `ids.rs`, `command.rs`: types of note §4 and §5.1/§5.2 as written (boxed large payloads).
- `pool.rs`: one allocation of `pool_buffers × 2,048`, `Vec<u32>` free stack, `BufRef {
  shard, index }`. No refcount yet (Phase 2).
- Slabs for sessions, tracks, subscriptions (`Vec<Option<T>>` + free list, debug
  generation check); `*Id → *Idx` maps used only by command handling; address map and
  ufrag map (`rustc-hash`), note §7.1.
- Command handling: `CreateSession`, `InstallSrtp` (reject a second one), `AddTrack`,
  `RemoveTrack`, `Subscribe` (out-SSRC monotonic check of note §9.3: reject reused or
  out-of-order), `Unsubscribe` (retire the SSRC), `CloseSession` (eager removal of tracks,
  subscriptions to them, its own subscriptions, map entries), `SendDatagram`. Unknown ids →
  `CommandRejected`.
- `ice.rs`: binding-request handler of note §8.2 (parse, USERNAME → ufrag map,
  `verify_message_integrity`, `verify_fingerprint`, success response with XOR-MAPPED-ADDRESS
  signed and fingerprinted into a pool buffer), nomination (§8.3) and rebinding (§8.4) with
  `rebind_silence`, `AddressSelected` events.
- Ingress (note §10.1): classify (STUN 0-3, DTLS 20-63, RTP/RTCP 128-191 with RTCP when
  `byte1 & 0x7F` in 64..=95); DTLS → `DtlsDatagram` until `srtp_verified`, then drop;
  RTP → unprotect → `PeerSrtpVerified` once → SSRC → track → fan-out.
- Egress (note §10.2) with a first `rewrite()` that writes the 12-byte header (mapped PT,
  seq/ts offsets, out SSRC), copies CSRCs, **drops the extension block**, copies the payload.
  First packet sets random offsets (note §11.1).
- `Shard::iterate(now)` with the loop body of note §3.2 minus parking and cross-shard;
  `tx` batch of 256, flushed when full and at the end; bounded command drain (64).

**Code notes (checked 2026-09-26):**
- STUN pieces: `StunMessage::parse` (`ice/stun/message.rs:310`, ≈ 2 KB struct returned by
  value), `verify_message_integrity` (`integrity.rs:100`), `verify_fingerprint`
  (`integrity.rs:185`), `StunAttribute::XorMappedAddress(..).encode` (`attributes.rs:464`),
  `sign_message` (`integrity.rs:365`). `StunServer::handle_request` allocates; not used.
  `derive_short_term_key` allocates; the key is the password bytes.
- `RtpHeader::parse` (`nexus-media/src/rtp/header.rs:76`) is allocation-free.
- `demux.rs`'s RTCP range is 72..=79 and its validators allocate: do not reuse.
- `mio`, `crossbeam-queue`, `rustc-hash`, `libc` are in `Cargo.lock`; add them with the
  locked versions (`mio` 1.1.1 needs features `os-poll`, `net`, `os-ext` in 1.3).

**Tests** (`tests/shard.rs`, scripted peers on `MemIo`; each peer uses `SrtpContext` as its
own SRTP and builds STUN with `create_binding_request`):
- STUN: valid request answered with correct XOR-MAPPED-ADDRESS; wrong password, wrong
  ufrag, bad fingerprint, truncated message: no answer, no state change.
- Nomination selects the address; a request without USE-CANDIDATE before nomination selects
  nothing; rebinding switches only after 2 s of silence (drive `now`), and a USE-CANDIDATE
  switches immediately.
- Publisher → 3 subscribers: each gets its own out SSRC, mapped PT, contiguous seq from a
  random start, timestamps offset consistently, payload intact after the peer decrypts.
- Reordering in (seq 5, 7, 6) is reordering out; a subscriber without SRTP or address is
  skipped; SRTP from an unknown address is dropped and does not move the session.
- `Subscribe` with a reused or smaller out SSRC is rejected; after `Unsubscribe` +
  `Subscribe`, no (SSRC, seq) repeats on the captured output.
- `CloseSession` removes everything: later packets from its address are dropped, its
  subscribers get nothing, slab entries freed.
- DTLS datagrams produce events until the first authenticated SRTP, then none.

**Checkpoint:** `cargo test -p nexus-dataplane` green; the rest of the workspace untouched
and green.

---

### 1.2b Shard core: extensions, SSRC learning, RTCP, housekeeping

**Goal:** complete the Phase 1 shard logic: header extension mapping, `mid` SSRC learning,
SR translation, keyframe requests, liveness, stats, and the zero-allocation test.

**Files:** `crates/nexus-dataplane/src/{rewrite.rs, subscription.rs, track.rs, rtcp.rs,
session.rs, shard/mod.rs, shard/stats.rs, ext.rs (new: the fixed extension table)}`,
`tests/{shard.rs, alloc.rs (new)}`.

**Change:**
- `ext.rs`: the fixed table of note §11.2 as constants (ID, URI, kinds, offered-in-v1),
  shared later by the negotiator (1.4). ID 4 (transport-cc) and 5 (abs-send-time) are **not
  offered** in Phase 1; 10/11 reserved.
- `rewrite()` complete (note §11.4): parse one-byte and two-byte extension elements (write an
  element iterator; `get_extension_value` is per id), write mapped elements in one-byte form,
  drop the publisher's `mid`, append the subscriber's `mid`, pad, clear X if empty. Bounded
  to 16 elements.
- SSRC learning (note §7.2): unknown SSRC + unbound tracks → read the publisher's `mid`
  element → bind.
- `rtcp.rs` (note §12): compound iteration via `demux_compound`; SR from a publisher →
  stored per layer → translated SR + SDES CNAME to each started subscription, protected with
  the subscriber's `srtp_out` under the out SSRC; PLI and FIR (parsed in place) from a
  subscriber → `request_keyframe(track, layer)` with the 500 ms throttle, PLI protected with
  the **publisher's** `srtp_out` under its session's `rtcp_ssrc`. Keyframe also requested on
  `Subscribe` for a session with SRTP, and on `InstallSrtp` for each existing subscription.
  Everything else counted and ignored.
- `housekeeping(now)` every 1 s (note §3.4): `ConsentLost` after `consent_timeout`
  without authenticated traffic, inbound SSRC eviction, stale address-map entries from
  rebinding removed, counters copied to `ShardStats` atomics. Event retention queue of 256
  (note §5.3).

**Code notes (checked 2026-09-26):**
- `demux_compound` (`nexus-media/src/rtcp/compound.rs:33`), `SenderReport::parse`
  (`rtcp/packet.rs:62`) and `PliPacket` are allocation-free; `FirPacket`, `ReceiverReport`,
  `NackPacket`, `RembPacket` parse into `Vec`s and every `build()` returns a `Vec`: write the
  SR/SDES/PLI builders and the FIR scan in `rtcp.rs`.
- RTP padding: keep the P bit and copy the padding with the payload.

**Tests:**
- Rewrite: table-driven over input headers (no extensions, one-byte, two-byte, with CSRCs,
  with padding, declined extensions, subscriber without `mid`) → exact output bytes; the
  payload is copied once and unchanged.
- SSRC learning: publisher with `ssrc: None` is bound by the `mid` element; a wrong mid is
  dropped.
- SR translation: parse the SR a subscriber decrypts: sender SSRC = out SSRC, NTP = the
  publisher's, RTP = publisher RTP + `ts_offset`, counts = packets/octets sent so far,
  followed by SDES with the publisher's cname; SRTCP indices of that SSRC increase.
- Keyframes: PLI from a subscriber reaches the publisher with the right media SSRC; 5 PLIs
  in 100 ms → 1; FIR → PLI; `Subscribe` on an SRTP session → PLI; `InstallSrtp` on a session
  with 2 subscriptions → 1 PLI per track (throttled).
- Liveness: no authenticated packet for 30 s of `now` → exactly one `ConsentLost`.
- `tests/alloc.rs` (note §17.7): own test binary with a counting `#[global_allocator]`;
  11 sessions, 10 subscribers on audio and video, warm-up, then 10,000 RTP + 100 SR + 100 PLI
  through `iterate`: allocation count unchanged, output = 10 × input. Runs for AES-GCM and
  AES-CM.

**Checkpoint:** `cargo test -p nexus-dataplane` green including `alloc.rs` (**exit criterion
2**).

---

### 1.3 Shard thread and I/O

**Goal:** real sockets and threads: `Dataplane::start` binds one socket per shard, spawns the
shard threads, and the control plane talks to them through `DataplaneHandle`.

**Files:** `crates/nexus-dataplane/src/{lib.rs, handle.rs, placement.rs, config.rs,
shard/io.rs, shard/park.rs, shard/mod.rs}`, `tests/loopback.rs` (new).

**Change:**
- `LinuxIo`: `recvmmsg` / `sendmmsg` with `mmsghdr`/`iovec`/`sockaddr_storage` arrays
  allocated once, receiving into pool buffers, `MSG_TRUNC` dropped, short sends drop the rest
  (counted). `PortableIo`: `recv_from` loop (≤ 64, until `WouldBlock`), `send_to` each.
  Selected by `cfg(target_os)`.
- `park.rs`: `mio::Poll` with the socket (`SourceFd`) and a `mio::Waker`; the parked-flag
  protocol of note §3.3; park only after a receive returned `WouldBlock`; timeout = next
  housekeeping. `busy_poll_rounds` from config.
- `DataplaneHandle`: `send(shard, Command) -> Result<(), CommandQueueFull>` (ArrayQueue
  4,096 + wake if parked), `events() -> tokio mpsc::Receiver<Event>` (8,192, shards use
  `try_send`), `stats(shard)`, `shutdown()` (stop flag, wake, join).
- `Dataplane::start(config) -> (DataplaneHandle, Vec<ShardInfo>)`: bind `media_bind_addr`
  port + i (port 0: ephemeral per shard), apply `socket_config` buffer sizes, spawn
  `nexus-shard-{i}`, pin and SCHED_FIFO when configured (Linux; `warn!` once on macOS).
  Validation: `shards == 1` in Phase 1; port range fits and avoids the other ports.
- `placement.rs`: `Placement` trait and `ShardLoad` (note §13.2), `SingleShard`.

**Code notes (checked 2026-09-26):**
- Syscall code to start from: `benches/udp_floor.rs` (`sendmmsg` ≈ line 159, `recvmmsg`
  ≈ 242 and 273), already allocation-free. Not `nexus-transport/src/udp.rs` (allocates).
- Pinning and SCHED_FIFO helpers are in `src/worker/pool.rs` (`set_realtime_scheduling`
  line 32, the affinity code uses `core_affinity`); copy them into `nexus-dataplane` (the
  originals go in C3).
- `socket_config.rs` (`configure_high_performance_socket`, buffer checks) has no users
  today; it becomes the dataplane's.

**Tests** (`tests/loopback.rs`, Linux and macOS):
- Two in-process peers on real UDP sockets against a running shard: STUN, nomination,
  `InstallSrtp` with synthetic keys, publisher → subscriber media through the kernel.
- Commands sent to a parked shard are handled within 10 ms (wake works).
- With `busy_poll_rounds = 0` an idle shard's CPU time over 1 s stays under 5% (parking
  works). **Local only** (`#[ignore]`, run with `--ignored`): CPU time on shared CI runners
  is too noisy to gate on.
- `shutdown()` joins within 100 ms.
- A burst larger than the send batch and a flood beyond socket buffers: drops counted, no
  blocking, no panic.

**Checkpoint:** `cargo test -p nexus-dataplane` green on macOS and in the Linux container
(CLAUDE.md "check Linux in Docker").

---

### 1.4 SDP groundwork and shared DTLS certificate

**Goal:** the SDP and DTLS changes the switch needs, made so the old path keeps working.

**Files:** `crates/nexus-webrtc/src/sdp/{mod.rs, session.rs, parser.rs, printer.rs,
negotiator.rs, media.rs}`, `crates/nexus-webrtc/src/webrtc/session.rs` (compile fixes only),
`src/orchestrator/negotiation.rs` (compile fixes only),
`crates/nexus-transport/src/dtls/openssl_backend.rs`.

**Change:**
- `SessionDescription::media: Vec<MediaDescription>`, bounded by `MAX_MEDIA_SECTIONS = 32`
  (parse error beyond it); remove the compile-time assertion that claims 8 "per WebRTC
  spec"; `media_count` becomes `media.len()` or stays as a mirror, whichever touches less.
- `RecycledMline::rtcp_fbs`; `OfferMline::Track { stream_id, cname }` printed as
  `a=msid:<stream_id> <track>` and `a=ssrc:<ssrc> cname:<cname>`.
- Extension table: the negotiator takes its extmaps from `nexus-dataplane`'s `ext.rs` (or a
  copy of the constant in `nexus-webrtc` if the dependency direction is awkward; one of them
  asserts they match in a test).
- `DtlsCertificate` (EC P-256 key + self-signed X.509 + fingerprint), created once;
  `OpenSslDtlsEngine::with_certificate(role, &DtlsCertificate)` builds only the `Ssl` from a
  shared `SslContext`. `new(role)` stays for the old path until C6.

**Code notes (checked 2026-09-26):**
- `.media[` / `media_count` uses: `parser.rs` 29, `session.rs` 17, `negotiator.rs` 13,
  `webrtc/session.rs` 8, `negotiation.rs` 9, `printer.rs` 4. `negotiation.rs` loops cap at
  `.min(8)` / `.min(16)` (lines 596, 616, 637, 853): replace with the vector's length.
- `OpenSslDtlsEngine::new` generates the key and certificate at
  `openssl_backend.rs:177-≈250`; `use_srtp` order at ≈ line 280 (changed in 1.5b, not here,
  because the old path's e2e runs are what keep this part honest).
- The old path offers subscriber m-lines with the publisher's SSRC and no extmaps; this part
  adds the fields but the old orchestrator keeps passing today's values.

**Tests:**
- Parser/printer round trip with 20 and 32 m-lines; 33 is an error.
- An offer with `stream_id`/`cname` prints the expected `a=msid` and `a=ssrc ... cname`
  lines; a recycled m-line prints its `rtcp_fbs`.
- Two engines from one `DtlsCertificate` handshake with each other and report the same local
  fingerprint.

**Checkpoint:** the whole workspace green, **e2e still green on the old path**.

---

### 1.5a Control-plane pieces

**Goal:** the new orchestrator building blocks as standalone, unit-tested modules, before the
switch: nothing calls them yet.

**Files:** `src/orchestrator/{transports.rs (new), tracks.rs (new), sdp_params.rs (new)}`.

**Change:**
- `transports.rs` (note §6.5): `Transports` = `HashMap<SessionId, TransportEntry>` with
  `shard`, `IceParams` (16-char ufrag, 32-char password, random), `DtlsHandshake`, state,
  `SsrcAllocator`, timestamps. `DtlsHandshake` wraps `OpenSslDtlsEngine::with_certificate`,
  role, pinned fingerprint; `process(datagram) -> Vec<Vec<u8>>`, `start()` (client role),
  `handle_timeout()`, completion check (fingerprint match; logic of `check_dtls_completion`
  and `initialize_srtp`, `session.rs:1479`, `:1645`) returning `(profile, local, remote)`
  key material by role; `free_ssl()`.
- `SsrcAllocator`: random `base`, strictly increasing offset, skips 0 and the peer's SSRCs
  (bounded loop).
- `tracks.rs`: `TrackRegistry` (TrackId → publisher session, shard, kind, codec, mid, ssrc,
  ext ids, cname, content type).
- `sdp_params.rs`: from a parsed answer, build `TrackSpec` for a publish m-line (primary
  SSRC = first `a=ssrc` not a secondary in an `a=ssrc-group`, PT, `ExtIds` by URI, cname) and
  `SubSpec` for a subscribe m-line (`PtMap` by codec name + clock rate, `ExtMap` publisher id
  → URI → subscriber id, `mid`).

**Tests:**
- Handshake between a `DtlsHandshake` and a plain OpenSSL peer in both roles; keys picked
  by role match the peer's; fingerprint mismatch fails; `free_ssl` leaves the entry usable.
- `SsrcAllocator`: 10,000 allocations strictly increasing in offset, never 0 or a peer SSRC.
- `sdp_params`: Chrome-shaped and Firefox-shaped answers (fixtures in the test) give the
  expected specs; a declined extension maps to 0; an FID group's secondary SSRC is not the
  track's SSRC; a remapped subscriber PT is found.

**Checkpoint:** workspace green, old path unchanged.

---

### 1.5b Switch: orchestrator on commands

**Goal:** the SFU runs on `nexus-dataplane`. One commit. The old path is no longer started
but still compiles.

**Files:** `src/server.rs`, `src/orchestrator/{mod.rs, negotiation.rs, subscription.rs,
connection.rs, events.rs, candidates.rs}`, `src/config/*`, `crates/nexus-core/src/config.rs`,
`config/*.toml`, `openssl_backend.rs` (`use_srtp` order), `tests/e2e.rs`,
`tests/e2e/harness.rs`, `crates/nexus-loadtest/src/{client.rs, media.rs, track_stats.rs}`.

**Change** (the file-by-file tables of note §6.5, in full):
- `server.rs`: `Dataplane::start`; per-shard candidates via `candidates::resolve`;
  `DistributedState`, gossip thread, `MetricsCollector` and the shutdown notification move
  out of `Sfu::new` / `Sfu::shutdown` into `server.rs`; `ServerHandle.media_addrs`
  (per shard); the ingress thread and `PacketSender` go.
- `mod.rs`: constructor takes `DataplaneHandle`, `Vec<ShardInfo>`, placement; `select!` on
  dataplane events; ICE/consent/cleanup intervals removed; 1 s sweep added (ICE-connect
  timeout, note §6.4); `Unpublish` → `RemoveTrack`.
- `negotiation.rs`: `create_transport` → `SessionId`, placement, `CreateSession`; offers
  with `a=ice-lite`, fixed extmaps, publish rtcp-fb `nack pli` + `ccm fir`, subscription
  m-lines with the allocated out SSRC, `stream_id`/`cname` of the publisher; `handle_answer`
  → `AddTrack` per publish m-line and `Subscribe` per answered subscribe m-line (from
  `sdp_params`); remote candidates ignored; `cleanup_participant` → `CloseSession`.
- `subscription.rs`: `Unsubscribe` commands; `handle_session_established` deleted (active
  on answer); viewport / content type without data-plane effect.
- `connection.rs`: `handle_event` for `DtlsDatagram`, `AddressSelected` (start handshake as
  client), `PeerSrtpVerified` (`free_ssl`), `ConsentLost`; `InstallSrtp` on completion;
  200 ms tick keeps DTLS retransmission and the handshake timeout. `DisconnectReason`
  gains `DtlsFailed`.
- Config `[dataplane]` (note §14) with `shards = 1`, `busy_poll_rounds`, `pool_buffers`,
  `consent_timeout_ms`, `rebind_silence_ms`, `cpu_affinity`, `realtime_priority(_level)`;
  `--shards` / `NEXUS_SHARDS`. The old `[worker]`/`[memory]` fields stay readable until C7
  so the old code compiles.
- `use_srtp`: `SRTP_AEAD_AES_128_GCM` first.
- Tests (note §17.1): `two_party_audio_video` compares against the SSRCs each client's offer
  announced for the peer's tracks; payload marker (publisher SSRC + frame counter) written
  by `media.rs` and checked by the subscriber; `candidate_is_announced_address` uses
  `media_addrs[0]`.

**Code notes (checked 2026-09-26):**
- Old-path references to replace (from the dependency survey): `negotiation.rs` 12, 15,
  146-180, 249, 544-557, 877-913, 1146, 1226-1230; `subscription.rs` 12, 55, 63, 219, 296,
  361, 429, 466, 481; `mod.rs` 22, 25, 53-65, 265; `server.rs` 126-178.
- Payload marker: the VP8 payloader prepends a payload descriptor (1 byte for these frames)
  and splits frames, so the marker is only in the first packet of a frame, after the
  descriptor; Opus samples are the payload as is. The subscriber checks what it can see.
- `ColdPathPacket` and the ingress channel go with `events.rs` changes; `Sfu` still builds
  (it is not started) until C1.

**Tests:** the three Phase 0 e2e tests, adapted, pass on macOS and in the Linux container;
`cargo test --workspace` green.

**Checkpoint:** as above, plus an **early browser check**: Chrome and Firefox connect through
the new path (note §17.9 steps 1-2: media both ways, ICE-lite remote, cipher reported), using
the page from 1.8 if it exists, else a scratch page. Result recorded in the session log. A
failure here stops the phase until understood (note §19, first risk).

---

### Deletion steps C1-C7

One commit per step, green after each (build, clippy `--all-targets`, `cargo test
--workspace`, benches build). C1-C3 fit one session, C4-C5 one, C6-C7 one.

| Step | Removed | Also |
|------|---------|------|
| C1 | `Sfu` and the packet loop (`src/sfu.rs`), `SRTCP_SENT_CACHE`, `tests/pps_pipeline.rs`, root `sim` feature, `src/spin.rs`, `src/clock.rs` | `DrainState`/`DropTracker` only if unused after the move to `server.rs`; `lib.rs:169` re-exports |
| C2 | The old `real_path` and `memory` bench code, replaced by the ports from 1.7 (**do 1.7 first**, so CI's bench smoke and memory budget never lose coverage); `benches/forwarding.rs` deleted (it measures `SsrcRouter`) | `Cargo.toml` `[[bench]]` entries |
| C3 | `src/worker/`, `src/forward/`, `src/transport/`, `lib.rs` re-exports (50, 59, 168, 188-190), `WorkerError` in `error.rs`, `src/proto.rs` and the root `build.rs` protobuf **and** capnp steps (the root crate includes neither; `nexus-signal` compiles its own schemas, check it still builds), `prost`/`prost-build`/`capnpc` root dependencies, `crossbeam`, `dashmap`, `memmap2`, `core_affinity` root dependencies if unused | CLAUDE.md prerequisites: drop `protoc` if nothing needs it |
| C4 | `crates/nexus-actor`, `crates/nexus-dst`, workspace entries, `config/mod.rs:157-181` limits (use the orchestrator's own constants), `config/tests.rs:333-338`, `lib.rs:70-75` | `nexus-core/types.rs` and `production.toml` comments that mention actors |
| C5 | `nexus-transport`: `arena.rs`, `ring_buffer.rs`, `batch.rs`, `udp.rs`, `media_transport.rs`, `io_uring.rs`, their proptests, the `io_uring` and `sim` features (root and crate), `build.rs` `check_io_uring_feature`; ICE `agent.rs`, `checklist.rs`, `StunServer` if unused; pure-Rust DTLS (`dtls/session.rs`, `handshake.rs`, `record.rs`, the parts of `crypto.rs` nothing live imports) | Keep `gro.rs`, `gso.rs`, `socket_config.rs`, `stun/`, `candidate.rs`, `gather.rs` enumeration, `SrtpContext` (tests use it) |
| C6 | `nexus-webrtc`: `webrtc/transport.rs`, `webrtc/session.rs`, `webrtc/demux.rs`, the `test-hooks` feature, `OpenSslDtlsEngine::new` (per-session certificate) | SDP stays |
| C7 | Config fields of note §14 (`[worker]`, `[memory]`, `actor.*`, `transport.batch_*`, `stun_servers`, `--workers`, `NEXUS_WORKER_COUNT`, `NEXUS_ARENA_SIZE_MB`), `config/*.toml`, README config and feature sections, `deploy/docker/run.sh`, `nexus-metrics` `WorkerPoolMetrics` → shard metrics (note §5.4) | e2e harness config |

**Code notes (checked 2026-09-26):** the full list of old-path users was surveyed while writing the note;
the risky ones are `tests/pps_pipeline.rs` (only compiled with `--features sim`, not in CI:
delete, don't port) and `nexus-dst`, whose `engine.rs`/`invariant.rs` import `nexus-actor`.
After C5, `grep -rn "arena\|io_uring\|MediaTransport" crates src` must be empty outside
comments that are updated in 1.9.

---

### 1.6a E2E: harness, ten clients, resubscribe

**Goal:** the harness changes and two of the new exit tests.

**Files:** `crates/nexus-loadtest/src/{client.rs, lossy.rs, track_stats.rs}`,
`tests/e2e.rs`, `tests/e2e/harness.rs`.

**Change:**
- `HeadlessClient::unsubscribe(track_ids)` and a public `subscribe_batch` path usable after
  `discover_and_subscribe`: lock the shared signaling connection and send, the background
  task keeps answering the renegotiation offers.
- `LossyUdpConn` tap: an optional bounded recorder of inbound datagrams' (class, SSRC,
  seq) for SRTP and (sender SSRC, E+index) for SRTCP, parsed from cleartext fields (SRTCP
  E+index sits before the tag for AES-CM and after it for GCM: the test knows the profile
  from the negotiated cipher, or reads both layouts and keeps the one whose E bit is set).
- Offer bookkeeping on the client: mid → track id (from `Offer.tracks`) and mid → SSRC (from
  `a=ssrc`), so tests map received SSRCs to publishers.
- Tests `ten_clients_audio_video` (note §17.2) and `resubscribe_no_srtp_index_reuse`
  (note §17.4).

**Code notes (checked 2026-09-26):**
- The signaling connection is `Arc<Mutex<SignalingConnection>>` (`client.rs:82`); the
  background task holds the lock only for 200 ms receive timeouts (`client.rs:1120`), so
  `unsubscribe` can lock and send without a new channel (simpler than the note's "command
  channel").
- Every datagram passes `LossRules::should_drop` (`lossy.rs:144`): the tap goes next to it.
- Subscribe requests accept at most 10 track ids (`MAX_TRACKS_PER_PARTICIPANT`,
  `subscription.rs`); `ten_clients` sends 18 ids in two requests.

**Tests:** the two tests pass on macOS and Linux; `resubscribe_no_srtp_index_reuse` is
checked to fail when the shard's out-SSRC check and the orchestrator allocator are
temporarily bypassed (reuse the first SSRC), then restored. Suite runtime noted.

**Checkpoint:** e2e green; total e2e runtime under 60 s on macOS.

---

### 1.6b E2E: address change, SR translation, keyframes

**Goal:** the remaining three exit tests.

**Files:** `crates/nexus-loadtest/src/{client.rs, lossy.rs}`, `tests/e2e.rs`,
`crates/nexus-dataplane` (test hook for events, if needed).

**Change:**
- `LossyUdpConn::rebind()`: inner socket behind `ArcSwap<UdpSocket>` (or a lock taken only
  on rebind), new ephemeral port, the receive loop moves to the new socket.
- Client RTCP readers: `on_track` spawns a `receiver.read_rtcp()` task recording SRs per
  SSRC (and SDES CNAME); the publisher spawns `sender.read_rtcp()` per sender recording PLI
  and FIR per media SSRC with arrival times; a `send_pli(ssrc)` helper using
  `write_rtcp`.
- A test-only way to observe `AddressSelected{Rebound}`: a counter in `ShardStats`
  (`rebinds`) read through `ServerHandle`, rather than tapping the event channel.
- Tests `address_change_mid_call`, `sender_report_translation`, `keyframe_requests` (note
  §17.3, §17.5, §17.6).

**Code notes (checked 2026-09-26):**
- `on_track` ignores `_receiver` (`client.rs:413`); `register_default_interceptors`
  (`client.rs:193`) includes the sender-report interceptor, so publishers send SRs and the
  receiver's `read_rtcp` sees what the SFU sends.
- `LossyUdpConn { socket: UdpSocket, .. }` (`lossy.rs:189`), bound once in `new`.
- webrtc-ice sends a keepalive binding request every 2 s (`DEFAULT_KEEPALIVE_INTERVAL`),
  which is what lets the SFU see the new address after a rebind (note §8.4).

**Tests:** the three tests pass on macOS and Linux; `address_change_mid_call` is checked to
fail with the rebinding rule disabled.

**Checkpoint:** all e2e exit tests green (**exit criterion 1**, except CI on macOS: 1.7).

---

### 1.7 Benches, memory budget, CI

**Goal:** the ported benches, the memory budget in CI, macOS in CI.

**Files:** `benches/real_path.rs`, `benches/memory.rs`, `Cargo.toml`, `.github/workflows/ci.yml`.

**Change:**
- `real_path`: same scenario names; ingress (socket buffer → decrypted and routed) and
  egress per subscriber (copy + rewrite + encrypt + `sendmmsg`) with 1, 10, 100 subscribers,
  AES-CM and AES-GCM, through `nexus-dataplane` on real loopback sockets; prints allocations
  per packet (counting allocator).
- `memory` (note §17.8): data plane through commands on `MemIo`; control plane through the
  orchestrator managers with a fake signaling channel and the transport entry after
  `free_ssl`; scenarios "A+V publisher, no subscriptions" and "+ subscribed to 10 tracks";
  also the `Ssl` size during a handshake. `NEXUS_MEM_BUDGET_KB` checks the per-participant
  total.
- CI: `NEXUS_MEM_BUDGET_KB: "25"` (was `"1700"`, `ci.yml:92`); bench smoke uses the ported
  benches; a `macos-14` job running `cargo test --test e2e` and `cargo test -p
  nexus-dataplane` (install `capnp` via Homebrew, `protoc` only if C3 did not remove the
  need).

**Tests:** the benches run locally on macOS and in the Linux container; numbers recorded in
architecture.md Part 5 in 1.9 (Phase 1 baseline, one shard).

**Checkpoint:** CI green on all jobs (**exit criteria 1 and 3**).

---

### 1.8 Browser page and manual check

**Goal:** `examples/web/` and the manual call of note §17.9.

**Files:** `examples/web/{index.html, main.js, README.md}`.

**Change:** a static page importing the SDK's ESM build (`sdk/dist/index.js`, package
`"type": "module"`): signaling URL and room from the query string, join, publish camera and
microphone, subscribe to everyone, show a video element per remote participant, leave
button. No build step; served by any static server (`python3 -m http.server`). README: how to
run the SFU with `NEXUS_ANNOUNCED_IPS` and open the page.

**Manual check** (note §17.9 steps 1-6), recorded below in the Status notes with date,
browser versions, networks, negotiated SRTP cipher (expected `AEAD_AES_128_GCM`) and
anything that failed.

**Checkpoint:** the recorded check passes (**exit criterion 4**). Step 6 (network switch)
passes or is recorded as the known ICE-restart limitation.

---

### 1.9 Documents and merge

**Files:** `architecture.md`, `CLAUDE.md`, `README.md`, `docs/dataplane-design.md` (revision
log only, if anything in Phase 1 changed a decision), this plan.

**Change:**
- `architecture.md` Parts 1-2 describe the new path (process layout, data path, what is not
  built yet); Part 5 gets the Phase 1 numbers (one shard). The full rewrite is at release.
- CLAUDE.md: "Current step", "Architecture (today)", workspace structure (no `nexus-actor`,
  `nexus-dst`; new `nexus-dataplane`), commands (benches, e2e), prerequisites.
- Status table and session log complete; merge `phase-1` into `main`.

**Checkpoint:** every exit criterion checked off in the Status table; merged.

---

## Status

| Part | State | Commits | Notes |
|------|-------|---------|-------|
| 1.1 SRTP per direction | Not started | | |
| 1.2a Shard core: tables, commands, ICE-lite, forwarding | Not started | | |
| 1.2b Shard core: extensions, RTCP, housekeeping, alloc test | Not started | | |
| 1.3 Shard thread and I/O | Not started | | |
| 1.4 SDP groundwork, shared certificate | Not started | | |
| 1.5a Control-plane pieces | Not started | | |
| 1.5b Switch (one commit) | Not started | | Early browser check result goes here |
| C1 `Sfu`, packet loop, `sim` | Not started | | |
| C2 Old benches | Not started | | |
| C3 `worker/`, `forward/`, `proto.rs` | Not started | | |
| C4 `nexus-actor`, `nexus-dst` | Not started | | |
| C5 Replaced `nexus-transport` modules | Not started | | |
| C6 `WebRtcTransport`, session, demux | Not started | | |
| C7 Config, README, Docker | Not started | | |
| 1.6a E2E: harness, ten clients, resubscribe | Not started | | |
| 1.6b E2E: address change, SR, keyframes | Not started | | |
| 1.7 Benches, memory budget, CI | Not started | | |
| 1.8 Browser page, manual check | Not started | | Browser versions, cipher, results |
| 1.9 Documents, merge | Not started | | |

Exit criteria: 1 ☐ e2e · 2 ☐ 0 allocations · 3 ☐ 25 KB budget · 4 ☐ browsers · 5 ☐ old path
deleted · 6 ☐ documents.

### Session log

Add one line per working session: date, part, what was done, what is left.

- 2026-09-26: plan written from the approved design note; branch `phase-1` created from
  `4fabfc6`. Code notes checked against that commit. Reviewed and approved: merge target
  `main` (fast-forwarded to `v0.1.0`), idle-CPU test local only. Realistic size: ≈ 15
  working sessions for Phase 1 (1.2a may need two). Next: 1.1.
