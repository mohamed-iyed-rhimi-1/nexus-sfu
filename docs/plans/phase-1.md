# Phase 1 — New data plane, one shard

**State: in progress** (1.1-1.4 done; plan written 2026-09-26, audited against the code the same day).

**Design:** [`docs/design/dataplane-v1.md`](../design/dataplane-v1.md) (approved; §16 gives the
parts and order, §17 the tests), within [`docs/dataplane-design.md`](../dataplane-design.md)
§5, Phase 1. Where the code differs from the note's facts, this plan says so and the
[corrections](#corrections-to-the-design-note) section lists them. No decision (D1-D10, R1-R9)
changes.
**Current state:** [`architecture.md`](../../architecture.md).
**Branch:** `phase-1` (from `4fabfc6`). Merged into `main` only when every exit criterion
passes (design §7). `main` was fast-forwarded to `v0.1.0` at `4fabfc6` and is the trunk from
now on; `v0.1.0` is no longer used.

Phase 1 replaces the old data plane (ingress loop, worker pool, SSRC router) with
`nexus-dataplane` running **one shard**, moves the orchestrator to the command/event
interface, and deletes the old path. Multiple shards are Phase 2; NACK, RR and TWCC toward
publishers are Phase 3.

Section references like "note §9.3" point into the design note. "Code notes" were checked
against `e825887`; line numbers drift, so prefer the symbol names.

## Exit criteria

1. **E2E on the new path**, in CI on Linux (x86_64 and arm64, both already in `ci.yml`) and
   macOS (new job, 1.7):
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
3. **Fixed memory per participant ≤ 25 KB** (design §3.11) for the "A+V publisher subscribed
   to 10 tracks" scenario, enforced in CI by the ported `benches/memory.rs` (note §17.8).
4. **Manual Chrome and Firefox call** with AES-GCM offered first, recorded in this plan with
   browser versions and the negotiated cipher (note §17.9, all six steps).
5. **Old path deleted:** `src/worker/`, `src/forward/`, the packet loop and `Sfu`,
   `nexus-actor`, `nexus-dst`, the replaced `nexus-transport` and `nexus-webrtc` modules
   (steps C1-C7 below). `real_path` and `memory` benches ported with the same scenarios.
6. **No panic on network input** anywhere a datagram reaches: the shard, the SRTP and STUN
   code it calls, and the DTLS path in the control plane (fuzz-style tests in 1.1, 1.2a,
   1.5a). Release builds use `panic = "abort"`, so one bad packet would end the process.
7. `architecture.md` Parts 1-2 and CLAUDE.md describe the new path.

## Engineering rules for this phase

These apply to every part; a part is not done until they hold.

- **Every commit is green:** `cargo build`, `cargo clippy --workspace --all-targets -- -D
  warnings`, `cargo fmt --all --check`, `cargo test --workspace`, and all benches and
  examples compile (`--all-targets` covers them). The branch can be bisected.
- **`Cargo.lock` is committed with every dependency change.** CI builds with `--locked`.
  New direct dependencies use the version already in the lock file.
- **Linux check:** a part that touches I/O, SRTP, benches or `cfg(target_os)` code is run in
  the Linux container (CLAUDE.md) before it is marked done. Linux-only code is otherwise
  exercised only in CI.
- **Network input never panics.** Every function a datagram reaches returns `None` or `Err`
  on bad input. `assert!` is only for the shard's own invariants. Where an existing function
  asserts on packet contents before its graceful check, the assert goes (the audit found
  several; they are listed in the parts).
- **Hot path:** no allocation, no lock, no clock read (`now` is passed in), every loop
  bounded. `debug_assert!` for per-packet invariants, `assert!` in command handling.
- **New crate:** `#![deny(warnings)]`; `#![deny(unsafe_code)]` at the crate root with a
  local `#[allow(unsafe_code)]` only in `shard/io.rs` (Linux syscalls), every block with a
  `// SAFETY:` comment. Dev profile: `[profile.dev.package.nexus-dataplane] opt-level = 1`
  (like `nexus-transport`) and `[profile.dev.package.ring] opt-level = 3`, or e2e runs
  unoptimised crypto.
- **Assertions:** new functions assert preconditions and postconditions (CLAUDE.md PR
  checklist); functions stay under ≈ 60 lines.

## Parts

Each part is sized for one working session and ends at a green checkpoint.

- **Add**, with the old path still live: 1.1 → 1.2a → 1.2b → 1.3 → 1.4 → 1.5a → 1.5b-prep.
  1.1 and 1.4 are independent of the rest and can move earlier or later.
- **Switch** (one commit): 1.5b.
- **After the switch:** the deletion steps run in this order, because each one removes code
  the next one's targets still import (checked in the audit):
  **1.7 → C2 → C1+C3 → C4 → C6 → C5 → C7**. Parts 1.6a and 1.6b can be interleaved anywhere
  after 1.5b. The note's order (C1 alone, C5 before C6) does not build: see
  [corrections](#corrections-to-the-design-note).
- The browser page and SDK work (1.8) can be done any time; having it by 1.5b makes the
  early browser check easier. 1.9 is last.

---

### 1.1 SRTP per direction

**Goal:** the per-session SRTP contexts of note §9, in `nexus-transport`, with the backends
decided in Phase 0 (GCM on `ring`, AES-CM on RustCrypto), and no panic on any packet.

**Files:** `crates/nexus-transport/src/srtp/{direction.rs (new), crypto.rs, context.rs,
replay.rs, mod.rs, rfc_vectors.rs}`, root `Cargo.toml` (dev profile), `benches/srtp_backends.rs`.

**Change:**
- `SrtpCipher::AesGcm` reimplemented on `ring` (`LessSafeKey`, `seal_in_place_separate_tag`
  / `open_in_place`), starting from `RingGcmBackend` (`benches/srtp_backends.rs:343-389`).
  That backend covers **RTP only**; SRTCP is new code: nonce as in `build_rtcp_nonce`
  (`crypto.rs:180`, RFC 7714 §9.1), AAD = 8-byte header ‖ E+index, tag, then E+index after
  the tag (the Phase 0 fix). Checked against the RFC 7714 §16 vectors and against the current
  RustCrypto GCM output before the RustCrypto path is removed.
- AES-256-GCM (`AesGcmCipherInner::Aes256`, `crypto.rs:49-52`) stays on RustCrypto: it is not
  offered, and `rfc_vectors.rs:142` uses the public `AesGcmCipher` directly.
- Move the RFC 3711 index/ROC estimate (`estimate_index_for_ssrc`, `context.rs:144-179`;
  `update_roc_for_ssrc`, `:186-214`) and the replay check out of `SrtpContext` into free
  functions, called by both `SrtpContext` and the new types.
- `direction.rs`: `SrtpInbound` (16 SSRC slots: ROC, highest seq, RTP and RTCP replay
  windows, `last_seen_s`) and `SrtpOutbound` (32 slots: ROC, highest seq, **sent-index
  window**, SRTCP index), fixed arrays with linear scan, API of note §9.1.
  - Inbound: a slot is taken only **after** the packet authenticates (`SrtpContext` inserts
    into its `HashMap` before decryption, `context.rs:343`, so unauthenticated SSRCs grow it
    without bound). Full table: evict the entry idle longest if > 30 s, else drop.
  - Outbound: `retire(ssrc)`. The sent-index window reuses `ReplayProtection`
    (`replay.rs`, 64-bit bitmap); its `check` returns the same error for "duplicate" and
    "too old", which is fine: both are refused.
  - SRTCP unprotect rejects E = 0 (the GCM path ignores the E flag today).
  - All failures return `None`.
- **Remove every assert on packet contents** on the protect/unprotect paths (the old path
  benefits too, it stays live until 1.5b):
  - `context.rs:307` (length before the graceful check at 315), `:311` (≤ 8,192, no
    graceful path), `:250-258` (protect buffer room), `:371`, `:405` (`len ≥ 8`);
  - `crypto.rs:222` (`protect_rtp` `len ≥ 12`), `:304` (GCM `unprotect_rtp`), `:463` (GCM
    `unprotect_rtcp`), `:745` (CM `unprotect_rtp`);
  - the GCM AAD copy into `[u8; 128]` (`crypto.rs:270`, `:354`), which runs **before
    authentication** on unprotect: any peer can crash the process with a header over
    128 bytes. It disappears with `ring` (the AAD is a slice of the packet).
- `[profile.dev.package.ring] opt-level = 3` next to the existing `aes`/`ctr` entries
  (`Cargo.toml:167-186`).

**Code notes (audited 2026-09-26):**
- `ring = "0.17"` is a `nexus-transport` dependency and **is** imported, by the pure-Rust
  DTLS (`dtls/session.rs:43`, `dtls/crypto.rs:31-32`). After C5 deletes that DTLS, SRTP is
  its only user. Root `Cargo.toml:128` has it as a dev-dependency for the bench.
- `SrtpCipher` (`crypto.rs:934`) already takes the packet index from the caller and has
  separate RTP and RTCP key schedules; `unprotect_rtcp` returns `(len, index)` with no replay
  check. The new types only add per-SSRC state around it.
- `SrtpContext` stays: besides the old worker and benches, `rfc_vectors.rs` (CM vectors),
  `crates/nexus-transport/tests/{srtp_interop,srtp_100sub,srtp_forwarding}.rs`, and
  `nexus-webrtc` `session.rs` use it. It is the reference the new types are checked against.
- The old path keeps working: it builds its contexts through `SrtpContext`, which now uses
  the ring GCM cipher. The e2e tests negotiate AES-CM until 1.5b, so the GCM change is
  covered by the vectors and the bench check until then.
- Found while implementing (2026-09-26):
  - Three more asserts on packet contents: `crypto.rs:701` (CM `protect_rtp` `len ≥ 12`),
    `:858` (CM `unprotect_rtcp` `len > 4`, before its graceful check), `context.rs:223`
    (`len ≥ 12`, reached from `protect_rtp` with 1-11 bytes). The 128-byte GCM AAD copy
    also ran on **protect**, which the old path calls with publisher headers.
  - **ROC estimate bug** in `estimate_index_for_ssrc`: `seq.wrapping_sub(s_l) > 32768`
    where RFC 3711 Appendix A means signed `SEQ - s_l`. With ROC > 0 and s_l < 2^15,
    every reordered packet (seq < s_l) was put in the previous ROC and failed
    authentication. Fixed in the shared `srtp/index.rs`, so the old path gets it too. On
    the **send** side the same estimate also reused keystream: at ROC 1 with s_l = 2, a
    packet with seq 1 was encrypted as index (0, 1), already sent in the first cycle.
  - Once `SrtpCipher` GCM is ring, the bench's GCM `verify()` compares ring with ring. The
    independent checks are `gcm_ring_matches_rustcrypto_{rtp,rtcp}` (RustCrypto
    `Aes128Gcm` stays a dependency for AES-256) and `webrtc-srtp` in `direction.rs` tests.
  - `size_of::<SrtpInbound>() + size_of::<SrtpOutbound>()` = 7,728 B (tested ≤ 8 KB),
    a third of the 25 KB budget. `ReplayProtection` is 48 B (window size, enable flag and
    two stats counters beside the 16 B of state) × 64 instances: slimming it saves ≈ 2 KB
    if 1.7's memory bench needs it.
  - **Review fixes (2026-09-26), before commit:**
    - `SrtpOutbound::retire` reopened keystream reuse: protecting the SSRC again started a
      fresh slot at index 0 and SRTCP index 0 under the same key, guarded only by a doc
      comment. Now `SrtpOutbound` protects only SSRCs `register`ed by the control path, and
      `register` applies §9.3's monotonic rule itself (offset from the session's SSRC base
      strictly increasing, `< 2^31`), so a retired SSRC can never be registered or sent
      again. The rule sits on registration, not on first use: first packets of two
      subscriptions can go out in either order. This is the second, independent protection
      the note promises; the shard's `Subscribe` check stays.
    - Inbound eviction could kill a stream: a media SSRC idle > 30 s evicted from a full
      table came back at ROC 0 after a wrap and failed authentication for the rest of the
      session, and lost its replay window. Now SDP-signaled SSRCs are `pin`ned (≤ 12 of the
      16 slots) and never evicted; only unsignaled SSRCs (receiver RTCP) are.
    - Both regression tests were checked to fail with the fix disabled.
    - **Precondition for 1.2a's rewriter:** the sequence numbers a subscription sends never
      jump forward by 2^15 or more. The outbound index estimate follows RFC 3711, so a
      larger jump is read as the previous ROC and the packets are refused (no reuse, but a
      long run of drops). The rewriter asserts this in debug builds and counts it in
      release.

**Tests:**
- RFC 3711 B.2 and RFC 7714 §16 vectors pass through `SrtpInbound`/`SrtpOutbound` (RTP and
  RTCP, both profiles).
- Round trip against `SrtpContext` byte for byte, including a ROC rollover (start seq
  65,500) and reordering across the rollover.
- `SrtpOutbound` refuses an index it already sent and one older than the window; accepts a
  reordered, not-yet-sent index.
- Inbound: replayed packet refused; a packet that fails authentication takes no slot; 17th
  SSRC with all slots fresh refused; evicts after 30 s idle; SRTCP with E = 0 refused.
- Short and malformed packets (0-12 bytes, header length beyond the packet, CSRC count
  beyond the packet, 200-byte extension header, a 140-byte header of 15 CSRCs plus a
  16-word extension, length 8,193) return `None`, never panic, through **both** the new
  types and `SrtpContext`.
- `benches/srtp_backends.rs` byte-for-byte `verify()` still passes.

**Checkpoint:** tests above green; `cargo bench --bench srtp_backends` numbers within noise
of architecture.md Part 5 (ring GCM ≈ 0.28 µs / 1,200 B on macOS); Linux container run.

---

### 1.2a Shard core: tables, commands, ICE-lite, forwarding

**Goal:** `nexus-dataplane` with a shard that can be driven entirely through `MemIo` and
explicit `now`: sessions are created by commands, answer STUN, install SRTP, and forward RTP
from a publisher to subscribers with seq/ts/SSRC/PT rewritten. No header extensions yet.

**Files:** new `crates/nexus-dataplane/` (`Cargo.toml` Apache-2.0, workspace member),
`src/{lib.rs, ids.rs, command.rs, config.rs, session.rs, ice.rs, track.rs, subscription.rs,
rewrite.rs, pool.rs, shard/mod.rs, shard/io.rs (MemIo only)}`, `tests/shard.rs`;
`crates/nexus-transport/src/ice/stun/{attributes.rs, message.rs, integrity.rs, mod.rs}`
(UB and panic fixes, one re-export).

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
- SRTP contexts (from 1.1's review): `SrtpOutbound::new(km, ssrc_base)` with the base from
  `CreateSession`; `register(out_ssrc)` on `Subscribe` and for `rtcp_ssrc` (so `rtcp_ssrc`
  must come from the same base + offset allocator, before any subscription), `retire` on
  `Unsubscribe`. `SrtpInbound::pin(ssrc)` on `AddTrack` with an SSRC and when SSRC learning
  binds one (1.2b), `unpin` on `RemoveTrack`. `Subscribe`/`AddTrack` can precede
  `InstallSrtp`: at `InstallSrtp`, register the session's existing out SSRCs in offset
  order and pin its existing track SSRCs. A `register`/`pin` error rejects the command.
- `ice.rs`: binding-request handler of note §8.2, with one change: **a slim in-place scan
  instead of `StunMessage::parse`**. `StunMessage` is ≈ 19 KB (16 × `Option<StunAttribute>`
  of ≈ 1,208 B, the `Data` variant holds 1,200 bytes), returned by value and moved twice,
  and it does not record the attribute offsets `verify_*` needs. The scan is one bounded
  pass (≤ 32 attributes) that records the offsets of USERNAME, USE-CANDIDATE,
  MESSAGE-INTEGRITY and FINGERPRINT, then calls `verify_message_integrity`
  (`integrity.rs:100`) and `verify_fingerprint` (`:185`) on slices. USERNAME is compared as
  bytes against the ufrag map; the remote half is not checked (note §8.2 step 3). Success
  response with `XOR-MAPPED-ADDRESS` (`attributes.rs:464`) and `sign_message`
  (`integrity.rs:365`) into a pool buffer. Nomination (§8.3) and rebinding (§8.4) with
  `rebind_silence`, `AddressSelected` events.
- STUN fixes in `nexus-transport` (shared with the old path):
  - USERNAME parse (`attributes.rs:231-243`) copies raw bytes and `get_username`
    (`message.rs:249`) then calls `from_utf8_unchecked`: undefined behaviour on attacker
    input. Validate UTF-8 at parse (reject the attribute) and make `get_username` safe.
  - `compute_message_integrity` asserts a 1-256-byte key: callers reject an empty password
    first; the shard never creates a session with one (`IceParams` is fixed 32 bytes).
  - `pub use` `create_binding_request` from `stun/mod.rs` (test peers need it; only
    `create_binding_indication` is exported).
- Ingress (note §10.1): classify (STUN 0-3, DTLS 20-63, RTP/RTCP 128-191 with RTCP when
  `byte1 & 0x7F` in 64..=95); DTLS → `DtlsDatagram` until `srtp_verified`, then drop;
  RTP → unprotect → `PeerSrtpVerified` once → `RtpHeader::parse` → SSRC → track → fan-out.
  `RtpHeader::parse` is called only **after** unprotect: it validates padding from the last
  byte, which is auth tag on an encrypted packet.
- Egress (note §10.2) with a first `rewrite()` that writes the 12-byte header (mapped PT,
  seq/ts offsets, out SSRC), copies CSRCs, **drops the extension block**, copies the payload.
  First packet sets random offsets (note §11.1).
- `Shard::iterate(now)` with the loop body of note §3.2 minus parking and cross-shard;
  `tx` batch of 256, flushed when full and at the end; bounded command drain (64).

**Code notes (audited 2026-09-26):**
- `StunServer::handle_request` allocates (`username.to_string()`) and its
  `validate_request` asserts a non-empty local ufrag (a request with USERNAME `":x"` panics
  the old path). Not reused; deleted with `IceAgent` in C5.
- `derive_short_term_key` allocates; the short-term key is the password bytes.
- `create_binding_request` (`stun/server.rs:399`) asserts `buf ≥ 128`, username ≤ 128 and a
  non-empty password, and writes USE-CANDIDATE only when `use_candidate && ice_controlling`:
  test peers pass `ice_controlling = true`.
- `RtpHeader::parse` (`nexus-media/src/rtp/header.rs:76`) is allocation-free. There is no
  extension element iterator (only `get_extension_value`, per id); 1.2b writes one.
- `demux.rs`'s RTCP range is 72..=79 (its comment claims 64-71 too) and its validators
  `format!` on invalid input: do not reuse.
- Found while implementing (2026-09-26):
  - More STUN asserts reachable from input: `StunAttribute::parse` had a
    `debug_assert!(len <= 1200)` (fires in debug builds, now an error);
    `verify_message_integrity`/`verify_fingerprint` asserted on offsets and key length (now
    `false`); `StunServer` panicked on an empty local password. All fixed, with tests.
  - The scan also rejects a USERNAME that is not UTF-8; only the local half is compared.
  - **Liveness timestamp:** the session keeps `last_rx_selected`, updated only by
    authenticated packets from the *selected* address. If authenticated STUN from another
    candidate refreshed it, a peer checking a second pair would block rebinding forever.
  - Random rewrite offsets come from a shard-local SplitMix64 seeded by
    `ShardConfig::rng_seed` (deterministic tests, no clock).
  - 1.1's "no forward jump ≥ 2^15" precondition does **not** hold by construction (first
    draft claimed it did; review found it): when forwarding to one subscriber pauses (no
    address, empty pool, unmapped PT) while the publisher continues, the next packet can be
    ≥ 2^15 ahead of the last one sent and the outbound estimate refuses it and every later
    one. The rewrite now rebases (the subscriber's stream continues right after its last
    packet, the timestamp advanced by the wall time, note §11.5's rule) when the input is
    more than `REBASE_GAP` (2^14) ahead of the last forwarded packet, more than
    `REORDER_LIMIT` (64) behind it (inbound SRTP refuses anything that old, so the input
    moved on by 2^15 or more), or when `REBASE_IDLE` (5 s) passed since the last forwarded
    packet (over a long pause the input seq can wrap into a small step). The rewrite
    returns its state change and the shard commits it only after `protect_rtp` succeeds,
    so an unsent packet does not start a stream or move `last_out_*`.
  - `InstallSrtp` carries `Box<SrtpInstall { local, remote }>` (the profile is inside
    `KeyMaterial`); `size_of::<Command>()` is ≤ 72 B (`IceParams` inline).
  - `RemoveTrack` removes the subscriptions to the track; a later `Unsubscribe` for one of
    them gets `CommandRejected{UnknownSubscription}`, which 1.5b ignores.
  - Events go through an `EventSink` trait (tokio sender in 1.3, `Vec` in tests), so the
    crate has no tokio dependency. `DtlsDatagram` is never retained when the sink is full.
  - **Review fixes (2026-09-26), before commit:**
    - DTLS flood: a peer that passed STUN but sends no SRTP could copy every datagram into
      the event channel all sessions share and starve other handshakes. Now at most
      `DTLS_BUDGET_PER_SWEEP` (32) DTLS datagrams per session per second, checked before
      the copy.
    - Lost events: `PeerSrtpVerified` and `ConsentLost` flags are set only when the sink
      or retention queue accepted the event (else the next packet / sweep retries);
      a refused `AddressSelected` is re-sent by the sweep. Before, a full queue lost them
      for good and the session leaked.
    - Switch flapping: at most one address switch per `MIN_SWITCH_INTERVAL` (100 ms). A
      nomination refused by the interval is stored (the latest one wins; a nomination of
      the current address cancels it) and applied as soon as the interval has passed.
    - Replay: the last 16 binding-request transaction ids per session are remembered; a
      repeated id is answered but never moves the session. An on-path attacker replaying a
      captured nomination from its own address no longer takes the session. Residual: a
      request older than the last 16 can still be replayed (after ≈ 1 minute of browser
      consent checks); see the ICE-lite injection risk below.
    - Previous address kept at least `PREV_ADDR_GRACE` (1 s) after a switch, not until
      the next sweep (which could be immediate).
    - One translated SR per SSRC per compound (a compound of 16 SRs sent 16 per
      subscriber).
    - Extension parsing: in the one-byte form any ID-0 byte is one byte of padding, as in
      libwebrtc. `Subscribe` also rejects an ext map that maps two ids to one subscriber
      id, reuses the `mid` id, or maps publisher id 0.
    - After `ConsentLost` is delivered, the shard emits nothing more for that session
      (`drop_after_consent`): the control plane is closing it.
    - Each regression test was checked to fail with its fix disabled.
  - Only `rustc-hash` and `crossbeam-queue` were added in 1.2; `mio` and `libc` come with
    1.3's I/O.
- New direct dependencies, versions as locked: `mio` 1.1.1 (features `os-poll`, `os-ext`;
  `net` is not needed with `SourceFd`), `crossbeam-queue` 0.3.12, `rustc-hash` 2.1.1,
  `libc` 0.2.180. `crossbeam-queue` and `rustc-hash` are only transitive today.

**Tests** (`tests/shard.rs`, scripted peers on `MemIo`; each peer uses `SrtpContext` as its
own SRTP and builds STUN with `create_binding_request`):
- STUN: valid request answered with correct XOR-MAPPED-ADDRESS (IPv4 and IPv6); wrong
  password, wrong ufrag, bad fingerprint, truncated message, invalid UTF-8 USERNAME, 40
  unknown attributes before MESSAGE-INTEGRITY: no answer, no state change.
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
- **Robustness:** a `proptest` feeding random datagrams (every first-byte class, lengths
  0-2,048, from known and unknown addresses) into `iterate` never panics and leaves the
  tables unchanged unless the datagram authenticated.

**Checkpoint:** `cargo test -p nexus-dataplane` green; the rest of the workspace green.

---

### 1.2b Shard core: extensions, SSRC learning, RTCP, housekeeping

**Goal:** complete the Phase 1 shard logic: header extension mapping, `mid` SSRC learning,
SR translation, keyframe requests, liveness, stats, and the zero-allocation test.

**Files:** `crates/nexus-dataplane/src/{rewrite.rs, subscription.rs, track.rs, rtcp.rs,
session.rs, shard/mod.rs, shard/stats.rs, ext.rs (new: the fixed extension table)}`,
`tests/{shard.rs, alloc.rs (new)}`.

**Change:**
- `ext.rs`: the fixed table of note §11.2 as constants (ID, URI, kinds, offered-in-v1),
  shared later by the negotiator (1.4; the table moved to `nexus_media::rtp::extensions`
  there, and `ext.rs` re-exports it). ID 4 (transport-cc) and 5 (abs-send-time) are **not
  offered** in Phase 1; 10/11 reserved.
- `rewrite()` complete (note §11.4): an extension element iterator over one-byte and
  two-byte forms (bounded to 16 elements), write mapped elements in one-byte form, drop the
  publisher's `mid`, append the subscriber's `mid`, pad, clear X if empty.
- SSRC learning (note §7.2): unknown SSRC + unbound tracks → read the publisher's `mid`
  element → bind.
- `rtcp.rs` (note §12): compound iteration via `demux_compound`; SR from a publisher →
  stored per layer → translated SR + SDES CNAME to each started subscription, protected with
  the subscriber's `srtp_out` under the out SSRC; PLI and FIR (FIR parsed in place) from a
  subscriber → `request_keyframe(track, layer)` with the 500 ms throttle, PLI protected with
  the **publisher's** `srtp_out` under its session's `rtcp_ssrc`. Keyframe also requested on
  `Subscribe` for a session with SRTP, and on `InstallSrtp` for each existing subscription.
  RR, NACK, REMB, TWCC, SDES, BYE, XR counted and ignored (webrtc-rs subscribers send RR and
  NACK every second; they must cost nothing).
- The SR, SDES and PLI builders write into pool buffers. **None exists allocation-free:**
  `PliPacket::build` and `SenderReportGenerator::generate` return `Vec`, and there is no SDES
  builder anywhere in the workspace.
- `housekeeping(now)` every 1 s (note §3.4): `ConsentLost` after `consent_timeout`
  without authenticated traffic, inbound SSRC eviction, stale address-map entries from
  rebinding removed, counters copied to `ShardStats` atomics. Event retention queue of 256
  (note §5.3).

**Code notes (audited 2026-09-26):**
- `demux_compound` (`nexus-media/src/rtcp/compound.rs:33`) returns a fixed
  `[Option<CompoundEntry>; 16]`, allocation-free, but **returns `Err` for the whole compound**
  if any block is malformed and silently truncates beyond 16. The shard counts and drops
  such packets.
- `SenderReport::parse` (`rtcp/packet.rs:62`) reads 28 bytes and ignores report blocks;
  `PliPacket::parse` (`:253`) is allocation-free. `FirPacket`, `ReceiverReport`,
  `NackPacket`, `RembPacket` parse into `Vec`s: not used on the shard.
- RTP padding: keep the P bit and copy the padding with the payload.
- Found while implementing (2026-09-26):
  - `demux_compound` keeps going past 16 blocks silently; the shard compares the blocks'
    total length with the datagram and drops a compound that is not fully covered.
  - Keyframe throttle: `last_pli` is set only when a PLI was actually sent, so a request
    made before the publisher has SRTP, an address or a known SSRC does not suppress the
    next one.
  - `Subscribe` rejects extension ids above 14 (`RejectReason::InvalidSpec`): the rewrite
    writes the one-byte form only.
  - `tests/alloc.rs` counts per thread, only around `Shard::iterate`; the peers'
    `SrtpContext`s and test bookkeeping run outside the window. Checked to fail (10,000
    allocations) with a `vec!` injected into the fan-out.

**Tests:**
- Rewrite: table-driven over input headers (no extensions, one-byte, two-byte, with CSRCs,
  with padding, declined extensions, subscriber without `mid`, 16+ elements) → exact output
  bytes; the payload is copied once and unchanged.
- SSRC learning: publisher with `ssrc: None` is bound by the `mid` element; a wrong mid is
  dropped.
- SR translation: parse the SR a subscriber decrypts: sender SSRC = out SSRC, NTP = the
  publisher's, RTP = publisher RTP + `ts_offset`, counts = packets/octets sent so far,
  followed by SDES with the publisher's cname; SRTCP indices of that SSRC increase.
- Keyframes: PLI from a subscriber reaches the publisher with the right media SSRC; 5 PLIs
  in 100 ms → 1; FIR → PLI; `Subscribe` on an SRTP session → PLI; `InstallSrtp` on a session
  with 2 subscriptions → 1 PLI per track (throttled).
- RTCP robustness: a compound with a malformed trailing block, and one with 17 blocks, is
  counted and dropped without panic.
- Liveness: no authenticated packet for 30 s of `now` → exactly one `ConsentLost`.
- `tests/alloc.rs` (note §17.7): own test binary with a counting `#[global_allocator]`;
  11 sessions, 10 subscribers on audio and video. Warm-up sends every SSRC in both
  directions, RTP and RTCP, through the peers' `SrtpContext`s (they allocate a `HashMap`
  entry on the first packet of each SSRC) and through the shard. Then 10,000 RTP + 100 SR +
  100 PLI + 100 RR + 100 NACK through `iterate`: allocation count unchanged, output = 10 ×
  RTP input. Runs for AES-GCM and AES-CM.

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
  allocated once, receiving into pool buffers. Beyond `benches/udp_floor.rs` (IPv4 only, no
  source address, no truncation check): `msg_name` set to a `sockaddr_storage` per slot and
  `msg_namelen`/`iov_len` reset before every call; IPv4 and IPv6; datagrams with `MSG_TRUNC`
  in `msg_flags` dropped and counted; short sends drop the rest (counted). `PortableIo`:
  `recv_from` loop (≤ 64, until `WouldBlock`), `send_to` each. Selected by
  `cfg(target_os)`.
- Socket setup with `socket_config::configure_socket_buffers` (`socket_config.rs:86`) only.
  **Not** `configure_high_performance_socket`: it enables UDP_GRO (`enable_gro`,
  `:254`), and the kernel would then coalesce datagrams into reads larger than a 2,048-byte
  buffer.
- `park.rs`: `mio::Poll` with the socket (`SourceFd`) and a `mio::Waker`; the parked-flag
  protocol of note §3.3; park only after a receive returned `WouldBlock`; timeout = next
  housekeeping. `busy_poll_rounds` from config.
- `DataplaneHandle`: `send(shard, Command) -> Result<(), CommandQueueFull>` (ArrayQueue
  4,096 + wake if parked), `events() -> tokio mpsc::Receiver<Event>` (8,192, shards use
  `try_send`), `stats(shard)`, `is_running()` (backs `ServerHandle::is_finished()`,
  polled by `main.rs:379`), `shutdown()` (stop flag, wake, join).
- `Dataplane::start(config) -> (DataplaneHandle, Vec<ShardInfo>)`: bind `media_bind_addr`
  port + i (port 0: ephemeral per shard), `ShardInfo.local_addr` from `local_addr()` after
  bind, apply buffer sizes, spawn `nexus-shard-{i}` with an explicit stack size (1 MB; the
  shard never recurses, but a STUN parse on the old types moves ≈ 19 KB), pin and
  SCHED_FIFO when configured (Linux; `warn!` once on macOS). Validation: `shards == 1` in
  Phase 1; port range fits and avoids the other ports.
- `placement.rs`: `Placement` trait and `ShardLoad` (note §13.2), `SingleShard`.

**Code notes (audited 2026-09-26):**
- Syscall code to start from: `benches/udp_floor.rs` (Linux-only module at line 33;
  `sendmmsg` at 159 and 242, `recvmmsg` at 273), allocation-free. Not
  `nexus-transport/src/udp.rs` (allocates).
- Pinning and SCHED_FIFO: `set_realtime_scheduling` (`src/worker/pool.rs:156`,
  Linux only, **asserts** priority 1..=99) and `has_cap_sys_nice` (`:83`, reads
  `/proc/self/status`); affinity via `core_affinity::get_core_ids()` / `set_for_current`
  (`pool.rs:3616`, `:3759`). Copy them into `nexus-dataplane` with the priority validated in
  config instead of asserted (the originals go in C1+C3).
- `configure_high_performance_socket` is not unused: `io_uring.rs:335` calls it (deleted in
  C5).
- Found while implementing (2026-09-27):
  - **Dual-stack addresses.** A socket bound to `::` receives IPv4 peers as `::ffff:a.b.c.d`;
    the shard keys `by_addr` on `SocketAddr` and reports `AddressSelected`. Both backends
    normalise v4-mapped sources to `V4` and send to `V4` destinations through the v4-mapped
    form on an IPv6 socket (macOS `send_to` refuses a `V4` address there).
  - **One bad destination.** `sendmmsg` stops at the first failing message. `EAGAIN` /
    `ENOBUFS` drop the rest of the batch (counted); any other errno (unreachable, wrong
    family) drops only that datagram and the send continues (bounded by the batch).
  - **macOS truncation is silent.** `recv_from` reports none, so `PortableIo` receives into
    a scratch buffer of `BUF_SIZE + 1` and drops a datagram that fills it (one copy per
    datagram on macOS). The truncation check runs on both platforms.
  - **Parking and retries.** Retained events and deferred nominations are only retried by
    `iterate`: the park timeout is capped at `PARK_RETRY_INTERVAL` (10 ms) while either
    waits, else it is the next housekeeping. A receive that got nothing without
    `WouldBlock` (pool dry, `EINTR`) parks ≤ 1 ms: mio is edge-triggered.
  - **tokio.** The note's "no tokio" means no runtime on shard threads: the crate depends on
    tokio with the `sync` feature only, for the event channel (`try_send` needs no runtime).
    tokio was already in the tree through `nexus-transport`.
  - **Random offsets.** `ShardConfig::rng_seed` was a constant default: `DataplaneConfig`
    takes `rng_seed: Option<u64>` and `None` seeds from the standard library's per-process
    hash keys (tests pass `Some`).
  - **Lost wake-up on Linux** (found by the Linux run, 4 failures in 5): the `Parker` did not
    own the `mio::Waker`, only the producers' `Wake` did. A producer that woke the shard and
    then dropped the last `Wake` closed the eventfd, and closing an fd removes its pending
    readiness from epoll, so the wake-up vanished (kqueue keeps it: macOS never failed). The
    `Parker` now holds the waker too; 15/15 runs pass.
  - **Unsafe** is confined to `shard/io/linux.rs` (a submodule of `io.rs`): `recvmmsg`,
    `sendmmsg`, `sched_setscheduler`, the `UDP_GRO` query, sockaddr conversion. `LinuxIo` is
    `unsafe impl Send`: its header arrays hold raw pointers, rewritten before every call.
  - **Shard-wide DTLS cap** (risk table): `ShardConfig::dtls_budget_per_sweep` (1,024 per
    second), checked after the per-session budget, counted in `drop_dtls_shard_budget`.
  - New counters `parks`, `rx_truncated`, `rx_errors`, `drop_dtls_shard_budget`; gauge
    `rx_pps` (feeds `ShardLoad`). Stats are also published when a shard stops.
  - `DataplaneHandle::take_events()` hands out the receiver once; `shutdown()` is idempotent
    and also runs on drop. A drop guard clears `running` if a shard thread panics. Release
    builds use `panic = "abort"`, so a shard panic ends the process there: the drop guard
    and `is_running() == false` after a panic are a debug/test path only; in release,
    `is_running()` only turns false after `shutdown`.
  - **Review fixes (2026-09-27), before commit:**
    - An all-dropped receive batch (truncated or unreadable source) counted as idle and
      parked 1 ms, pacing an oversized flood to ≈ 64 datagrams per ms. `IterationStats`
      now carries `taken` (every datagram taken from the socket) and the runner treats any
      as work. Deterministic test in `runner.rs` (500 all-truncated batches: 585 ms with
      the old rule, < 1 ms now) and a loopback test (media arrives after 2,000 oversized
      datagrams, sent only after a STUN probe shows the flood drained; session log).
    - `LinuxIo::new` refuses a socket with UDP_GRO on; `udp_gro_enabled` maps
      `ENOPROTOOPT` to `false` (kernels before 5.0 lack the option; the
      `socket_config.rs` comment said 4.18, which is `UDP_SEGMENT`).
    - The burst test with 3 subscribers never exceeded `SEND_BATCH` (64 × 3 = 192): it
      now uses 5, and `tests/shard.rs` proves the mid-batch flush deterministically with
      the new counter `tx_full_flushes` (one `iterate`, 64 packets, 5 subscribers).
    - `shutdown` holds the threads lock across the joins: a concurrent caller returned
      while shards still ran (test: two callers, 20 rounds; fails without the fix).
    - `DatagramIo::flush` returns `Sent { datagrams, bytes }`, so `tx_bytes` counts what
      was sent on a partial failure (Linux: `msg_len` per message). `EventSink` returns
      `Refused::{Full, Closed}`; a closed channel is counted in `drop_event_closed` and
      never retained. `zeroed_box` is bounded by an `unsafe trait Zeroable` implemented
      for the three C structs. `DataplaneConfig::warnings()` (logged by `validate`) flags
      `realtime_priority` with `busy_poll_rounds > 0` and `cpu_affinity` (shard 0
      busy-polls as SCHED_FIFO on core 0). New counters: `rx_unreadable`,
      `tx_full_flushes`, `drop_event_closed`.

**Tests** (`tests/loopback.rs`, Linux and macOS):
- Two in-process peers on real UDP sockets against a running shard: STUN, nomination,
  `InstallSrtp` with synthetic keys, publisher → subscriber media through the kernel, over
  IPv4 and (where the host has it) IPv6 loopback.
- Commands sent to a parked shard are handled within 10 ms (wake works).
- With `busy_poll_rounds = 0` an idle shard's CPU time over 1 s stays under 5% (parking
  works). **Local only** (`#[ignore]`, run with `--ignored`): CPU time on shared CI runners
  is too noisy to gate on.
- `shutdown()` joins within 100 ms; `is_running()` false after.
- A burst larger than the send batch and a flood beyond socket buffers: drops counted, no
  blocking, no panic.
- Linux: the shard socket has UDP_GRO off; a 1,600-byte datagram into a 2,048-byte buffer is
  delivered, a 3,000-byte one is dropped as truncated.

**Checkpoint:** `cargo test -p nexus-dataplane` green on macOS and in the Linux container.

---

### 1.4 SDP groundwork and shared DTLS certificate

**Goal:** the SDP, signaling and DTLS changes the switch needs, made so the old path keeps
working.

**Files:** `crates/nexus-webrtc/src/sdp/{mod.rs, session.rs, parser.rs, printer.rs,
negotiator.rs, media.rs}`, `crates/nexus-webrtc/src/webrtc/session.rs` (compile fixes only),
`src/orchestrator/negotiation.rs` (compile fixes, old-path cap),
`crates/nexus-signal/src/websocket/server.rs`,
`crates/nexus-transport/src/dtls/openssl_backend.rs`.

**Change:**
- `SessionDescription::media: Vec<MediaDescription>`, bounded by `MAX_MEDIA_SECTIONS = 32`
  (parse error beyond it); remove the compile-time assertion that claims 8 "per WebRTC
  spec" (`sdp/mod.rs:75-78`, and its test at `:130`); `media_count` becomes `media.len()` or
  stays as a mirror, whichever touches less.
- **BUNDLE:** `bundle_group: [u8; 64]` (`session.rs:130`) is silently truncated when set
  (`:241`) and parsed (`parser.rs:179`, `:581`), which breaks BUNDLE at ≈ 22 mids. Size it
  for 32 mids (`MAX_MEDIA_SECTIONS × (MAX_MID_LEN + 1)`) and return an error instead of
  truncating.
- **Size limits:** `MAX_SDP_SIZE` (64 KB, `sdp/mod.rs:69`) is enforced by `assert!` in
  `printer.rs:69` and `session.rs:332`: raise to 128 KB and return an error. The WebSocket
  server drops text messages over `MAX_MESSAGE_SIZE` (64 KB,
  `nexus-signal/src/websocket/server.rs:41`, `:470`) silently: raise to 256 KB and log a
  drop.
- The old path's m-line cap is `MAX_MLINES = MAX_MEDIA_SECTIONS` (`negotiation.rs:27`):
  give it its own constant of 8 until 1.5b, so raising the SDP bound does not change what
  the old path accepts (its `webrtc/session.rs:1860,1957` assert `media_count ≤ 10`).
- `RecycledMline::rtcp_fbs` (today: `mid, media_kind, codecs, fmtps, offer_pts, extmaps,
  direction`, `negotiator.rs:149-162`). `OfferMline::Track { ssrc, media_kind, mid }` gains
  `stream_id` and `cname`; also built by `create_renegotiation_offer` (`:722-770`).
  - Today it prints `a=ssrc:<ssrc> cname:nexus-<ssrc>` and
    `a=ssrc:<ssrc> msid:nexus-stream-<ssrc> nexus-track-<mid>` (`negotiator.rs:1062-1072`),
    with no media-level `a=msid`. Print `a=msid:<stream_id> <track>`,
    `a=ssrc:<ssrc> cname:<cname>` and `a=ssrc:<ssrc> msid:<stream_id> <track>` with the
    **same** values; never two different msids for one m-line.
- Extension table: the negotiator takes its extmaps from `nexus-dataplane`'s `ext.rs` (or a
  copy of the constant in `nexus-webrtc` if the dependency direction is awkward; one of them
  asserts they match in a test). Today `create_ordered_offer` takes extmaps per kind
  (`:787-788`) and the orchestrator passes `&[]`; only recycled m-lines get `sdes:mid`,
  added by the negotiator (`:882-897`).
- `DtlsCertificate` (EC P-256 key + self-signed X.509 + fingerprint), created once;
  `OpenSslDtlsEngine::with_certificate(role, &DtlsCertificate)` builds only the `Ssl` from a
  shared `SslContext`. `new(role)` stays for the old path until C6.

**Code notes (audited 2026-09-26):**
- `.media[` / `media_count` uses: `parser.rs` 29, `session.rs` 17, `negotiator.rs` 13,
  `webrtc/session.rs` 8, `negotiation.rs` 9, `printer.rs` 4; no other files.
  `negotiation.rs` loops cap at `.min(8)` / `.min(16)` (lines 596, 616, 637, 853): replace
  with the vector's length.
- `MediaDescription` is ≈ 18 KB of inline arrays (estimate), so a 32-m-line
  `SessionDescription` is ≈ 580 KB while it lives. Control-plane memory is in the budget
  (1.7): if the memory bench shows `NegotiationState` keeping descriptions, box or shrink
  them there.
- `OpenSslDtlsEngine::new` generates the key and certificate at `openssl_backend.rs:177`
  (fingerprint at `:240-247`, context from `:249`). `start_handshake` builds the `Ssl` from
  `self.ctx` (`:400-404`), so `with_certificate` is small. `use_srtp` order
  (`AES128_CM_SHA1_80:AEAD_AES_128_GCM`, `:279-284`) changes in 1.5b, not here: the old
  path's e2e runs are what keep this part honest.
- Rtcp-fb offered today (`negotiator.rs:1003-1034`): subscribe video `nack`, `nack pli`,
  `goog-remb`, `transport-cc`; subscribe audio `transport-cc`; publish m-lines none; `ccm
  fir` never.
- Found while implementing (2026-09-27), corrections to the notes above:
  - **Two remote panics in the SDP parser**, reached by any client through `Answer.sdp`
    (exit criterion 6): `parse_line` sliced `&line[2..]` after checking the second
    *char*, so a line such as `€=x` panicked; `parse_hex_bytes` (`attributes.rs`) sliced
    byte pairs of a fingerprint with only an even-length guard, so a non-ASCII value
    panicked. Both are errors now; unit tests and four proptests (arbitrary lines,
    `<char>=` lines, every attribute name with arbitrary values, fingerprint values),
    each checked to fail with its fix disabled; 20,000 cases per property found nothing
    else.
  - `MAX_SDP_SIZE` had its own const assertion (`== 64 KB`), changed with it.
    `MAX_MID_LEN` did not exist: `Mid` silently cut at 16 bytes. `Mid::parse` (used by the
    parser) refuses an empty or longer mid; `Mid::new` stays for our own mids.
  - BUNDLE was cut at `parser.rs:581` and `session.rs:240` (not `:179`, which is `s=`),
    from the 26th numeric mid on (not ≈ 22) or at 4 mids of 16 characters.
    `bundle_group` is `[u8; MAX_BUNDLE_LEN]` (32 × 17) with a `u16` length;
    `set_bundle_value` refuses an over-long value.
  - `media_count` is gone (not mirrored): every user iterates `media`.
  - `SdpPrinter::print` and `SessionDescription::to_sdp` return `Result`: answers copy
    the offer's rtcp-fb and extmaps, so a 32-m-line answer can exceed 128 KB (≈ 180 KB
    worst case) and the size assert was reachable.
  - The old path's `media_count <= 10` asserts (`webrtc/session.rs`) are in
    `handle_renegotiation_{offer,answer}`, which nothing calls; they return
    `InvalidConfig` now. The old orchestrator refuses an answer with more than
    `OLD_PATH_MAX_MLINES` (8) m-lines, since the parser now accepts 32.
  - The WebSocket server logged oversized messages (`warn!`), it did not drop them
    silently, but sent nothing back; and tungstenite ran with its defaults (64 MB per
    message buffered before the check). Now 256 KB with an `Error{MESSAGE_TOO_LARGE}`
    reply, and 1 MB `max_message_size`/`max_frame_size` (connection closed above).
  - **Extension table** moved to `nexus_media::rtp::extensions` (owner's decision:
    neither `nexus-webrtc` nor `nexus-dataplane` depends on the other);
    `nexus_dataplane::ext` re-exports it, `nexus_webrtc::sdp::offered_extmaps(kind)`
    yields `(id, uri)` for `create_ordered_offer`.
  - `RecycledMline::rtcp_fbs` is `&[(type, params)]`, printed for every codec of the
    m-line; more than `MAX_RTCP_FB_PER_MEDIA` in total is an error (the media type
    silently drops extras). `OfferMline::Track` gains `stream_id`/`cname`;
    `create_renegotiation_offer` takes `&[TrackMline]`. An id that `Msid` (128 B) or
    `SsrcInfo` (256 B) cannot store whole, or that is empty or contains whitespace, is
    an error, so the two msid lines can never differ. The old path passes today's values
    (`nexus-stream-<ssrc>`, `nexus-<ssrc>`) and only gains a media-level `a=msid` with
    the same value.
  - Track m-lines keep their hard-coded rtcp-fb (`nack`, `nack pli`, `goog-remb`,
    `transport-cc`): the old path runs on them. 1.5b decides the subscribe set (§12.4:
    no transport-cc or REMB in v1).
  - `DtlsCertificate` (`Clone`: refcounted `SslContext`, `Arc<[u8]>` DER) with the key,
    certificate and context code split out of `new` into `generate_key`,
    `build_certificate`, `fingerprint_of`, `build_context`; the engine holds a
    `DtlsCertificate` and `new(role)` = `with_certificate(role, &generate()?)`.
    `openssl_backend.rs` had no tests: engine-to-engine handshake on one certificate
    (fingerprints, peer fingerprints, identical exported keys), two sessions on one
    context, `new` still per engine.
  - Control-plane memory for 1.7: each engine preallocates `pending_output` of
    `MAX_BIO_READ` (16 KB) until the `Ssl` is freed.
  - **Review fixes (2026-09-27), before commit:**
    - The first publish skipped the old-path m-line cap (only the existing-transport
      branch checked it): 9-10 kinds produced an offer whose answer `handle_answer`
      refuses, `offer_pending` stayed set, and `send_ordered_offer`'s assert was
      reachable. The cap is now checked before `create_transport` for both branches
      (`TOO_MANY_TRACKS`); test on a real `NegotiationManager`.
    - `create_answer_media` asserted the offered m-line had codecs or formats: an offer
      with `m=application ... webrtc-datachannel` (or non-numeric formats) panicked
      `SdpNegotiator::negotiate`. Now `NoCommonCodec`. `rtpmap` accepted PTs up to 255,
      and `create_ordered_offer` indexes a 128-entry `used_pts` with recycled and
      negotiated PTs (which come from answers in 1.5b): `RtpCodec::parse` refuses
      PT > 127, and `create_ordered_offer` returns an error for one.
    - Shared DTLS context: session cache off (`SslSessionCacheMode::OFF`). Measured:
      with `SSL_VERIFY_PEER` and no session id context OpenSSL already caches nothing on
      the server, so this is defence in depth; the test checks the mode (it was 2,
      `SERVER`) and that three handshakes leave the cache empty. Serial is a random
      64-bit number (was 1 for every certificate), `not_before` one day back.
    - Parser: no meaning-changing truncation. ice-ufrag/pwd are 1-256 ice-chars
      (RFC 8445 §5.3), msid ids ≤ 128 bytes (`Msid::new`), ssrc attribute ≤ 32 and value
      ≤ 256 bytes, extmap URI ≤ 128 bytes and id ≠ 0: anything else is a parse error. The
      remaining cuts (session name, origin, codec name, fmtp params, rtcp-fb, candidate
      foundation, rid, simulcast) are not read for meaning by the SFU. `Mid::parse`
      accepts token characters only (RFC 5888), duplicate mids are refused. The m=
      format list stored PT 0 for every unparsable entry before a valid one; it now
      skips them (and PTs > 127). ssrc lines beyond 8 per m-line are still dropped
      (simulcast with RTX needs ≈ 12: after v1).
    - Proptests: `PROPTEST_CASES` sets the case count (default 50), values up to 300
      characters (past every field's capacity), a value strategy shaped like ssrc/extmap
      /rtpmap values, and `prop_negotiate_never_panics` (weighted offers: ≈ 36% produce
      an answer, the rest exercise the error paths). It catches the old
      `create_answer_media` assert. 20,000 cases per property found nothing else.
    - Each new test checked to fail with its fix disabled.
    - Left for 1.5b (found in the verification, not crashes): the parser accepts extmap
      ids 1-255; the switch must refuse ids above 14 before writing one-byte header
      extensions (15 is reserved). On the old path an answer with more than 8 m-lines
      is refused with `offer_pending` still set, so only that client stalls.

**Tests:**
- Parser/printer round trip with 20 and 32 m-lines, BUNDLE with all 32 mids intact; 33
  m-lines and an over-long BUNDLE line are errors, not truncations.
- A 32-m-line offer with extmaps and rtcp-fb prints under 128 KB and passes the WebSocket
  server's size check.
- An offer with `stream_id`/`cname` prints the expected `a=msid` and `a=ssrc` lines with one
  msid value; a recycled m-line prints its `rtcp_fbs`.
- Two engines from one `DtlsCertificate` handshake with each other and report the same local
  fingerprint.

**Checkpoint:** the whole workspace green, **e2e still green on the old path**.

---

### 1.5a Control-plane pieces

**Goal:** the new orchestrator building blocks as standalone, unit-tested modules, before the
switch: nothing calls them yet.

**Files:** `src/orchestrator/{ids.rs, dtls.rs, transports.rs, tracks.rs, sdp_params.rs}` (new),
root `Cargo.toml` (`nexus-dataplane` dependency) and `Cargo.lock`,
`crates/nexus-transport/src/dtls/{openssl_backend.rs, crypto.rs}` (input guards, MTU, profile
conversion), `crates/nexus-webrtc/src/sdp/{attributes.rs, media.rs}` (read accessors only).

**Change:**
- Root crate depends on `nexus-dataplane` (today only a workspace member, `Cargo.toml:2`).
- `ids.rs`: `IdAllocator` with counters for `SessionId`, `TrackId`, `SubscriptionId` (start
  at 1, never 0, asserted never to wrap). `TrackId`s come from `WorkerPool::assign_track`
  (`pool.rs:3981`) today; the value stays the signaling `track_id` (note §4).
- `dtls.rs`: `DtlsHandshake` wraps `OpenSslDtlsEngine::with_certificate` and the pinned
  fingerprint, with the logic of `check_dtls_completion` / `initialize_srtp`
  (`webrtc/session.rs:1480`, `:1646`) without the copy into the pure-Rust `DtlsSession`
  (`:2298-2331`). Details the note leaves out:
  - **Role, fixed lazily.** The SFU offers `actpass`; browsers answer `active` (SFU = DTLS
    **server**), webrtc-rs answers `passive` in `dtls_survives_lost_first_flight` (SFU =
    client). The engine's role cannot change once started (`set_role` asserts `!started`,
    `openssl_backend.rs:440`), and a ClientHello can arrive before the answer is processed.
    So the engine is created by whichever comes first: a ClientHello (role Server, engine
    put in accept state, then fed) or the answer (`active` → Server, accept state at once;
    `passive` → Client, started on the first `AddressSelected`). An answer that contradicts
    a role already fixed by a ClientHello fails the handshake.
  - **Fingerprint.** DTLS can complete before the answer: completion is Pending until the
    fingerprint is pinned, then Match or Mismatch (as `check_dtls_completion`; no peer
    fingerprint is Mismatch, an all-zero pinned value is an error, not an assert).
  - **Output.** `process` and `handle_timeout` return one concatenated `Vec<u8>` (the
    memory BIO appends), and no MTU is set: the BIO answers the MTU query with 0, so OpenSSL
    fragments at its minimum and the old path sends the whole flight as one datagram. Now
    `start_handshake` sets `DTLS_MTU` = 1,200 (`SslRef::set_mtu`, `NO_QUERY_MTU` on the
    context) and `DtlsHandshake` splits the output at record boundaries into datagrams of
    ≤ 1,200 bytes (one `SendDatagram` each in 1.5b).
  - **Input guards.** `process` and `MemBio::feed` assert non-empty and ≤ 16,384 bytes
    (`openssl_backend.rs:504-505`, `:81-82`); `set_role`/`start_handshake` assert
    `!started`. `process` returns an error instead, the role/start asserts become errors,
    and `DtlsHandshake` checks the length first.
  - **Timeout.** Own constant `DTLS_HANDSHAKE_TIMEOUT` = 10 s from the first
    `AddressSelected`. Today there are two: `webrtc/mod.rs:70` (10 s) and `session.rs:104`
    (30 s, the one used); both go in C6. OpenSSL retransmits at 1, 2, 4 s fit.
  - **Keys.** No export API: keys come from `engine.srtp_keys()` (`SrtpKeyMaterial`). New
    `SrtpProfile` → `srtp::ProtectionProfile` conversion (none exists; `initialize_srtp`
    matches by hand). `SrtpInstall` by role (server: local = server key‖salt, remote = client
    key‖salt; client: the reverse) via `KeyMaterial::from_dtls_export`. All-zero keys are an
    error. Beware `nexus_transport::dtls::KeyMaterial` (TLS record keys): use
    `srtp::KeyMaterial`.
  - `free_ssl()` drops the engine; the entry stays usable (later datagrams ignored).
- `transports.rs` (note §6.5): `Transports` = `HashMap<SessionId, TransportEntry>` plus
  participant ↔ session maps (replacing `register_transport` / `transport_to_participant`
  in 1.5b). Entry: `shard`, `IceParams` (random 16-char ufrag, 32-char password from the
  ice-char set), `DtlsHandshake`, state, `SsrcAllocator`, `created_at`,
  `address_selected_at`. `sweep(now)` reports the ICE-connect timeout (30 s without an
  address) and the DTLS timeout.
- `SsrcAllocator`: random non-zero `base` (offset 0 is the session's `rtcp_ssrc` on the
  shard, `session.rs:172`), offsets from 1 strictly increasing and `< 2^31`, skips 0 and the peer's
  SSRCs (bounded loop, `None` when exhausted).
- `tracks.rs`: `TrackRegistry` (TrackId → publisher, session, shard, kind, codec + name,
  mid, ssrc, ext ids, cname, content type).
- `sdp_params.rs` (pure, on `&MediaDescription`): `TrackSpec` for a publish m-line (primary
  SSRC = first `a=ssrc` that is not a non-first member of an `a=ssrc-group`, an
  `a=ssrc-group:SIM` is an error since v1 has no simulcast; PT and clock rate of the
  offered codec; `ExtIds` by URI; cname = the SFU's `nexus-{publisher}` passed in, never
  the publisher's own, note §6.5) and `SubSpec` for
  a subscribe m-line (`PtMap` by codec name + clock rate, `ExtMap` publisher id → URI →
  subscriber id, subscriber `mid`; inactive or rejected m-line → none). Extension ids > 14
  are an error (left open by 1.4). The SDP types have no string accessors for extmap URI,
  `a=ssrc` attribute/value or ssrc-group semantics: small ones are added in `nexus-webrtc`.

**Tests:**
- Handshake between a `DtlsHandshake` and a plain OpenSSL peer (`OpenSslDtlsEngine::new`) in
  both roles, including ClientHello before the answer and a ClientHello followed by a
  `passive` answer (error); keys picked by role match the peer's; fingerprint mismatch
  fails; completion before the fingerprint waits and then succeeds; `free_ssl` leaves the
  entry usable; every datagram of the certificate flight is ≤ 1,200 bytes and the handshake
  completes with datagrams fed one at a time; a lost first flight recovers through
  `handle_timeout`.
- Empty, 1-byte, 16,385-byte and random datagrams into `DtlsHandshake::process` in every
  state and into `OpenSslDtlsEngine::process`: error or nothing, no panic; the record
  splitter fuzzed.
- `SsrcAllocator`: 10,000 allocations strictly increasing in offset, never 0 or a peer SSRC.
- `sdp_params`: Chrome-, Firefox- and webrtc-rs-shaped answers (fixtures in the test) give
  the expected specs; a declined extension maps to 0; id 15 is an error; an FID group's
  secondary SSRC is not the track's SSRC; a remapped subscriber PT is found; a codec the
  publisher does not send is an error.

**Code notes:**
- Found while implementing (2026-09-27):
  - **MTU measured.** Without an MTU OpenSSL cut records at its 256-byte minimum (the
    certificate spread over records of ≤ 180 bytes); with `DTLS_MTU` the certificate is one
    320-byte record. The whole server flight is ≈ 650 bytes, so the split rarely produces
    more than one datagram today; it is the guarantee, not a fix for an observed failure.
    `flights_are_cut_into_records_that_fit_the_mtu` fails without the MTU.
  - `OpenSslDtlsEngine::set_role` returns `Result` (the old `WebRtcSession::set_dtls_role`
    maps it to `InvalidState`); `start_handshake` twice and `process` on empty or
    oversized input are errors. `SrtpKeyMaterial`, `DTLS_MTU`, `MAX_BIO_READ` exported from
    `nexus_transport::dtls`; `SrtpProfile::protection_profile()` added.
  - `DtlsHandshake` lives in its own `src/orchestrator/dtls.rs` (tests in `dtls_tests.rs`).
    An invalid-length datagram is refused without a state change; any other error fails
    the handshake for good and drops the OpenSSL state. Before the engine exists, only a
    ClientHello starts it; other datagrams are ignored. `Progress::completed` is true once,
    on the step that completes with a matching fingerprint.
  - `sdp_params` also refuses two used extensions on one id (the shard would reject the
    `Subscribe`). `TrackSpec` and `SubSpec` derive `PartialEq`/`Eq` (tests).
  - **CNAME (review):** `TrackSpec::cname` is the SFU's `nexus-{publisher}` (note §6.5),
    given by the caller; the publisher's own `a=ssrc … cname:` is not read. The same value
    goes into subscriber offers and translated SDES, and one participant's CNAME is never
    shown to another.
  - **Review fixes (2026-09-27), before commit:**
    - `free_ssl` acts only on a complete handshake (it was a `debug_assert`: in release, a
      stray early `free_ssl` dropped the engine and a later ClientHello started a second
      one, reporting `completed` twice). It returns whether it freed.
    - `a=ssrc-group:SIM` on a publish m-line is `ParamsError::Simulcast` (was: first layer).
    - `SsrcAllocator` redraws a zero base (`new(0)` asserts: the base is the RTCP SSRC).
    - Tests: the peer's flights reach the SFU one record per datagram; lost server flight
      with the SFU as server, recovered by the peer's ClientHello retransmission (no SFU
      timer); fingerprint mismatch when the answer arrives after DTLS completed.
  - Each new safeguard checked to fail with its fix disabled: role conflict, peer-SSRC
    skip, length guard, FID secondary, fingerprint mismatch, MTU; after review also
    `free_ssl` before completion, SIM refusal, zero-base redraw.

**Checkpoint:** workspace green, old path unchanged (e2e 3/3; Linux container, the part
touches DTLS I/O).

---

### 1.5b-prep Groundwork that keeps the old path green

**Goal:** everything the switch needs that works on the old path too, so the switch commit
only rewires. One commit.

**Files:** `src/node.rs` (new), `src/sfu.rs`, `src/config/{mod.rs, loader.rs, tests.rs}`,
`src/main.rs`, `config/*.toml`, `crates/nexus-webrtc/src/sdp/negotiator.rs`,
`crates/nexus-loadtest/src/{client.rs, media.rs, track_stats.rs}`, `tests/e2e.rs`.

**Change:**
- `node.rs`: node id generation, `DistributedState`, SWIM and the gossip thread
  (`sfu.rs:492-778`) and the client shutdown notice (`:2232`) move out of `Sfu`. `Sfu::new`
  calls them until C1+C3, `server.rs` after the switch: no copy exists at any time.
  `clock::now_ns` and `WorkerError` are not used there.
- Config `[dataplane]` (note §14) with `#[serde(default)]`: `shards`, `busy_poll_rounds`,
  `pool_buffers`, `consent_timeout_ms`, `rebind_silence_ms`, `cpu_affinity`,
  `realtime_priority(_level)`. `to_dataplane_config` builds `DataplaneConfig` (bind address
  and buffers from `[transport]`, `reserved_ports` = signaling, API and metrics ports,
  `max_sessions` from `max_webrtc_sessions`) and validation calls its `validate`.
  `--shards` (`main.rs:65-131`), `NEXUS_SHARDS` (`loader.rs:96`), the section in the four
  `config/*.toml` (production: `busy_poll_rounds = 256`). Not used until the switch.
- Negotiator: `ice_lite` option (`SessionDescription::ice_lite`, never set today); Track
  m-line rtcp-fb passed in instead of hard-coded (`negotiator.rs:1121-1156`); the old path
  passes today's set (test: its offer is unchanged).
- Loadtest client (on the old path SSRCs and payloads pass through unchanged, so the checks
  hold there too): one `stream_id` per client (`client.rs:640`, `:653`; no longer needed for
the CNAME check, since the SFU writes `nexus-{publisher}` itself, but it makes the client
announce one stream like a browser; optional); the senders of
  `add_track` kept; payload marker (SSRC, frame counter) in the first 8 bytes of each frame
  (`media.rs`), checked by the `on_track` reader, mismatches in `TrackStatsMap`; the SSRCs
  of each SFU offer recorded per mid (`announced_ssrcs()`).
- `two_party_audio_video` checks the marker. The SSRC comparison stays "published" until
  the switch.

**Checkpoint:** workspace green, e2e 3/3 on the old path, Linux container.

---

### 1.5b Switch: orchestrator on commands

**Goal:** the SFU runs on `nexus-dataplane`. One commit. The old path is no longer started
but still compiles.

**Files:** `src/server.rs`, `src/main.rs`, `src/orchestrator/{mod.rs, negotiation.rs,
subscription.rs, connection.rs, events.rs, candidates.rs}`, `openssl_backend.rs` (`use_srtp`
order), `tests/e2e.rs`, `tests/e2e/harness.rs`. Config, `node.rs`, the negotiator options and
the loadtest client changes land before, in 1.5b-prep.

**Change** (the file-by-file tables of note §6.5, in full, plus):
- `server.rs`: `to_dataplane_config` → `Dataplane::start`; per-shard candidates via
  `candidates::resolve` (signature `(&[IpAddr], SocketAddr) -> Result<Vec<SocketAddr>,
  String>`, unchanged). `node.rs` (1.5b-prep) for node id, `DistributedState`, gossip and the
  shutdown notice with its drain sleep; `shared_shutdown` and `MetricsCollector::new(shards)`
  created here. `start_api` gets the collector and state from there. `dataplane.shutdown()`
  runs in `spawn_blocking`. `ServerHandle.media_addr` → `media_addrs` (per shard);
  `packet_loop` → the dataplane handle; `ServerHandle::is_finished()` (`main.rs:379`)
  reports whether the shards stopped. The ingress
  thread and `PacketSender` go.
- `mod.rs`: constructor takes `DataplaneHandle`, `Vec<ShardInfo>`, placement; `select!` on
  dataplane events; ICE/consent/cleanup intervals removed; 1 s sweep added (ICE-connect and
  DTLS timeouts, `Transports::sweep`); `Unpublish` → `RemoveTrack` **and** the
  `TrackRegistry` and `DistributedState` entries (today it only touches `ssrc_router`,
  `mod.rs:259-299`). One helper pushes commands: `CommandQueueFull` → `Error` to the client
  and the session closed (note §5.3), never dropped silently.
- `negotiation.rs`: `create_transport` → `SessionId`, placement, `CreateSession`; offers
  with `a=ice-lite` (`SessionDescription::ice_lite`, never set today), fixed extmaps,
  publish rtcp-fb `nack pli` + `ccm fir`, subscription m-lines with the allocated out SSRC,
  `stream_id`/`cname` `nexus-{publisher participant}` (the cname is `TrackSpec::cname`, the
  same value the translated SDES carries); `handle_answer` → `AddTrack` per
  publish m-line and `Subscribe` per answered subscribe m-line (from `sdp_params`); remote
  candidates accepted and ignored; `cleanup_participant` → `CloseSession`.
  - **Every offer goes through `create_ordered_offer`.** The first publish builds its offer
    by hand today (`negotiation.rs:347-386`: no extmaps, no BUNDLE, no rtcp-fb, no
    media-level ICE), so `mid` SSRC learning could not work on it. Codecs passed explicitly
    (VP8, Opus): with `None` the Track m-lines offer the default list (VP9, H264, AV1
    included) and a subscriber answering another codec gets no `PtMap` match.
  - `MlineRole::Subscribe` carries `SubscriptionId`, out SSRC (allocated when the slot is
    filled, at offer time) and whether it is on the shard. `handle_answer` pushes
    `Subscribe` for every answered, active slot not yet on the shard, in increasing out-SSRC
    offset (monotonic by construction, given the fresh-SSRC rule for a slot overtaken by a
    higher offset below). This replaces `pending_mid_map`.
  - DTLS role and fingerprint from the answer go to `DtlsHandshake::on_answer`; remote ICE
    credentials are no longer read. A `sdp_params` error answers `Error` for that m-line.
  - **Fingerprint:** only `sha-256`. An answer may carry several `a=fingerprint` lines
    (RFC 8122); pick the sha-256 one, refuse an answer without one, and never truncate a
    longer digest to 32 bytes. Check what the parser keeps when a level has several lines
    (today one `Option<DtlsFingerprint>` per level) and fix it here if it keeps the wrong
    one.
  - **Setup:** `a=setup:active` or no `a=setup` → the SFU is server; `passive` → client;
    `actpass` (not a valid answer) and `holdconn` are errors (as
    `dtls_role_from_answer` does today, `negotiation.rs:616`).
  - **Out SSRC of a late slot:** a subscribe slot whose out SSRC was allocated in an offer
    but not yet registered on the shard, when a slot with a higher offset has been
    registered since (the shard's high-water mark), gets a fresh SSRC on its next offer;
    an SSRC below the high-water mark is never sent in a `Subscribe` (the shard would
    refuse it as `OutSsrcNotMonotonic`).
  - **Local candidates stay trickled:** `start_ice_gathering` (`:652`) sends the session's
    shard candidates as `IceCandidate` messages plus end-of-candidates; `ice-options:trickle`
    stays in the offer. No connectivity checks are started.
  - `register_transport` / `transport_to_participant` are re-keyed by `SessionId`.
  - The old m-line cap constant from 1.4 goes; the limit is `MAX_MEDIA_SECTIONS` with an
    error to the client beyond it (R9).
  - Subscribe (Track) m-lines still offer `nack`, `nack pli`, `goog-remb`, `transport-cc`
    (kept in 1.4 for the old path). v1 set: `nack pli` and `ccm fir` only (§12.4: no
    transport-cc or REMB in v1; the shard ignores NACK from subscribers).
- `subscription.rs`: `Unsubscribe` commands; `handle_session_established` deleted (active
  on answer; called from `mod.rs:204`, `:332`); viewport / content type without data-plane
  effect. A `Subscribe` request with more than 10 ids is answered with `Error` instead of
  being silently cut to 10 (`subscription.rs:135`); the constant duplicated at
  `negotiation.rs:25` is removed.
- `connection.rs`: `handle_event` for `DtlsDatagram` (one `SendDatagram` per output
  datagram), `AddressSelected` (start the handshake if the SFU is DTLS client; the first one
  starts the DTLS timeout), `PeerSrtpVerified` (`free_ssl`), `ConsentLost`,
  `CommandRejected` (logged; `UnknownSubscription` after `RemoveTrack` is expected);
  `InstallSrtp` on completion with a matching fingerprint; 200 ms tick keeps DTLS retransmission and the handshake
  timeout. `DisconnectReason` (`events.rs:26`) gains `DtlsFailed`; `IceFailed`, never
  constructed today, is now used by the ICE-connect timeout.
- `use_srtp`: `SRTP_AEAD_AES_128_GCM` first.
- **Shard: DTLS only from the selected address.** `handle_dtls`
  (`nexus-dataplane/src/shard/ingress.rs:209`) looks the source up in `by_addr`, which
  holds every address that sent an authenticated binding request and the previous address
  after a switch. It forwards `DtlsDatagram` only when the source is the session's
  selected address (`session.addr`), else counts a drop; `SendDatagram` already goes to
  that address. Test in `tests/shard.rs`: DTLS from a checked but unselected candidate
  produces no event.
- `ServerHandle` users: `main.rs:349`, `harness.rs:66`, `e2e.rs:150` use `media_addrs[0]`.
- Tests (note §17.1): `two_party_audio_video` compares against the SSRCs each client's offer
  announced for the peer's tracks (`announced_ssrcs()`, 1.5b-prep; `tests/e2e.rs:61-67`
  already flags this) plus the marker; `candidate_is_announced_address` uses
  `media_addrs[0]`.

**Code notes (audited 2026-09-26):**
- Old-path references to replace. `SsrcRouter`/`WorkerPool`: `negotiation.rs` 12, 15,
  145-181, 249, 544-557, 877-913, 1146, 1226-1230; `subscription.rs` 12, 55, 63, 219, 296,
  361, 429, 466, 481; `mod.rs` 22, 25, 53-65, 265; `server.rs` 126-178.
  `WebRtcTransport`/`TransportId`: `negotiation.rs` 21, 45-56, 85, 145-254, 325, 399-509,
  652, 729-829, 984, 1068-1099, 1236; `mod.rs` 27-30, 52-78; `connection.rs` throughout.
- Functions deleted (line numbers as of `474583a`): `pending_mid_map` (`negotiation.rs:92`),
  `settled_established_transport` (`:203`), `get_srtp_key_material` (`:223`),
  `take_pending_mid_map` (`:238`), `selected_remote_addr` (`:246`). `start_ice_gathering` is
  at `:671`. The older line lists above drifted by ≈ 4 lines after 1.4: grep the names.
- Payload marker: the VP8 payloader prepends a 1-byte descriptor and splits frames, so the
  marker is only in the first packet of a frame, after the descriptor; Opus samples (960
  bytes of PCM) are the payload as is. The marker's first byte becomes the VP8 payload's
  first byte, whose bit 0 is the inter-frame flag: no test may rely on keyframe detection of
  synthetic frames.
- `ColdPathPacket` (`events.rs:37`) and the ingress channel go; `Sfu` still builds (it is not
  started) until C1+C3.

**Tests:** the three Phase 0 e2e tests, adapted, pass on macOS and in the Linux container;
`cargo test --workspace` green.

**Checkpoint:** as above, plus an **early browser check**: Chrome and Firefox connect through
the new path (note §17.9 steps 1-2: media both ways, ICE-lite remote, cipher reported), using
the page from 1.8 if it exists, else a scratch page. Result recorded in the session log. A
failure here stops the phase until understood (note §19, first risk).

---

### Deletion steps

One commit per step, green after each (engineering rules above). Run them in the table's
order; each step lists what forces it after the previous ones. Budget: C2 and C1+C3 one
session, C4 and C6 one, C5 and C7 one.

| Step | After | Removed | Also |
|------|-------|---------|------|
| C2 | 1.7 | The old `real_path` and `memory` bench code, replaced by the ports from 1.7, so CI's bench smoke and memory budget never lose coverage; `benches/forwarding.rs` (measures `SsrcRouter`); `benches/packet_processing.rs` ported to the shard's classifier or deleted (it imports `quick_classify`/`PacketType` from `nexus-webrtc` `demux.rs`) | `Cargo.toml` `[[bench]]` entries |
| C1+C3 | C2 (the old benches use the worker and router) | `Sfu` and the packet loop (`src/sfu.rs`), `SRTCP_SENT_CACHE`, `tests/pps_pipeline.rs`, root `sim` feature, `src/spin.rs`, `src/clock.rs`, `DrainState`, `DropTracker`; `src/worker/`, `src/forward/`, `src/transport/`; `src/proto.rs` and the root `build.rs` prost step (the root crate `include!`s its output only in `proto.rs`) and `check_io_uring_feature` (root `build.rs:19,31`) with the root `io_uring` feature; `lib.rs` modules and re-exports (39, 47, 50, 52, 56, 59, 134-139, 161-190); `CoreSfuError::Worker` / `WorkerError` (`nexus-core/src/error.rs:52`, `:322`) and the root `src/error.rs:24,61,85` wrappers | Merged because `worker/pool.rs` uses `SpinLoop` (`:367`, `:786`), `clock::now_us` (`:2296`) and `sfu::forget_publisher_srtcp` (`:4038`): deleting `sfu.rs` alone does not build. Root deps removed if unused after the step, each checked by a build: `prost`, `prost-build`, `capnp`, `capnpc`, `crossbeam`, `dashmap`, `memmap2`, `core_affinity`, `once_cell`, and the already unused `sysinfo`, `getrandom`, `tokio-util`, `futures-util`, `tokio-tungstenite`, `hyper`, `tower`, `tower-http`, `axum`, `rustls`, `tokio-rustls`, `rustls-pemfile`, `http`. `protoc` stays required (`nexus-signal` compiles its own schemas); CLAUDE.md unchanged on that point |
| C4 | C1+C3 (the worker imports `nexus-actor` migration types) | `crates/nexus-actor`, `crates/nexus-dst` (it also turns on `nexus-transport/sim` for the whole workspace), workspace entries, `config/mod.rs:157-181` limits (use the orchestrator's constants), `config/tests.rs:333-338`, `lib.rs:70-75`; the `nexus_actor_*` gauges (`nexus-metrics/src/prometheus.rs:228-242`), their test, `scripts/verify_metrics.sh:51` | `nexus_actor::MAX_ROOMS` is 1,000, the orchestrator's `MAX_ROOMS` 10,000 (`room.rs:13`): validation accepts more rooms after this step; tests updated to the new limit. `nexus-core/types.rs` and `production.toml` comments that mention actors |
| C6 | C1+C3, C2 (`Sfu` and the old benches use `WebRtcTransport` and `test-hooks`) | `nexus-webrtc`: `webrtc/transport.rs`, `webrtc/session.rs`, `webrtc/demux.rs`, `webrtc/mod.rs` constants, the `test-hooks` feature and the root dev-dependency that enables it (`Cargo.toml:123`), `OpenSslDtlsEngine::new` (per-session certificate) | SDP stays |
| C5 | C6 (`webrtc/session.rs:69-74` imports `DtlsSession`, `IceAgent`, `IceConfig` and more), C4 (`nexus-dst` uses the arena) | `nexus-transport`: `arena.rs`, `ring_buffer.rs`, `batch.rs`, `udp.rs`, `media_transport.rs`, `io_uring.rs`, `arena_proptest.rs`, `arena_refcount_proptest.rs`, the crate's `io_uring` and `sim` features; ICE `agent.rs`, `checklist.rs`, and `StunServer`; pure-Rust DTLS (`dtls/session.rs`, `handshake.rs`, `record.rs`, and the parts of `dtls/crypto.rs` nothing imports) | Keep `ice/stun/server.rs`'s `create_binding_request` and `generate_transaction_id` (used by `gather.rs` and the tests: move them if `server.rs` goes), `SrtpProfile` and `SrtpKeyMaterial` from `dtls/crypto.rs` (used by `openssl_backend.rs:37`), `gro.rs`, `gso.rs`, `socket_config.rs`, `stun/`, `candidate.rs`, `gather.rs` enumeration, `SrtpContext` (tests use it). `ring` stays (SRTP GCM) |
| C7 | C4, C1+C3 | Config fields of note §14 (`[worker]`, `[memory]`, `actor.*`, `transport.batch_*`, `stun_servers`, `--workers`, `NEXUS_WORKER_COUNT`, `NEXUS_ARENA_SIZE_MB`), the arena ≥ 16 MB and workers ≤ 2 × CPU checks in `validate_cross_module` (`config/mod.rs:148-155`, `:183-196`), `config/*.toml`, README config and feature sections (lines 32-33, 65, 73, 84, 123-127, 142-143, 201), `nexus-metrics` `WorkerPoolMetrics` (`worker.rs:122`) → shard metrics (note §5.4) | `examples/basic_sfu.rs` (reads `memory.*`, `worker.*`, `batch_*`: rewrite or delete, or `--all-targets` breaks); e2e `harness.rs:56-58`; `deploy/docker/run.sh` unchanged for one shard (publishes `10000/udp`) |

**Code notes (audited 2026-09-26):** `tests/pps_pipeline.rs` is `#![cfg(feature = "sim")]`,
not in CI: delete, don't port. After C5, `grep -rn "arena\|io_uring\|MediaTransport" crates
src` must be empty outside comments updated in 1.9. Before each step, `grep -rn` the removed
module and type names in what remains; the audit's importer lists are in this table.

---

### 1.6a E2E: harness, ten clients, resubscribe

**Goal:** the harness changes and two of the new exit tests.

**Files:** `crates/nexus-loadtest/src/{client.rs, lossy.rs, track_stats.rs}`,
`tests/e2e.rs`, `tests/e2e/harness.rs`.

**Change:**
- **Signaling task.** The background task (spawned today only inside
  `discover_and_subscribe`, `client.rs:1120-1170`) becomes the single reader of the
  signaling connection for every client, publisher-only ones included:
  - started once after join; a second start is an error (today a second
    `discover_and_subscribe` overwrites `signaling_stop_flag` and leaks the first task);
  - it keeps answering offers (`answer_offer`, `:1217-1245`) and forwards `Subscribed`,
    `Unsubscribed`, `Error`, `TrackPublished` and each `Offer.tracks` (mid → track id) to the
    test through an `mpsc` channel (today it drops them, `:1160-1162`);
  - `pump_signaling` is not called once the task runs (two readers on one socket).
- `HeadlessClient::unsubscribe(track_ids)` and `subscribe_batch` after the task started: lock
  the shared connection (`Arc<tokio::sync::Mutex<SignalingConnection>>`, `client.rs:82`) and
  send; the task holds the lock only for 200 ms receive timeouts, so a send waits ≤ 200 ms.
  Both wait for the confirmation on the channel.
- Offer bookkeeping on the client: mid → track id (from `Offer.tracks`) and mid → SSRC (from
  `a=ssrc`), so tests map received SSRCs to publishers.
- `LossyUdpConn` tap: an optional bounded recorder of inbound datagrams' (class, SSRC, seq)
  for SRTP and (sender SSRC, E+index) for SRTCP, parsed from cleartext fields (E+index sits
  before the tag for AES-CM and after it for GCM: the test knows the profile from the
  negotiated cipher). **`LossyUdpConn` exists only for clients built with
  `lossy_client_config`** (`client.rs:205-216`, `harness.rs:93`); the new tests build every
  client that way, with zero loss where none is wanted.
- Tests `ten_clients_audio_video` (note §17.2) and `resubscribe_no_srtp_index_reuse`
  (note §17.4).
  - `ten_clients` does not use `discover_and_subscribe`: that stops after one quiet 200 ms
    receive (`:991-996`), so it can miss tracks, and it sends all ids in one request. The test
    waits until each client has seen all 18 `TrackPublished`, subscribes in requests of ≤ 10
    ids, and waits for 18 confirmations.
  - Resubscribe: webrtc-rs replaces a receiver only when an offer without the old SSRC
    arrives before the one with the new SSRC (`peer_connection_internal.rs:170-221`). The
    test checks that `Unsubscribe` produces such an offer (m-line inactive) before the
    resubscribe.

**Tests:** the two tests pass on macOS and Linux; `resubscribe_no_srtp_index_reuse` is
checked to fail when the shard's out-SSRC check and the orchestrator allocator are
temporarily bypassed (reuse the first SSRC), then restored. Suite runtime noted.

**Checkpoint:** e2e green; total e2e runtime under 60 s on macOS. The tests run one at a time
(`harness.rs:21`, `SERIAL`), and the three Phase 0 tests took ≈ 10 s, so `ten_clients` must
stay under 30 s.

---

### 1.6b E2E: address change, SR translation, keyframes

**Goal:** the remaining three exit tests.

**Files:** `crates/nexus-loadtest/src/{client.rs, lossy.rs, Cargo.toml}`, `tests/e2e.rs`,
`crates/nexus-dataplane/src/shard/stats.rs`.

**Change:**
- `LossyUdpConn::rebind()` (the struct is `{ socket: UdpSocket, rules }`, bound once in
  `bind()`, `lossy.rs:189-197`):
  - socket behind `ArcSwap` (add `arc-swap` as a direct dependency at the locked version) plus
    a `tokio::sync::Notify`;
  - `recv_from` selects on the current socket and the notification, so a receive already
    pending on the old socket moves to the new one;
  - the swap never surfaces an error: `UDPMuxDefault`'s loop ends for good on any error other
    than `TimedOut` (`webrtc-ice-0.10.1/src/udp_mux/mod.rs:205-208`).
  - The advertised candidate stays stale; that is fine, the ufrag is unchanged, so the SFU
    sees the same USERNAME from the new port.
- Client RTCP readers: `on_track` (`client.rs:413`, `_receiver` ignored today) spawns a
  `receiver.read_rtcp()` task recording SRs per SSRC and SDES CNAMEs; the publisher spawns
  `sender.read_rtcp()` per sender (from `get_senders()`) recording PLI and FIR per media SSRC
  with arrival times, **before** any subscriber joins; a `send_pli(ssrc)` helper using
  `RTCPeerConnection::write_rtcp` (`peer_connection/mod.rs:1894`).
- `ShardStats` gains `rebinds`, read through `ServerHandle`, to observe
  `AddressSelected{Rebound}` without tapping the event channel.
- Tests `address_change_mid_call`, `sender_report_translation`, `keyframe_requests` (note
  §17.3, §17.5, §17.6).

**Code notes (audited 2026-09-26):**
- **Keepalive timing** (corrects note §17.3). webrtc-ice sends a binding request on the
  selected pair only when nothing was sent **or** nothing was received on it for 2 s
  (`check_keepalive`, `agent_internal.rs:482-512`), checked every 200 ms. During a call it
  sends none. After a rebind the SFU keeps sending to the old port, so the client's receive
  time goes stale: requests start ≈ 2.0-2.2 s after the rebind and repeat every 200 ms. With
  `rebind_silence = 2 s` the first one may be refused and the next accepted: expected
  resume ≈ 2.2-2.6 s. The test asserts < 5 s and logs the measured value. ICE goes
  Disconnected after 5 s without input, Failed after 30 s.
- `register_default_interceptors` (`client.rs:193`) includes the sender and receiver report
  interceptors (reports every 1 s). webrtc-rs sends bare SRs without SDES; the SFU's
  translated compound adds SDES from `TrackSpec::cname` (`nexus-{publisher}`); the check
  compares it with the `a=ssrc … cname:` of the subscriber's offer.

**Tests:** the three tests pass on macOS and Linux; `address_change_mid_call` is checked to
fail with the rebinding rule disabled.

**Checkpoint:** all e2e exit tests green (**exit criterion 1**, except CI on macOS: 1.7).

---

### 1.7 Benches, memory budget, CI

**Goal:** the ported benches, the memory budget in CI, macOS in CI.

**Files:** `benches/real_path.rs`, `benches/memory.rs`, `Cargo.toml`,
`.github/workflows/{ci.yml, release.yml}`.

**Change:**
- `real_path`: same groups (`ingress`, `egress`, `srtp`) and ids
  (`{gcm|cm_sha1_80}/{audio|video}`) and subscriber counts **1, 10, 100, 500**
  (`real_path.rs:55`); ingress (socket buffer → decrypted and routed) and egress per
  subscriber (copy + rewrite + encrypt + send) through `nexus-dataplane` on real loopback
  sockets; prints allocations per packet (a counting allocator, which it lacks today). Keeps
  a criterion harness: the CI smoke run passes `--test`. `LinuxIo` on Linux, `PortableIo`
  on macOS; numbers are only compared within one platform.
- `memory` (note §17.8): data plane through commands on `MemIo`; control plane through the
  orchestrator managers with a fake signaling channel and the transport entry after
  `free_ssl`; scenarios "A+V publisher, no subscriptions" and "+ subscribed to 10 tracks";
  also the `Ssl` size during a handshake. `NEXUS_MEM_BUDGET_KB` checks **"+ subscribed to 10
  tracks"** (the §3.11 scenario; today only the 0-subscription case is checked,
  `memory.rs:382-390`). The budget uses the counting allocator only: malloc zone statistics
  are process-wide (tokio threads add noise at a 25 KB scale) and `mallinfo2` misses mmap'd
  chunks; they stay for the OpenSSL report.
- CI: `NEXUS_MEM_BUDGET_KB: "25"` (was `"1700"`, `ci.yml:92`); bench smoke uses the ported
  benches; a `macos-14` (arm64) job with the pinned 1.83.0 toolchain, `Swatinem/rust-cache`,
  `brew install capnp protobuf`, running `cargo test --workspace` and clippy. `release.yml`
  pins 1.83.0 (it uses `stable`, `release.yml:32`).

**Tests:** the benches run locally on macOS and in the Linux container; numbers recorded in
architecture.md Part 5 in 1.9 (Phase 1 baseline, one shard).

**Checkpoint:** CI green on all jobs (**exit criteria 1 and 3**).

---

### 1.8 SDK, browser page and manual check

**Goal:** what the manual call of note §17.9 needs: SDK calls for every step, a dev token, a
static page, and the recorded check.

**Files:** `sdk/src/{client.ts, …}` and its tests, `crates/nexus-loadtest/src/{cli.rs,
signaling.rs}`, `examples/web/{index.html, main.js, README.md}`.

**Change:**
- **SDK** (`sdk/src/client.ts`; today `connect`, `join`, `publishCamera`/`Microphone`/
  `Screen`, `subscribe`, `attach`, `close`): add `createRoom`, `unpublish(trackId)`,
  `unsubscribe(trackIds)`, `leave()` (sends `Leave`; `close()` only closes the socket), and
  split `subscribe` into requests of ≤ 10 ids. Unit tests for the new calls with a mocked
  socket; `npm run build` and the SDK tests pass.
- **Dev token:** `nexus-loadtest token --sub <name> [--secret …]` prints a JWT signed with
  `NEXUS_JWT_SECRET`, reusing `resolve_token` (`signaling.rs:385`, private today). Nothing
  else issues tokens (`nexus-api` only validates).
- **Page:** static, importing the SDK's ESM build (`"type": "module"`, tsup `esm`). Query
  string: signaling URL, room, token. Create or join the room, publish camera and
  microphone, subscribe to everyone, a video element per remote participant, buttons for
  unpublish/republish, leave/rejoin.
- **README:** `cd sdk && npm ci && npm run build` (`sdk/dist` is gitignored), then serve the
  **repo root** (`python3 -m http.server`) so `../../sdk/dist/index.js` resolves; run the SFU
  with `NEXUS_ANNOUNCED_IPS`. Secure context: `getUserMedia` needs HTTPS or `localhost`, and
  an HTTPS page cannot open `ws://`. Same machine: `localhost`. Second machine: TLS on the
  SFU (`wss://`, existing TLS config) and an HTTPS static server, or Chrome's
  `--unsafely-treat-insecure-origin-as-secure` for a test profile.

**Manual check** (note §17.9 steps 1-6), recorded below in the Status notes with date,
browser versions, networks, negotiated SRTP cipher (expected `AEAD_AES_128_GCM`) and
anything that failed.

**Checkpoint:** SDK tests green; the recorded check passes (**exit criterion 4**). Step 6
(network switch) passes or is recorded as the known ICE-restart limitation.

---

### 1.9 Documents and merge

**Files:** `architecture.md`, `CLAUDE.md`, `README.md`, `docs/dataplane-design.md` (revision
log only, if anything in Phase 1 changed a decision), `docs/design/dataplane-v1.md` (a note
pointing to the corrections below), this plan.

**Change:**
- `architecture.md` Parts 1-2 describe the new path (process layout, data path, what is not
  built yet); Part 2.2 marks the re-subscribe and SRTCP issues fixed; Part 5 gets the Phase 1
  numbers (one shard). The full rewrite is at release.
- CLAUDE.md: "Current phase", "Architecture (today)", workspace structure (no `nexus-actor`,
  `nexus-dst`; new `nexus-dataplane`), commands (benches, e2e; no `--features sim`),
  `[dataplane]` config, the SDK token command.
- Status table and session log complete; merge `phase-1` into `main`.

**Checkpoint:** every exit criterion checked off in the Status table; merged.

---

## Corrections to the design note

Facts in `docs/design/dataplane-v1.md` the audit found wrong. None changes a decision; the
parts above already follow the corrected facts.

| Note | Says | Code |
|------|------|------|
| §8.2, §19 | `StunMessage` ≈ 2 KB; slim scan "if the bench shows" | ≈ 19 KB, moved twice, no attribute offsets: the slim scan is in 1.2a |
| §3.5 | `socket_config.rs` used at bind time | Only `configure_socket_buffers`; `configure_high_performance_socket` enables UDP_GRO |
| §9.1 | `SrtpContext` goes in C5 if only benches use it | Tests and `nexus-webrtc` use it; it stays through Phase 1 |
| §6.1, §6.5 | "start the handshake as client" on `AddressSelected` | With browsers the SFU is usually the DTLS server; client only when the answer says `passive` |
| §16 | C1 alone; C5 before C6 | C1 and C3 must be one step; C6 before C5 |
| §17.3 | webrtc-rs keepalive every 2 s | No keepalive while traffic flows; requests start ≈ 2 s after the rebind, then every 200 ms |
| §17.4 | Client signaling handle becomes a command channel | A lock on the shared connection suffices; the task must forward confirmations |
| §17.5 | Audio and video SRs carry the same CNAME | Holds because the SFU writes `nexus-{publisher}` for every track of a publisher (1.5a review), not the publisher's own CNAME |
| §17.9 | Page needs no build step | `sdk/dist` is gitignored; token and secure context needed |
| §6.1, §6.5 | The answer's `a=setup` fixes the DTLS role | A ClientHello can arrive first and fix it (engine role cannot change once started); a contradicting answer fails the handshake |
| §6.3 | DTLS flights sent as they come | No MTU is set (the BIO reports 0): output is split at record boundaries into ≤ 1,200-byte datagrams |
| §11.2 | The table lives in `nexus-dataplane`, shared with the negotiator | It lives in `nexus_media::rtp::extensions` (no dependency between the two crates); `nexus_dataplane::ext` re-exports it |

## Risks for this phase

The note's §19 risks stand; these are the ones the audit added.

| Risk | Mitigation |
|------|------------|
| Rebind resume ≈ 2.2-2.6 s is close to the 2 s silence rule | Assert < 5 s, log the measured value; if flaky, lower `rebind_silence` in the test config only |
| A 32-m-line session hits signaling size limits | 1.4 raises the SDP and WebSocket limits and turns silent drops into errors; tested with 32 m-lines |
| The manual browser check is blocked by HTTPS/token setup | 1.8 documents both setups; the SDK and token work can start before 1.5b |
| Linux-only code (`LinuxIo`, pinning, GRO check) only runs in the container and CI | Container run is part of every I/O part's checkpoint |
| Remote panics remain in code the shard does not use but the control plane does (DTLS, SDP parser) | Exit criterion 6; DTLS input guards in 1.5a; SDP errors instead of asserts in 1.4 (done: two parser panics fixed, fuzz proptests on the parser) |
| **Known limit, aggregate DTLS pressure.** The per-session budget (32 DTLS datagrams per second, 1.2) bounds one peer, but many sessions that passed STUN and never finish DTLS can together fill the event channel all shards share, and other sessions' handshake datagrams are then dropped (peers retransmit) | 1.3 (done): a shard-wide cap on `DtlsDatagram` events per second (`dtls_budget_per_sweep`, 1,024). 1.5a/1.5b: the orchestrator's DTLS handshake timeout closes sessions that do not complete, so the pressure is bounded in time |
| **Known limit, ICE-lite on-path injection.** STUN authenticates the request, not its source address (RFC 8445). An attacker on the path can drop a fresh nomination and send it from its own address before the original arrives, or replay one older than the last 16 transaction ids, and the session moves to it. Media stays SRTP-encrypted; the real peer is cut off until its next nomination | Inherent to ICE-lite; accepted for v1. 1.2 refuses repeated transaction ids and rate-limits switches. A full fix needs proof of liveness at the new address (e.g. consent from the SFU side) and comes after v1 |

## Status

| Part | State | Commits | Notes |
|------|-------|---------|-------|
| 1.1 SRTP per direction | Done | see git log (1.1) | ring GCM, `direction.rs`, `index.rs`, robustness tests; ROC reorder bug fixed; review fixes: outbound registration (monotonic offsets), pinned inbound SSRCs |
| 1.2a Shard core: tables, commands, ICE-lite, forwarding | Done | see git log (1.2) | `nexus-dataplane` crate on `MemIo`: slabs, commands, slim STUN scan, address rules, SRTP in, rewrite, fan-out; STUN panic/UB fixes in `nexus-transport`; `tests/shard.rs` incl. proptest |
| 1.2b Shard core: extensions, RTCP, housekeeping, alloc test | Done | see git log (1.2) | `ext.rs` table + element iterator, full rewrite, `mid` SSRC learning, SR+SDES translation, PLI/FIR with throttle, housekeeping, `ShardStats`, event retention; `tests/alloc.rs` 0 allocations (GCM and CM) |
| 1.3 Shard thread and I/O | Done | see git log (1.3) | `LinuxIo`/`PortableIo`, park/wake, shard thread, `DataplaneHandle`, `Dataplane::start`, `DataplaneConfig`, `Placement`/`SingleShard`, shard-wide DTLS cap; `tests/loopback.rs`; lost-wake-up fix; review fixes: oversized flood pacing, GRO refusal, concurrent shutdown, bytes sent, closed event channel |
| 1.4 SDP groundwork, signaling limits, shared certificate | Done | see git log (1.4) | `media: Vec` (32), BUNDLE 544 B, 128 KB SDP and printer errors, two SDP parser panics fixed + proptests, `Mid::parse`, `rtcp_fbs`, `stream_id`/`cname` with one msid, extension table in `nexus-media`, WebSocket 256 KB + error reply + 1 MB cap, `DtlsCertificate` + `with_certificate`; old-path cap 8 |
| 1.5a Control-plane pieces | Done | see git log (1.5a) | `ids`, `dtls` (`DtlsHandshake`: lazy role, MTU split, keys by role), `transports` (`SsrcAllocator`, timeouts), `tracks`, `sdp_params`; engine input guards and `DTLS_MTU`; SDP accessors |
| 1.5b-prep Node module, config, negotiator options, loadtest marker | Not started | | Old path green |
| 1.5b Switch (one commit) | Not started | | Early browser check result goes here |
| 1.7 Benches, memory budget, CI | Not started | | Before C2 |
| C2 Old benches | Not started | | |
| C1+C3 `Sfu`, packet loop, `worker/`, `forward/`, `proto.rs` | Not started | | |
| C4 `nexus-actor`, `nexus-dst` | Not started | | |
| C6 `WebRtcTransport`, session, demux | Not started | | Before C5 |
| C5 Replaced `nexus-transport` modules | Not started | | |
| C7 Config, README, example | Not started | | |
| 1.6a E2E: harness, ten clients, resubscribe | Not started | | |
| 1.6b E2E: address change, SR, keyframes | Not started | | |
| 1.8 SDK, browser page, manual check | Not started | | Browser versions, cipher, results |
| 1.9 Documents, merge | Not started | | |

Exit criteria: 1 ☐ e2e · 2 ☑ 0 allocations · 3 ☐ 25 KB budget · 4 ☐ browsers · 5 ☐ old path
deleted · 6 ☐ no panic on input · 7 ☐ documents.

### Session log

Add one line per working session: date, part, what was done, what is left.

- 2026-09-26: plan written from the approved design note; branch `phase-1` created from
  `4fabfc6`. Code notes checked against that commit. Reviewed and approved: merge target
  `main` (fast-forwarded to `v0.1.0`), idle-CPU test local only. Realistic size: ≈ 15
  working sessions for Phase 1 (1.2a may need two). Next: 1.1.
- 2026-09-26: plan audited against `e825887` (SRTP/IO/STUN, orchestrator/SDP/DTLS, tests/CI/
  SDK). Deletion order fixed (C1+C3 merged, C6 before C5); remote panics and STUN UB added to
  1.1/1.2a and exit criterion 6; SDP BUNDLE and size limits added to 1.4; DTLS role, output
  and input details added to 1.5a; harness, keepalive and CNAME findings added to 1.5b-1.6b;
  SDK extension and dev token added to 1.8 (owner's decision). ≈ 16-17 sessions. Next: 1.1.
- 2026-09-26: 1.1 implemented (uncommitted, for review). AES-128-GCM on `ring`, checked
  byte for byte against RustCrypto (headers up to 300 B, ROC up to `u32::MAX`, SRTCP);
  packet-content asserts in `crypto.rs`/`context.rs` replaced by errors;
  `srtp/robustness.rs` (malformed list + proptest through `SrtpContext`, `SrtpCipher`,
  `SrtpInbound`, `SrtpOutbound`); `srtp/index.rs` (`RocState`, shared); `srtp/direction.rs`
  with RFC vectors, rollover and reordering against `SrtpContext` and `webrtc-srtp`, sent-
  index window, slot rules. Found and fixed the ROC reorder bug (code notes).
  `srtp_backends` (`verify()` passes; ns, protect 160/1,200 B, unprotect 160/1,200 B):
  macOS arm64 `SrtpCipher` GCM 102/282/107/297 (ring reference 99/282/101/297 in Part 5),
  `SrtpContext` GCM 136/320/167/366 (was 156/809/218/871). Linux container: SRTP tests
  green; every backend, OpenSSL included, ran ≈ 35% slower than Part 5 (VM not idle), and
  within that run `SrtpCipher` GCM 129/321/147/369 vs the ring reference 137/330/147/349.
  Next: 1.2a.
- 2026-09-26: 1.1 review fixes (uncommitted). `SrtpOutbound` takes the session's SSRC base
  and protects only `register`ed SSRCs, with the monotonic rule enforced in `register`
  (a retired SSRC never sends again); `SrtpInbound::pin`/`unpin` keep signaled SSRCs from
  eviction. Tests for both, each checked to fail without its fix. 1.2a's command handling
  updated to call `register`/`retire`/`pin`/`unpin`. Next: commit, then 1.2a.
- 2026-09-26, review of 1.1 (separate session): adversarial review found `retire()`
  reopening keystream reuse and inbound eviction able to kill a stream; both fixed with
  regression tests (fail without the fix). Verified: fmt, clippy, all tests on macOS
  (1,842) and Linux arm64 (1,843, incl. e2e). Committed. Next: 1.2a (register the session's
  `rtcp_ssrc` at offset 0 from the SSRC base).
- 2026-09-26: 1.2a and 1.2b implemented (uncommitted, for review). New crate
  `nexus-dataplane` (shard on `MemIo`, explicit `now`): commands and events, slabs and id
  maps, ICE-lite slim STUN scan with nomination and 2 s rebinding, SRTP in and out,
  rewrite with extension mapping and subscriber `mid`, fan-out, `mid` SSRC learning, SR +
  SDES translation, PLI/FIR with 500 ms throttle and PLI on `Subscribe`/`InstallSrtp`,
  housekeeping (consent, SSRC eviction, stale address, `ShardStats`), 256-event retention.
  STUN input panics and the `get_username` UB fixed in `nexus-transport`. Tests:
  `tests/shard.rs` (22; its proptest fed raw, unauthenticated datagrams only),
  `tests/alloc.rs` (0 allocations over 10,000 RTP without header extensions + 100 each of
  SR, PLI, RR, NACK; GCM and CM). fmt, clippy and `cargo test --workspace`
  green on macOS and in the Linux container (arm64), `alloc.rs` included. Exit criterion 2
  is met once committed.
  Next: review and commit, then 1.3.
- 2026-09-26, review of 1.2 (separate session): found a shared-channel DTLS flood, events
  lost on a full queue (session leak), address flapping, nomination replay, subscriptions
  dying after a > 2^15 forwarding gap, and five smaller issues. All fixed with regression
  tests (each fails without its fix); code notes above. 1,914 tests pass on macOS, 1,915 in the
  Linux container (arm64), clippy clean on both. Next: commit, then 1.3.
- 2026-09-27, verification review of 1.2: the earlier test claims were weaker than stated:
  the proptest never authenticated, so it did not reach the RTP parser, rewrite, extension
  or RTCP code; `alloc.rs` measured no header extensions, STUN or FIR; the resubscribe test
  compared two different SSRCs and could not fail. Fixed:
  - Rewrite rebases also when the input is > 64 behind the last forwarded packet, and after
    a 5 s forwarding pause (a wrapped seq looks like a small step); unit test for the wrap.
  - A nomination refused by the 100 ms switch limit is stored (latest wins) and applied
    when the interval passes; test.
  - No events for a session after its `ConsentLost`; the full-sink test no longer expects
    `PeerSrtpVerified` after it and now checks the suppression.
  - New proptest: random RTP/RTCP plaintexts (both extension forms, CSRCs, padding, bad
    lengths, SR/PLI/FIR blocks) protected with the peers' keys; every output must decrypt
    and parse at its receiver. Measured over 256 cases: ≈ 2,400 forwarded packets, 380
    malformed headers, 140 rebases, 700 authenticated compounds (440 malformed), 64
    translated SRs, 36 forwarded PLIs. The raw-datagram proptest stays.
  - `alloc.rs`: every forwarded packet goes through the extension rewrite (mid and audio
    level in, audio level mapped and the subscriber's mid out), and each round adds a STUN
    binding request and a FIR. Checked: an allocation injected on the STUN path is caught
    (100 = one per round).
  - Resubscribe test: an orchestrator re-using the retired SSRC is refused; one subscriber
    SRTP context decrypts both subscriptions and a per-SSRC RFC 3711 index tracker finds no
    repeat. With the shard check and `SrtpOutbound::register`'s rule both disabled, the test
    fails (120 packets instead of 80: the retired SSRC is sent again).
  - Known limits added to the risks: aggregate DTLS pressure and ICE-lite on-path
    injection.
  Every new or changed check was run with its fix disabled and fails. fmt, clippy clean;
  `cargo test --workspace` 1,918 passed on macOS; Linux container (arm64, own target
  volume `nexus-dataplane-target`): fmt, clippy clean, 1,919 passed, 0 failed. Stopped for
  review; not committed.
- 2026-09-27, verification of the 1.2 fixes (separate session): gap rebase (incl. wrap after
  a long pause), deferred nominations, no events after `ConsentLost`, authenticated-plaintext
  proptest, extended `alloc.rs` and the resubscribe test checked in the code. 1,918 tests on
  macOS, 1,919 on Linux arm64 with a fresh target volume (the earlier config-test failure
  came from a shared Docker target volume mounted at another path, not from the code).
  Committed. Exit criterion 2 met. Next: 1.3 (use your own Docker target volume).
- 2026-09-27: 1.3 implemented (uncommitted, for review). `nexus-dataplane` runs on real
  sockets and threads: `LinuxIo` (`recvmmsg`/`sendmmsg`, IPv4/IPv6, `MSG_TRUNC` dropped,
  one bad destination drops one datagram), `PortableIo` (scratch buffer detects truncation),
  v4-mapped addresses normalised, `mio` park/wake protocol, shard thread with busy-poll and
  a drop guard, `DataplaneHandle` (commands, events once, stats, loads, `is_running`,
  idempotent `shutdown`), `DataplaneConfig` (Phase 1: one shard, port range vs reserved
  ports, buffer and priority checks, per-process seed), `Placement`/`SingleShard`, pinning
  and SCHED_FIFO (best effort), shard-wide DTLS cap, counters `parks`, `rx_truncated`,
  `rx_errors`, `drop_dtls_shard_budget`, gauge `rx_pps`. The Linux run found a lost wake-up
  (eventfd closed with the last `Wake`, see code notes); fixed. Tests: backend conformance
  on both platforms, park unit tests, `tests/loopback.rs` (media over IPv4, IPv6 and
  dual-stack; wake; shutdown; burst > send batch; flood; idle CPU `#[ignore]`; GRO off on
  Linux), shard DTLS cap and park deadline. Each new safeguard checked to fail with its fix
  disabled. Measured (Linux arm64 container / macOS): wake round trip median 1.2 ms / 0.3
  ms, max 2.5 ms / 0.9 ms; shutdown 0.45 ms / 0.37 ms; idle CPU over 1 s 0.2 ms / 0.1 ms.
  fmt, clippy clean; `cargo test --workspace` 1,945 passed on Linux, 1,940 on macOS
  (Linux-only tests account for the difference), 0 failed. Next: review and commit, then 1.4.
- 2026-09-27, review of 1.3 (verified findings), fixed (uncommitted, for review): taken
  datagrams count as work (an oversized flood no longer parks 1 ms per batch); `LinuxIo`
  refuses UDP_GRO, `ENOPROTOOPT` read as off, GRO kernel version corrected; burst test on 5
  subscribers plus a deterministic mid-batch flush test (`tx_full_flushes`); `shutdown`
  safe under concurrent callers; `flush` reports bytes actually sent; closed event channel
  counted apart (`drop_event_closed`) and not retained; `Zeroable` bound for `zeroed_box`;
  config warning for SCHED_FIFO + busy-poll on core 0; `panic = "abort"` note. Each new
  test checked to fail with its fix disabled (flood drain 585 ms with the old rule; GRO
  refusal on Linux; concurrent shutdown; closed channel). Linux arm64 container (own target
  volume `nexus-dataplane-target`): fmt, clippy clean, 1,952 passed, 0 failed; wake median
  1.0 ms / max 2.0 ms, 20 packets after the flood in 0.25 ms, 2 mid-batch flushes in the
  loopback burst. macOS: fmt, clippy clean, 1,946 passed, 0 failed. Next: review, commit,
  then 1.4.
- 2026-09-27, fix before commit (uncommitted, for review): `media_arrives_after_an_oversized_flood`
  failed under the full workspace on Linux (0 of 20: the media reached a still-full socket
  buffer and the kernel dropped it). The test no longer sends into a full buffer: after the
  flood the publisher sends a binding request every 10 ms until one is answered (the queue
  is FIFO, so an answer means the flood before it was consumed; published stats refresh
  only once per second, too coarse to time the drain), asserts the drain took < 500 ms,
  then requires all 20 packets. The pacing regression stays covered by `runner.rs`.
  `cargo test --workspace` in the Linux container (own volume `nexus-dataplane-target`)
  three times: 1,952 passed, 0 failed each run; drain 0.26 / 0.17 / 0.13 ms. fmt and
  clippy clean. macOS: 1,946 passed, 0 failed. Next: review, commit, then 1.4.
- 2026-09-27, verification of the 1.3 fixes: all five review fixes confirmed in code and
  tests; flood test no longer races the kernel buffer. macOS: fmt, clippy clean, 1,946
  passed; Linux arm64 (own target volume): clippy clean, 1,952 passed in each of 3 full
  runs; loopback 10/10 on Linux, 5/5 on macOS. Committed. Next: 1.4.
- 2026-09-27: 1.4 implemented (uncommitted, for review). SDP: `media: Vec` bounded by 32
  (`media_count` removed), BUNDLE for 32 mids of 16 bytes (error, not truncation),
  `MAX_SDP_SIZE` 128 KB with `SdpPrinter::print`/`to_sdp` returning `Result`, `Mid::parse`;
  two remote panics in the SDP parser fixed (multi-byte line type, non-ASCII fingerprint)
  with unit tests and four fuzz proptests. Negotiator: `RecycledMline::rtcp_fbs`,
  `OfferMline::Track { stream_id, cname }` with one msid (media-level and per ssrc),
  `offered_extmaps` from the extension table, now in `nexus_media::rtp::extensions`
  (re-exported by `nexus_dataplane::ext`). Old path unchanged in behaviour:
  `OLD_PATH_MAX_MLINES` = 8, answers above it refused, today's msid/cname values, dead
  renegotiation asserts turned into errors. WebSocket: 256 KB with an
  `Error{MESSAGE_TOO_LARGE}` reply, 1 MB tungstenite cap. `DtlsCertificate` +
  `OpenSslDtlsEngine::with_certificate` (first tests of the OpenSSL engine). Each new guard's
  test checked to fail with its fix disabled. macOS: fmt, clippy clean, 1,966 passed, e2e
  (old path) 3/3; Linux arm64 container (own target volume): fmt, clippy clean, 1,972
  passed, 0 failed. Next: review, commit, then 1.5a.
- 2026-09-27, review fixes for 1.4 (uncommitted, for review): old-path m-line cap checked
  before the first publish creates a transport (test on a real `NegotiationManager`);
  `create_answer_media` and PT indexing return errors instead of panicking on offers
  without RTP codecs or with PT > 127; shared DTLS context with session cache off,
  random 64-bit serial, `not_before` backdated a day; parser refuses over-capacity
  ice-ufrag/pwd (and non ice-char), msid, ssrc attributes, extmap URIs, extmap id 0,
  non-token and duplicate mids, and skips unparsable m= formats; proptests honour
  `PROPTEST_CASES`, use values up to 300 characters, and `negotiate` is fuzzed on
  arbitrary offers (20,000 cases per property: no panic). Each new test checked to fail
  with its fix disabled. macOS: fmt, clippy clean, 1,975 passed, e2e 3/3. Linux arm64
  container (own target volume): fmt, clippy clean; the first `cargo test --workspace`
  failed once in `two_party_audio_video` (`tests/e2e.rs:122`, the ≥ 10 packets/s rate
  check, right after a cold build in the same container; detail not captured), then e2e
  5/5 alone and `cargo test --workspace --no-fail-fast` 1,981 passed, 0 failed. The
  one-off failure is unexplained; watch for it. Next: review, commit, then 1.5a.
- 2026-09-27, review and verification of 1.4: five review fixes (first-publish m-line cap,
  negotiator assert on offers without formats, PT > 127, DTLS session cache off with random
  serial, no meaning-changing truncation in the parser, proptests honour `PROPTEST_CASES`
  and cover `negotiate`) confirmed in code and tests; no browser SDP form found that the
  stricter parser refuses. macOS: fmt, clippy clean, 1,975 passed, e2e 3/3, SDP proptests
  at 5,000 cases clean; Linux arm64 (own target volume): clippy clean, 1,981 passed, e2e
  2/2. Committed. Next: 1.5a.
- 2026-09-27: 1.5 planned against the code (three read-only audits: DTLS engine, orchestrator
  and SDP, dataplane/config/e2e). §1.5a/§1.5b refined, new part 1.5b-prep (node module,
  `[dataplane]` config, negotiator options, loadtest marker; old path stays green) so the
  switch commit only rewires; two corrections added (DTLS role fixed by a ClientHello, no
  MTU set). 1.5a implemented (uncommitted, for review): root crate depends on
  `nexus-dataplane`; `src/orchestrator/{ids, dtls, transports, tracks, sdp_params}.rs` with
  unit tests and proptests (random datagrams into every handshake state, record splitter);
  OpenSSL engine input asserts turned into errors, `DTLS_MTU` = 1,200, SDP read accessors.
  Each new safeguard checked to fail with its fix disabled. macOS: fmt, clippy clean,
  2,008 passed, e2e (old path) 3/3; Linux arm64 container (own target volume
  `nexus-dataplane-target`): fmt, clippy clean, 2,014 passed, 0 failed. Next: review and
  commit 1.5a, then 1.5b-prep.
- 2026-09-27, review fixes for 1.5a (uncommitted, for review): `free_ssl` only frees a
  complete handshake (a stray early call could start a second engine and complete twice in
  release); `TrackSpec::cname` is the SFU's `nexus-{publisher}` (note §6.5), the
  publisher's own CNAME is not read (the "For 1.5b: CNAME" note replaced); a publish
  m-line with `a=ssrc-group:SIM` is an error; `SsrcAllocator` redraws a zero base. New
  tests: peer flights one record per datagram, lost server flight recovered by the
  peer's ClientHello retransmission, fingerprint mismatch after completion, `free_ssl`
  before completion. 1.5b gains: sha-256 fingerprint selection, `a=setup` rules, fresh
  SSRC for a slot overtaken by a higher offset, shard DTLS only from the selected address
  (today any `by_addr` entry). Each new safeguard checked to fail with its fix disabled.
  macOS: fmt, clippy clean, 2,012 passed, e2e 3/3; Linux arm64 container (own target
  volume `nexus-dataplane-target`): fmt, clippy clean, 2,018 passed, 0 failed, e2e 3/3.
  Next: review, commit 1.5a, then 1.5b-prep.
- 2026-09-27, verification of the 1.5a fixes: `free_ssl`, CNAME `nexus-{publisher}`, SIM
  refusal, zero SSRC base and the four new DTLS tests confirmed in code and tests; stale
  CNAME wording fixed in the design note (§6.5 table) and `tracks.rs`. Left for 1.5b:
  `SsrcAllocator` does not check peer SSRCs against `base`, and `allocate` uses up offsets
  when it returns `None`. macOS: fmt, clippy clean, 2,012 passed, e2e 3/3; Linux arm64
  (own target volume): clippy clean, 2,018 passed, e2e 2/2. Committed. Next: 1.5b-prep.
