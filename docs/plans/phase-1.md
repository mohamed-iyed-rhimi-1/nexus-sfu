# Phase 1 — New data plane, one shard

**State: in progress** (1.1-1.5b, 1.6a, 1.6b, 1.7, C1-C7, 1.8 code, "Before 1.9" done; 1.9 documents done, merge waiting for the owner's browser check (exit criterion 4); plan written 2026-09-26, audited against the code the same day).

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

"In CI" below means **GitHub Actions, or while it is unavailable, a recorded
`scripts/ci-local.sh all` run** (owner's decision, 2026-09-27: Actions has never run a job on
this repository because of an account billing lock). The script runs the jobs of `ci.yml`
on macOS (natively) and on Linux arm64 and x86_64 (Docker; x86_64 emulated on Apple Silicon).
Its summary, with the commit it ran on, goes in the session log.

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
   Session state only (data plane + control plane); the signaling connection is measured and
   reported beside it, not in it (design §3.11, clarified 2026-09-28).
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
  exercised only in CI. From 1.7 on, `scripts/ci-local.sh` (macOS + Linux arm64 by default)
  is that check; its summary goes in the session log.
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

**Files:** `src/node.rs` (new), `src/sfu.rs`, `src/config/{mod.rs, dataplane.rs (new), loader.rs,
tests.rs}`, `src/main.rs`, `config/*.toml`, `crates/nexus-webrtc/src/sdp/{negotiator.rs, parser.rs,
testdata/legacy_offer.sdp}`, `src/orchestrator/transports.rs`,
`crates/nexus-dataplane/src/shard/{ingress.rs, stats.rs}`, `crates/nexus-dataplane/tests/shard.rs`,
`crates/nexus-loadtest/src/{announced.rs (new), client.rs, media.rs, track_stats.rs}`,
`tests/e2e.rs`, `.gitattributes`.

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
- **Moved in from 1.5b** (owner's decision, 2026-09-27; none is used by the old path):
  - Parser: several `a=fingerprint` lines per level keep sha-256 (else the first); a line
    with an unsupported algorithm (sha-1) is skipped instead of failing the whole parse.
  - `SsrcAllocator`: a peer SSRC equal to the base (the RTCP SSRC) or to an out SSRC already
    handed out is refused (`note_peer_ssrc` returns `false`); `allocate` returning `None`
    consumes no offset; `offset_of`, `mark_registered`, `is_stale` mirror the shard's
    monotonic `Subscribe` rule for the late-slot rule of 1.5b.
  - Shard: DTLS only from the selected address (`drop_dtls_unselected`).

**Code notes:**
- Found while implementing (2026-09-27):
  - `node.rs` uses `SystemTime` (not `clock::now_ns`) and its own `NodeError`; `Sfu::new`
    maps it to `SfuError::Worker(WorkerError::InvalidConfig)` with the same "MAX_ACTORS"
    message, so `Sfu`'s behaviour is unchanged. `Node::stop` joins (at most one probe
    interval; call it through `spawn_blocking` from async code); `Drop` only signals.
    `notify_and_drain` (notice, then sleep) is for `server.rs` after the switch.
  - Config: `DataplaneSettings` lives in the root crate (`src/config/dataplane.rs`), since it
    converts into `nexus_dataplane::DataplaneConfig`. `reserved_ports` = signaling, API (only
    if `api.enabled`) and metrics ports, port 0 skipped; `max_sessions` =
    `ceil(max_webrtc_sessions / shards)`. Production has `realtime_priority = false`: with
    `cpu_affinity` and `busy_poll_rounds = 256`, SCHED_FIFO would trigger
    `DataplaneConfig::warnings()` (shard 0 spinning as a real-time thread on core 0).
  - Negotiator: Track m-line rtcp-fb goes on the **first codec's PT only**, as before (the
    old path offers the default codec list there); `add_rtcp_fbs` (every codec) is not
    reused. Too many entries are now an error, not silently dropped. The old path's offer
    is pinned byte for byte in `testdata/legacy_offer.sdp` (captured before the change;
    `.gitattributes` keeps its CRLF). It shows the old path's Track video m-line reusing PT
    96 of a recycled publish m-line: a BUNDLE PT collision, left alone (old path).
  - Loadtest: VP8 marker read after the payload descriptor only when S is set and the
    partition is 0 (extended descriptor parsed: PictureID 7/15 bits, TL0PICIDX, TID/KEYIDX).
    `TrackRxStats` counts `marker_mismatches` (another publisher SSRC) and
    `marker_regressions` (frame counter backwards) apart. `AnnouncedSsrcs` records the first
    `a=ssrc` of every sendonly m-line with the offer's `tracks` entry for its mid. Each
    sender's RTCP is drained (needed for 1.6b's PLI reader).
  - The e2e old-path self-check (announced SSRCs = published SSRCs, every announced m-line in
    `Offer.tracks`) passes, so 1.5b can rely on the recording.
  - **Docker bind mount.** Two container runs read a truncated file through the bind mount
    right after edits (`src/config/tests.rs` cut mid-line; `default.toml` giving a TOML error
    at line 1, column 1). The same files were intact inside the container a moment later.
    Linux checks now run on a copy made inside the container (`rsync --exclude target
    --exclude .git /host/ /work/`), with the target volume mounted at `/work/target`.

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
- **Shard: DTLS only from the selected address:** done in 1.5b-prep (`drop_dtls_unselected`;
  the address map holds only the selected and, during its grace period, the previous
  address, so the test sends DTLS from the previous address after a switch).
- `ServerHandle` users: `main.rs:349`, `harness.rs:66`, `e2e.rs:150` use `media_addrs[0]`.
- Tests (note §17.1): `two_party_audio_video` compares against the SSRCs each client's offer
  announced for the peer's tracks (`announced_ssrcs()`, 1.5b-prep; `check_received` takes
  expected and publisher SSRCs separately) plus the marker (it names the peer's published
  SSRC); one client answers `answering_dtls_role = Client`; `candidate_is_announced_address`
  uses `media_addrs[0]`.
- Work on a local branch (`phase-1-switch-wip`) in stages, squashed into the one switch
  commit on `phase-1`.

**Code notes (implementation, 2026-09-27):**
- New `src/orchestrator/plane.rs` (a file the plan did not list): `Plane` holds the
  dataplane handle, placement, shard candidates, the certificate, `Transports`,
  `TrackRegistry`, `IdAllocator` and the `DistributedState`. Every command goes through
  `Plane::push`; a full queue records the participant as closing (`Overloaded`) and the
  operation stops. `close_session` falls back to `pending_close`, retried by the 1 s sweep.
  Failures anywhere (DTLS, consent, timeouts, shard refusals of orchestrator bugs) are
  recorded with `close_participant` and handled by `SessionOrchestrator::settle` after each
  step: `Error{<reason code>}` to the client, room leave, cleanup.
- `SessionEvent` is gone with `ColdPathPacket`: `events.rs` keeps `DisconnectReason`
  (`ConsentExpired`, `IceFailed`, `DtlsFailed`, `Overloaded`, `Internal`; `IdleTimeout`
  removed) with the error code sent to the client.
- Candidates are trickled synchronously after the first offer (no gathering task or
  channel); remote candidates are ignored.
- Publish m-lines: VP8 96 / Opus 111, the fixed extmaps, rtcp-fb `nack pli` + `ccm fir`
  on video. Subscribe m-lines: VP8/Opus passed explicitly (remapped by the negotiator when
  a publish m-line holds the PT), `stream_id` = `cname` = `nexus-{publisher}`, same rtcp-fb.
- An answer is applied only if it has the offered mids in order; otherwise `INVALID_ANSWER`
  and the offer is settled. Unknown track ids in `Subscribe` are left out of `Subscribed`.
- `Unpublish` and a publisher leaving: `RemoveTrack`/`CloseSession`, then every subscriber
  m-line of those tracks turns inactive and the subscribers are re-offered.
- `use_srtp` is `AEAD_AES_128_GCM:AES128_CM_SHA1_80`; the "DTLS established" log carries
  the role and the negotiated profile. E2E: GCM with both roles.
- `ServerHandle`: `media_addrs()`, `dataplane()` (stats), `is_finished()` = shards
  stopped; `shutdown` = notice + drain, shared flag, tasks, then `dataplane.shutdown()` and
  gossip stop in `spawn_blocking`. `MetricsCollector::new(shards)`: no worker feeds it.

**Code notes (review fixes, 2026-09-27):**
- **Rooms.** `Publish` needs a room (`NOT_IN_ROOM`); `TrackInfo.room` records where a track
  was published, and `Subscribe` accepts only tracks of the subscriber's room (others are
  left out of `Subscribed`, as unknown ids are).
- **Limits are the shard's.** Published tracks per session ≤ `MAX_TRACKS_PER_SESSION` (10),
  counting registered, in-offer and queued ones; subscriptions ≤ `MAX_SUBS_PER_SESSION` (31);
  beyond either, `TOO_MANY_TRACKS`. Both constants are re-exported by `nexus-dataplane`.
- **Shard refusals close.** `CommandRejected` names the session, not the track or the
  subscription, so a registration cannot be undone selectively: `SessionLimit`,
  `TrackLimit`, `SubscriptionLimit` close the participant as `Overloaded`, any other
  refusal (`InvalidSpec`, `SsrcInUse`, `OutSsrcNotMonotonic`, ...) as `Internal`. Only
  unknown-id refusals (expected after removals) are logged and ignored.
- **Publish flow.** A `Publish` during an open offer is appended to the queue (bounded by the
  track limit), not overwritten; `INVALID_ANSWER` settles the offer and replays the queued
  publish/renegotiation; `Unpublish` turns the publish m-line inactive, and the next publish
  or subscription of that kind reuses it (`claim_mline`).
- **Fingerprint.** The first sha-256 fingerprint, session level then m-lines in order.
- **Stable PTs (found by the browser check).** A participant that subscribed before it
  published had its subscribe m-line's VP8 moved from 96 to 97 by the next offer (the
  negotiator remapped Track PTs that collide with a recycled m-line), while the shard kept
  the first answer's PT map: Chrome counted the packets and decoded nothing. The e2e
  clients always publish first, so they never saw it. `OfferMline::Track { keep_pt }`
  offers the codec under its own PT; the orchestrator sets it (VP8 is 96 and Opus 111 on
  every m-line, the MID extension demuxes); the old path passes `false` and its pinned
  offer is unchanged. Regression test `subscribe_mline_keeps_its_pt_when_a_publish_mline_follows`.
- **Observability.** `ServerHandle::established()` lists established sessions with the
  SFU's DTLS role and the SRTP profile (last 1,024); e2e asserts the role per client and
  AES-GCM. `/ready` turns 503 when the data plane stops (`Readiness` handle in `nexus-api`).
- **Tests match their claims.** Orchestrator tests use a barrier (`CloseSession` of an id
  never created, whose rejection names it) and read the shard's gauges (tracks, sessions,
  subscriptions) and `commands_rejected`; the full-queue test uses a `CommandSink` double
  and shows the close retried once the queue has room; closes check the error code sent.
  The e2e marker check maps each received SSRC, through the offer's announced SSRC and its
  kind, to the one publisher SSRC its payload must name.
- **`/metrics`:** nothing feeds `MetricsCollector`'s worker series after the switch; they
  read zero until shard stats are exported in C7 (`WorkerPoolMetrics` → shard metrics, note
  §5.4; the C7 row owns it, 1.7 does not).

**Code notes (last fixes before the squash, 2026-09-27):**
- `Join` while already in a room is refused (`ALREADY_IN_ROOM`): switching kept the old
  room's membership and the participant's tracks and subscriptions there, and left it a
  member of both rooms. Leaving (which ends the session) comes first.
- After `INVALID_ANSWER` with nothing queued, the unanswered publish and subscribe m-lines
  are offered again, once (`MAX_REOFFERS`); a second invalid answer in a row releases the
  publish m-lines (inactive, reusable) instead of looping. A valid answer resets the count.
- Tests: a shard refusal after the tracks were registered undoes `TrackRegistry` and
  `DistributedState` and sends `TrackUnpublished` to the room; a republish on a reused
  m-line with the same SSRC (Chrome reuses the transceiver) is accepted by the shard.
- `/ready` reports 503 from the start of the shutdown drain (the API keeps answering
  `/health` until the tasks stop after the drain). `.playwright-mcp/` is ignored.

**Early browser check (2026-09-27, note §17.9 steps 1-2):**
- Setup: the SFU from this branch (`target/debug/nexus-sfu`, `config/development.toml` with
  plain WebSocket and the API moved to 18081, `NEXUS_ANNOUNCED_IPS` = the LAN address),
  a scratch page (two participants in one tab, canvas video and oscillator audio, token
  minted with WebCrypto) served from `localhost`, driven through Playwright.
- **Chrome 153 (headless):** both participants publish and receive audio and video through
  the new path. Offers carry `a=ice-lite`; Chrome is ICE controlling and DTLS client (the
  SFU is DTLS server); `srtpCipher` = `SRTP_AEAD_AES_128_GCM` (the SFU logs
  `AeadAes128Gcm`); received SSRCs differ from the sent ones (rewritten); video decoded on
  both sides (≈ 650 frames in 20 s, one keyframe each); ≈ 1,100 audio packets each way,
  decoded without concealment. No warning or error in the SFU log.
- First run failed on the subscriber that subscribed before publishing (0 frames decoded):
  the PT bug above, fixed and re-run.
- Received audio level reads 0 in headless Chrome, as for a direct peer-to-peer call in the
  same page (checked): no audio output device, not the SFU.
- **Firefox: deferred to 1.8** (owner's decision, 2026-09-27). The browser tooling here runs
  Chromium only. Left for the owner
  (and a headed Chrome with real devices) before 1.5b is committed, or in 1.8 at the latest.

**Code notes (planning audit 2026-09-27, before implementation):**
- `src/sfu.rs` must change too: `Sfu` uses `ColdPathPacket` (`connection_tx` field,
  `set_connection_tx`, the forward in `process_packet`). Remove the field, the setter and the
  forward (`Sfu` is not started after the switch).
- webrtc-rs answers **`a=setup:passive`** to an offer with `a=ice-lite` when no role is set
  (`webrtc-0.10.1/src/peer_connection/mod.rs:941`), and becomes ICE-controlling (so it
  nominates). Every default e2e client therefore makes the SFU the DTLS **client**; set
  `answering_dtls_role = Client` on one client of `two_party_audio_video` so the SFU-as-server
  path (the browsers' case) stays covered.
- The shard's address map holds only the selected address and the previous one during its
  grace period (`switch_to` is its only insert); unselected candidates were already dropped.
  The DTLS rule (done in 1.5b-prep) therefore only concerns the previous address.
- `Unpublish` (`mod.rs:264`) has no ownership check: any participant can unpublish any track.
  Check `TrackRegistry` publisher = sender.
- A full command queue cannot carry the `CloseSession` of the session it fails: keep failed
  closes in a bounded list retried by the 1 s sweep.
- Subscribe m-lines of the old path offer the default codec list (`None` codecs); 1.5b passes
  VP8/Opus explicitly, and publish slots Opus 111 / VP8 96.
- Metrics: `MetricsCollector` has no worker feeding it after the switch; `/metrics` reports
  zeros for worker series until shard stats are exported (note §5.4).

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
| C2 | 1.7 | (`real_path` and `memory` were rewritten in place by 1.7, so CI's bench smoke and memory budget never lose coverage.) `benches/forwarding.rs` (measures `SsrcRouter`); `benches/packet_processing.rs` ported to the shard's classifier or deleted (it imports `quick_classify`/`PacketType` from `nexus-webrtc` `demux.rs`) | `Cargo.toml` `[[bench]]` entries |
| C1+C3 | C2 (the old benches use the worker and router) | `Sfu` and the packet loop (`src/sfu.rs`), `SRTCP_SENT_CACHE`, `tests/pps_pipeline.rs`, root `sim` feature, `src/spin.rs`, `src/clock.rs`, `DrainState`, `DropTracker`; `src/worker/`, `src/forward/`, `src/transport/`; `src/proto.rs` and the root `build.rs` prost step (the root crate `include!`s its output only in `proto.rs`) and `check_io_uring_feature` (root `build.rs:19,31`) with the root `io_uring` feature; `lib.rs` modules and re-exports (39, 47, 50, 52, 56, 59, 134-139, 161-190); `CoreSfuError::Worker` / `WorkerError` (`nexus-core/src/error.rs:52`, `:322`) and the root `src/error.rs:24,61,85` wrappers | Merged because `worker/pool.rs` uses `SpinLoop` (`:367`, `:786`), `clock::now_us` (`:2296`) and `sfu::forget_publisher_srtcp` (`:4038`): deleting `sfu.rs` alone does not build. Root deps removed if unused after the step, each checked by a build: `prost`, `prost-build`, `capnp`, `capnpc`, `crossbeam`, `dashmap`, `memmap2`, `core_affinity`, `once_cell`, and the already unused `sysinfo`, `getrandom`, `tokio-util`, `futures-util`, `tokio-tungstenite`, `hyper`, `tower`, `tower-http`, `axum`, `rustls`, `tokio-rustls`, `rustls-pemfile`, `http`. `protoc` stays required (`nexus-signal` compiles its own schemas); CLAUDE.md unchanged on that point (**wrong**, see the C1+C3 notes below: nothing needs `protoc` after this step) |
| C4 | C1+C3 (the worker imports `nexus-actor` migration types) | `crates/nexus-actor`, `crates/nexus-dst` (it also turns on `nexus-transport/sim` for the whole workspace), workspace entries, `config/mod.rs:157-181` limits (use the orchestrator's constants), `config/tests.rs:333-338`, `lib.rs:70-75`; the `nexus_actor_*` gauges (`nexus-metrics/src/prometheus.rs:228-242`), their test, `scripts/verify_metrics.sh:51` | `nexus_actor::MAX_ROOMS` is 1,000, the orchestrator's `MAX_ROOMS` 10,000 (`room.rs:13`): validation accepts more rooms after this step; tests updated to the new limit. `nexus-core/types.rs` and `production.toml` comments that mention actors |
| C6 | C1+C3, C2 (`Sfu` and the old benches use `WebRtcTransport` and `test-hooks`) | `nexus-webrtc`: `webrtc/transport.rs`, `webrtc/session.rs`, `webrtc/demux.rs`, `webrtc/mod.rs` constants, the `test-hooks` feature (the root dev-dependency that enabled it went in C2), `OpenSslDtlsEngine::new` (per-session certificate) | SDP stays |
| C5 | C6 (`webrtc/session.rs:69-74` imports `DtlsSession`, `IceAgent`, `IceConfig` and more), C4 (`nexus-dst` uses the arena) | `nexus-transport`: `arena.rs`, `ring_buffer.rs`, `batch.rs`, `udp.rs`, `media_transport.rs`, `io_uring.rs`, `arena_proptest.rs`, `arena_refcount_proptest.rs`, the crate's `io_uring` and `sim` features; ICE `agent.rs`, `checklist.rs`, and `StunServer`; pure-Rust DTLS (`dtls/session.rs`, `handshake.rs`, `record.rs`, and the parts of `dtls/crypto.rs` nothing imports) | Keep `ice/stun/server.rs`'s `create_binding_request` and `generate_transaction_id` (used by `gather.rs` and the tests: move them if `server.rs` goes), `SrtpProfile` and `SrtpKeyMaterial` from `dtls/crypto.rs` (used by `openssl_backend.rs:37`), `gro.rs`, `gso.rs`, `socket_config.rs`, `stun/`, `candidate.rs`, `gather.rs` enumeration, `SrtpContext` (tests use it). `ring` stays (SRTP GCM) |
| C7 | C4, C1+C3 | Config fields of note §14 (`[worker]`, `[memory]`, `actor.*`, `transport.batch_*`, `stun_servers`, `--workers`, `NEXUS_WORKER_COUNT`, `NEXUS_ARENA_SIZE_MB`), the arena ≥ 16 MB and workers ≤ 2 × CPU checks in `validate_cross_module` (`config/mod.rs:148-155`, `:183-196`), `config/*.toml`, README config and feature sections (lines 32-33, 65, 73, 84, 123-127, 142-143, 201), `nexus-metrics` `WorkerPoolMetrics` (`worker.rs:122`) → shard metrics (note §5.4) | `examples/basic_sfu.rs` (reads `memory.*`, `worker.*`, `batch_*`: rewrite or delete, or `--all-targets` breaks); e2e `harness.rs:56-58`; `deploy/docker/run.sh` unchanged for one shard (publishes `10000/udp`) |

**C2 done (2026-09-28):** `benches/forwarding.rs` and its `[[bench]]` deleted.
`packet_processing.rs` keeps its four `rtcp_parse` benches (`nexus-media`, which stays; the
shard uses `SenderReport::parse` and `PliPacket::parse`) and loses the three demux groups
(`quick_classify`, deleted in C6): the shard's classifier is a first-byte range check inside
ingress, measured as part of `real_path`'s `ingress`, so it is not made public for a
micro-bench. Moved here from C6: the root dev-dependency `nexus-webrtc` with `test-hooks`
(its only users were the old `real_path` and `memory`); C6 still removes the feature from
`nexus-webrtc`. No bench imports `nexus_webrtc` now. CLAUDE.md's bench list updated.

**C1+C3 done (2026-09-28):** deleted `src/sfu.rs` (with `SRTCP_SENT_CACHE`, `DrainState`,
`DropTracker`), `src/spin.rs`, `src/clock.rs`, `src/proto.rs`, `src/worker/`, `src/forward/`,
`src/transport/`, `tests/pps_pipeline.rs`, the root `build.rs` (capnp, prost and the io_uring
warning) and the root `proto/` directory (only that `build.rs` read it; `nexus-signal` has
its own); `lib.rs` modules and re-exports (the `nexus-actor` ones stay for C4, the arena/ICE
ones for C5); `WorkerError` and the `Worker` variants in `nexus-core` and the root
`SfuError`; root features `io_uring`, `sim` and the unused `production`; the optional
`io-uring` dependency; build-dependencies `capnpc`, `prost-build`. Root dependencies removed
(no user left, each checked by a grep of `src`, `tests`, `benches`, `examples` and a build):
`prost`, `capnp`, `crossbeam`, `dashmap`, `memmap2`, `core_affinity`, `once_cell`,
`sysinfo`, `getrandom`, `tokio-util`, `futures-util`, `tokio-tungstenite`, `hyper`, `tower`,
`tower-http`, `axum`, `http`, `rustls`, `tokio-rustls`, `rustls-pemfile`. Kept (used):
`notify`, `num_cpus`, `rand`, `toml`, `serde_json`, `parking_lot`, `thiserror`,
`tracing-subscriber`, `libc`. `Cargo.lock`: 16 packages gone (prost and its build chain,
`sysinfo`, `h2`, the second `tungstenite`/`tokio-tungstenite`, `tower-http`), nothing
upgraded. **Correction:** "`protoc` stays required" was wrong: `nexus-signal`'s `build.rs`
compiles Cap'n Proto only, and nothing else compiles protobuf. `protobuf-compiler` is no
longer installed by `ci.yml`, `release.yml`, the Dockerfile or `ci-local.sh`'s image, and
CLAUDE.md/README list only `capnp`. The Dockerfile no longer copies `build.rs` and `proto/`.
CLAUDE.md: the "Architecture (today)" data-plane line, the workspace layout and the
"do not fix" list describe the tree as it is now (`architecture.md` waits for 1.9).

**C4 done (2026-09-28):** `crates/nexus-actor` and `crates/nexus-dst` deleted with their
workspace entries and the root dependency; `lib.rs`'s `nexus_actor` re-exports removed.
`[actor]` validation now checks the orchestrator's limits (`room::MAX_ROOMS`, now `pub`,
10,000; `transports::MAX_TRANSPORTS`) instead of `nexus_actor`'s (1,000 rooms); the
"× 10 tracks" check went with the registry. Nothing reads `[actor]` (C7 removes the
section). The config test now asserts 10,000 rooms accepted and 10,001 refused.
`nexus-metrics`: `ActorMetrics` (nothing fed it) and the eight `nexus_actor_*` series
removed with their test and example lines; the collector test asserts none is exported;
`scripts/verify_metrics.sh` step 7 and the two Grafana panels (Actor Counts, Actor Message
Queue Depth) removed. Comments: `production.toml` `[actor]`, `nexus-core` `types.rs`.
README crate table and the `nexus-dst` command, CLAUDE.md layout. `Cargo.lock`: the two
crates only. With `nexus-dst` gone nothing turns on `nexus-transport/sim`: its sim-gated
code is no longer built by the workspace (deleted in C5).

**C6 done (2026-09-28):** the whole `nexus-webrtc` `webrtc` module deleted (`transport.rs`,
`session.rs`, `demux.rs`, `types.rs`, `error.rs`, `mod.rs`; nothing outside the crate used
it, and `sdp` does not import it), with its re-exports and the `test-hooks` feature. The crate
is SDP only: its dependencies shrink to `nexus-core`, `nexus-media`, `thiserror` (dev:
`proptest`); `nexus-transport`, `serde`, `tracing`, `rand`, `parking_lot`, `arc-swap`,
`dashmap` and dev `tokio` dropped (`Cargo.lock`: dependency lines only, no package leaves
the tree). `OpenSslDtlsEngine::new` removed; its test callers (`openssl_backend.rs`,
`src/orchestrator/dtls_tests.rs`) build peers with `with_certificate` on a certificate of
their own, and the test of `new` itself went with it. CLAUDE.md and README describe the
crate as SDP.

**C5 done (2026-09-28):** `nexus-transport` loses `arena.rs`, its two proptests,
`ring_buffer.rs`, `batch.rs`, `udp.rs`, `media_transport.rs`, `io_uring.rs`; ICE `agent.rs`
and `checklist.rs`; `StunServer` (`stun/server.rs` becomes `stun/request.rs`: the binding
request/indication builders and `generate_transaction_id`, with their tests; the two tests of
`StunServer`'s panic fixes went with it, the shard's STUN scan has its own); the pure-Rust
DTLS (`session.rs`, `handshake.rs`, `record.rs`, `crypto.rs`). `SrtpProfile` and
`SrtpKeyMaterial` (the only parts of `crypto.rs` the OpenSSL engine used) moved to
`dtls/srtp_keys.rs` with their seven tests. Features `io_uring` and `sim`, the `io-uring`
dependency, and `nexus-core`, `nexus-media`, `memmap2`, `crossbeam`, `core_affinity`, `sha2`,
`rcgen` dropped (`Cargo.lock`: `crossbeam`, `io-uring`, `memmap2`, `rcgen` leave the tree).
Kept as planned: `srtp`, `dtls` (OpenSSL engine, certificate, types, error), `ice` (`stun`,
`candidate`, `gather`, `types`, `error`), `socket_config`, `gro`, `gso`; `ring` stays.
Also removed, since nothing constructs them: `ArenaError` and the `Arena` variants (core and
root `SfuError`), `TransportError::IoUringQueueFull`/`IoUringInitFailed` (three error
tests now use `BufferExhausted`); the root `lib.rs` arena and ICE-agent re-exports; the
Dockerfile's `liburing-dev`. The grep check of the code notes below: what remains is the
`[memory]` config (C7), Cap'n Proto's own "arena" in `nexus-signal`, and one `lib.rs`
comment (1.9). Crate docs (`lib.rs`, `ice`, `dtls`), CLAUDE.md and README describe what is
left.

**C7 done (2026-09-28):**
- **Config (note §14):** `MemoryConfig`, `WorkerConfig`, `ActorConfig` and their sections,
  `transport.batch_size`, `batch_flush_interval_us`, `stun_servers` (the `[transport]` one;
  `[ice_servers]` stays), `--workers`, `NEXUS_WORKER_COUNT`, `NEXUS_ARENA_SIZE_MB`, and
  `validate_cross_module` (all three of its checks were about removed sections) removed,
  with their tests; the four TOMLs, the e2e harness, `examples/basic_sfu.rs` (prints the
  `[dataplane]` settings), `main.rs`'s startup summary. Root dependency `num_cpus` dropped.
- **Fail fast, not silent:** `NexusConfig` and `TransportConfig` are
  `#[serde(deny_unknown_fields)]`, so a file that still has `[worker]`, `[memory]`,
  `[actor]` or the removed `[transport]` fields fails to load instead of loading with those
  settings ignored (the ones that still apply are under `[dataplane]`); the two removed
  environment variables are an error naming their replacement. Tests for both, checked to
  fail without the fix. Unknown **CLI** arguments were already ignored before (the parser
  has no error path): `--workers` is now one of them; noted, not changed here.
- **Metrics (note §5.4):** `WorkerPoolMetrics` and the six `nexus_worker_*` series replaced
  by shard metrics: `nexus_shard_<counter>_total{shard}` for every `ShardCounters` field
  (the stats macro now exposes `NAMES` and `values()`) and `nexus_shard_{sessions, tracks,
  subscriptions, rx_pps}{shard}`. `nexus-metrics` depends on `nexus-dataplane`;
  `MetricsCollector::new(shards)`; the server installs a stats source
  (`ShardMetrics::set_source`, reading `DataplaneHandle::stats`) and `/metrics` reads it
  at render time: no copy task, freshness = the shard's once-per-second publish. Tests: the
  names/values order, the collector's per-shard export, and a real one-shard data plane
  whose `drop_unclassified` shows up in `/metrics` output. `verify_metrics.sh` and the
  Grafana dashboard (Worker CPU → Shard Datagrams) follow. **Still zero:** the
  `nexus_sfu_*` and `nexus_crdt_*` series (nothing feeds `SfuMetrics`/`CrdtMetrics` since
  the old path; the Grafana panels on them read zero). Not in C7's scope; left for 1.9 or
  later (open item).
- README: features, architecture paragraph and orchestrator modules, crate table
  (`nexus-dataplane` row), config example (`[dataplane]`), env table (`NEXUS_SHARDS`), CPU
  pinning, memory target (≤ 25 KB session state). CLAUDE.md: config files and the
  refusal rules. `config/*.toml` `[dataplane]` comments no longer say "not started".

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

**Re-audited against `c5e9f76` (2026-09-28), before starting:** offer bookkeeping already
existed (`nexus-loadtest` `announced.rs`, from 1.5b: mid → track id and SSRC, replaced per
offer); what was missing is a history across offers and the CNAME. `discover_and_subscribe`
sent every id in one `Subscribe`, which the SFU refuses above 10 (`TOO_MANY_TRACKS`, whole
request). Line numbers above have moved (task `client.rs:1114-1184`, `answer_offer` `:1295`).

**1.6a done (2026-09-28):**
- `signal_task.rs` (new): `SignalTask`, started once by `HeadlessClient::start_signaling_task`
  (a second start is an error; `pump_signaling` refuses to run while it does). It answers
  offers, adds candidates, records `TrackPublished`/`TrackUnpublished` in `KnownTracks`
  (with `Joined.tracks`), and forwards `Subscribed`, `Unsubscribed`, `Error` and
  `OfferAnswered{tracks, announced}` through a bounded channel (256; overflow counted,
  `signal_events_dropped`). `discover_and_subscribe` starts it instead of its own loop.
- Client API: `known_tracks`, `wait_for_known_tracks`, `subscribe_confirmed` (requests of
  ≤ 10, waits for every confirmation and an answered offer carrying all ids),
  `unsubscribe` (waits for `Unsubscribed` and the offer after it that no longer lists the
  ids), `announced_history`. `subscribe_batch` splits into requests of ≤ 10
  (`MAX_SUBSCRIBE_BATCH`), which also fixes the load generator above 10 tracks. The
  `[diag]` transceiver dumps are gone.
- `AnnouncedSsrcs`: CNAME per m-line, bounded history (256) of every (mid, SSRC) announced.
- `LossRules::enable_tap(capacity)` / `tap()`: inbound SRTP (SSRC, seq) and SRTCP (sender
  SSRC, 14-byte trailer) of datagrams that pass; `TapEntry::srtcp_e_index(SrtcpLayout)`
  reads E+index after the GCM tag or before the AES-CM tag. Unit tests for the parser, the
  bound, history and CNAME.
- Tests `ten_clients_audio_video` (8 worker threads; 18 tracks per client in two requests;
  per client exactly the 18 announced SSRCs, rate, loss, timestamps, markers of the right
  publisher; shard gauges 10 sessions / 180 subscriptions, 0 commands rejected) and
  `resubscribe_no_srtp_index_reuse` (3 rounds; new SSRCs each round; the offer after
  `Unsubscribe` drops them; tap: no (SSRC, seq) or (SSRC, SRTCP index) repeats, E set, SRTP
  on all 6 SSRCs).
- **Negative check:** with the allocator reusing its first two offsets, the shard's
  `OutSsrcNotMonotonic` check and `SrtpOutbound::register`'s offset rule removed (and the
  test's own SSRC-reuse assert off), the test fails on the wire: `SRTCP (0x7059d60f, 0) sent
  twice` (a new slot restarts the SRTCP index under the same key and SSRC). Restored.
- Runtime (macOS): `ten_clients` 9.7 s (setup 4.6 s), `resubscribe` ≈ 5 s, suite 27.1 s
  (5 tests); Linux arm64 27.1 s.
- **Review fixes (with 1.6b):** the tap records round boundaries (`LossRules::mark_tap`,
  `tap_rounds`); `resubscribe` asserts every SRTP/SRTCP SSRC on the wire in a round is one
  announced in that round and none of an earlier round's appears later, that rounds 1-2
  reuse round 0's mids, and, from stats read after the next once-a-second publish,
  `commands_rejected == 0` and `drop_srtp_protect == 0`. `ten_clients` also asserts
  `drop_srtp_protect`, `drop_pool_empty`, `drop_send_failed` and `drop_too_large` are 0.

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

**Re-audited against `c5e9f76` (2026-09-28):**
- `ShardStats` already has `rebinds` (`shard/stats.rs`), counted in `switch_to` and readable
  through `server.dataplane().stats(ShardId::new(0))`: nothing to add in `stats.rs`.
- The publisher already reads each sender's RTCP (`spawn_rtcp_drain`, discarding); the
  PLI/FIR recorder **replaces** it, or two readers split the packets.
- `arc-swap` is only transitive (1.8.1 in `Cargo.lock`, via webrtc); add it to
  `nexus-loadtest` as `1.8`.
- The shard, not the orchestrator, sends the PLI on subscribe (`subscribe`, or
  `install_srtp` when DTLS finishes later), throttled 500 ms per track (`PLI_THROTTLE`), and
  also to audio tracks: step 2 and 3 of the test wait > 500 ms after the previous PLI.
- The tap and signaling task of 1.6a are there; `on_track` is `client.rs:~430`.

**Code notes (audited 2026-09-26):**
- **Keepalive timing** (corrects note §17.3). webrtc-ice sends a binding request on the
  selected pair only when nothing was sent **or** nothing was received on it for 2 s
  (`check_keepalive`, `agent_internal.rs:482-512`), checked every 200 ms. During a call it
  sends none. After a rebind the SFU keeps sending to the old port, so the client's receive
  time goes stale: requests start ≈ 2.0-2.2 s after the rebind and repeat every 200 ms. With
  `rebind_silence = 2 s` the first one may be refused and the next accepted: expected
  resume ≈ 2.2-2.6 s. The test asserts ≥ `rebind_silence` − 200 ms and < 4.5 s and logs the measured value. ICE goes
  Disconnected after 5 s without input, Failed after 30 s.
- `register_default_interceptors` (`client.rs:193`) includes the sender and receiver report
  interceptors (reports every 1 s). webrtc-rs sends bare SRs without SDES; the SFU's
  translated compound adds SDES from `TrackSpec::cname` (`nexus-{publisher}`); the check
  compares it with the `a=ssrc … cname:` of the subscriber's offer.

**Tests:** the three tests pass on macOS and Linux; `address_change_mid_call` is checked to
fail with the rebinding rule disabled.

**Checkpoint:** all e2e exit tests green (**exit criterion 1**, except CI on macOS: 1.7).

**1.6b done (2026-09-28):**
- `LossRules::rebind()`: `LossyUdpConn` keeps its socket in an `ArcSwap` registered with its
  rules (one connection per rule set); a rebind binds a new port, swaps, and wakes pending
  receives (`Notify`), which move to the new socket; the swap never surfaces as an error. The
  old socket stays open, and what still reaches it is counted and discarded (a dead NAT
  mapping; `retired_received`). Unit test: a pending receive moves, the old port no longer
  delivers (the datagram is counted), sends leave from the new port. `arc-swap = "1.8"`
  added.
- `rtcp_log.rs` (new): `RtcpLog`, bounded, records PLI/FIR (media SSRC, arrival), SRs (SSRC,
  NTP, RTP time, arrival wall clock) and SDES CNAMEs. The publisher's `spawn_rtcp_drain` is
  replaced by `spawn_rtcp_recorder` (`sender.read_rtcp()`); `on_track` reads each receiver's
  RTCP; both readers log their error when they stop. `HeadlessClient::rtcp_log`, `send_pli`
  (`write_rtcp`); `TrackRxStats` gains `last_arrival_wall`; `ntp_to_system_time`.
- `ShardStats`: nothing to add (`rebinds` existed).
- Tests:
  - `address_change_mid_call`: resume measured as the first packet after a ≥ 500 ms stall;
    2.06-2.26 s both ways on macOS. Bounds: both directions < 3.5 s, and A → B at least
    `rebind_silence` − 200 ms (A's media from the new port is dropped until the old address
    has been silent that long; an earlier resume would mean the rule was bypassed). 3 s window
    after it with ≤ 1 % missing (sequence numbers in the window); A's old port receives
    nothing from 1 s after media to A resumed (≈ 165 datagrams reach it before); `rebinds`
    + 1. **Negative check:** with rebinding effectively disabled
    (`rebind_silence_ms = 29,000`, so an address is never silent long enough within the test)
    media does not resume within 10 s. Restored.
  - `sender_report_translation`: ≥ 2 SRs per track in 5 s, only on the announced SSRCs,
    packet counts never decrease; RTP time vs the media extrapolated to the SR's NTP time:
    1.3-5.7 ms off (limit 20 ms); SDES CNAME per SSRC = the offer's `a=ssrc … cname`, same
    for audio and video; `sr_translated`.
  - `keyframe_requests`: PLI on subscribe 0.2-0.4 s after the subscribe request (B's ICE and
    DTLS included; asserted < 3 s for emulated runners); no PLI in the quiet periods before step 2 and the burst; B's PLI
    forwarded in < 2 ms; a burst of 5 with 5 ms gaps → exactly 1 at A, and
    `keyframe_throttled` exactly + 4 (stats read after the next publish). FIR is recorded but
    not exercised (webrtc-rs subscribers send PLI).
- Review fixes outside the tests:
  - `scripts/ci-local.sh` takes a lock (`$TMPDIR/nexus-ci-local.lock`, owner pid, stale lock
    taken over) and refuses to start while another run holds it: two runs share
    `target/ci-local` and the Docker target volumes, and a collision on 2026-09-28 produced a
    false FAIL (x86_64 `real_path`, while a duplicate container was stopped by hand).
  - Grafana dashboard: six panels on `nexus_shard_*` only (datagrams, bandwidth, drops by
    counter, sessions/tracks/subscriptions, SRs and keyframe requests, nominations/rebinds/
    consent); the `nexus_sfu_*` and `nexus_crdt_*` series (exported, zero since the old path
    went) are no longer shown, and the dashboard description says so. `verify_metrics.sh`
    marks those two sections as zero series and checks every `nexus_shard_*` series the
    dashboard plots is exported.
  - `verify_cleanup.sh`: the `src/sfu.rs` check removed (the file went in C1+C3). Its other
    five failing checks (RoomManager, SignalingServer, serde_json, JSON methods, `loss.rs`)
    predate Phase 1 and are left for 1.9; its `rg` calls without a path hang when stdin is
    not a terminal (run it with `</dev/null`).
  - `config/production.toml` no longer uses realtime priority: `[dataplane]` has
    `realtime_priority = false` since 1.5b-prep, while the old `[worker]` section (live until
    1.5b, removed in C7) had `realtime_priority = true`. With busy polling and pinning,
    SCHED_FIFO would make shard 0 spin as a real-time thread on core 0
    (`DataplaneConfig::warnings()`). `architecture.md` still describes the old SCHED_FIFO
    worker (rewritten in 1.9).
- e2e suite: 8 tests, 47 s on macOS.

---

### 1.7 Benches, memory budget, CI

**Goal:** the `real_path` and `memory` benches measure the new path, the 25 KB budget is
enforced on the §3.11 scenario, and CI runs on macOS as well as Linux. Two sessions:
**1.7a** (`real_path`, CI files) and **1.7b** (`memory`, budget). They are independent;
1.7a first because C2 waits on both.

**Files:** `benches/{real_path.rs, memory.rs, common/mod.rs}` (rewritten in place),
`Cargo.toml` (`[[bench]]` unchanged), `src/orchestrator/mod.rs` (one hidden entry point),
`crates/nexus-dataplane/src/handle.rs` (socket buffer fallback),
`.github/workflows/{ci.yml, release.yml}`.

**CI is unavailable:** GitHub Actions has **never run a job** on this repository. Every run in
`gh run list`, `main` and all `phase-1` pushes included (latest 36327569855, 2026-09-27),
stops in seconds with "The job was not started because your account is locked due to a
billing issue". No existing job, the Linux arm64 one included, has ever been proven. Owner's
decision (2026-09-27): do not wait for it. `scripts/ci-local.sh` runs the same jobs locally
and stands in for CI in the exit criteria (see the note above them); `ci.yml` is kept in
sync with it so real CI works once the lock is cleared.

#### 1.7a `real_path` and CI

**Change:**
- **Rewrite `benches/real_path.rs` in place** on `nexus-dataplane`. The old code cannot
  survive C1+C3 (it imports `crossbeam`, `dashmap`, `MediaWorker`/`WorkerMessage`,
  `SsrcRouter`, `PacketArena`, `WebRtcTransport` and the `test-hooks` method
  `install_srtp_for_testing`, `real_path.rs:25-45`, `:169`), and its numbers are already
  recorded in architecture.md Part 5. C2 then no longer touches `real_path`/`memory`.
- Same groups and ids: `srtp` (`protect|unprotect/{gcm|cm_sha1_80}/{audio|video}`),
  `ingress` (`{profile}/{media}`), `egress` (`{profile}/{media}/{1,10,100,500}`), same payload
  sizes (100 / 1,100 B). The publisher's packets carry the extensions the shard now
  rewrites (`mid` and audio level, as in `tests/alloc.rs`), not the old TWCC id 3.
- **Setup** reuses the data-plane test helpers without a new crate feature:
  `#[path = "../crates/nexus-dataplane/tests/support/mod.rs"] mod support;` (`Peer`,
  `key`, `track_spec`, `sub_spec`, `rtp_with_ext`; all their crates are root
  dependencies). They allocate, so they stay outside timed and counted regions.
- **Shard on a real socket**, driven on the bench thread (no shard thread, so timing is the
  work, not a wake-up): `Shard::new(config, PlatformIo::new(socket), events, now)` with the
  socket from `bind_shard_socket` (GRO off on Linux, `LinuxIo::new` refuses it on). `now`
  is advanced by the bench. `max_sessions` ≥ 501; `pool_buffers` ≥ 500 + `RECV_BATCH` (64);
  the event `Vec` pre-sized and drained between iterations.
- **`ingress`** (socket buffer → decrypted, parsed, routed; zero subscribers so no egress
  is timed): the publisher's protected packet is sent in the untimed setup with
  `BatchSize::PerIteration`, so each timed `iterate` receives exactly one datagram (with
  `SmallInput` several setups run first and one `iterate` drains up to 64). Setup waits
  until the datagram is in the shard's socket (review fix below); iterations that receive
  other than one are counted and printed. **Not comparable with Part 5:** the old ingress
  started from a slice (`WebRtcTransport::process_packet`, no `recv`); recorded as a new
  baseline.
- **`egress`**: one publisher, N subscriber sessions (one per sink; `MAX_SUBS_PER_SESSION`
  limits per session, not per track), each connected and with SRTP installed through
  commands. Timed: one publisher packet in, N rewritten + protected packets out through
  `sendmmsg`/`send_to` (500 subscribers: mid-packet flushes at `SEND_BATCH` = 256).
  `Throughput::Elements(N)` so the number is per subscriber, as before. Sinks drained by
  `common::Sinks`; `raise_fd_limit()` (macOS soft limit 256). After each id print
  `tx_datagrams`, `drop_send_failed`, `drop_srtp_auth` and `tx_full_flushes` from
  `shard.stats()`, like the old `report()`; a run with send failures or auth drops is
  reported, not silently averaged.
- **Sequence wrap:** a full Criterion run sends ≫ 65,536 packets per stream. The shard
  handles ROC (1.1), but the publisher peer's `SrtpContext` and the inbound replay window
  must see increasing indices: keep one peer per id and never rewind its seq. `srtp`
  group: `SrtpOutbound`/`SrtpInbound` (the shard's types, registered SSRC) instead of
  `SrtpContext`; unprotect gets fresh ciphertext per batch as today (`:425-427`).
- **Allocations per packet:** a counting `#[global_allocator]` with the thread-local gate of
  `tests/alloc.rs` (counts calls; gate only around `Shard::iterate`). One untimed pass per
  id before Criterion measures it: 1,000 packets, print allocations per packet. Not an
  assert (`alloc.rs` is the gate, exit criterion 2); a non-zero value is printed with
  `!!` like the old ring-decay warning.
- `--test` smoke still works (Criterion's flag). Setup of the 500-subscriber rigs runs in
  smoke mode too: keep it under ≈ 10 s.
- `benches/common/mod.rs`: doc comment names `real_path` and `udp_floor` (still both users).
- **Socket buffers on macOS** (`handle.rs:100`): the default 8 MiB `SO_RCVBUF`/`SO_SNDBUF`
  (`nexus-core` `config.rs:137-138`, `DataplaneConfig` `config.rs:120-121`) is accepted on
  Darwin 25 (`kern.ipc.maxsockbuf` = 8 MiB) but older XNU returns `ENOBUFS` above ≈ 7.1 MiB,
  and `configure_socket_buffers` turns that into a hard `Err` (`socket_config.rs:99-125`):
  every server test would fail on a `macos-14` (Darwin 23) runner. `bind_shard_socket`
  halves the request on `ENOBUFS` (bounded: down to 256 KB) and `warn!`s the size it got;
  any other error stays fatal. Design §3.12 already says "warn". Unit test with a size
  above `maxsockbuf`.
- **CI** (`ci.yml`):
  - bench smoke unchanged in form (`cargo bench --bench real_path -- --test`,
    `cargo bench --bench memory`), plus `--locked` on both and on clippy (`:39`; the
    engineering rules say CI builds with `--locked`).
  - `NEXUS_MEM_BUDGET_KB: "25"` (`:92`) **lands with 1.7b**, not before: today's bench
    checks the 0-subscription malloc total (≈ 1.55 MB) and would fail.
  - New job `macos` on `macos-14` (arm64): `dtolnay/rust-toolchain@master` with
    `toolchain: "1.83.0"` and `components: clippy`; `HOMEBREW_NO_AUTO_UPDATE=1`, `brew
    install capnp protobuf` (root `build.rs:48-66` and `nexus-signal/build.rs` need both
    until C1+C3); `Swatinem/rust-cache@v2`; `cargo clippy --workspace --all-targets --locked
    -- -D warnings`; `cargo test --workspace --locked` (a superset of note §16's `cargo
    test --test e2e`; `alloc.rs` included). No bench smoke on macOS (`memory` and
    `real_path` run there locally; `udp_floor` is Linux only).
  - `timeout-minutes: 60` on every job (default 360) and a `concurrency` group per ref
    with `cancel-in-progress`, so a burst of `phase-1` pushes does not queue.
- `release.yml:32`: `dtolnay/rust-toolchain@master` with `toolchain: "1.83.0"` and
  `targets:`. Today `@stable` installs stable and `rust-toolchain.toml` silently selects
  1.83.0 anyway; the `targets:` go to the wrong toolchain (harmless only because each
  target equals its host). `docker/build-push-action@v5` → `@v6` like `ci.yml`.

**Code notes (planning audit 2026-09-27):**
- The root crate already depends on `nexus-dataplane` (`Cargo.toml:38`); `PlatformIo` picks
  `LinuxIo`/`PortableIo` (`shard/io.rs:28-32`); `impl EventSink for Vec<Event>`
  (`command.rs:284`) grows without bound: pre-size and drain.
- The shard's classifier is `pub(crate)` (`shard/ingress.rs:31`): C2 drops
  `packet_processing.rs`'s demux groups (or makes `classify` public); not 1.7's concern.
- Criterion 0.5.1; `[profile.bench]` inherits release (`codegen-units = 1`) with thin LTO,
  so compile time dominates the smoke run. `scripts/build_and_test.sh:29` (`cargo bench
  --no-run`) and the Dockerfile's `COPY benches/` need every `[[bench]]` to exist and build.
- The CI release build (`ci.yml:62`, fat LTO) before the tests is the largest single cost
  of the `test` job; left as is (it checks the shipped profile builds).
- macOS runner timing: `loopback.rs` asserts wake ≤ 10 ms median / 100 ms max (`:294`),
  shutdown ≤ 100 ms (`:310`), flood drain < 500 ms (`:399`); e2e DTLS < 3 s after a lost
  flight (`e2e.rs:302`). All pass locally with wide margin; if one flakes on a 3-vCPU
  runner, widen it for CI only with a comment, never skip it.
- e2e needs a non-loopback IPv4 (`harness.rs:36-43`): macOS runners have `en0` with a
  private address (expected fine, unverified until the first run). IPv6 loopback tests skip
  if `::1` cannot bind (`loopback.rs:254-273`).

**Tests:** `cargo bench --bench real_path -- --test` on macOS and in the Linux container; a
full run on each, numbers kept in the session log (architecture.md Part 5 in 1.9); the
`ENOBUFS` fallback unit test; `actionlint` (or a YAML parse) on both workflows.

**Found while implementing 1.7a (2026-09-27):**
- **Injected input.** Sink sockets belong to the drain threads, so subscribers cannot send
  their STUN from them. `BenchIo` wraps `PlatformIo` and hands the shard datagrams from
  memory first (any source address), then reads the socket. Setup STUN comes in that way,
  as does the egress input, so egress measures no receive syscall but still decrypts the
  publisher packet (at N = 1 that is part of the result). Ingress uses a real client socket.
- **Split rigs.** Criterion's setup and routine closures both borrow mutably: the publisher
  (ciphertext builder) and the shard are separate values.
- `now` is fixed per rig: housekeeping never runs inside a timed call (it costs once per
  second in production).
- **The fallback is not reachable on this Mac.** Darwin 25 caps a 1 GiB request silently,
  so the loopback test `oversized_socket_buffers_fall_back` passes with or without the fix.
  The halving logic is a pure function (`fit_buffer_sizes`) with a fake setter that
  refuses above 7,456,540 B (older XNU's limit): its tests fail with the `ENOBUFS` arm
  disabled. Both sizes are halved (`configure_socket_buffers` does not say which one was
  refused), down to 256 KB, never raised; other errors stay fatal.
- The bench smoke (`-- --test`) takes ≈ 5 s after the build (2 min for the bench profile).

**Review fixes for 1.7a (2026-09-27, from an instrumented review run):**
- **Ingress timed empty and double receives.** Loopback delivery lags `send_to` (macOS: in
  60-70% of timed iterations the datagram was not there yet, and the next iteration
  received 2), so the first macOS ingress numbers averaged empty and double iterations.
  Setup now waits until the shard's socket has the datagram: `peek_from` on a clone of the
  shard socket (`try_clone`, the same socket), bounded by 100 ms. An always-on counter of
  iterations with `received != 1` is printed per id and marked `!!` when non-zero (the
  `debug_assert` never ran in the bench profile). After the fix: 0 on macOS and Linux;
  macOS ingress medians 14-28% lower than the first run.
- **Sink-side drops.** On Linux `sendmmsg` succeeds when a sink's receive buffer is full, so
  `tx_datagrams` can overstate delivery (the review run read 63-88% at 1 and 10
  subscribers). After each egress id the bench waits (≤ 500 ms, until the count stops
  moving) and prints what the sinks read against `tx_datagrams`, marked `!!` below 99%.
  Larger sink buffers would not help in the container (`net.core.rmem_max` = 208 KB there).
  In this session's runs the sinks read ≥ 99.97% on every id (numbers below); the drop
  rate evidently depends on load on the VM, which is what the check is for.
- `report()` counts `drop_send_failed` as invalidating the result, like the SRTP and pool
  drops.
- **Relative to the kernel floor.** Phase 0's `udp_floor` number came from another session
  and VM state; `udp_floor` is now run in the same session as `real_path`, and egress is
  recorded relative to it (numbers below).
- `fit_buffer_sizes` is a bounded `for` loop (`FIT_ROUNDS` = 14: from `i32::MAX`, 13
  halvings reach the 256 KB floor and the 14th attempt ends it; a test counts the calls).
- `ci.yml`: `cancel-in-progress` only off `main` and tags; the `macos` job raises the
  open-file limit to 4,096 in the test step (`ulimit` lasts one step's shell; the runner
  default is 256). `ci-local.sh` does the same. `release.yml` jobs have `timeout-minutes`.
- **Numbers** (Criterion medians, after the review fixes below; the first run's macOS
  ingress numbers averaged empty and double receives and are replaced; not comparable with
  Part 5, see the bench header). `udp_floor` ran in the same container session as
  `real_path`:

  | | macOS arm64 (M2 Pro, `PortableIo`) | Linux arm64 container (6 vCPU, `LinuxIo`) |
  |---|---|---|
  | ingress gcm audio / video | 1.52 / 1.71 µs | 0.67 / 0.80 µs |
  | ingress cm audio / video | 1.55 / 2.20 µs | 0.71 / 1.24 µs |
  | egress gcm video, per subscriber at 1 / 10 / 100 / 500 | 7.61 / 7.98 / 7.34 / 7.51 µs | 2.14 / 1.30 / 1.07 / 0.94 µs |
  | egress cm video, per subscriber at 1 / 10 / 100 / 500 | 8.57 / 8.34 / 7.74 / 7.88 µs | 3.15 / 1.74 / 1.52 / 1.35 µs |
  | egress gcm audio, per subscriber at 100 | 7.05 µs | 0.75 µs |
  | `udp_floor` `sendmmsg`, 1,200 B, per datagram, to 1 / 10 / 100 destinations | (Linux only) | 0.51 / 0.82 / 0.69 µs |
  | **egress video ÷ floor** at 10 / 100 subscribers, gcm | | **1.58× / 1.55×** |
  | **egress video ÷ floor** at 10 / 100 subscribers, cm | | **2.12× / 2.20×** |
  | srtp protect gcm audio / video | 112 / 259 ns | 150 / 295 ns |
  | srtp protect cm audio / video | 158 / 675 ns | 193 / 716 ns |

  0 allocations per packet on every `ingress` and `egress` id on both platforms; every
  ingress iteration received exactly one datagram; the sinks read ≥ 99.9% of what was sent
  on every egress id (macOS 100%); no send failure, SRTP drop or rejected command. macOS
  egress is one `send_to` syscall per datagram (design §3.12: correct, not fast). The
  review run measured the floor at 1.57 µs per datagram in a busier VM: only ratios within
  one session are meaningful. The old path at `062e668` (Part 5, Linux arm64, another
  session): egress video at 100 subscribers 3.13 µs (GCM) / 2.19 µs (CM) per subscriber,
  ingress video 3.78 / 2.47 µs from a slice.

#### 1.7b `memory` and the 25 KB budget

**Change:**
- **Rewrite `benches/memory.rs` in place** (note §17.8). The old one builds
  `WebRtcTransport`, `MediaWorker`, `PacketArena` and `OpenSslDtlsEngine::new` (removed in
  C6), and checks only the 0-subscription case using **malloc totals**
  (`created_malloc.unwrap_or(created_rust)`, `memory.rs:364`; assert at `:386`). Its
  "+ subscribed to 10 A+V others" row was 20 subscriptions (`:376-378`); the §3.11 scenario
  is 10 tracks (5 A+V pairs). Both are changes of method, stated in the report's header and
  in architecture.md Part 5 (1.9).
- **Scenario:** rooms of 6 participants; each publishes audio + video and subscribes to the
  other 5 (10 tracks). This is exactly "A+V publisher subscribed to 10 tracks" per
  participant, and the fan-out entries a subscription adds to the *publisher's* track are
  shared evenly. Measure `R` = 10 rooms (60 participants) and divide: the slabs and id maps
  double on demand (`slab.rs:28-35`, `shard/mod.rs:137-144`), so one participant's delta is
  mostly resizing. Also measure the "no subscriptions" step (all published, nothing
  subscribed) in the same run.
- **One process, both planes, one thread, no tokio runtime:**
  - Shard on `MemIo`, `max_sessions` 1,000, synthetic keys; `iterate` called by the bench.
  - `SessionOrchestrator` (public constructor, `mod.rs:64`) with a `CommandSink` wrapping
    `shard.command_queue()` (an `Arc<ArrayQueue<Command>>`), `SingleShard`,
    `DtlsCertificate::generate()`, `DistributedState::new(DistributedStateConfig::new(1))`.
  - The orchestrator's handlers are private (`dispatch_event` `:160`, `settle` `:130`). Add
    one `#[doc(hidden)] pub fn handle(&mut self, event: OrchestratorEvent)` that runs
    `dispatch_event` then `settle` (what `orchestrator_tests.rs:165` does), documented as
    the bench and test entry. Driving the managers one by one would duplicate the private
    glue in `SessionOrchestrator::handle_answer`.
  - Fake signaling: `OrchestratorEvent::Connected` with an `mpsc::channel` sender per
    participant (`orchestrator_tests.rs:173`); the bench drains every receiver after each
    step (with `try_recv`, no runtime) so queued `Offer` SDP strings are not counted as
    session state. Answers built by rewriting offers: copy `answer_for`
    (`orchestrator_tests.rs:212`, ≈ 50 lines) into the bench.
  - DTLS to "after `free_ssl`": `free_ssl` frees only a `Complete` handshake (`dtls.rs:292`),
    so each participant runs a real handshake: a peer `OpenSslDtlsEngine::with_certificate`
    (`openssl_backend.rs:361`); `Event::AddressSelected`, the peer's flights as
    `Event::DtlsDatagram`, the SFU's flights taken from the `SendDatagram` commands in the
    queue, then `Event::PeerSrtpVerified` (triggers `free_ssl`, `connection.rs:61-64`). The
    shard sees the resulting `InstallSrtp`. Peer engines are dropped before the "after"
    sample.
- **What the window excludes** (built before the baseline sample): the shard (pool 2 MiB,
  command queue, pre-sized `by_addr`, retention), the orchestrator and `DistributedState`
  (global `Orswot` ≈ 500 KB), and the rooms (≈ 440 KB each, created first, empty). Reported
  separately as "fixed per shard / per room".
- **Measured with the counting allocator only** (live bytes, alloc − dealloc, per thread
  gate around the bench's own calls as in `alloc.rs`, so nothing else in the process is
  counted). Malloc zone statistics / `mallinfo2` stay for the OpenSSL lines only.
- **Report** (per participant, KB, one decimal):
  - "A+V publisher, no subscriptions" and "+ subscribed to 10 tracks" (Rust heap, delta/N),
    each split into data plane and control plane (two gated counters: the bench tags which
    plane it is calling). Command boxes are allocated by the orchestrator and freed by the
    shard, so the split is by **who holds the memory at the end**: the per-plane figures
    come from each plane's frees and allocations netted together, and only the total is
    asserted. If the split misattributes, report the structural line as the split instead.
  - A **structural line** next to them: `size_of` of `Session`, `SrtpInbound` +
    `SrtpOutbound`, 2 × `PublishedTrack`, 10 × `Subscription`, and the inline entries of
    the pre-sized control-plane maps (`sessions`, negotiation and subscription `states`,
    capacity 1,024, `mod.rs:70`, `negotiation.rs:154`, `subscription.rs:55`), which an
    allocation delta cannot see. Printed, not asserted.
  - Transient peaks, reported: the parsed answer during `accept_answer` (≈ 18 KB per
    `MediaDescription`, ≈ 216 KB for 12 m-lines, freed after), the DTLS engine's Rust
    buffers during the handshake (`pending_output` + two `MemBio` buffers, 3 × 16 KB,
    `openssl_backend.rs:78-80`, `:370`).
  - `Ssl` during the handshake and after `free_ssl`: malloc delta per session (macOS
    `malloc_zone_statistics`, Linux `mallinfo2`; "n/a" elsewhere), averaged over the 60.
    Expected ≈ 0 after `free_ssl`; printed, not asserted (process-wide and noisy).
- **Budget:** `NEXUS_MEM_BUDGET_KB` asserts "+ subscribed to 10 tracks" (data + control,
  delta/N) ≤ budget. CI sets `"25"` in this step (`ci.yml:92`). The assert message names
  the scenario and prints both planes.
- **Expected** (audit estimate from struct layouts; only SRTP measured): data plane ≈ 11 KB
  (SRTP 7.5 KB measured, `direction.rs:866-871`; session ≈ 0.7 KB; 2 tracks ≈ 0.8 KB; 10
  subscriptions ≈ 1.3 KB; maps and fan-out ≈ 0.6 KB), control plane ≈ 3.5 KB
  (`NegotiationState` m-line slots and mids ≈ 1.2 KB, `TransportEntry` ≈ 0.6 KB with the
  engine slot inline, `TrackRegistry` 2 × 0.33 KB, subscriptions, `DistributedState`
  track registers). **≈ 14.5 KB**, the note's §15 said ≈ 11 KB with SRTP at 4.6 KB. If the
  measurement exceeds 25 KB, in this order: slim `ReplayProtection` (48 B × 64, ≈ 2 KB,
  1.1 code notes), box the engine in `DtlsHandshake` (≈ 320 B), move the 256-byte CNAME
  out of `TrackSpec` (4 copies per A+V publisher). Record the measured split either way.

**Code notes (planning audit 2026-09-27):**
- `NegotiationState` does **not** keep `SessionDescription`s (1.4's concern): the parsed
  answer lives only in `accept_answer` (`negotiation.rs:341-370`). No boxing needed.
- `Session`, `PublishedTrack`, `Subscription` have no size tests; the structural line gives
  them visibility, a `size_of` assert is not added (layout changes in Phase 2-3).
- `CRYPTO_set_mem_functions` would measure OpenSSL exactly but `openssl-sys` 0.9.111 does
  not bind it; not worth a hand-written binding for a reported (not budgeted) number.
- The note's §15 table is off on SRTP (4.6 KB estimated, 7.5 KB measured) and the total;
  add a row to the corrections table.

**Tests:** `cargo bench --bench memory` with `NEXUS_MEM_BUDGET_KB=25` passes on macOS and in
the Linux container; checked to fail with the budget set to the measured value minus 1 KB,
and with a 4 KB `Vec` leaked per `CreateSession` in a scratch change (proves the window
sees data-plane state), then with one leaked per `Subscribe` handled in the orchestrator
(control plane).

**Found while implementing 1.7b (2026-09-27):**
- **Two hidden entry points, not one:** `SessionOrchestrator::handle_signal(OrchestratorEvent)`
  and `handle_dataplane(Event)` (each: dispatch, then `settle`, as `run` does). Data-plane
  events need the orchestrator's private `plane`. The shard's `Session`,
  `PublishedTrack`, `Subscription` live in private modules: `nexus_dataplane::sizes`
  (`#[doc(hidden)]`) gives their `size_of` for the structural line.
- **Attribution by allocating plane.** Instead of two gated counters, the bench's allocator
  prefixes each block with a 16-byte header holding the tag in force when it was made
  (data, control, other); `dealloc` subtracts from that tag. A plane's figure is what it
  allocated and still holds, so command boxes (allocated by the orchestrator, freed by the
  shard) and event payloads (the other way) net to zero wherever they are freed; the
  split needed no correction. `realloc` is the trait default (allocate, copy, free).
- **The bench's own copies counted as the control plane.** The first run read 17.7 KB of
  control plane: the fake client kept the offer `String` (≈ 14 KB, allocated by the
  orchestrator) for its ICE credentials. Found by recording the control-plane allocations
  that survived one participant's subscribe (one of 14,140-14,200 B each time, the size
  varying with id digits). Clients now keep their own copy.
- Signaling channels are created and warmed up (96 messages, so tokio's blocks exist)
  before the baseline; rooms are created before it by an admin participant that never
  joins (≈ 440 KB each would swamp the per-participant figure).
- **The SFU's DTLS engine starts at the publish answer** (the answer says `active`, the SFU
  is server and starts at once), before the first datagram. Its size is measured as what
  `free_ssl` frees; OpenSSL's as the malloc growth since the baseline that the Rust
  counter does not explain (headers included on the Rust side; malloc rounding remains).
- **LLVM removed the first control-plane leak.** `std::mem::forget(vec![..])` in
  `handle_subscribe` changed nothing: the unused allocation was optimised away. With
  `black_box` it showed. The data-plane leak did not need it; both checks are now
  written with `black_box`.
- **Results** (identical Rust numbers on macOS and Linux arm64):

  | per participant | data plane | control plane | total |
  |---|---|---|---|
  | A+V publisher, no subscriptions | 9.3 KB | 2.8 KB | 12.2 KB |
  | **+ subscribed to 10 tracks** (budget 25 KB) | **12.0 KB** | **3.8 KB** | **15.8 KB** |
  | structural (`size_of`): session 664 B, SRTP in/out 7,856 B, 2 tracks × 384 B, 10 subscriptions × 120 B | 10.2 KB | 248 B in pre-sized maps; `TransportEntry` 528 B | |

  - DTLS per session: engine Rust buffers 32.1 KB (freed by `free_ssl`); OpenSSL with
    the handshake complete, before `free_ssl`: 151.6 KB (macOS) / 124.8 KB (Linux); after
    `free_ssl`: 3.8 / 1.9 KB (malloc rounding and OpenSSL caches; not asserted).
  - Transient: the control plane peaks 420 KB above its resting level while handling one
    subscribe (12 m-lines: offer printing, answer parse), then returns.
  - Fixed, before the baseline: data plane 8.9 MB (pool 2 MiB, command queue, pre-sized
    `by_addr`, and 6 MB of the bench's `MemIo` capture), control plane 13.2 MB
    (`DistributedState`'s pre-sized CRDTs and 10 rooms).
  - Checks: `NEXUS_MEM_BUDGET_KB=14.8` fails with the per-plane split in the message; a
    4 KB leak per `CreateSession` on the shard moves only the data-plane column (+4.0 KB),
    one per `Subscribe` in the orchestrator only the control-plane column (+4.0 KB in the
    subscribed row). The run asserts its own claims: 60 sessions, 120 tracks, 600
    subscriptions on the shard, no refused command, no consent loss, 60 established
    handshakes with the SFU as DTLS server.
  - vs. the note's §15 estimate (≈ 11 KB): SRTP is 7.7 KB, not 4.6 KB (already in the
    corrections table); the rest matches. 9.2 KB of headroom; none of the fallbacks
    (slimmer `ReplayProtection`, boxed engine, CNAME out of `TrackSpec`) is needed.

**Review fixes for 1.7 (2026-09-28; the review ran `ci-local.sh all`, x86_64 and `docker`
included, and passed):**
- **Signaling reported, not budgeted.** `benches/memory/signaling.rs` runs the real
  `SignalingServer` on its own thread (every allocation there tagged `Signaling`) and real
  `nexus-loadtest` clients on the bench thread; 50 connections each authenticate, receive a
  15 KB offer and send a 15 KB answer, and stay open. Server side per connection: **≈ 49 KB
  over WebSocket, ≈ 57 KB over TLS** (connection task, outbound channel, tungstenite
  buffers, rustls state), three times the session state. Not in the budget (note §15;
  design §3.11 now says so, revision 2026-09-28); worth a look after v1 (tungstenite's
  buffers are sized for large messages).
- **Allocator overhead line.** Live blocks per participant (23) and the malloc residual,
  split into what OpenSSL still holds after `free_ssl` (2.8-3.8 KB) and the allocator's
  rounding and per-block overhead (≈ 0.9-1.1 KB per participant). Printed, not checked.
- **Fixed costs split:** shard 8.9 MB (incl. 6 MB of the bench's `MemIo` capture),
  orchestrator 8.9 MB (`DistributedState`'s pre-sized CRDTs), **430 KB per room**
  (`DistributedState::create_room`).
- **Two runs, past the doubling point.** 10 rooms (60 sessions in a 64-slot slab) and 11
  rooms (66 in 128). The data plane grows from 12.0 to 13.0 KB per participant in the 11-room
  run; the checked figure is the larger run plus the control plane's entries in maps
  pre-sized before the baseline (248 B, from `size_of`, invisible to the deltas):

  | per participant | 10 rooms | 11 rooms |
  |---|---|---|
  | A+V publisher, no subscriptions | 12.2 KB | 13.2 KB |
  | + subscribed to 10 tracks (data / control) | 15.8 KB (12.0 / 3.8) | 16.6 KB (13.0 / 3.6) |
  | **checked: larger run + pre-sized entries** | | **16.9 KB ≤ 25 KB** |

  `NEXUS_MEM_BUDGET_KB=16.8` fails with the split and the room count in the message.
  **Later ("Before 1.9", Room memory):** rooms no longer preallocate their participant
  sets (≈ 430-440 KB per room → ≈ 0.1 KB), and a set grows at each join, so the checked
  figure is **17.5 KB** (re-measured in 1.9 at `fa8a6a9`: 17.3 KB at 11 rooms + 248 B).
- `ci-local.sh`: the summary line says `clean` or how many paths are uncommitted or
  untracked (`git status --porcelain`; untracked files are copied into the Linux jobs), and
  which targets ran; `docker` builds `--platform linux/amd64` like the CI job (emulated on
  Apple Silicon); `set -eo pipefail` inside the container. CLAUDE.md: only `all` covers
  every job; the `docker` and x86_64 targets are emulated.

**Checkpoint (1.7):** both benches run locally on macOS and in the Linux container (smoke
and full); `scripts/ci-local.sh all` green (every `ci.yml` job, `bench-smoke` with
`NEXUS_MEM_BUDGET_KB=25`, the `macos` job, Linux x86_64 emulated), its summary in the
session log. **Exit criterion 3** is met then (the budget holds and `ci.yml` and the script
enforce it). **Exit criterion 1** needs the 1.6 tests, then another `all` run.

**`scripts/ci-local.sh`** (added 2026-09-27, after 1.7a):
- Targets `macos`, `linux-arm64`, `linux-x86_64`, `docker`, `all`; default `macos
  linux-arm64` on a Mac. Jobs run one after another (timing tests share the CPU) and go on
  after a failure (`fail-fast: false`); the exit code is 1 if any step failed.
- Linux jobs run in `nexus-ci:1.83.0-<arch>`, built on first use from
  `rust:1.83.0-bookworm` with the packages `ci.yml` installs, on a copy of the working tree
  (uncommitted changes included; `target/`, `node_modules/`, `.git` excluded). The target
  directory is a named volume per architecture (`nexus-ci-target-<arch>`), the cargo
  registry a shared one (`nexus-ci-cargo`).
- The memory budget is read from `ci.yml` (`NEXUS_MEM_BUDGET_KB`), so the two cannot differ.
- Logs per job and `summary.txt` in `target/ci-local/`; the summary's last line names the
  commit, whether the tree had uncommitted changes, the budget, and PASS/FAIL.
- Differences from Actions, by necessity: arm64 Linux runs in a VM on the Mac (Docker
  Desktop), x86_64 under emulation (slow; a timing assert that fails only there is noted
  and re-run, not ignored), macOS is Darwin 25 rather than `macos-14` (the `ENOBUFS` limit
  of 1.7a cannot show up here).

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

**Code notes (implementation audit 2026-09-28, before the code):**
- **A publisher never learned its own track ids.** `Joined` excludes self, `TrackPublished`
  skips the publisher, and `Offer.tracks` lists only subscribe m-lines, so `unpublish(trackId)`
  had nothing to send.
  - Owner's decision: a new server message `Published { track_id, mid, kind }`, sent only to
    the publisher from `register_publish`, once per registered track.
  - This is a protocol addition. No D/R decision changes.
  - Loadtest and e2e ignore it (`_ =>` arms).
- **`Leave` ends the session.** The server removes it, and anything later on that socket is
  dropped.
  - `leave()` sends `Leave`, then closes the peer connection and the socket.
  - Rejoin is `connect()` + `join()`: a new socket, a new participant id, a new PC.
  - `SignalingTransport.close()` drops queued messages, so a `Leave` queued while
    disconnected cannot end the next session. Handlers of a replaced socket are ignored,
    so there is no stray reconnect.
- **`Unpublish` sends the publisher no offer.** `unpublish()` detaches the track
  (`replaceTrack(null)`) and sets the transceiver to `recvonly`, not `inactive`, because
  the SFU may reuse that m-line for a subscription (`claim_mline`).
- **`Subscribe`:** more than 10 ids fail the whole request (`TOO_MANY_TRACKS`), so the SDK
  splits into chunks of `MAX_TRACKS_PER_REQUEST = 10`. `Unsubscribe` is split the same way.
- **Token:** the flag is the existing global `--jwt-secret`, falling back to
  `NEXUS_JWT_SECRET`. `mint_token` refuses secrets shorter than 32 characters, as the SFU
  does.
- **SDK defaults:** `iceServers` defaults to `[]` (ICE-lite; no Google STUN).
  `createRoom(name)` relies on rooms being idempotent by name.
- **Clearing TLS:** `NEXUS_TLS_CERT_PATH=` / `NEXUS_TLS_KEY_PATH=` (empty) do not give plain
  WS. They also clear `[quic] cert_path`, which validation refuses. The page README uses a
  config copy with the `[transport]` TLS paths cleared.
- **SDK tests:** `node:test` against `dist/`, with no new dependencies. They run in the
  `ci.yml` `sdk` job and in `ci-local.sh` (macOS target).
  - Node is pinned in `sdk/.nvmrc` (20). `ci.yml` reads it with `node-version-file`,
    `ci-local.sh` refuses a different major, and `engines` says `>=20`.
- **Review fixes (2026-09-28):**
  - **Matching errors to requests.** SFU errors carry no request id. The orchestrator
    handles a participant's messages in order and replies to each synchronously
    (`handle_message`, `Ping` → `Pong` included). So the SDK sends a `Ping` behind each
    Publish, Subscribe and Answer, and an error belongs to the oldest request whose
    `Pong` has not arrived yet. The 30 s keepalive `Ping` is counted too.
    - A Subscribe error no longer rejects a publish that is in flight.
    - Limit, documented on `NexusClient`: a `Ping` the SFU drops (above 100 messages per
      second) shifts the matching. The publish timeout still cleans up.
  - **A refused or timed-out publish undoes its state:**
    - it leaves `localTracks` and `unattachedTracks`;
    - `offerPending` is cleared when no offer is coming, and queued requests go out;
    - an attached track is detached.
    - Answer-time refusals (`INVALID_TRACK`, `SSRC_COLLISION`, ...) fail one track each,
      in m-line order. A track with neither `Published` nor a refusal by the `Pong` fails
      as `NOT_REGISTERED`.
    - In each case the same track can be published again.
  - `requestTimeoutMs` option (tests use 30 ms). Tests 9 → 14. Negative check: when errors
    are matched by code only, the Subscribe-error test fails.
  - **Server: a refused publish m-line is released (second review).**
    - `register_publish` returns whether it registered a track.
    - On every refusal (declined or no SSRC, `INVALID_TRACK`, `SSRC_COLLISION`,
      `DUPLICATE_SSRC`, the track limit, a failed push) the caller turns the m-line
      `Inactive`. Before, it stayed `Publish`: it was re-offered as a `recvonly` m-line no
      track would ever register, and `claim_mline` could not reuse it.
    - Test: `refused_publish_mline_is_released_and_reused`. Negative check: without the
      release, the m-line stays `Publish` and the test fails.
  - **SDK fences (second review):**
    - A publish whose `Pong` came with no offer is one the SFU queued (`serverQueued`). An
      answer's replies are its m-line results, then the queued publish's outcome. So an
      answer-time `TOO_MANY_TRACKS`/`OFFER_FAILED`/... with no m-line pending fails the
      queued publish's tracks, and no others.
      - Negative check: failing the first unattached track instead fails the new test.
      - Limit, documented: a failed subscription renegotiation in the same answer also
        fails a queued publish.
    - Create, Join, Unpublish and Unsubscribe are fenced too. `createRoom`/`join` reject
      only on their own errors, and no error of theirs touches a publish.
    - A disconnect drops the fences and the queued `Ping`s.
    - A `Published` after the publish timed out emits `lateTrackPublished`
      `{ trackId, mid }`, so the app can `unpublish` it.
    - The mock SFU offers every m-line with its direction, so the republish tests offer
      what the SFU now does (a refused m-line inactive, then reused `recvonly`).
    - SDK tests 14 → 20.
  - The README no longer overwrites `certs/dev-*.pem`: a LAN certificate goes in
    `certs/lan-*.pem` through `NEXUS_TLS_*`. It adds an HTTPS static server (Python stdlib,
    same certificate), and passes the secret in `NEXUS_JWT_SECRET`. These commands were run
    once: PKCS#8 key, HTTPS 200, SFU TLS 1.3 handshake on 8080.

**Recorded check.**

*Chromium pre-check (automated), 2026-09-28:*
- Setup:
  - HeadlessChrome 153 through Playwright, three tabs on one Mac, `fake=1` media;
  - SFU from this branch with plain WS and `NEXUS_ANNOUNCED_IPS=192.168.100.88`;
  - the page served from `localhost`.
- Step 2: media flows both ways.
  - `a=ice-lite` in every offer.
  - Chrome is DTLS client.
  - `srtpCipher` is `SRTP_AEAD_AES_128_GCM`; the SFU logs `AeadAes128Gcm` for all 8
    sessions.
  - 0 packets lost.
  - The remote candidate is `host 192.168.100.88:10000`.
- Step 3: a third tab joining late decoded its first video frame 166 ms and 233 ms after
  Start (PLI on subscribe).
- Step 4 (lip sync) cannot be judged headless.
- Step 5:
  - Unpublish then republish of the camera: peers got `TrackUnpublished`, then the new
    track on the reused m-line, decoding at ≈ 30 fps.
  - Leave then rejoin: peers got `ParticipantLeft` and `TrackUnpublished`, then the new
    participant's tracks. The rejoined tab decoded both peers after 112 ms.
- No warning or error in the SFU log.

*Owner's check (§17.9 steps 1-6):* to fill in.

| Field | Value |
|-------|-------|
| Date | |
| Machine A: OS, browser + version, network | |
| Machine B: OS, browser + version, network | |
| SFU host, `NEXUS_ANNOUNCED_IPS`, signaling (ws/wss) | |
| Negotiated SRTP cipher (Chrome / Firefox) | |
| ICE-lite remote shown (`webrtc-internals` / `about:webrtc`) | |
| 1-2. Both see and hear each other | |
| 3. Third tab late, video within ≈ 1 s | |
| 4. Lip sync | |
| 5. Unpublish/republish, leave/rejoin | |
| 6. Wi-Fi ↔ wired switch (recovers, or ICE restart = known limit) | |
| Anything that failed | |

---

### Before 1.9: SR test flake, exit criterion 6 sweep

**SR test flake (`sender_report_translation`).**
- **What happened:** the test compared the last SR with the track's last packet read at
  the end of the test, up to about 1 s of extrapolation. That packet's arrival time was
  also taken from any packet, while its RTP timestamp came only from in-order packets.
  One run in five (the run right after the Docker jobs) measured 28.9 ms against 20 ms.
- **Change:**
  - The loadtest's `RtcpLog::record_with_media` stores the receiver's last in-order
    packet (`LastPacket`: timestamp and that packet's arrival) with each SR when the SR
    arrives.
  - The test measures every SR after media arrived (at least 3 per track) and asserts
    the median error ≤ 50 ms and every SR ≤ 200 ms.
- **Measured:** 2-3 ms per SR.
- **Negative check:** a 100 ms offset in the shard's SR translation fails the test
  (median 105.5 ms).

**Exit criterion 6: no reachable panic on network input (2026-09-28).**
- **Method:** each input path traced from the socket or WebSocket to every `unwrap`,
  `expect`, `assert!`, index, slice, split and time-arithmetic site. Release builds
  (`panic = "abort"`, no overflow checks) are what counts.
- **Coverage:** the data plane end to end, STUN and DTLS, and SDP plus the signaling
  JSON and orchestrator. Each finding was then checked against the code, with a test
  that fails without the fix.

| Path | Checked | Result |
|------|---------|--------|
| Shard receive and classify (`io/linux.rs`, `portable.rs`, `ingress.rs`) | Batch and pool bounds, truncation, `classify` | Safe |
| STUN in the shard (`ice.rs` scan, `integrity.rs`, `write_success`) | Header, attribute walk (≤ 32), USERNAME/ufrag split, MI/FINGERPRINT offsets, response size | Safe |
| ICE-lite address selection (`select_address`, `apply_pending_switches`) | Nomination, throttle, rebind, replay | **Fixed**: see below |
| SRTP/SRTCP in and out (`nexus-transport/src/srtp`: `direction`, `index`, `replay`, `crypto` GCM and CM) | Length and tag checks before splits, ROC and index limits, replay window shifts | Safe |
| RTP parse, rewrite, extensions (`nexus-media` `RtpHeader::parse`, `rewrite.rs`, `ext.rs`) | CSRC, extension and padding bounds, one- and two-byte elements, output room | Safe |
| RTCP (`demux_compound`, SR/PLI/FIR parse, `shard/rtcp.rs` translation, keyframe requests) | Compound walk (≤ 16), fixed lengths, `FixedVec` caps | Safe |
| DTLS to the control plane (`handle_dtls`, `orchestrator/dtls.rs`, `openssl_backend.rs`, `srtp_keys.rs`) | Budgets, empty and oversized input guards, record split, role and ClientHello, fingerprint (SHA-256, 32 bytes), keying export, verify callback (`\|_, _\| true`) | Safe |
| WebSocket and auth (`nexus-signal/websocket/server.rs`, `nexus-api/auth.rs`) | 1 MB frame and 256 KB message caps, rate limit, auth frame, JWT decode | Safe |
| Orchestrator messages (`mod.rs`, `room.rs`, `negotiation.rs`, `subscription.rs`, `plane.rs`, `sdp_params.rs`) | Each client message; `claim_mline`'s assert against the limit checks, expects after state lookups, `answer.media[index]` after `mids_match`, id casts | **Fixed**: `Create`/`Join`, see below |
| SDP answer (`nexus-webrtc` parser, `Mid::parse`, `track_spec`, `extract_fingerprint`) | Byte-based line types, `min`-bounded copies, `parts[i]` behind length checks, hex decode, UTF-8 accessors | Safe |
| REST (`nexus-api/rest.rs`) | Name length, participant range, `Bearer` slice | Safe. The room-id wrap after 2^32 POSTs now gets an error from `create_room` |
| **SWIM gossip** (`nexus-state/src/gossip/`: `transport`, `types`, `protocol`, `membership`; `DistributedState` apply paths; CRDT merges). Missed by the first sweep, found in review | Receive size, every decoder, piggyback counts, sender-supplied actor ids and incarnations, updates applied to the state | **Fixed**: see "Gossip" below. It is also no longer started on a single node |

**Fixes:**
- **Duplicate nomination entries aborted the shard.**
  - Cause: a nomination from the current address cleared `pending_nomination` but left
    the session in `pending_switches`, and the next throttled nomination listed it
    again. Batches ending on the new address kept the copies until
    `assert!(len < capacity)` aborted the process.
  - Who could trigger it: any peer with the session's ICE credentials, in about
    `2 × max_sessions` requests within 100 ms.
  - Fix: `Session::switch_listed`, so a session is listed at most once.
  - Tests: `alternating_throttled_nominations_list_the_session_once`, and
    `authenticated_stun_sequences_never_panic` (a proptest of signed requests with random
    source addresses, including one shared address, nomination, replays, timing and
    batching). Both fail without the fix; the proptest found the abort on its own once
    requests could share a batch.
- **`Create` with a room name over 256 bytes aborted the process, in one message.**
  - Cause: `RoomMetadata::new` asserts on the length.
  - Fix: `handle_create` refuses the name with `INVALID_INPUT`, and
    `DistributedState::create_room` returns `InvalidState` for a room id of 0, an
    over-long name or out-of-range `max_participants`, instead of asserting.
- **The room-id counter overflowed.**
  - Cause: `next_room_id += 1` panicked in debug builds and wrapped to 0 in release,
    where `create_room` asserted.
  - Fix: `checked_add`. The last id is never handed out, and the counter advances only
    when the room was created.
  - Also changed: a failed create now sends an error instead of `Created` for a room
    that does not exist.
- **`Join` checks (not panics, fixed in passing):**
  - `participant_name` over 256 bytes gets `INVALID_INPUT`. It was copied to every
    peer, so it was a memory amplification.
  - A `room_id` above `u32::MAX` gets `ROOM_NOT_FOUND`; it used to wrap onto another
    room.
- **Tests for these:**
  - `create_and_join_refuse_input_that_used_to_panic`;
  - `test_create_room_refuses_invalid_input` (`nexus-state`);
  - `random_signaling_never_panics`: a 128-case proptest over random and well-formed
    messages from three participants, with answers to the latest offer, declined
    m-lines, disconnects and reconnects. It reaches registered tracks, subscriptions,
    `NOT_OWNER`, `TOO_MANY_TRACKS` and `INVALID_ANSWER`. Negative check: without the
    name checks it finds the `Create` abort.

**Gossip (second review of the sweep).**
- **What was wrong:** `Node::start` always opened the SWIM socket on `0.0.0.0:0`, with no
  authentication. Several received datagrams aborted the process:
  - an empty datagram (`transport.rs` `assert!(size > 0)`);
  - updates with zero or out-of-range ids (asserts in the `types.rs` decoders and in
    `DistributedState` add/remove participant, track and subscription);
  - an `LWWReg` timestamp of 0;
  - a ping-req naming this node;
  - a full membership whose anti-entropy snapshot exceeded the datagram size;
  - an incarnation at `u64::MAX` (overflow).
- **Received data no longer panics:**
  - An empty datagram is dropped and counted. A datagram longer than the receive
    buffer (`MAX_MESSAGE_SIZE`) is truncated by the kernel, and the truncated bytes are
    decoded like any other input, safely.
  - Decoders return `None` and apply paths return errors.
  - The receive loop drops and counts bad datagrams (`SwimProtocol::handle_datagram`,
    `messages_dropped`).
  - Snapshots are capped at 38 members.
  - Incarnations saturate.
  - The subscription-update decoder now reads the layout the encoder writes (it never
    matched, so a legitimate update decoded to track 0).
  - Asserts on local invariants stay.
- **Tests:** `crates/nexus-state/tests/gossip_robustness.rs` (14 tests: an empty and an
  oversized datagram, each crafted update, framing, actor ranges, messages about the local
  node, and proptests over random bytes, 2,000 cases, and over structured messages, 3,000
  cases), plus unit tests in `types.rs`, `transport.rs`, `membership.rs` and
  `distributed_state.rs`. Each fix was checked by reverting it: the matching test panics
  at the original site.
- **Gossip is off unless a cluster is configured.** `cluster.gossip_enabled` defaults to
  false: the node creates its state and opens no gossip socket.
  - When on, `cluster.gossip_bind_addr` is required and may not be 0.0.0.0 or `::`.
  - `gossip.seed_peers` without `gossip_enabled` is a config error.
  - The config files document both keys.
  - Tests: `single_node_opens_no_gossip_socket`, `gossip_config_is_validated`.
- **Gossip is unauthenticated** (spoofed membership, rooms, participants and tracks;
  ping-req reflection). `dataplane-design.md` §2 non-goals and its revision log say it
  must be authenticated before clustering ships.
- **Found and not fixed** (gossip is off in v1):
  - applied updates are re-broadcast as local operations and can echo between nodes;
  - one datagram per probe interval means junk can starve real pings;
  - `drain_relay_events` has no caller, so the relay queue fills.

**Room exhaustion (second review).**
- **Every room counts against `MAX_ROOMS`.** The check uses `DistributedState::room_count`,
  named or not, REST-created too. Test: `unnamed_rooms_count_against_the_room_cap`.
- **Per-connection limit:** a connection may hold `MAX_ROOMS_PER_CREATOR` (4) rooms it
  created.
- **Release:** a room still empty when its creator leaves or disconnects is released. A
  joined room is released by its last member, as before. Test:
  `created_rooms_are_limited_and_released_with_their_creator`.
- **Room memory:**
  - The participant `Orswot` no longer preallocates 10,000 entries and 5,000 tombstones
    (≈ 440 KB per room, computed from the layout).
  - Entries and tombstones grow on demand up to their caps (control path, at join and
    leave).
  - A room's set is capped at the room's participant limit (`Orswot::with_capacity`).
  - Measured with a counting allocator: an empty room adds 0 B of heap beyond the state's
    preallocated maps; 10 participants add 512 B. 10,000 empty rooms now fit in a unit
    test.
- **`create_room` refuses an existing id** (`DuplicateElement`) instead of replacing its
  metadata and participant set.
- **One room-id allocator (third review).** REST kept its own counter from 1, so after
  the orchestrator had created rooms, REST creates got a 500 (`DuplicateElement`).
  - `DistributedState::create_room_auto` hands out the next free id under the rooms lock:
    taken ids are skipped, ids are never reused, and the last id is never handed out, so
    there is no wrap to 0.
  - The orchestrator's `Create` and REST (whenever it has the state) both use it. The
    orchestrator's own counter is gone.
  - Tests: `test_rest_create_after_orchestrator_rooms` (`nexus-api`),
    `test_create_room_auto_skips_taken_ids_and_never_wraps`,
    `test_create_room_keeps_an_existing_room`, `create_skips_a_room_id_taken_elsewhere`,
    `test_orswot_grows_on_demand_up_to_its_capacity`.
- **Tombstones recycle (third review).**
  - Before: a participant set kept up to `MAX_TOMBSTONES` (5,000) and never cleared
    them. After 5,000 leaves in one room's lifetime, `remove_participant` failed with
    `TombstoneOverflow`: the leaver stayed as a ghost and the room never emptied.
  - Now: tombstones are a ring of twice the set's element limit (at most 5,000), and the
    oldest is overwritten when it is full, so a remove never fails for lack of room.
  - Cost, only with gossip: a remove older than the ring can be undone by a stale remote
    add of that element. On a single node, local adds always carry newer clocks.
  - Tests: `test_orswot_tombstones_recycle_oldest_first`,
    `test_join_leave_churn_never_leaves_ghosts` (6,000 cycles in `DistributedState`),
    `join_leave_churn_keeps_the_room_usable` (6,000 participants through the
    orchestrator).
  - Negative check: when a full ring fails the remove, as before, the orchestrator test
    ends with 1,000 ghosts in the room.

**`address_change_mid_call` window (found while running this change).**
- **What happened:** the test failed twice inside a full `cargo test --workspace` run,
  once on Linux arm64 and once on macOS. Both times one stream to A had 31 of 75
  sequence numbers missing in the window after the rebind.
- **Not reproduced:** 0 failures in 19 runs alone or of the whole e2e binary.
- **Likely cause:** the window was measured from the moment the *sum* of a direction's
  streams moved again. A stream that resumed later (the sparse audio stream, under load)
  could have its outage gap counted as loss.
- **Change:** `wait_for_resume` tracks each stream and returns the earliest and the
  latest resume. The silence rule (≥ `rebind_silence` − 200 ms) is checked on the
  earliest stream of each direction (now both directions); `REBIND_RESUME_MAX` is checked
  on the latest. The window starts after the latest. This removes the bias but does not
  prove the cause. If the failure recurs, it is loss after resumption and needs a closer
  look.

**Known issues, not panics, not fixed (after v1 or 1.9 decides):**
- **Rooms from REST are never released** (only the orchestrator tracks creators).
- **Connections can hold slots before authenticating.** The TLS accept and WebSocket
  upgrade have no timeout, so 10,000 half-open connections block signaling. The
  connection-limit check is racy.
- **`Disconnected` can be lost.** It goes to the orchestrator with `try_send`, so a full
  queue leaks that participant's state.
- **`MemBio` grows without a limit** if OpenSSL stops reading after an alert. The shard's
  DTLS budget limits the rate.
- **Fuzzing gaps that remain:**
  - structured STUN attribute layouts (random bytes rarely pass the header check);
  - the SRTP profiles other than GCM-128 in the shard proptests;
  - no `cargo-fuzz` targets.

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
- Status table and session log complete; a `scripts/ci-local.sh all` run green on the
  commit to merge (or CI, if Actions works again), summary in the session log; merge
  `phase-1` into `main`.

**Checkpoint:** every exit criterion checked off in the Status table; merged.

**Done (2026-09-28, documents):**
- **Order (owner's decision):** the document work is committed now; the `ci-local.sh all`
  run and the merge wait for the owner's §17.9 check (exit criterion 4). After the merge,
  CLAUDE.md names Phase 2 as current, with its plan not written yet.
- `architecture.md`: header, Parts 1-2 and 3 from the code (traced from `src/main.rs`); 2.2
  marks the re-subscribe and SRTCP issues fixed and lists the open ones; Part 4 notes what
  Phase 1 answered; Part 5 has the Phase 1 numbers (1.7a `real_path`, 1.1 SRTP, memory
  re-measured at `fa8a6a9`: 17.5 KB, loopback, e2e) above the Phase 0 baseline.
- Design: revision 2026-09-28 "Phase 1 close" (GCM offered first since 1.5b, 17.5 KB, the
  tombstone text, `Published`); §3.4, §3.11, §4 (`cluster.gossip_enabled`) and the header
  follow. `dataplane-v1.md` points to the corrections below.
- **Decided here, not changed:** the always-zero `nexus_sfu_*` / `nexus_crdt_*` series are
  documented (architecture.md 2.1), not removed (after v1). `docs/architecture-vision.md`
  stays as a reference, as CLAUDE.md says. README performance targets are updated at
  release (design §5); a line points to Part 5.
- Old-path comments: `src/lib.rs` (crate comments, `tier::CURRENT`), `src/node.rs`,
  `src/error.rs` and `nexus-core` (arena), root `Cargo.toml` (description, dependency
  comments), `examples/basic_sfu.rs`. Left on purpose: provenance notes ("copied from
  `src/worker/pool.rs`"), the refusal messages for removed config.

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
| §15 | SRTP ≈ 4.6 KB per participant, fixed total ≈ 11 KB | `SrtpInbound` + `SrtpOutbound` measure 7,728 B; audit estimate ≈ 14.5 KB in total (1.7b measures it); still under 25 KB |
| §11.2 | The table lives in `nexus-dataplane`, shared with the negotiator | It lives in `nexus_media::rtp::extensions` (no dependency between the two crates); `nexus_dataplane::ext` re-exports it |

## Risks for this phase

The note's §19 risks stand; these are the ones the audit added.

| Risk | Mitigation |
|------|------------|
| Rebind resume ≈ 2.2-2.6 s is close to the 2 s silence rule | Assert ≥ `rebind_silence` − 200 ms and < 4.5 s, log the measured value; if flaky, lower `rebind_silence` in the test config only |
| A 32-m-line session hits signaling size limits | 1.4 raises the SDP and WebSocket limits and turns silent drops into errors; tested with 32 m-lines |
| The manual browser check is blocked by HTTPS/token setup | 1.8 documents both setups; the SDK and token work can start before 1.5b |
| Linux-only code (`LinuxIo`, pinning, GRO check) only runs in the container and CI | Container run is part of every I/O part's checkpoint |
| **CI has never run** (GitHub account billing lock; every run fails before starting, 2026-09-27) | Owner's decision: `scripts/ci-local.sh` stands in for CI (exit criteria note). Residual: no real `macos-14` or x86_64 hardware, and nothing runs automatically on push, so a session that skips the script is not caught. When Actions works again, the first run may surface failures in jobs that have never run |
| `macos-14` refuses 8 MiB socket buffers (`ENOBUFS` on older XNU) and every server test fails | 1.7a: `bind_shard_socket` halves on `ENOBUFS` and warns |
| Remote panics remain in code the shard does not use but the control plane does (DTLS, SDP parser) | Exit criterion 6; DTLS input guards in 1.5a; SDP errors instead of asserts in 1.4 (done: two parser panics fixed, fuzz proptests on the parser) |
| **Known limit, aggregate DTLS pressure.** The per-session budget (32 DTLS datagrams per second, 1.2) bounds one peer, but many sessions that passed STUN and never finish DTLS can together fill the event channel all shards share, and other sessions' handshake datagrams are then dropped (peers retransmit) | 1.3 (done): a shard-wide cap on `DtlsDatagram` events per second (`dtls_budget_per_sweep`, 1,024). 1.5a/1.5b: the orchestrator's DTLS handshake timeout closes sessions that do not complete, so the pressure is bounded in time |
| **Known limit, room authorization (v1 item).** Tokens carry no room claim: any authenticated user can join any room by id (sequential) and subscribe to its tracks. 1.5b confines subscriptions to the subscriber's own room and refuses a second `Join`, but not the first | Added to the v1 scope (`dataplane-design.md` §2, revision 2026-09-27). **Owner's decision 2026-09-28: fixed in Phase 1, part 1.9a, before the merge** (reproduced: a second token joined room 1 by id, and `Create` with the same name returned the same room). Needs a room claim in the JWT (`nexus-api`), checks in `Create`/`Join`, and the dev token of 1.8 minting it |
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
| 1.5b-prep Node module, config, negotiator options, loadtest marker | Done | see git log (1.5b-prep) | `node.rs`, `[dataplane]` config, `with_ice_lite` + Track rtcp-fb parameter (golden old-path offer), loadtest marker + announced SSRCs; moved in: sha-256 fingerprint choice, `SsrcAllocator` fixes, shard DTLS from the selected address only. Old path green (e2e 3/3) |
| 1.5b Switch (one commit) | Done | see git log (1.5b) | New path live: e2e 3/3 (both DTLS roles, AES-GCM), SSRCs rewritten. Early browser check: Chrome 153 passes (GCM, ICE-lite, media both ways) after the stable-PT fix; Firefox deferred to 1.8 (owner's decision) |
| 1.7 Benches, memory budget, CI | Done | see git log (1.7) | 1.7a: `real_path` on the shard, 0 allocations per packet, `ENOBUFS` fallback, macOS CI job, `--locked`, timeouts, release pinned. 1.7b: `memory` on both planes, 16.9 KB per participant checked (session state), signaling ≈ 49/57 KB reported apart, budget 25 in `ci.yml`. Before C2. CI unavailable (billing lock): `scripts/ci-local.sh` stands in |
| C2 Old benches | Done | see git log (C2) | `forwarding.rs` deleted; `packet_processing.rs` keeps RTCP parsing, demux groups dropped; root `test-hooks` dev-dependency removed (from C6) |
| C1+C3 `Sfu`, packet loop, `worker/`, `forward/`, `proto.rs` | Done | see git log (C1+C3) | ≈ 7,100 lines of old path + `sfu.rs` (2,284) gone; 20 root dependencies, `build.rs`, `proto/`, `protoc` no longer needed |
| C4 `nexus-actor`, `nexus-dst` | Done | see git log (C4) | Both crates, `ActorMetrics` and the `nexus_actor_*` series gone; `[actor]` checked against the orchestrator's limits until C7 |
| C6 `WebRtcTransport`, session, demux | Done | see git log (C6) | `nexus-webrtc` is SDP only (≈ 5,800 lines gone); `OpenSslDtlsEngine::new` removed |
| C5 Replaced `nexus-transport` modules | Done | see git log (C5) | Arena, ring buffer, UDP/io_uring/batch transports, ICE agent, `StunServer`, pure-Rust DTLS, `ArenaError` gone; `nexus-transport` is SRTP, STUN, candidates, OpenSSL DTLS, socket setup |
| C7 Config, README, example | Done | see git log (C7) | Old config sections/fields/env vars removed and refused (fail fast); shard stats on `/metrics`; README, example, TOMLs, dashboard |
| 1.6a E2E: harness, ten clients, resubscribe | Done | see git log (1.6a) | Signaling task + events, `subscribe_confirmed`/`unsubscribe`, announced history + CNAME, inbound tap; `ten_clients` 9.7 s, suite 27.1 s; negative check fails on SRTCP index reuse |
| 1.6b E2E: address change, SR, keyframes | Done | see git log (1.6b) | `LossRules::rebind`, `RtcpLog` (publisher PLI/FIR, subscriber SR/CNAME), three tests; resume 2.1-2.3 s, SR error ≤ 5.7 ms, burst → 1 PLI; negative check fails with the silence rule disabled. Review fixes (1.6a/1.6b checks, `ci-local.sh` lock, dashboard, scripts) |
| 1.8 SDK, browser page, manual check | Code done (see git log (1.8)); owner's check pending | | `Published` to the publisher, `nexus-loadtest token`, SDK `createRoom`/`publish`/`unpublish`/`unsubscribe`/`leave`/`getStats`, ≤ 10 ids per request, `node:test` (20) in CI, `examples/web/`, review fixes (fenced error matching, refused-publish cleanup, refused publish m-lines released on the server). Chromium 153 pre-check passes steps 2, 3, 5 (GCM, ICE-lite, late join ≈ 0.2 s). Exit criterion 4 waits for the owner's Chrome + Firefox run on two machines |
| SR flake, exit criterion 6 sweep | Done | `fa8a6a9` | SR errors measured per SR (median ≤ 50 ms, max ≤ 200 ms). Sweep of every network input path: aborts fixed in the shard (duplicate nomination entries), signaling (`Create` name over 256 bytes, room-id wrap) and **gossip** (empty datagram, crafted updates, found in review). Gossip off unless a cluster is configured. Room limits (every room counted, per-creator cap, release, rooms no longer preallocate ≈ 440 KB). Proptests: authenticated STUN, random signaling, gossip bytes and messages. **Exit criterion 6 met** |
| 1.9a Room authorization | Not started | | Owner's decision 2026-09-28: before the merge. Room claim in the JWT; `Create`/`Join` check it; `nexus-loadtest token --room`; SDK/page pass it; e2e: a token for room A cannot join room B by id or by name |
| 1.9 Documents, merge | Documents done; merge waits for 1.9a and exit criterion 4 | see git log (1.9) | `architecture.md` Parts 1-5 on the new path (Phase 1 numbers, Phase 0 kept as baseline), CLAUDE.md, README, design revision 2026-09-28 (GCM first, 17.5 KB, tombstones, `Published`), note in `dataplane-v1.md`, old-path comments in `src/lib.rs`, `node.rs`, `error.rs`, `Cargo.toml`, `basic_sfu.rs`. Left: owner's §17.9 table, `ci-local.sh all` on the merge commit, fast-forward `main` |

Exit criteria: 1 ☑ e2e (8 tests; `ci-local.sh all` on `b0a5ec5` + the 1.6b tree, 2026-09-28; re-run on the 1.6b commit) · 2 ☑ 0 allocations · 3 ☑ 25 KB budget (16.9 KB checked at 1.7, 17.5 KB after the rooms change, session state only; `ci-local.sh all` on `964291d`, 2026-09-28) · 4 ☐ browsers (owner's Chrome + Firefox run, table in 1.8) · 5 ☑ old path deleted (C1-C7, benches ported; 2026-09-28) · 6 ☑ no panic on input (`fa8a6a9`) · 7 ☑ documents (1.9).

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
- 2026-09-27: 1.5b-prep and 1.5b planned in detail against the code (three read-only
  audits: orchestrator/server, 1.5b-prep targets, dataplane and 1.5a APIs). Owner's
  decisions: the SsrcAllocator fixes, the sha-256 fingerprint choice and the shard DTLS rule
  move into 1.5b-prep; 1.5b is built on a local WIP branch and squashed into one commit.
  Corrections added to 1.5b's code notes (`sfu.rs` must change, webrtc-rs answers `passive`
  to ice-lite, address map contents, `Unpublish` ownership, closing on a full queue).
  1.5b-prep implemented (uncommitted, for review): `src/node.rs` (node id with `SystemTime`,
  `DistributedState`, gossip thread split into `GossipLoop`, shutdown notice; `Sfu` delegates),
  `[dataplane]` config (`DataplaneSettings`, `to_dataplane_config`, `reserved_ports`,
  `--shards`, `NEXUS_SHARDS`, four TOMLs), negotiator `with_ice_lite` and Track rtcp-fb
  parameter with the old path's offer pinned in `testdata/legacy_offer.sdp`, parser keeps
  the sha-256 fingerprint, `SsrcAllocator` peer/base check, no offsets used on failure and
  the registration high-water mark, shard `drop_dtls_unselected`, loadtest payload marker
  (VP8 descriptor parsed), `AnnouncedSsrcs`, kept senders with RTCP drains, one stream id;
  e2e checks markers and the announced SSRCs. Checked to fail with the fix disabled:
  fingerprint choice, shard DTLS rule, e2e marker check (wrong SSRC stamped). macOS: fmt,
  clippy clean, 2,034 passed, 0 failed, e2e 3/3; Linux arm64 container (copy of the repo
  inside the container, target volume `nexus-dataplane-target`): fmt, clippy clean, 2,040
  passed, 0 failed, twice. Committed. Next: 1.5b (WIP branch `phase-1-switch-wip`).
- 2026-09-27: 1.5b implemented on branch `phase-1-switch-wip` (uncommitted, for review):
  the orchestrator runs on `nexus-dataplane` (new `plane.rs`; `negotiation.rs`,
  `subscription.rs`, `connection.rs`, `events.rs`, `mod.rs` rewritten; `server.rs` starts
  `Node` and `Dataplane`; `Sfu` no longer started and no longer forwards STUN/DTLS).
  Orchestrator tests on a real one-shard data plane (answers made by rewriting offers):
  tracks added, late declined slot re-offered with a fresh SSRC (fails with the rule
  disabled), unpublish and publisher leave turn subscriber m-lines inactive, >10 ids, wrong
  mids, consent lost and shard refusals close, full queue closes and retries the close.
  E2E on the new path: `two_party_audio_video` receives the announced (rewritten) SSRCs,
  markers name the publisher, shard counters checked; DTLS client (webrtc-rs default
  `passive` against ICE-lite) and server (client A `active`) both complete; AES-GCM
  negotiated. macOS: fmt, clippy clean, 2,043 passed, 0 failed, e2e 3/3; Linux arm64
  container: fmt, clippy clean, 2,049 passed, 0 failed, e2e 5/5 runs. Left: early browser
  check (Chrome, Firefox; note §17.9 steps 1-2), review, squash-commit onto `phase-1`.
- 2026-09-27: 1.5b review fixes (uncommitted, for review): publish needs a room and
  subscribers only get their room's tracks; the shard's per-session limits (10 tracks, 31
  subscriptions) enforced with `TOO_MANY_TRACKS`; shard refusals close the participant
  (`Overloaded` for limits, `Internal` otherwise); queued publishes appended, replayed after
  `INVALID_ANSWER`; unpublished m-lines reused; first sha-256 fingerprint across levels;
  `ServerHandle::established()` (role, SRTP profile) asserted in e2e; `/ready` follows the
  data plane; orchestrator tests read shard gauges behind an id-matched barrier, the
  full-queue test shows the retried close succeeding, error codes checked; e2e marker
  check per received SSRC. Each new check was run with its fix disabled and fails. Early
  browser check in headless Chrome 153 found subscribe m-lines changing PT between offers
  (fixed: `OfferMline::Track { keep_pt }`); re-run passes (details in the 1.5b notes).
  macOS: fmt, clippy clean, 2,053 passed, 0 failed, e2e 5/5 runs; Linux arm64 container
  (repo copied in, target volume `nexus-dataplane-target`): fmt, clippy clean, 2,059
  passed, 0 failed, e2e 5/5 runs. Left: Firefox (not available here), review, squash-commit.
- 2026-09-27: last 1.5b fixes before the squash (uncommitted, for review): a second `Join`
  is refused (`ALREADY_IN_ROOM`; no ghost membership, the old room's subscriptions stay
  the old room's); after `INVALID_ANSWER` with nothing queued the unanswered m-lines are
  offered once more, then released; refusal test registers tracks first and checks the
  registry, cluster state and `TrackUnpublished` are undone; same-SSRC republish on a
  reused m-line accepted; `/ready` 503 during the shutdown drain; `.playwright-mcp/`
  ignored; `publish_codec` doc updated. Room authorization added to the v1 scope
  (`dataplane-design.md` §2 and revision log; risks table here). Each new check fails with
  its fix disabled. macOS: fmt, clippy clean, 2,054 passed, 0 failed, e2e 5/5 runs; Linux
  arm64 container (repo copied in, target volume `nexus-dataplane-target`): fmt, clippy
  clean, 2,060 passed, 0 failed, e2e 5/5 runs. Left: Firefox check, squash-commit.
- 2026-09-27, verification of the last 1.5b fixes: `ALREADY_IN_ROOM`, one re-offer then
  release after `INVALID_ANSWER`, refusal undo on registered tracks, same-SSRC republish,
  `/ready` 503 during the drain confirmed in code and tests. macOS: fmt, clippy clean, 2,054
  passed, e2e 5/5; Linux arm64 (own target volume): clippy clean, 2,060 passed, e2e 5/5.
  Firefox deferred to 1.8 (owner's decision). Left for later parts: Leave then Join on the
  same WebSocket is silently ignored (the session is removed; changing rooms needs a
  reconnect; SDK side in 1.8); `invalid_answers` is not reset when m-lines are released,
  and unanswered subscribe m-lines are not released; room authorization has no phase yet.
  Squash-committed onto `phase-1`. Next: 1.7 (benches, memory budget, CI), then the
  deletions.
- 2026-09-27: 1.7 planned against the code (three read-only audits: benches, data-plane and
  orchestrator memory, CI). Split into 1.7a (`real_path` rewritten in place on a shard driven
  on the bench thread over a real socket, one datagram per timed ingress iteration,
  allocations per packet printed; CI `macos-14` job, `--locked`, timeouts, `release.yml`
  pinned; `ENOBUFS` fallback for 8 MiB socket buffers on older macOS) and 1.7b (`memory`
  rewritten: rooms of 6 all-to-all, 60 participants, counting allocator only, both planes on
  one thread through a new hidden `SessionOrchestrator::handle`, real DTLS to `free_ssl`;
  budget on "+ subscribed to 10 tracks"; estimate ≈ 14.5 KB). Found: **CI has never run a
  job** (GitHub billing lock), the old budget used malloc totals and 20 subscriptions, the
  1.5b note promising shard metrics in 1.7 (moved to C7, which owns it), note §15's SRTP
  figure (corrections table). Next: 1.7a.
- 2026-09-27: 1.7a implemented (uncommitted, for review). `benches/real_path.rs` rewritten
  on `nexus-dataplane` (shard on the bench thread over a real loopback socket, `BenchIo`
  for injected setup/egress input, one datagram per timed ingress call, allocation pass
  per id, drop counters per id; `srtp` group on `SrtpOutbound`/`SrtpInbound`);
  `bind_shard_socket` halves buffer sizes on `ENOBUFS` (`fit_buffer_sizes`, tests fail
  with the fix disabled); CI: `macos` job (macos-14, clippy + tests), `--locked` on clippy
  and benches, `timeout-minutes`, `concurrency`; `release.yml` on 1.83.0 and
  build-push-action v6; actionlint clean. Billing lock set aside (owner's decision): CI
  itself not run. macOS: fmt, clippy clean, 2,058 passed, 0 failed; Linux arm64 container
  (repo copied in, target volume `nexus-dataplane-target`): fmt, clippy clean, 2,064
  passed, 0 failed; bench smoke and full run on both (numbers in the 1.7a notes). Not run:
  Linux x86_64. Next: 1.7b (`memory`, budget 25 in CI).
- 2026-09-27: `scripts/ci-local.sh` added (owner's decision: GitHub Actions stays locked, the
  script stands in for CI in the exit criteria; plan, CLAUDE.md updated). Review fixes for
  1.7a (uncommitted, for review): ingress setup waits for loopback delivery (`peek_from` on
  a clone of the shard socket) and counts iterations with `received != 1` (0 on both
  platforms after the fix; macOS ingress medians 14-28% lower than the first run); egress
  compares what the sinks read with `tx_datagrams` (≥ 99.9% in this session; the review
  run's 63-88% did not reproduce, the check marks it when it happens); `drop_send_failed`
  invalidates a result; `udp_floor` run in the same session, egress recorded relative to it
  (gcm video 1.55× the floor at 100 subscribers, cm 2.20×); `fit_buffer_sizes` a bounded
  `for` (14 rounds, tested); `cancel-in-progress` off `main`/tags only, `ulimit -n 4096` in
  the macOS test step and in `ci-local.sh`, `timeout-minutes` on `release.yml` jobs.
  `ci-local.sh` (default targets), summary:
  ```
  macos          PASS  cargo fmt --check                                1s
  macos          PASS  clippy                                           7s
  macos          PASS  cargo test --workspace                          82s (2058 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                1s
  linux-arm64    PASS  clippy                                           6s
  linux-arm64    PASS  release build                                   74s
  linux-arm64    PASS  cargo test --workspace                         107s (2064 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           37s
  linux-arm64    PASS  bench memory (budget 1700 KB)                    6s
  ci-local 2026-09-27 17:13, 9481ebf + uncommitted changes, budget 1700 KB: PASS
  ```
  Own target volume (`nexus-ci-target-arm64`). Full `real_path` on both platforms and
  `udp_floor` on Linux after that run (numbers in the 1.7a notes). Not run: `linux-x86_64`,
  `docker`. Stopped for review; not committed. Next: 1.7b.
- 2026-09-27: 1.7b implemented (uncommitted, for review). `benches/memory.rs` rewritten: 10
  rooms of 6 (each participant A+V, subscribed to the other 10 tracks), a shard on `MemIo`
  and the real `SessionOrchestrator` on the bench thread (commands into the shard queue,
  events back through the new hidden `handle_signal`/`handle_dataplane`), a real DTLS
  handshake per client up to `free_ssl`; allocator tagging each block with the plane that
  made it. 15.8 KB per participant (data 12.0, control 3.8) on macOS and Linux;
  `NEXUS_MEM_BUDGET_KB: "25"` in `ci.yml`. The first run's 17.7 KB control plane was the
  bench holding offer strings (fixed). Budget and both leak checks fail as they should
  (the control-plane leak needed `black_box`). `nexus_dataplane::sizes` added.
  `ci-local.sh` (default targets), summary:
  ```
  macos          PASS  cargo fmt --check                                1s
  macos          PASS  clippy                                           8s
  macos          PASS  cargo test --workspace                          84s (2058 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                1s
  linux-arm64    PASS  clippy                                           7s
  linux-arm64    PASS  release build                                   68s
  linux-arm64    PASS  cargo test --workspace                         116s (2064 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                          343s
  linux-arm64    PASS  bench memory (budget 25 KB)                      6s
  ci-local 2026-09-27 17:46, 9481ebf + uncommitted changes, budget 25 KB: PASS
  ```
  (`real_path` smoke 343 s: the bench profile rebuilt after the library changes.) Exit
  criterion 3 holds on these targets; it is checked off after the `all` run. Not run: `linux-x86_64`, `docker` (the 1.7 checkpoint asks for `all`
  before C2). Next: review 1.7a + 1.7b, commit, `ci-local.sh all`, then C2.
- 2026-09-28: review fixes for 1.7 (uncommitted, for review). `memory`: signaling measured
  apart (real `SignalingServer` on its own thread, 50 `nexus-loadtest` clients, 15 KB
  offer/answer each: ≈ 49 KB per connection over WebSocket, ≈ 57 KB over TLS, not in the
  budget; design §3.11 clarified, revision 2026-09-28); allocator overhead line (malloc
  residual = OpenSSL after `free_ssl` 2.8-3.8 KB + allocator ≈ 1 KB per participant);
  fixed costs split (shard, orchestrator, 430 KB per room); runs at 10 and 11 rooms (past
  the 64-slot slab), the checked figure is the larger run plus the pre-sized control-plane
  map entries (248 B): **16.9 KB** (fails at a 16.8 KB budget). `ci-local.sh`: untracked
  files in the tree state, targets in the summary, `docker` for `linux/amd64`, `pipefail`
  in the container. CLAUDE.md: only `all` covers every job. `ci-local.sh` (default
  targets), summary:
  ```
  macos          PASS  cargo fmt --check                                1s
  macos          PASS  clippy                                           7s
  macos          PASS  cargo test --workspace                          91s (2058 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                1s
  linux-arm64    PASS  clippy                                           4s
  linux-arm64    PASS  release build                                    1s
  linux-arm64    PASS  cargo test --workspace                          74s (2064 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                            2s
  linux-arm64    PASS  bench memory (budget 25 KB)                     22s
  ci-local 2026-09-28 07:26, 9481ebf (13 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  Linux figures identical to macOS (16.9 KB checked; ws 49.2 KB, wss 56.8 KB). Not run after
  these fixes: `linux-x86_64`, `docker` (the review's `all` run predates them). Stopped for
  review; not committed.
- 2026-09-28: `ci-local.sh all` on the 1.7 commit (a detached worktree at `964291d`, so the
  run saw exactly the commit): PASS on every target. Exit criterion 3 checked off.
  ```
  macos          PASS  cargo fmt --check                                1s
  macos          PASS  clippy                                          82s
  macos          PASS  cargo test --workspace                         150s (2058 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                2s
  linux-arm64    PASS  clippy                                          10s
  linux-arm64    PASS  release build                                   62s
  linux-arm64    PASS  cargo test --workspace                         120s (2064 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           46s
  linux-arm64    PASS  bench memory (budget 25 KB)                     19s
  linux-x86_64   PASS  cargo fmt --check                                3s
  linux-x86_64   PASS  clippy                                          24s
  linux-x86_64   PASS  release build                                   88s
  linux-x86_64   PASS  cargo test --workspace                         165s (2064 passed, 0 failed)
  linux-x86_64   PASS  bench smoke real_path                           80s
  linux-x86_64   PASS  bench memory (budget 25 KB)                     25s
  docker         PASS  docker build (linux/amd64)                     394s
  ci-local 2026-09-28 07:50, 964291d (clean), targets: macos linux-arm64 linux-x86_64 docker, budget 25 KB: PASS
  ```
  x86_64 memory figures identical (16.9 KB checked; signaling ws 49.2 KB, wss 56.9 KB).
- 2026-09-28: C2 implemented (uncommitted, for review): `benches/forwarding.rs` deleted;
  `packet_processing.rs` down to its RTCP parse benches (demux groups dropped); root
  dev-dependency on `nexus-webrtc` `test-hooks` removed (moved from C6); CLAUDE.md bench
  list. `Cargo.lock` unchanged. `ci-local.sh` (default targets), summary:
  ```
  macos          PASS  cargo fmt --check                                1s
  macos          PASS  clippy                                           1s
  macos          PASS  cargo test --workspace                          93s (2058 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                1s
  linux-arm64    PASS  clippy                                          11s
  linux-arm64    PASS  release build                                   56s
  linux-arm64    PASS  cargo test --workspace                         104s (2064 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           35s
  linux-arm64    PASS  bench memory (budget 25 KB)                     19s
  ci-local 2026-09-28 07:56, 964291d (5 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  Next: review and commit C2, then C1+C3.
- 2026-09-28: C2 committed (`7e7b689`). C1+C3 implemented (uncommitted, for review): the
  old ingress loop, worker pool, SSRC router, root transport wrappers, sim clock, proto
  bindings and their tests deleted; `WorkerError` gone; 20 root dependencies, the
  build-dependencies, `build.rs`, `proto/` and the `io_uring`/`sim`/`production` features
  removed; `protoc` no longer needed (CI, release, Dockerfile, `ci-local.sh`, CLAUDE.md,
  README). Tests: 2,058 → 1,976 on macOS (the old path's unit tests). `ci-local.sh`
  (default targets), summary:
  ```
  macos          PASS  cargo fmt --check                                1s
  macos          PASS  clippy                                           0s
  macos          PASS  cargo test --workspace                         112s (1976 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                1s
  linux-arm64    PASS  clippy                                          14s
  linux-arm64    PASS  release build                                   55s
  linux-arm64    PASS  cargo test --workspace                         128s (1982 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           48s
  linux-arm64    PASS  bench memory (budget 25 KB)                     19s
  ci-local 2026-09-28 08:07, 7e7b689 (31 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  and, since the Dockerfile changed, `ci-local.sh docker`:
  ```
  docker         PASS  docker build (linux/amd64)                      88s
  ci-local 2026-09-28 08:08, 7e7b689 (31 uncommitted or untracked paths), targets: docker, budget 25 KB: PASS
  ```
  Next: review and commit C1+C3, then C4 (`nexus-actor`, `nexus-dst`).
- 2026-09-28: C1+C3 committed (`372cbcd`). C4 implemented (uncommitted, for review):
  `nexus-actor`, `nexus-dst`, `ActorMetrics` and the `nexus_actor_*` series removed;
  `[actor]` validated against the orchestrator's limits. Tests 1,976 → 1,683 on macOS:
  the two crates held 291 test items (176 + 115), plus the `ActorMetrics` test and
  `nexus-transport` code built only with `sim` (which `nexus-dst` turned on).
  `ci-local.sh` (default targets), summary:
  ```
  macos          PASS  cargo fmt --check                                1s
  macos          PASS  clippy                                          13s
  macos          PASS  cargo test --workspace                          95s (1683 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                1s
  linux-arm64    PASS  clippy                                          16s
  linux-arm64    PASS  release build                                   63s
  linux-arm64    PASS  cargo test --workspace                         136s (1689 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           44s
  linux-arm64    PASS  bench memory (budget 25 KB)                     20s
  ci-local 2026-09-28 08:18, 372cbcd (49 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  Next: review and commit C4, then C6 (before C5).
- 2026-09-28: C4 committed (`08adb78`). C6 implemented (uncommitted, for review):
  `nexus-webrtc` reduced to `sdp` (the `webrtc` module, its re-exports, `test-hooks` and
  seven dependencies gone), `OpenSslDtlsEngine::new` removed (tests use
  `with_certificate`). Tests 1,683 → 1,632: the module's 50 tests and the test of `new`.
  `ci-local.sh` (default targets), summary:
  ```
  macos          PASS  cargo fmt --check                                0s
  macos          PASS  clippy                                           1s
  macos          PASS  cargo test --workspace                          78s (1632 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                2s
  linux-arm64    PASS  clippy                                           6s
  linux-arm64    PASS  release build                                   54s
  linux-arm64    PASS  cargo test --workspace                          84s (1638 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           36s
  linux-arm64    PASS  bench memory (budget 25 KB)                     20s
  ci-local 2026-09-28 08:25, 08adb78 (14 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  Next: review and commit C6, then C5 (the replaced `nexus-transport` modules).
- 2026-09-28: C6 committed (`3d914bc`). C5 implemented (uncommitted, for review): the old
  `nexus-transport` modules deleted (≈ 17,000 lines), `SrtpProfile`/`SrtpKeyMaterial` moved
  to `dtls/srtp_keys.rs`, `StunServer` gone (`stun/request.rs` keeps the request builders),
  seven crate dependencies and the `io_uring`/`sim` features dropped, `ArenaError` and the
  io_uring error variants removed, `liburing-dev` out of the Dockerfile. Tests 1,632 →
  1,417: 223 tests in the deleted files, minus the 10 moved, plus the 2 `StunServer` tests
  in `stun/mod.rs`. `Cargo.lock`: `crossbeam`, `io-uring`, `memmap2`, `rcgen` 0.12 gone
  (`rcgen` 0.11.3 stays for webrtc-rs; its references lose the version suffix).
  `ci-local.sh macos linux-arm64 docker`, summary:
  ```
  macos          PASS  cargo fmt --check                                0s
  macos          PASS  clippy                                           1s
  macos          PASS  cargo test --workspace                          97s (1417 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                1s
  linux-arm64    PASS  clippy                                          11s
  linux-arm64    PASS  release build                                   59s
  linux-arm64    PASS  cargo test --workspace                         136s (1423 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           39s
  linux-arm64    PASS  bench memory (budget 25 KB)                     22s
  docker         PASS  docker build (linux/amd64)                      91s
  ci-local 2026-09-28 08:38, 3d914bc (33 uncommitted or untracked paths), targets: macos linux-arm64 docker, budget 25 KB: PASS
  ```
  Next: review and commit C5, then C7 (config, README, example; shard metrics export).
- 2026-09-28: C5 committed (`cf105a8`). C7 implemented (uncommitted, for review): the old
  `[worker]`/`[memory]`/`[actor]` config, `transport.batch_*`/`stun_servers`,
  `--workers` and the two environment variables removed, and refused when still present
  (`deny_unknown_fields`, env error); shard stats on `/metrics` (`nexus_shard_*{shard}`,
  read at render time from `DataplaneHandle::stats`), `WorkerPoolMetrics` gone; README,
  example, TOMLs, dashboard, `verify_metrics.sh`, CLAUDE.md. Tests 1,417 → 1,405: 17 tests
  of removed config types and worker metrics, 5 new (stats names, shard source, per-shard
  export, server `/metrics` on a real shard, config refusals). **Exit criterion 5 met**
  (every deletion step done). Open: `nexus_sfu_*`/`nexus_crdt_*` series read zero.
  `ci-local.sh` (default targets), summary:
  ```
  macos          PASS  cargo fmt --check                                0s
  macos          PASS  clippy                                           1s
  macos          PASS  cargo test --workspace                         102s (1405 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                2s
  linux-arm64    PASS  clippy                                          13s
  linux-arm64    PASS  release build                                   60s
  linux-arm64    PASS  cargo test --workspace                         141s (1411 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           35s
  linux-arm64    PASS  bench memory (budget 25 KB)                     20s
  ci-local 2026-09-28 08:55, cf105a8 (29 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  Next: review and commit C7. Left in Phase 1: 1.6a, 1.6b (e2e), 1.8 (SDK, browsers), 1.9.
- 2026-09-28: 1.6a implemented (uncommitted, for review), after re-auditing 1.6a/1.6b against
  `c5e9f76` (corrections in both parts: bookkeeping and `rebinds` already existed, the RTCP
  drain must be replaced, `arc-swap` is transitive, 10-id `Subscribe` cap). `nexus-loadtest`:
  `signal_task.rs`, client subscribe/unsubscribe with confirmations, `subscribe_batch` in
  requests of ≤ 10, announced history and CNAME, inbound SRTP/SRTCP tap. Tests
  `ten_clients_audio_video` and `resubscribe_no_srtp_index_reuse` pass; the second fails as
  expected with the SSRC protections bypassed. Tests 1,405 → 1,412 on macOS.
  `ci-local.sh` (default targets), summary:
  ```
  macos          PASS  cargo fmt --check                                1s
  macos          PASS  clippy                                           1s
  macos          PASS  cargo test --workspace                         125s (1412 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                1s
  linux-arm64    PASS  clippy                                           9s
  linux-arm64    PASS  release build                                   58s
  linux-arm64    PASS  cargo test --workspace                         145s (1418 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           40s
  linux-arm64    PASS  bench memory (budget 25 KB)                     19s
  ci-local 2026-09-28 09:20, c5e9f76 (8 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  Next: review and commit 1.6a, then 1.6b (rebind, RTCP recorders, three tests).
- 2026-09-28: 1.6a committed (`b0a5ec5`). 1.6b implemented (uncommitted, for review):
  `LossRules::rebind` (swappable socket, pending receives move, old port counted),
  `RtcpLog` (publisher PLI/FIR replacing the RTCP drain, subscriber SR/CNAME per receiver),
  `send_pli`; tests `address_change_mid_call` (resume 2.1-2.3 s), `sender_report_translation`
  (SR error ≤ 5.7 ms), `keyframe_requests` (burst of 5 → 1). Negative check: with rebinding
  effectively disabled, media does not resume. Review fixes: stricter 1.6a/1.6b
  assertions (tap rounds, mid reuse, drop counters, resume bounds, old port quiet, exact
  throttle count, SR packet counts), RTCP reader errors logged, `ci-local.sh` lock, dashboard
  and `verify_metrics.sh` on `nexus_shard_*`, `verify_cleanup.sh` without `src/sfu.rs`,
  `production.toml` realtime note. A first `ci-local.sh all` run collided with a second
  run (shared `target/ci-local` and Docker volumes; a duplicate container stopped by hand)
  and reported a false FAIL on x86_64 `real_path`; discarded, which led to the lock. e2e
  suite 8 tests: 47 s macOS, 48 s Linux arm64, 51 s Linux x86_64 (emulated). Tests 1,412 →
  1,419 on macOS. **Exit criterion 1 met.** `ci-local.sh all`, alone, summary:
  ```
  macos          PASS  cargo fmt --check                                1s
  macos          PASS  clippy                                           1s
  macos          PASS  cargo test --workspace                         146s (1419 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                2s
  linux-arm64    PASS  clippy                                           8s
  linux-arm64    PASS  release build                                    1s
  linux-arm64    PASS  cargo test --workspace                         206s (1425 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           47s
  linux-arm64    PASS  bench memory (budget 25 KB)                     28s
  linux-x86_64   PASS  cargo fmt --check                                2s
  linux-x86_64   PASS  clippy                                          16s
  linux-x86_64   PASS  release build                                    2s
  linux-x86_64   PASS  cargo test --workspace                         220s (1425 passed, 0 failed)
  linux-x86_64   PASS  bench smoke real_path                           63s
  linux-x86_64   PASS  bench memory (budget 25 KB)                     40s
  docker         PASS  docker build (linux/amd64)                       7s
  ci-local 2026-09-28 10:13, b0a5ec5 (13 uncommitted or untracked paths), targets: macos linux-arm64 linux-x86_64 docker, budget 25 KB: PASS
  ```
  Next: review and commit 1.6b; left in Phase 1: 1.8 (SDK, browsers), exit criterion 6
  check, 1.9.
- 2026-09-28, review of 1.6 (1.6a committed earlier, 1.6b and review fixes): fixes confirmed
  in code and tests; `ci-local.sh all` alone on `b0a5ec5` + 1.6b: PASS on every target
  (macOS 1,419, Linux arm64 and x86_64 1,425 passed, docker). Timing bounds widened for
  emulated runners: PLI on subscribe < 3 s (was 1 s), rebind resume < 4.5 s (was 3.5 s).
  Negative-check wording corrected (rebinding disabled, not the silence rule). Known limits
  of the `ci-local.sh` lock, not fixed: an empty pid file during creation reads as stale,
  two runs can both take over the same stale lock, and Ctrl-C releases the lock while a
  `docker run` may still be running. **Exit criterion 1 met** (all e2e tests on the new path,
  `ci-local.sh all`). Committed 1.6b; pushed 1.7, C2-C7, 1.6a, 1.6b. Next: 1.8, then 1.9.
- 2026-09-28: 1.8 planned and implemented (uncommitted, for review). The plan audit found
  three things the SDK could not do from the plan's text: a publisher never learned its own
  track ids, `Leave` ends the session, and `Unpublish` sends the publisher no offer (1.8 code
  notes).
  - Owner's decisions: a new `Published` message; `node:test` with no new dependencies; the
    SDK in `ci.yml` and `ci-local.sh`; a Chromium pre-check here and the full §17.9 check by
    the owner.
  - Done:
    - `Published` from `register_publish`, with orchestrator and serde tests;
    - `nexus-loadtest token` (`mint_token`, refuses secrets under 32 characters);
    - the SDK calls and signaling fixes (queue dropped on close, a replaced socket ignored);
    - `sdk/test/client.test.mjs` (9 tests);
    - `examples/web/` page and README.
  - Chromium pre-check passes steps 2, 3 and 5 (Recorded check in 1.8).
  - Found: an empty `NEXUS_TLS_*` does not give plain WS, because the QUIC cert path is
    refused. The README uses a config copy instead.
  - Tests 1,419 → 1,421 on macOS. `ci-local.sh`, summary:
  ```
  macos          PASS  cargo fmt --check                                1s
  macos          PASS  clippy                                          10s
  macos          PASS  cargo test --workspace                         163s (1421 passed, 0 failed)
  macos          PASS  sdk npm ci + npm test                            5s (9 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                6s
  linux-arm64    PASS  clippy                                          21s
  linux-arm64    PASS  release build                                   90s
  linux-arm64    PASS  cargo test --workspace                         303s (1427 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           44s
  linux-arm64    PASS  bench memory (budget 25 KB)                     22s
  ci-local 2026-09-28 12:06, 8b7a688 (16 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  Next: review and commit 1.8. The owner runs §17.9 with Chrome and Firefox on two
  machines and fills in the table in 1.8; then exit criterion 4, the exit criterion 6
  check, and 1.9.
- 2026-09-28, review of 1.8 (uncommitted, for review): five verified findings fixed.
  - The SDK matches each SFU error to its request with a `Ping` fence, so a Subscribe
    error no longer rejects a publish.
  - A refused or timed-out publish undoes its state and releases queued requests.
  - Answer-time refusals and unregistered m-lines detach the track, so it can be
    republished.
  - `node --test test/*.test.mjs`; Node pinned in `sdk/.nvmrc` (used by `ci.yml` and
    checked by `ci-local.sh`).
  - README: a LAN certificate in `certs/lan-*.pem`, an HTTPS static server, and
    `NEXUS_JWT_SECRET`.
  - SDK tests 9 → 14, with a negative check (details in the 1.8 code notes).
  - Found while testing: an `async` test helper that returned the publish promise waited
    for it (promise flattening), and a failed test left a keepalive timer running. Tests
    now close their clients in `afterEach`.
  - `ci-local.sh`, summary:
  ```
  macos          PASS  cargo fmt --check                                0s
  macos          PASS  clippy                                           2s
  macos          PASS  cargo test --workspace                         113s (1421 passed, 0 failed)
  macos          PASS  sdk npm ci + npm test                            3s (14 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                2s
  linux-arm64    PASS  clippy                                           3s
  linux-arm64    PASS  release build                                    1s
  linux-arm64    PASS  cargo test --workspace                          91s (1427 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                            2s
  linux-arm64    PASS  bench memory (budget 25 KB)                      5s
  ci-local 2026-09-28 13:48, 8b7a688 (17 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  Next: review, then commit 1.8. Then the owner's §17.9 run with Chrome and Firefox (the
  table in 1.8), exit criterion 6, and 1.9.
- 2026-09-28, second review of 1.8 (uncommitted, for review):
  - Server: a refused publish m-line is released (`register_publish` → bool,
    `release_unregistered_publish`). New orchestrator test, with a negative check.
  - SDK:
    - an answer-time refusal of a queued publish fails that publish's tracks only
      (`serverQueued`);
    - Create, Join, Unpublish and Unsubscribe are fenced;
    - a disconnect drops the fences and the queued `Ping`s;
    - `lateTrackPublished`.
  - The mock offers full m-line lists. Tests: SDK 14 → 20 (negative check on the queued
    publish), Rust 1,421 → 1,422 (macOS).
  - **e2e:** green in `ci-local.sh` (macOS and Linux arm64). The separate run right after
    it failed once: `sender_report_translation` measured a video SR error of 28.9 ms
    against the 20 ms `SR_TOLERANCE_MS`. Three reruns passed (8/8, 46 s each).
    - Nothing in this diff touches `tests/`, the data plane or SR translation; the run
      directly followed the Docker jobs.
    - Recorded as a timing flake (1 in 5 runs), not fixed. Watch for it; if it recurs,
      look at the tolerance or the SR sampling rather than 1.8.
  - `ci-local.sh`, summary:
  ```
  macos          PASS  cargo fmt --check                                0s
  macos          PASS  clippy                                           1s
  macos          PASS  cargo test --workspace                         120s (1422 passed, 0 failed)
  macos          PASS  sdk npm ci + npm test                            4s (20 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                3s
  linux-arm64    PASS  clippy                                           8s
  linux-arm64    PASS  release build                                  105s
  linux-arm64    PASS  cargo test --workspace                         157s (1428 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           43s
  linux-arm64    PASS  bench memory (budget 25 KB)                     25s
  ci-local 2026-09-28 14:07, 8b7a688 (17 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  Next: review, then commit 1.8. Then the owner's §17.9 run, exit criterion 6, and 1.9.
- 2026-09-28, review of the last 1.8 fixes: refused publish m-lines released on every path,
  SDK error fences confirmed in code and tests; e2e 6/6, SDK 20 passed. Known edges, not
  fixed: a declined m-line can hold a subscription reusing its mid until the next offer;
  peer SSRCs noted before a refusal stay recorded (bounded). The `sender_report_translation`
  flake is a test bug: the last packet is read after the wait, up to ≈ 1 s after the SR.
  Fix before 1.9: record the last packet when each SR arrives, assert the median error
  ≤ 50 ms and every SR ≤ 200 ms. Code committed; the owner's §17.9 check (exit criterion 4)
  is still pending. Next: SR test fix and exit criterion 6 sweep, owner's check, then 1.9.
- 2026-09-28, before 1.9 (uncommitted, for review): SR flake fixed and exit criterion 6
  swept (section "Before 1.9").
  - **SR test:** each SR is paired with the last in-order packet received when it
    arrived; the test asserts median ≤ 50 ms and every SR ≤ 200 ms. Measured 2-5 ms,
    also in the two e2e runs right after the Docker jobs (8/8 each). Negative check: a
    100 ms translation offset fails.
  - **Sweep:** every path network input reaches. Two reachable aborts fixed:
    - duplicate `pending_switches` entries from alternating nominations (`switch_listed`);
    - `Create` with a room name over 256 bytes (checked in the orchestrator, and
      `create_room` returns errors instead of asserting).
  - Also fixed: the room-id counter overflow, the `Join` name cap and `room_id` above
    u32.
  - New tests: two regressions, a `nexus-state` test, and two proptests (authenticated
    STUN sequences, random signaling). Each fails without its fix.
  - Known non-panic issues are listed in that section. **Exit criterion 6 met.**
  - Tests 1,422 → 1,428 (macOS). `ci-local.sh`, summary:
  ```
  macos          PASS  cargo fmt --check                                0s
  macos          PASS  clippy                                          19s
  macos          PASS  cargo test --workspace                         164s (1428 passed, 0 failed)
  macos          PASS  sdk npm ci + npm test                            5s (20 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                4s
  linux-arm64    PASS  clippy                                          17s
  linux-arm64    PASS  release build                                   87s
  linux-arm64    PASS  cargo test --workspace                         236s (1434 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           60s
  linux-arm64    PASS  bench memory (budget 25 KB)                     26s
  ci-local 2026-09-28 14:48, 5888a11 (15 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  Next: review and commit. Then the owner's §17.9 browser run (exit criterion 4), then
  1.9.
- 2026-09-28, second review of the exit criterion 6 sweep (uncommitted, for review): the
  first sweep missed the SWIM gossip socket (details under "Before 1.9").
  - **Gossip receive path hardened:**
    - an empty datagram is dropped; an oversized one is truncated by the kernel and
      its bytes decoded safely; every decoder returns `None` or an error;
    - apply paths in `DistributedState` return errors;
    - snapshots are capped and incarnations saturate;
    - the subscription decoder now matches its encoder.
    - Tests: `gossip_robustness.rs` (14 tests, including proptests over random and
      structured bytes). Each fix was checked by reverting it.
  - **Gossip off unless a cluster is configured:** `cluster.gossip_enabled`, default off,
    with a specific `gossip_bind_addr`. Design doc §2 non-goals and revision log record
    that gossip is unauthenticated and must be authenticated before clustering.
  - **Rooms:**
    - every room counts against `MAX_ROOMS`;
    - 4 rooms per creating connection, released with their creator if still empty;
    - participant sets grow on demand, capped at the room's limit (≈ 440 KB → 0 B heap
      for an empty room, measured);
    - `create_room` refuses an existing id.
  - The memory bench creates rooms from one admin connection per room. The checked figure
    is 17.5 KB, up from 16.9 KB: a room's participant set now grows at join and is counted
    per participant.
  - `address_change_mid_call`: the window now starts after every stream resumed (two
    failures under full-suite load; cause not proven, see the section).
  - Tests 1,428 → 1,456 (macOS). **Exit criterion 6 met.**
  - `ci-local.sh`, summary:
  ```
  macos          PASS  cargo fmt --check                                1s
  macos          PASS  clippy                                           4s
  macos          PASS  cargo test --workspace                         135s (1456 passed, 0 failed)
  macos          PASS  sdk npm ci + npm test                            4s (20 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                4s
  linux-arm64    PASS  clippy                                          10s
  linux-arm64    PASS  release build                                    1s
  linux-arm64    PASS  cargo test --workspace                         163s (1462 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                            2s
  linux-arm64    PASS  bench memory (budget 25 KB)                      6s
  ci-local 2026-09-28 16:21, 5888a11 (30 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  Next: review and commit. Then the owner's §17.9 browser run (exit criterion 4), then
  1.9.
- 2026-09-28, third review before 1.9 (uncommitted, for review):
  - one room-id allocator for REST and the orchestrator (`create_room_auto`);
  - participant-set tombstones recycle (6,000 join/leave cycles pass; a ghost-per-leave
    before);
  - `address_change_mid_call` checks the silence rule on the earliest stream of both
    directions and the resume bound on the latest;
  - the plan's wording on oversized gossip datagrams (truncated by the kernel, decoded
    safely);
  - the startup log line and doc comments say gossip runs only in a cluster.
  Tests 1,456 → 1,461 (macOS). `ci-local.sh`, summary:
  ```
  macos          PASS  cargo fmt --check                                1s
  macos          PASS  clippy                                           1s
  macos          PASS  cargo test --workspace                         155s (1461 passed, 0 failed)
  macos          PASS  sdk npm ci + npm test                            4s (20 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                4s
  linux-arm64    PASS  clippy                                          22s
  linux-arm64    PASS  release build                                   88s
  linux-arm64    PASS  cargo test --workspace                         273s (1467 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           61s
  linux-arm64    PASS  bench memory (budget 25 KB)                     27s
  ci-local 2026-09-28 16:50, 5888a11 (33 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  Next: review and commit "before 1.9". Then the owner's §17.9 browser run (exit
  criterion 4), then 1.9.
- 2026-09-28, verification of the third review before 1.9: one room-id allocator (atomic,
  capped, never 0), tombstone recycling (correct on one node; unsafe with gossip, now also
  in design §2 non-goals), rebind silence rule on the earliest stream, gossip log line
  confirmed. macOS: 1,461 passed, e2e 4/4, SDK 20 passed. **Exit criterion 6 met.**
  Committed and pushed. Left: the owner's §17.9 browser check (exit criterion 4), then 1.9.
- 2026-09-28, 1.9 documents (uncommitted, for review): plan for 1.9 written and approved
  (owner: documents now, merge after the §17.9 check; Phase 2 named next after the merge).
  - `architecture.md` Parts 1-5 describe the new path, traced from `src/main.rs`; Phase 1
    numbers in Part 5 above the Phase 0 baseline; memory re-measured at `fa8a6a9` (17.5 KB
    checked, ws 49.3 / wss 56.9 KB).
  - CLAUDE.md, README (feature list: SIMD parsing, simulcast and GCC are not on the live
    path; testing section), design revision "Phase 1 close", `dataplane-v1.md` note, old-path
    comments in code (`tier::CURRENT` and its test string, crate comments, `Cargo.toml`
    description, `basic_sfu.rs`). Details under 1.9 "Done". Exit criteria 6 and 7 ☑.
  - `ci-local.sh`, summary:
  ```
  macos          PASS  cargo fmt --check                                1s
  macos          PASS  clippy                                          18s
  macos          PASS  cargo test --workspace                         158s (1461 passed, 0 failed)
  macos          PASS  sdk npm ci + npm test                            4s (20 passed, 0 failed)
  linux-arm64    PASS  cargo fmt --check                                5s
  linux-arm64    PASS  clippy                                          20s
  linux-arm64    PASS  release build                                  105s
  linux-arm64    PASS  cargo test --workspace                         233s (1467 passed, 0 failed)
  linux-arm64    PASS  bench smoke real_path                           77s
  linux-arm64    PASS  bench memory (budget 25 KB)                     29s
  ci-local 2026-09-28 17:34, fa8a6a9 (12 uncommitted or untracked paths), targets: macos linux-arm64, budget 25 KB: PASS
  ```
  Next: review and commit. Then the owner's §17.9 Chrome + Firefox run (table in 1.8, exit
  criterion 4); then CLAUDE.md "Current phase: 2", design §5 Phase 1 "(done)",
  `ci-local.sh all` on the commit to merge, `git merge --ff-only phase-1` into `main`.
- 2026-09-28, review of the 1.9 documents: claims checked against the code (≈ 25 constants,
  paths and thread names correct). Fixed here: REST routes (`GET /rooms`, `DELETE
  /rooms/:id`) and REST room release in `architecture.md`, SRTP ≈ 7.9 KB (7,856 B, current
  bench), loopback test path; CLAUDE.md port 9090 (reserved; `/metrics` is on 8081); README
  `[room]`/`[bwe]` examples (not read) and the metrics location; `tier::metrics` latency and
  memory targets (1 / 5 ms, 25 KB) and the `main.rs` startup list. The orchestrator's fixed
  cost is 9.3 MB in the current bench (the 8.9 MB above was before the room changes).
  **Owner's decisions** (tests against a running release build, design revision
  2026-09-28): room authorization fixed before the merge (new part 1.9a: a second token
  joined room 1 by id, and `Create` with the same name returned the same room); signaling
  memory accepted for v1 (RSS: 19 KB per idle connection, ≈ 37 KB after a 15 KB message,
  ≈ 49 KB with an outbound offer in the bench). Also seen: `Joined` lists other
  participants with an empty name. Next: commit 1.9 documents, then 1.9a, the owner's
  §17.9 check, `ci-local.sh all`, merge.
