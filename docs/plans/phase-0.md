# Phase 0 — Ground work

**Design:** [`docs/dataplane-design.md`](../dataplane-design.md) §5, Phase 0.
**Current state:** [`architecture.md`](../../architecture.md).
**Branch:** `v0.1.0` (or a `phase-0/*` branch per part, merged back).

Phase 0 changes the **current** code only. Nothing here depends on the new data plane, and
nothing here is thrown away by it: the fixes are in code that stays (ICE candidates, DTLS,
signaling) or that runs until Phase 6 (the SRTCP fix), and the harness and measurements
are what every later phase is judged by.

## Exit criteria

1. The three live bugs are fixed, each with a test that fails before the fix.
2. The dead code in architecture.md 2.3 is gone (except `nexus-actor`, see 0.2), with
   build, clippy and all tests passing on macOS and Linux.
3. `cargo test --test e2e` passes on the legacy path: two clients, each publishing audio +
   video, each receiving the other's two tracks; runs in CI in under 60 s.
4. SRTP backend chosen and kernel send floor measured; `dataplane-design.md` §2 and §3.4
   confirmed or revised through its revision log.

## Parts

Each part is sized for one working session. Do them in this order: 0.1 is urgent and small,
0.2 shrinks the code before 0.3 builds on it, 0.4 is independent and can run any time.

---

### 0.1 Live bug fixes

Three separate commits, each with its own GitHub issue (milestone "Phase 0 — Ground work").

#### a) Announced IP for ICE candidates

**Problem:** the only candidate is `transport.media_bind_addr`, `0.0.0.0:10000` in every
shipped config (`src/orchestrator/negotiation.rs`, `start_ice_gathering`). Remote clients
cannot connect.

**Change:**
- Config: `transport.announced_ips: Vec<IpAddr>` (default empty) and env
  `NEXUS_ANNOUNCED_IPS` (comma-separated), in `crates/nexus-core/src/config.rs` and
  `src/config/loader.rs`.
- Candidate port is the **actually bound** media port (so port 0 works in tests), passed to
  the orchestrator instead of the configured bind address.
- One host candidate per announced IP. If none are configured: the bind IP if it is a
  specific address; otherwise the interface addresses from `ice/gather.rs`
  (`getifaddrs`, loopback excluded unless nothing else exists) with a startup `warn!` that
  names the chosen addresses.
- Never emit `0.0.0.0` or `::`: assert on it.
- Validation: announced IPs must not be unspecified or multicast.
- `deploy/docker/run.sh` and README: document `NEXUS_ANNOUNCED_IPS` (a container needs the
  host's public address).

**Code notes (checked 2026-09-26):**
- The core default and `config/default.toml` bind `127.0.0.1:10000`; `development`,
  `production` and `loadtest` bind `0.0.0.0:10000`.
- `enumerate_interfaces` in `gather.rs` is private and keeps loopback; add a public
  wrapper that filters loopback and IPv4 link-local.
- The bound address is only logged in `Sfu::new`; store it and expose
  `Sfu::media_local_addr()`. `SessionOrchestrator::new` takes the bound address instead of
  `config.transport.media_bind_addr` (`main.rs`).
- `TransportConfig` has no struct-level `#[serde(default)]`: the new field needs its own.
- Docker: `run.sh` can map another host port onto 10000, and the candidate carries 10000.
  Document that `MEDIA_PORT` must stay 10000 when announcing; no port override yet.
- README has no env var section; add one and fix the stale `[transport]` example.

**Tests:** unit tests for candidate selection (announced list, specific bind IP, wildcard
bind with interface fallback, never unspecified); config env test.

#### b) DTLS handshake retransmission

**Problem:** OpenSSL's DTLS timer is never driven. `poll_dtls_retransmit`
(`crates/nexus-webrtc/src/webrtc/session.rs`) polls the unused pure-Rust `DtlsSession`.
Matters mostly when the SFU ends up as DTLS client.

**Change:**
- `OpenSslDtlsEngine` (`crates/nexus-transport/src/dtls/openssl_backend.rs`): add
  `handle_timeout(&mut self) -> Result<Vec<u8>, DtlsError>` that, while handshaking, calls
  `SSL_ctrl(ssl, DTLS_CTRL_HANDLE_TIMEOUT /* 74 */, 0, null)` on the mid-handshake stream's
  `SslRef::as_ptr()`, then returns `take_pending_output()`. Optionally
  `DTLS_CTRL_GET_TIMEOUT` (73) to skip calls before the deadline. Document the `unsafe`
  block (the `openssl` crate has no safe wrapper).
- `poll_dtls_retransmit` uses the OpenSSL engine when it is the active one; the pure-Rust
  path stays for sessions that use it.
- The 200 ms orchestrator timer is fine (OpenSSL's initial timeout is 1 s, doubling).
- **Honor the answer's `a=setup`.** Today the SFU is never the DTLS client: sessions are
  created with `DtlsRole::Server` (`negotiation.rs`), the offer says `actpass`, and
  `handle_answer` never reads `setup`. An answer with `setup:passive` must make the SFU the
  DTLS client (the engine supports it, `init_dtls`); otherwise both sides wait as servers
  and this fix cannot be exercised end to end (0.3 test 3).

**Code notes (checked 2026-09-26):**
- `take_pending_output()` only holds an alert saved when `start_handshake` fails.
  Retransmitted records land in the `MemBio`: return `mid.get_mut().take_outgoing()`.
- `openssl-sys` (for `SSL_ctrl`) and `foreign-types` (for `SslRef::as_ptr`) are not direct
  dependencies of `nexus-transport`; both are in `Cargo.lock`. openssl-sys 0.9.111 has no
  constants for 73/74: declare them locally.
- OpenSSL's DTLS timer uses the real clock; there is nothing to advance. Tests wait past
  the ~1 s initial timeout.

**Tests:** in `crates/nexus-webrtc/src/webrtc/transport.rs` (the fingerprint tests already
run a real handshake): run a handshake where the first flight from each side is dropped,
wait past the timeout, call the poll, and assert the handshake completes. A second
test asserts nothing is retransmitted before the timeout. A third asserts an answer with
`setup:passive` gives a client-role session.

#### c) SRTCP nonce reuse toward publishers

**Problem:** per-track SRTCP contexts share the publisher's key; REMB uses sender SSRC 1
(`src/worker/pool.rs`, `RembGenerator::new(1)`), forwarded PLI/NACK keep the subscriber's
SSRC, and every context starts its SRTCP index at 0. In addition, `SRTCP_SENT_CACHE`
(`src/sfu.rs`, `send_publisher_srtcp_if_needed`) never removes ended tracks and, past 4,096
entries, evicts half; an evicted live track then gets a **new** context with the same key
and index 0.

**Change** (the proper fix, one context per session, is Phase 1; this closes the hole on
the legacy path):
- Each `TrackActorState` gets a random, non-zero `rtcp_sender_ssrc` at creation, distinct
  from the track's media SSRCs. Every RTCP packet the worker sends to that track's publisher
  (REMB in `generate_and_send_remb` and `perform_bandwidth_allocation`, PLI in
  `handle_rtcp_pli`, NACK in `handle_rtcp_nack`, TWCC feedback) uses it as sender SSRC.
  One (key, sender SSRC) pair then belongs to exactly one context.
- The `SetPublisherSrtcp` handler keeps the existing context when the key material is
  unchanged (compare keys, not just "is some"), so its SRTCP index is never reset.
- Remove the track's entry from `SRTCP_SENT_CACHE` when the track is removed, so the cache
  no longer fills over the process lifetime.

**Code notes (checked 2026-09-26):**
- `perform_bandwidth_allocation` builds REMB with the track's own media SSRC as sender
  (`coordinator.rs`, `RembGenerator::new(ssrc)`) and protects it with the first actor found
  by publisher address, possibly another track's context. Use one actor for both.
- TWCC feedback is also sent with sender SSRC 1 (`TwccFeedbackBuilder::build(1, ...)`).
- Tracks can be created with SSRC 0; media SSRCs arrive later via `SetSsrc` /
  `SetSimulcastSsrc`. Re-check `rtcp_sender_ssrc` for collisions there.
- `SRTCP_SENT_CACHE` is a function-local static; move it to module level so track removal
  (`WorkerPool::remove_track`) can clear its entry.
- `KeyMaterial` has no `PartialEq`; add one (fields are public).
- For NACK, the subscriber's SSRC still selects the subscriber in
  `retransmit_from_ring_buffer`; only the packet forwarded upstream changes sender SSRC.

**Tests:** worker-level test: two video tracks of one publisher, drive REMB and PLI for
both, decrypt what was sent with the publisher's inbound context and assert no
(SSRC, SRTCP index) repeats; a test that a repeated `SetPublisherSrtcp` with the same key
keeps the index; a test that the cache entry is gone after `RemoveTrack`.

---

### 0.2 Delete dead code

One commit per item, so each can be reverted alone. After each: `cargo build`, `clippy
--all-targets`, `cargo test --workspace`, and the benches still build.

| Item | Also touch |
|------|------------|
| `XdpPacketLoop` in `src/sfu.rs`; `src/forward/{processor,multicast,selective}.rs`; `src/transport/af_xdp.rs`; `src/state/forward_table.rs` and the forward-table stub if only XDP uses it; `bpf/`; the `xdp` feature | `benches/forwarding.rs` (drop the `SubscriberList` group); `src/config/xdp.rs` and the `[xdp]` sections in `config/*.toml`; README feature list |
| `src/relay/` and relay plumbing | Worker `relay_out_tx`, `AddRelaySubscriber`/`RelayPacket` messages, `process_relay_events` in the orchestrator, `RelayEvent` forwarding from the gossip thread, `step_once` relay block |
| `nexus-recorder` | `nexus-api` dependency and `recording.rs`; workspace members |
| TURN (`crates/nexus-transport/src/turn`) | Re-export in `src/lib.rs` |
| `SignalingHandler` (`crates/nexus-signal/src/websocket/handler.rs`) | Re-exports |
| `src/track_registry.rs` | `main.rs` (`_ssrc_resolver`) |
| `tests/{integration,stress,unit,validation,common}` | Keep `tests/pps_pipeline.rs` (compiled with `--features sim`) |
| QUIC signaling from startup | `src/signal/server.rs` runs WebSocket only; keep the `nexus-signal` QUIC module and `[quic]` config (marked unused in the config comments) |
| `ActorManager` from startup | `src/sfu.rs`, orchestrator constructor, `room_count()` stat (take it from the orchestrator's room map). **Keep the `nexus-actor` crate**: config validation uses its limits and the worker uses its migration types; it goes with the worker pool in Phase 6 |

**Code notes (checked 2026-09-26):**
- XDP: `UdpTransport` in `sfu.rs` is only used by `XdpPacketLoop`, and `src/state/` goes
  entirely (the stub exists only for the ungated `forward_table()` accessors). Keep
  `ICE_CREDENTIALS` / `register_ice_credentials`, which sit next to the XDP block.
- Relay: `ActorSubscriber.is_relay` / `relay_node` go too, or `deny(warnings)` fails.
- TURN: root `hmac`, `sha1`, `md-5` are unused by the root crate; drop them there, keep
  them in `nexus-transport`. ICE's own TURN gathering in `ice/gather.rs` stays.
- ActorManager: `Sfu::subscribe_to_track` takes `worker_id` from it; use
  `ssrc_router.lookup_by_track` instead. `stats().room_count` comes from
  `distributed_state.room_count()` (the orchestrator is moved into a task).
  **`tests/pps_pipeline.rs` uses `ActorManager`** and only compiles with `--features sim`:
  rewrite it and run `cargo test --features sim --test pps_pipeline`.
- Scripts: `scripts/verify_cleanup.sh` and `scripts/run_all_tests.sh` reference removed
  code and tests. `Cargo.lock` must be committed (CI uses `--locked`).

Leave `nexus-dst` and `nexus-state` alone (separate binary; gossip is a cluster feature,
not dead code). Update architecture.md 2.3 and CLAUDE.md at the end; report the line-count
change in the status section.

---

### 0.3 End-to-end harness

**Goal:** a test that fails whenever media stops flowing between real WebRTC clients,
running in CI on every push. Every later phase adds its exit checks here.

**Change:**
- Move the startup sequence out of `src/main.rs` (`run`) into the library, e.g.
  `nexus_sfu::server::start(config) -> ServerHandle` with `shutdown()` and the bound
  addresses (media port, signaling address). `main.rs` becomes a thin wrapper. Needs 0.1a
  (candidate port = bound port) so tests can use port 0.
- `tests/e2e.rs` (top level, so cargo compiles it) with `tests/e2e/` helpers:
  - start the server with a test config: ports 0, `announced_ips` = the host's first
    non-loopback IPv4 address (webrtc-rs never offers loopback candidates, so a
    `127.0.0.1` SFU candidate has no partner), plain WS, short timeouts;
  - clients from `nexus-loadtest` (it already has a `webrtc-rs` client: `client.rs`,
    `media.rs`, `signaling.rs`); reuse it as a dev-dependency rather than copying it;
  - assertions from the client side: per received track, packet count over a window,
    sequence continuity, RTP timestamps advancing, SSRC stable.
- Loss injection (`nexus_loadtest::lossy`, done instead of a separate UDP proxy): the
  client's ICE runs over one socket (webrtc-rs UDP mux) that drops datagrams by rule (by
  direction, by class STUN/DTLS/media, first N, rate). A proxy in front of the SFU does not
  work: the SFU is ICE-controlling and nominates the direct host pair, so its packets bypass
  the proxy. Used by 0.1b's end-to-end check here and by Phase 3.
- Tests to land in 0.3:
  1. `two_party_audio_video`: A and B each publish audio + video and receive the other's
     two tracks for 5 s.
  2. `candidate_is_announced_address`: the SFU's candidate is the announced IP and bound
     port, never unspecified.
  3. `dtls_survives_lost_first_flight`: client forced to DTLS server role (so the SFU is
     the client), proxy drops the SFU's first DTLS flight; the call still connects within
     3 s. Fails without 0.1b.
- CI: runs inside the existing `test` job (`cargo test --workspace`); check the runtime
  stays under 60 s.

**Prerequisites found in the code (checked 2026-09-26):**
- Port 0: `WebSocketServer::new` and `ApiServer::new` assert `port > 0` and bind inside
  `run()`. Bind the WebSocket listener up front and expose `local_addr()`; tests disable
  the API.
- `signaling_connections()` is process-global: one server's shutdown notifies another
  server's clients. Make it per server instance.
- The orchestrator task never exits on its own; give its `select!` a shutdown branch.
- The ingress loop blocks its thread (`thread::sleep` in `SpinLoop`): run it on a
  dedicated thread. `start()` must not initialise tracing.
- `nexus-loadtest` has only aggregate receive counters and falls back to Google STUN when
  `ice_servers` is empty. Add per-track receive stats, a no-STUN option, and a DTLS role
  option (`SettingEngine::set_answering_dtls_role`).
- webrtc-ice 0.10 drops loopback host candidates: the client offers LAN addresses. If a
  `127.0.0.1` SFU candidate does not work on CI, announce a non-loopback interface address.

---

### 0.4 Measurements

**Goal:** replace the two assumptions in design §2 and §3.4 with numbers.

- `benches/srtp_backends.rs`: protect and unprotect, 160-byte and 1,200-byte packets, for
  - RustCrypto (current `SrtpContext`),
  - OpenSSL EVP: `aes-128-ctr` + HMAC-SHA1 (keyed context reused per packet, not rebuilt)
    and `aes-128-gcm`,
  - `ring` AES-128-GCM (`LessSafeKey::seal_in_place_separate_tag`).
  Check each backend's output against RFC test vectors before timing it. Only the
  RFC 3711 KDF vector exists today (`srtp/keys.rs`): first add RFC 3711 B.2 (AES-CM) and
  RFC 7714 §16 (AES-GCM) packet vectors as unit tests in `crates/nexus-transport/src/srtp`.
  `openssl` and `ring` are `nexus-transport` dependencies only; add them as root
  dev-dependencies (same locked versions).
- `benches/udp_floor.rs`: raw `sendmmsg` of 1,200-byte datagrams to 1, 10 and 100 distinct
  loopback destinations (drained by receiver threads, as in `real_path.rs`), batches of 64;
  report ns per datagram. Same for `recvmmsg`. No SFU code involved.
- Run on Linux arm64 (Docker, as for the baseline) and Linux x86_64 (GitHub runner through a
  `workflow_dispatch` job once the account's billing lock is cleared; otherwise record
  arm64 only and say so).
- Record the results in architecture.md Part 5 and add a revision to `dataplane-design.md`:
  backend per profile, profile order in `use_srtp`, and the 500K/core target confirmed or
  changed using the rule in §2.

---

## Status

| Part | State | Commits | Notes |
|------|-------|---------|-------|
| 0.1a Announced IP | Done | Phase 0 commit | `transport.announced_ips` / `NEXUS_ANNOUNCED_IPS`, candidates carry the bound port (`src/orchestrator/candidates.rs`) |
| 0.1b DTLS retransmission | Done | Phase 0 commit | `OpenSslDtlsEngine::handle_timeout`; also honours the answer's `a=setup` (SFU as DTLS client) |
| 0.1c SRTCP nonce reuse | Done | Phase 0 commit | Per-track `rtcp_sender_ssrc` on REMB/TWCC/PLI/NACK; same key keeps the context; cache entry removed with the track |
| 0.2 Dead code | Done | Phase 0 commit | 21,700 lines removed, 3,900 added across all of Phase 0; `tests/pps_pipeline.rs` rewritten without `ActorManager` |
| 0.3 E2E harness | Done | Phase 0 commit | `src/server.rs` (`start` → `ServerHandle`), `tests/e2e.rs`: 3 tests, ~10 s on macOS |
| 0.4 Measurements | Partial | Phase 0 commit | Benches, RFC 3711/7714 packet vectors and macOS numbers done; two AES-GCM interop bugs found and fixed. **Left:** run `srtp_backends` and `udp_floor` on Linux arm64 (Docker) and x86_64, then confirm or revise §2 and pick the backends (revision log) |

### Session log

Add one line per working session: date, part, what was done, what is left.

- 2026-09-25: plan written.
- 2026-09-26: plan checked against the code; code notes and prerequisites added to 0.1a-c,
  0.2, 0.3, 0.4 (DTLS role from `a=setup` added to 0.1b).
- 2026-09-26: all parts implemented in one commit (at the user's request, instead of one
  commit per part). Each 0.1 fix has a test that fails without it (0.1b checked by
  disabling the fix: the unit and e2e DTLS tests fail). `cargo test --workspace`,
  clippy `--all-targets` and fmt pass on macOS; `cargo test --features sim --test
  pps_pipeline` passes. Also: the WebSocket server binds in `new` (port 0, `local_addr`),
  the signaling connection registry is per server, the orchestrator stops on the shutdown
  flag, and `Sfu::shutdown` now stops the worker pool (it used to give up because the
  orchestrator held the `Arc`). GitHub issues #1-#3 not created.
- 2026-09-26, 0.4: `benches/srtp_backends.rs` (RustCrypto, OpenSSL EVP, ring; outputs
  checked against `SrtpContext`), `benches/udp_floor.rs` (raw `sendmmsg`/`recvmmsg`, Linux
  only), `benches/common/`, `srtp/rfc_vectors.rs`. The vectors found two AES-GCM bugs (AEAD
  KDF label byte, SRTCP E+index position), fixed here. macOS numbers are recorded in
  architecture.md Part 5 and a provisional design revision. Docker Desktop crashed when the
  host disk filled, so nothing ran on Linux: the Linux build, clippy and `cargo test
  --workspace` (incl. e2e) are unverified locally and are left to CI. Next: Linux runs of
  both benches, then close exit criterion 4.
