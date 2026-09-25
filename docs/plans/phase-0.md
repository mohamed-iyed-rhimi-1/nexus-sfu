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

**Tests:** in `crates/nexus-webrtc/src/webrtc/transport.rs` (the fingerprint tests already
run a real handshake): run a handshake where the first flight from each side is dropped,
advance time past the timeout, call the poll, and assert the handshake completes. A second
test asserts nothing is retransmitted before the timeout.

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
  - start the server with a test config: ports 0, `announced_ips = [127.0.0.1]`, generated
    self-signed TLS or plain WS, short timeouts;
  - clients from `nexus-loadtest` (it already has a `webrtc-rs` client: `client.rs`,
    `media.rs`, `signaling.rs`); reuse it as a dev-dependency rather than copying it;
  - assertions from the client side: per received track, packet count over a window,
    sequence continuity, RTP timestamps advancing, SSRC stable.
- UDP loss proxy in the harness (`tests/e2e/proxy.rs`): sits between a client and the
  media port, drops packets by rule (by index, by kind, by rate). Used by 0.1b's
  end-to-end check here and by Phase 3.
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

---

### 0.4 Measurements

**Goal:** replace the two assumptions in design §2 and §3.4 with numbers.

- `benches/srtp_backends.rs`: protect and unprotect, 160-byte and 1,200-byte packets, for
  - RustCrypto (current `SrtpContext`),
  - OpenSSL EVP: `aes-128-ctr` + HMAC-SHA1 (keyed context reused per packet, not rebuilt)
    and `aes-128-gcm`,
  - `ring` AES-128-GCM (`LessSafeKey::seal_in_place_separate_tag`).
  Check each backend's output against the existing RFC test vectors in
  `crates/nexus-transport/src/srtp` before timing it.
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
| 0.1a Announced IP | Not started | | #1 |
| 0.1b DTLS retransmission | Not started | | #2 |
| 0.1c SRTCP nonce reuse | Not started | | #3 |
| 0.2 Dead code | Not started | | |
| 0.3 E2E harness | Not started | | |
| 0.4 Measurements | Not started | | |

### Session log

Add one line per working session: date, part, what was done, what is left.

- 2026-09-25: plan written.
