# Nexus SFU — RFC & Architecture Gap Fix Plan

> 26 issues across 6 phases. Each phase is self-contained and mergeable independently.

## Progress

| Phase | Status | Summary |
|-------|--------|---------|
| 1 | **DONE** | SRTP ROC overflow, SRTCP encryption (already done), DTLS use_srtp validation |
| 2 | **DONE** | RtcpScheduler created + integrated into worker pool |
| 3 | **DONE** | ICE consent keepalives, PRIORITY mandatory, MESSAGE-INTEGRITY ordering |
| 4 | **DONE** | Exponential backoff, lifetime validation, channel/permission auto-refresh |
| 5 | **DONE** | Subscription chain already wired, BWE param validation, delay threshold docs |
| 6 | **DONE** | Two-byte extensions, SDP validation, CCS epoch assertion, FIR seq tracking |

## Phase 1: Critical Security Fixes (SRTP/DTLS)

**Why first**: Plaintext RTCP and silent ROC wraparound are active security vulnerabilities.

### 1.1 SRTP ROC overflow — replace `assert!` with error handling
- **File**: `crates/nexus-transport/src/srtp/context.rs:163,191`
- **RFC**: 3711 §3.3.1
- **Problem**: `assert!(state.roc < u32::MAX)` compiles out in release builds. ROC silently wraps to 0, replaying the entire SRTP keystream.
- **Fix**: Replace both `assert!` with `if roc >= u32::MAX { return Err(SrtpError::RocOverflow) }`. Add `RocOverflow` variant to `SrtpError`. Caller should tear down the SRTP context and renegotiate.
- **Test**: Unit test that drives ROC to `u32::MAX - 1`, verifies next increment returns `Err`.

### 1.2 SRTCP encryption for relayed RTCP packets
- **File**: `src/worker/pool.rs:2712-2723`
- **RFC**: 3711 §3.4
- **Problem**: RTCP packets forwarded to subscribers in plaintext (`// TODO: SRTP-protect`).
- **Fix**: Before sending, call `srtp_context.protect_rtcp(&mut buf, len)` for each subscriber's SRTP context. Skip subscribers without an active context (not yet established).
- **Test**: Integration test: send RTCP through worker, verify output is SRTCP-protected (check encryption bit in SRTCP trailer).

### 1.3 DTLS `use_srtp` extension — fail if not negotiated
- **File**: `crates/nexus-transport/src/dtls/openssl_backend.rs:442-474`
- **RFC**: 5764 §4.1
- **Problem**: If `ssl.selected_srtp_profile()` returns `None`, code logs a warning and defaults to `AES128_CM_SHA1_80`. This masks negotiation failures.
- **Fix**: Change `warn` → `return Err(DtlsError::SrtpNotNegotiated)`. Add `SrtpNotNegotiated` variant. Remove the default fallback entirely.
- **Test**: Unit test with a DTLS config that omits `use_srtp` — verify handshake fails with correct error.

---

## Phase 2: RTCP Scheduling (RFC 3550 §6)

**Why second**: Without RTCP bandwidth control, the SFU can flood receivers in large rooms.

### 2.1 Create `RtcpScheduler` module
- **New file**: `crates/nexus-media/src/rtcp/scheduler.rs`
- **RFC**: 3550 §6.2–6.4
- **Implements**:
  - `Td` calculation: `max(RTCP_MIN_TIME, n * avg_rtcp_size / RTCP_BW)` where `RTCP_BW = 0.05 * session_bw`
  - Randomized interval: `uniform(0.5 * Td, 1.5 * Td)`
  - Minimum 5-second floor (`RTCP_MIN_TIME = 5.0`)
  - Initial delay: random in `[0, 0.5 * Td]` for first packet
  - Separate sender/receiver fractions (25% / 75% split per §6.3.1)
- **API**:
  ```rust
  pub struct RtcpScheduler {
      members: u32,
      senders: u32,
      avg_rtcp_size: f64,
      session_bw_bps: u64,
      we_sent: bool,
      last_rtcp_us: u64,
  }
  impl RtcpScheduler {
      pub fn new(session_bw_bps: u64) -> Self;
      pub fn update_members(&mut self, members: u32, senders: u32);
      pub fn on_rtcp_sent(&mut self, packet_size: usize, now_us: u64);
      pub fn next_send_time_us(&self, now_us: u64) -> u64;
      pub fn is_time_to_send(&self, now_us: u64) -> bool;
  }
  ```
- **Test**: Verify `Td >= 5s`, verify randomization distribution, verify sender/receiver fraction split.

### 2.2 Integrate `RtcpScheduler` into worker pool
- **File**: `src/worker/pool.rs`
- **Change**: Replace hardcoded `SR_INTERVAL_US = 1_000_000` and `REMB_INTERVAL_US = 1_000_000` with `RtcpScheduler::is_time_to_send()`. Pass `session_bw_bps` from BWE estimate. Update `members` count when subscribers join/leave.
- **Test**: Integration test: 100 simulated participants → verify SR interval adapts (>= 5s).

### 2.3 RTCP bandwidth accounting
- **File**: `src/worker/pool.rs` (extend SR/RR/REMB send paths)
- **RFC**: 3550 §6.2
- **Change**: After each RTCP send, call `scheduler.on_rtcp_sent(size, now)` to update `avg_rtcp_size`. Track cumulative RTCP bytes/sec. Log warning if exceeding 5% of session bandwidth.
- **Test**: Verify `avg_rtcp_size` converges to actual average over 100 packets.

---

## Phase 3: ICE/STUN Compliance

### 3.1 Consent refresh via binding indications (RFC 7675 §5)
- **File**: `crates/nexus-transport/src/ice/agent.rs`
- **Problem**: `is_consent_stale()` checks staleness but never proactively sends keepalives.
- **Fix**:
  1. Add `consent_check_interval: Duration = Duration::from_secs(15)` constant.
  2. Add `last_consent_check: Instant` field.
  3. In `poll_outbound()`, if `last_consent_check.elapsed() > consent_check_interval`, enqueue a binding indication to the selected pair and update timer.
  4. On receiving any authenticated response on the selected pair, update `last_consent`.
- **Test**: Simulate 20s without response → verify binding indication sent. Simulate 35s → verify consent declared stale.

### 3.2 PRIORITY attribute mandatory in binding requests (RFC 8445 §7.2.5.3.1)
- **File**: `crates/nexus-transport/src/ice/agent.rs:973-993`
- **Problem**: Missing PRIORITY silently falls back to a computed value.
- **Fix**: Replace `unwrap_or_else(|| ...)` with `ok_or(IceError::MissingPriority)?`. Add `MissingPriority` variant to `IceError`.
- **Test**: Send binding request without PRIORITY attribute → verify error returned.

### 3.3 MESSAGE-INTEGRITY attribute ordering (RFC 5389 §15.4)
- **File**: `crates/nexus-transport/src/ice/stun/message.rs:466`
- **Problem**: Parser accepts attributes after MESSAGE-INTEGRITY that aren't FINGERPRINT.
- **Fix**: Add `saw_integrity: bool` flag in parse loop. Once set, only accept `FINGERPRINT`. Any other attribute → `Err(StunError::AttributeAfterIntegrity)`.
- **Test**: Craft a STUN message with an attribute after MESSAGE-INTEGRITY (not FINGERPRINT) → verify parse error.

### 3.4 Binding indication MESSAGE-INTEGRITY (RFC 5389 §10.1.2)
- **File**: `crates/nexus-transport/src/ice/stun/server.rs:345-357`
- **RFC**: 5389 says indications SHOULD NOT require authentication. Current bare indication is fine for consent. No change needed — mark as resolved.

---

## Phase 4: TURN Compliance

### 4.1 Exponential backoff for retries (RFC 5766 §7.1 via RFC 5389 §7.2.1)
- **File**: `crates/nexus-transport/src/turn/allocation.rs:162-178`
- **Problem**: `timeout * (retries + 1)` is linear. RFC requires `RTO * 2^retries` capped at `RTO * 16`.
- **Fix**:
  ```rust
  pub fn is_timed_out(&self) -> bool {
      let backoff = self.timeout * (1u32 << self.retries.min(4)); // cap at 2^4 = 16x
      self.sent_at.elapsed() > backoff
  }
  ```
- **Test**: Verify retry sequence: 500ms, 1s, 2s, 4s, 8s, 8s (capped).

### 4.2 TURN allocation lifetime bounds (RFC 5766 §7.1)
- **File**: `crates/nexus-transport/src/turn/client.rs:753`
- **Problem**: Accepts any server lifetime without validation.
- **Fix**: After parsing, validate `lifetime` is in `[60, 3600]`. If 0, treat as allocation failure. If > 3600, clamp to 3600 with warning.
- **Test**: Server returns lifetime=0 → error. lifetime=7200 → clamped to 3600.

### 4.3 Channel binding auto-refresh (RFC 5766 §11.3)
- **File**: `crates/nexus-transport/src/turn/types.rs:344-347` + `client.rs`
- **Problem**: `ChannelBinding::refresh()` exists but is never called proactively.
- **Fix**:
  1. Add `needs_refresh(&self, margin: Duration) -> bool` to `ChannelBinding`.
  2. In `TurnClient::poll()`, iterate channel bindings, send `ChannelBind` refresh for any within margin of expiry (default: 60s before 600s lifetime).
- **Test**: Create channel binding, advance clock to 540s, verify refresh request sent.

### 4.4 Permission auto-refresh (RFC 5766 §9.2)
- **File**: `crates/nexus-transport/src/turn/types.rs:280` + `client.rs`
- **Problem**: Permissions expire after 300s with no proactive refresh.
- **Fix**: Same pattern as 4.3 — add `needs_refresh()` to `Permission`, poll in `TurnClient::poll()`.
- **Test**: Create permission, advance clock to 240s, verify `CreatePermission` refresh sent.

---

## Phase 5: Architecture Gaps

### 5.1 Wire subscription activation chain
- **File**: `src/orchestrator/subscription.rs` + `src/orchestrator/connection.rs`
- **Problem**: `handle_session_established()` exists but is never called. Subscriptions stay in `Negotiating` state forever.
- **Fix**: In `ConnectionMonitor`, when ICE/DTLS reaches `Established` state, emit a `SessionEstablished` event. In the orchestrator `select!` loop, match on this event and call `subscription_manager.handle_session_established(transport_id, srtp_ctx)`.
- **Test**: Full flow: join room → subscribe → complete ICE → verify subscription transitions to `Active`.

### 5.2 ICE candidate gathering — expand beyond stub
- **File**: `src/orchestrator/negotiation.rs:399-420`
- **Problem**: Single hardcoded host candidate with priority=1, component=0.
- **Fix**:
  1. Enumerate local network interfaces (use `if_addrs` crate or `getifaddrs`).
  2. Create host candidates for each valid interface (skip loopback, link-local).
  3. If STUN servers configured, send binding requests to gather server-reflexive candidates.
  4. Calculate priority per RFC 8445 §5.1.2.1 (type preference × 2^24 + local preference × 2^8 + component).
  5. Fire completion event after gathering timeout (default 3s) or all candidates gathered.
- **Test**: Mock interface enumeration → verify multiple host candidates with correct priorities.

### 5.3 FIR sequence number tracking (RFC 5104 §4.3)
- **File**: `crates/nexus-media/src/rtcp/packet.rs`
- **Problem**: FIR packets sent without incrementing `seq_nr` per target SSRC.
- **Fix**: Add `fir_seq_nr: HashMap<Ssrc, u8>` to the RTCP generator. Increment per-SSRC on each FIR send.
- **Test**: Send 3 FIR for same SSRC → verify seq_nr increments 0, 1, 2.

### 5.4 BWE parameter bounds validation (RFC 8698 §5)
- **File**: `crates/nexus-bwe/src/gcc.rs:82-90`
- **Problem**: AIMD config accepts any values without validation.
- **Fix**: In `AimdConfig::new()` / builder, validate:
  - `decrease_factor` in `[0.5, 0.95]`
  - `increase_rate_bps` > 0
  - `min_bitrate_bps < max_bitrate_bps`
  - `headroom_factor` in `[0.5, 1.0]`
  Return `Err` or panic on invalid config.
- **Test**: Invalid decrease_factor=0.1 → error. Valid config → Ok.

### 5.5 GCC delay threshold units clarification
- **File**: `crates/nexus-bwe/src/delay.rs:10-11`
- **Problem**: Hardcoded threshold constant with ambiguous units.
- **Fix**: Rename constant to include units (e.g., `OVERUSE_THRESHOLD_MS_PER_MS`), add doc comment referencing RFC 8698 §5 (12.5ms default threshold). Verify the value matches the RFC.
- **Test**: Existing tests should still pass after rename.

---

## Phase 6: Lower Priority / Feature Completions

### 6.1 Two-byte RTP header extension support (RFC 5285 §4.2)
- **File**: `crates/nexus-media/src/rtp/header.rs:519-554`
- **Problem**: Only one-byte format (0xBEDE) is parsed. Two-byte format (0x1000 + appbits) is ignored.
- **Fix**: After checking for `0xBEDE`, check for `profile_id & 0xFFF0 == 0x1000`. Parse two-byte extensions: `[id: u8][length: u8][data: length bytes]`.
- **Test**: Craft RTP packet with two-byte extension → verify correct parsing.

### 6.2 SDP mandatory field validation (RFC 8866 §5)
- **File**: `crates/nexus-webrtc/src/sdp/parser.rs`
- **Problem**: Parsed fields aren't checked for mandatory presence post-parse.
- **Fix**: After parsing, verify `v=`, `o=`, `s=` lines were present. `t=` line is mandatory per RFC but WebRTC SDP often omits it — validate conditionally.
- **Test**: SDP missing `o=` line → parse error.

### 6.3 DTLS ChangeCipherSpec epoch assertion (RFC 6347 §4.3.3)
- **File**: `crates/nexus-transport/src/dtls/session.rs:852-896`
- **Problem**: No explicit assertion that CCS is sent with epoch=0.
- **Fix**: After building CCS record, assert: `debug_assert!(self.record_layer.write_epoch() == 0)`. Add comment referencing RFC 6347 §4.3.3.
- **Test**: Verify CCS record has epoch=0 in output buffer.

### 6.4 Migration snapshot — extend with missing fields
- **File**: `src/worker/pool.rs:2170-2225`
- **Problem**: `participant_id`, `ssrc`, `kind` default to 0/Video when missing from snapshot.
- **Fix**: Make `MigrationSnapshot` include all required fields. Remove defaults — require callers to provide complete snapshots. Add assertion: `assert!(snapshot.ssrc != 0)`.
- **Test**: Incomplete snapshot → error instead of silent defaults.

### 6.5 AF_XDP ring operations (Linux-only)
- **File**: `src/transport/af_xdp.rs:708-769`
- **Problem**: All ring ops are stubs returning dummy values.
- **Fix**: Implement via `libbpf_sys` FFI:
  - `rx_ring_available()` → read `*ring.consumer` atomically
  - `rx_ring_consume()` → dequeue from rx ring, return frame descriptor
  - `tx_ring_produce()` → enqueue to tx ring
  - `kick_tx()` → `sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0)`
  - `refill_fill_ring()` → push UMEM frames back to fill ring
- **Note**: This is Linux-specific. Keep stubs for other platforms behind `#[cfg]`.
- **Test**: Requires Linux with XDP-capable NIC. Integration test with veth pair.

---

## Dependency Graph

```
Phase 1 (security) ─── no deps ──────────────────────────→ merge
Phase 2 (RTCP)     ─── depends on nothing ────────────────→ merge
Phase 3 (ICE/STUN) ─── depends on nothing ────────────────→ merge
Phase 4 (TURN)     ─── depends on nothing ────────────────→ merge
Phase 5 (arch)     ─── 5.1 depends on Phase 3.1 (consent) → merge after Phase 3
Phase 6 (lower)    ─── 6.5 depends on nothing (Linux-only) → merge independently
```

Phases 1–4 are fully independent and can be worked in parallel.
Phase 5.1 (subscription wiring) should come after Phase 3.1 (consent refresh) since the activation chain depends on properly established ICE.

## Estimated Scope

| Phase | Files Changed | New Files | Lines (approx) |
|-------|--------------|-----------|-----------------|
| 1     | 3            | 0         | ~80             |
| 2     | 3            | 1         | ~300            |
| 3     | 3            | 0         | ~120            |
| 4     | 3            | 0         | ~100            |
| 5     | 6            | 0         | ~400            |
| 6     | 5            | 0         | ~350            |
| **Total** | **~18**  | **1**     | **~1350**       |
