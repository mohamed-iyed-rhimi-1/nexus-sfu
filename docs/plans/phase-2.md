# Phase 2 — Multiple shards

**State: not started** (plan written 2026-09-29, audited against `75fcdd9` the same day, revised the same day after
the owner's review; waiting for the next review).

**Design:** [`docs/dataplane-design.md`](../dataplane-design.md) §5, Phase 2 ("Port per shard,
placement, cross-shard queues and buffer return"), within D1-D4 and D8, §3.1 and §3.3. Detailed
design: [`docs/design/dataplane-v1.md`](../design/dataplane-v1.md) §13 (interfaces for Phase 2),
§3.2-§3.3 (loop, parking), §12.2-§12.3 (SR, keyframes across shards), §10.2-§10.3 (fan-out,
pool). Where the code or the owner's decisions differ from the note, this plan says so, and
[corrections](#corrections-to-the-design-note) lists them. No decision (D1-D10, R1-R9) changes.
**Current state:** [`architecture.md`](../../architecture.md).
**Branch:** `phase-2` (from `75fcdd9`). It merges into `main` only when every exit criterion
passes (design §7).

Phase 1 left one shard with the hooks Phase 2 builds on: `ShardId` in `BufRef`, `TrackRef` and
`ShardInfo`, the `Placement` trait with `SingleShard`, port-per-shard binding (`port + i`) and
per-shard candidates, `RejectReason::WrongShard`, a Prometheus exporter labelled by shard.
Phase 2 makes the data plane run on N shards: a room's participants go to one shard until it
fills, and a track with subscribers on other shards is decrypted once and handed to each of
those shards by buffer handle (D3). NACK, RR and TWCC are Phase 3.

Section references like "note §13.4" point into the design note. Code notes were checked
against `75fcdd9`; line numbers drift, so prefer the symbol names.

## Owner's decisions (2026-09-29, while planning)

| Topic | Decision | Instead of (note) |
|-------|----------|-------------------|
| Cross-shard rings | `crossbeam_queue::ArrayQueue<XsMsg>` per ordered shard pair, used single-producer / single-consumer. Already a dependency (the command queues), no `unsafe`. A custom SPSC ring replaces it only if `benches/dataplane.rs` shows the queue is a measurable share of the per-packet cost | A generic SPSC ring from the deleted `src/worker/spsc.rs` (note §13.4) |
| Verifying the shared pool | A multi-thread stress test with canary bytes, plus Miri (nightly, local) on a small two-thread hand-off test | A `loom` model of one pair (note §13.4 item 6). `loom` is not in `Cargo.lock` and cannot model crossbeam's internals without cfg changes |
| Where the targets are measured | Linux arm64 in the Docker Desktop VM raised to ≈ 10 vCPU (M2 Pro host), recorded as a VM result. x86_64 on real hardware stays open (release item) | Linux arm64 and x86_64 (design §2) |

## Exit criteria

"In CI" means **`scripts/ci-local.sh all`**, recorded with its summary in the session log
(GitHub Actions still cannot run on this repository; Phase 1 owner's decision, 2026-09-27).

1. **E2E with participants on different shards**, in CI on macOS and Linux (arm64 native,
   x86_64 emulated as `linux/amd64` under `ci-local.sh all`, so a correctness check only):
   - `cross_shard_call`: two participants on different shards, A+V both ways, payload
     markers from the right publisher, SR translation (CNAME, timestamp consistency) and
     keyframe requests (PLI on subscribe, forwarded PLI, throttle) across shards;
   - `ten_clients_four_shards`: `ten_clients_audio_video` with `shards = 4`, participants
     spread over every shard;
   - `unpublish_and_leave_across_shards`: after unpublish and leave, every shard's
     `tracks` and `subscriptions` gauges and in-flight buffers return to 0;
   - `resubscribe_across_shards`: `resubscribe_no_srtp_index_reuse` with publisher and
     subscriber on different shards (no repeated (SSRC, index) on the wire);
   - the 9 existing tests stay green (the harness sums stats over shards).
2. **Throughput:** ≥ 500,000 subscriber-packets/s per shard on `benches/dataplane.rs`,
   **local** scenario (1,200-byte video, AES-GCM, end to end: receive, decrypt, fan-out,
   encrypt, `sendmmsg`; ingress cost amortised over 10 subscribers), Linux arm64, VM with
   ≈ 10 vCPU.
3. **Scaling:** ≥ 0.8 × linear from 1 to 4 shards on the same bench, for the **local** and
   the **cross** scenario (every publisher's subscribers spread over all shards). The cross
   scenario's absolute per-shard rate is reported beside it.
   For 2 and 3: a target that is not met is **revised in `dataplane-design.md` with the
   measurements** (design §2 rule), never quietly missed.
4. **0 heap allocations per packet** on the steady-state path, including the cross-shard
   path (hand-off, remote fan-out, buffer return, SR and keyframe messages):
   `crates/nexus-dataplane/tests/alloc.rs`, AES-GCM and AES-CM.
5. **Memory:** the §3.11 session-state budget (25 KB per participant) still met in CI; the
   per-shard fixed memory (pool, rings) for 4 shards reported beside it.
6. **No panic on network input, no leaked buffers, no stray state:** a proptest over random
   command and media sequences on 3 shards never panics and ends, at quiescence, with every
   pool full, every in-flight count 0, and the shards agreeing with the orchestrator's
   counting rule (no mirror, and no `remote_shards` bit, for a (track, shard) whose count is
   0; none missing where it is > 0). 2.4 adds the same check on the orchestrator's recorded
   command stream.
7. **Manual browser call** with `shards = 2` and the participants on different shards
   (Chrome and Firefox, recorded with versions), like Phase 1 criterion 4.
8. **Documents:** `architecture.md` (Parts 1-3, 5), CLAUDE.md, README, config files and
   `deploy/docker` describe N shards and the port range.

Latency (p99 < 200 µs inside the SFU at 50% of the target load, i.e. 250,000
subscriber-packets/s per shard, design §2) is **measured and reported** by the new bench, not
a gate: design §5's Phase 2 row lists throughput and scaling.

## Engineering rules for this phase

Phase 1's rules hold unchanged: every commit green (build, clippy `-D warnings`, fmt, `cargo
test --workspace`, all targets compile); `Cargo.lock` committed, `--locked`; the Linux
container run for any part that touches I/O, threads, benches or `cfg(target_os)`
(`scripts/ci-local.sh`, summary in the session log); network input never panics; hot path
with no allocation, no lock, no clock read (`now` passed in), every loop bounded;
`debug_assert!` per packet, `assert!` in command handling; functions under ≈ 60 lines.

Added for Phase 2:

- **`unsafe`** is allowed in one more module, `pool.rs` (the shared region, 2.1), under a
  local `#[allow(unsafe_code)]` with a `// SAFETY:` comment per block, next to
  `shard/io/linux.rs`. The crate root keeps `#![deny(unsafe_code)]`.
- **Never wait on another shard.** Every cross-shard push has a bounded budget, a "drop and
  count" path and a counter. A shard never spins or blocks on a peer's queue.
- **Ownership rule:** only the owning shard writes a pool buffer, takes it or puts it back;
  peers only read it and return the handle (note §13.4).
- **Clock reads:** still one per iteration. The only exception is the off-by-default
  `latency-probe` feature (2.6), which adds one after the last flush.
- **Shard-count coverage:** each new shard test runs with at least 2 shards; the proptest and
  alloc test with 3 and 2.

## Parts

Each part is sized for one or two working sessions and ends at a green checkpoint. Order:
**2.1 → 2.2 → 2.3 → 2.4 → 2.5 → 2.6 → 2.7**. 2.1-2.3 stay inside `nexus-dataplane` (the
binary still refuses `shards > 1` until 2.3 lifts it, and until 2.4 the orchestrator places
everything on shard 0, so every commit stays green). 2.6's bench scaffold can start after 2.3.
Realistic size: ≈ 8-10 sessions.

---

### 2.1 Shared pool region and cross-shard messages

**Goal:** the pieces for handing a buffer to another shard and getting it back, tested alone
before the shard uses them: a pool region peers can read, owner-local refcounts with a
per-peer credit, the message type and the ring mesh.

**Files:** `crates/nexus-dataplane/src/{pool.rs, xs.rs (new), ids.rs, lib.rs}`,
`crates/nexus-dataplane/tests/pool_handoff.rs` (new).

**Change:**
- **`PoolRegion`:** the pool's bytes in one allocation behind an `Arc`, one
  `UnsafeCell<[u8; BUF_SIZE]>` per buffer, `Sync` by an `unsafe impl` with the ownership
  argument. Peers hold a clone of every other shard's region and read
  `slice(buf, len) -> &[u8]`.
- **No reference ever spans the whole region.** Today `pair_mut` splits all of `memory`
  (`pool.rs:102-108`), which would alias a peer's shared read of a lent buffer. In the new
  pool, `buf_mut(buf)` and `pair_mut(read, write)` build **per-buffer** references from the
  buffers' own cells, and only for buffers the owner holds (free, being received into, or
  its own send buffers). `LinuxIo` keeps `buf_mut` pointers in its iovecs (`linux.rs:97`,
  `:116`); those buffers are receive slots and send buffers, never lent, so the rule holds.
- **Lend only after local fan-out:** the ingress buffer is lent after the local subscribers
  are served, and from then on the owner does not touch it until `release` brings its
  `refs` to 0. Nothing writes to a lent buffer (the plaintext is final after unprotect).
- **`BufferPool`** keeps its free stack and gains:
  - `refs: Box<[u16]>`, one per buffer, read and written only by the owner (note §13.4 item 2);
  - `in_flight: [u32; MAX_SHARDS]`, buffers currently lent to each peer (owner-local);
  - `can_lend(peer)` (`in_flight[peer] < XS_CREDIT`), `lend(buf, peer)`, `unlend(buf, peer)`
    (undo, for the push-failure path of 2.2), `release(buf, peer)` (a returned handle:
    `refs -= 1`, `in_flight -= 1`, `put` at 0), and `put_if_unshared(buf)` for the ingress
    path.
  - `put` and `take` keep their current checks; `put` on a buffer with `refs > 0` is a bug
    (`assert!`).
- **Credit, not ring capacity, bounds what is lent** (correction to note §13.4 item 7): the
  owner lends to peer j only while `in_flight[j] < XS_CREDIT`, and the return ring j→owner
  has capacity `XS_CREDIT`, so it can never be full. A full return ring is an `assert!`
  (it would leak a buffer). Starting values: media ring 1,024, `XS_CREDIT` 1,024,
  `XS_BUDGET` 256 messages per peer per iteration; 2.6 tunes them.
- **`XsMsg`** (`Copy`, a `const` assert of ≤ 24 bytes on the default build):
  `Rtp { buf: BufRef, len: u16, track: TrackId, layer: u8 }`,
  `SenderReport { track: TrackId, layer: u8, ntp: u64, rtp: u32 }`,
  `KeyframeRequest { track: TrackId, layer: u8, from: ShardId }`.
- **`XsMesh::new(n)`** builds, for every ordered pair (i, j), a media ring i→j and a return
  ring j→i (`ArrayQueue`), and hands each shard its `XsPorts`: producer ends to every peer,
  consumer ends from every peer, the peers' regions, and (2.3) the peers' `Wake`s.
  `ShardId` gets `Ord`; `MAX_SHARDS` stays 64 (a `ShardMask` is a `u64`).

**Code notes (audited 2026-09-29):**
- `BufferPool` today (`pool.rs:20-27`) is `{ shard, memory: Vec<u8>, free: Vec<u32>, taken
  (debug) }`: one `Vec<u8>` of `count × BUF_SIZE`, LIFO free stack, no refcount, no `unsafe`.
  `take` `:57`, `put` `:71` (debug asserts owner and double free; hard `assert!` on stack
  overflow), `buf` `:85`, `buf_mut` `:91`, `pair_mut` `:98` (safe `split_at_mut`).
  `BufRef { shard, index }` (`:11-17`) says "Phase 2 adds the owner-local refcount".
- The deleted `src/worker/spsc.rs` (last at `372cbcd^`, 481 lines) was `SpscChannel<N>` over
  `UnsafeCell<[Option<PacketSlot>; N]>`, head/tail `AtomicU32` without padding or cached
  indices, not generic, 8 single-thread tests: no proptest, no loom, no stress test. Not used
  (owner's decision).
- `crossbeam-queue = "0.3"` is already a `nexus-dataplane` dependency (`Cargo.toml`), used for
  the command `ArrayQueue` (`shard/mod.rs:38`, capacity 4,096). Its push/pop pair gives the
  Release/Acquire ordering the safety argument needs (owner write → peer read; peer read →
  owner reuse, through the return ring).
- `#![deny(unsafe_code)]` is at `lib.rs:16`; the only `#[allow(unsafe_code)]` is
  `shard/io.rs:19` (`mod linux`).
- `lib.rs` `sizes::{SESSION, PUBLISHED_TRACK, SUBSCRIPTION}` (`:63-70`) feed the memory
  bench; 2.1 does not change them (2.2 does).
- `TrackId` is a monotonic `u64` from the orchestrator's counter, never 0 and never reused
  (`src/orchestrator/ids.rs:40`, `bump` `:48-53`), so a late message naming a removed track
  can never be taken for a new one.

**Tests:**
- Unit: `can_lend` false at `XS_CREDIT`; `unlend` restores `refs` and `in_flight`;
  `release` frees at 0 and not before; `put` of a lent buffer panics; return of a handle from
  the wrong peer is caught (`debug_assert`); `pair_mut` of two buffers while a third is lent
  and read elsewhere (the stress test covers the concurrent case).
- `XsMsg` size (≤ 24 B) and `Copy`; `XsMesh` wiring for n = 1..4 (no self rings).
- `tests/pool_handoff.rs`: owner thread writes a canary (buffer index, generation) and lends;
  2-3 reader threads check the canary, return; the owner reuses only returned buffers. 10⁶
  hand-offs, no mismatch, pools full at the end.
- **Miri** on a reduced hand-off test (two threads, ≈ 100 hand-offs, `cfg(miri)` sizes):
  `cargo +nightly miri test -p nexus-dataplane --test pool_handoff`. Local only; the command
  and result go in the session log.

**Checkpoint:** `cargo test -p nexus-dataplane` green; Miri clean; Linux container run.

---

### 2.2 Shard: remote fan-out, mirror tracks, cross-shard RTCP

**Goal:** a shard that forwards to subscribers on other shards and serves subscriptions to
tracks published elsewhere, driven entirely through `MemIo` with several shards iterated on
one thread.

**Files:** `crates/nexus-dataplane/src/{command.rs, track.rs, subscription.rs, lib.rs
(sizes), shard/{mod.rs, ingress.rs, commands.rs, rtcp.rs, runner.rs, stats.rs, xs.rs
(new)}}`, `tests/{support/mod.rs, shard.rs, alloc.rs}`, `benches/memory.rs` (new
structure sizes reported; budget re-checked).

**Change:**
- **Commands** (to the publisher's shard): `AddRemoteShard { track, shard }` and
  `RemoveRemoteShard { track, shard }`. `PublishedTrack` gains `remote_shards: ShardMask`
  (`u64`). Unknown track → `CommandRejected{UnknownTrack}`, which the orchestrator ignores
  like a late `Unsubscribe` (the track may have gone first).
- **Mirror tracks** on the subscriber's shard. `Subscribe` with `source.shard != self`:
  - finds or creates a `MirrorTrack { id, source: ShardId, subscribers: Vec<SubIdx>,
    clock_rate, pub_mid, cname }` in its own slab and `mirror_ids: FxHashMap<TrackId, _>`;
  - `SubSpec` carries what `Subscribe` reads from the local track today (`pub_mid`,
    `clock_rate`, `commands.rs:247-248`) and the cname the SDES of a translated SR needs, so
    a mirror needs no command of its own;
  - `Subscription.track` becomes a two-way reference (local `TrackIdx` or `MirrorIdx`);
  - the mirror is freed with its last subscription (`Unsubscribe`, subscriber `CloseSession`)
    or by `RemoveTrack { track }` sent to this shard (removes it and its subscriptions, as on
    the publisher's shard).
  - A `Subscribe` whose source says this shard but whose track is unknown keeps
    `UnknownTrack`; `WrongShard` is kept for `source.track != track`.
- **Ingress (publisher's shard):** `handle_rtp` → local `fan_out` (`ingress.rs:360-374`)
  → for each shard in `remote_shards`: **check first, then lend and push**:
  `can_lend(peer) && !ring.is_full()` (the owner is the ring's only producer, so room seen
  now is still there at the push), then `lend` and `push`. A push that still fails
  (`debug_assert!`, never expected) is undone with `unlend`, so `refs` and `in_flight` never
  leak. No credit → `drop_xs_credit`; full ring → `drop_xs_full`. `iterate` no longer puts
  every ingress buffer right after `handle_datagram` (`mod.rs:189-193`); it calls
  `put_if_unshared`.
- **Returns first:** `iterate` drains every peer's return ring (`release`) at the **top**,
  before `recv_batch`, so credit freed by peers is available to this iteration's ingress
  (draining it after ingress would count spurious `drop_xs_credit`). Bounded by `XS_CREDIT`
  per peer.
- **`drain_cross_shard(now)`**, between the command drain and the second flush
  (`mod.rs:199-201`, so its output leaves in that flush), ≤ `XS_BUDGET` messages per peer:
  - `Rtp` → mirror by `TrackId` → re-parse `RtpHeader` from the peer's slice once per message
    (a failure is a bug on the sender's side: `debug_assert!` plus a counter, handle
    returned) → for each subscriber: `flush_if_full()` then `forward` (as `fan_out` does,
    `ingress.rs:370`), with `forward` taking a source slice instead of a local `BufRef` →
    return the handle. No mirror → `drop_xs_no_track`, handle returned.
  - **Borrows:** `forward` needs `&mut self` while reading a peer's region. The peer regions
    live in a field that `forward` does not touch and are borrowed apart (split borrows), or
    the ports are moved out of `self` for the drain and put back; no `Arc` clone per message.
  - `SenderReport` → translate for the mirror's subscriptions. `KeyframeRequest` →
    `request_keyframe` on the local track (subject to the ordering rule below).
  - `debug_assert!(layer < MAX_LAYERS)` on every received message (`MAX_LAYERS = 1`; no
    simulcast yet).
  - `IterationStats` gains messages and returns handled, so the runner does not count such an
    iteration as idle.
- **Parking and waking:** the runner's `pending` closure (`runner.rs:77`, today command queue
  and `stop` only) also checks every inbound media and return ring. A producer pushes, then
  calls the peer's `Wake::wake()` (a no-op unless the peer is parked; `park.rs:89-94`), so a
  busy peer costs nothing. For returns: after a drain that pushed at least one return to peer
  j, call `wake(j)` once (per drain, not per handle). A shard cannot know how much credit a
  peer has left (`in_flight` is owner-local), so it does not try.
- **SR:** `translate_sr` (`shard/rtcp.rs:101-146`) keeps the local translation and pushes
  `SenderReport` to each remote shard; the remote shard builds SR + SDES per subscription with
  its own `ts_offset`, counters and `srtp_out` (the same builder).
- **Keyframes:** `keyframe_wanted` (`rtcp.rs:149-160`), `Subscribe` and `InstallSrtp`
  (`commands.rs:137-140`, `:257-259`) on a subscription to a mirror push
  `KeyframeRequest { from: self }` to the source shard; `request_keyframe`
  (`rtcp.rs:165-201`) and its 500 ms throttle stay on the publisher's shard.
  **Ordering refinement** (commands to different shards are unordered, note §5.3): the
  publisher's shard ignores a `KeyframeRequest` from a shard not in `remote_shards`, and
  `AddRemoteShard` itself requests a keyframe. Otherwise a request that arrives before
  `AddRemoteShard` produces a keyframe the new shard never receives, and the throttle
  suppresses the next request.
- **Counters:** `xs_tx`, `xs_rx`, `xs_returned`, `drop_xs_full`, `drop_xs_credit`,
  `drop_xs_no_track`; gauges `mirrors`, `xs_in_flight` (sum over peers). They reach
  Prometheus through `ShardCounters::NAMES` with no exporter change.

**Code notes (audited 2026-09-29):**
- `Shard::iterate` (`shard/mod.rs:176-214`): recv → `handle_datagram` + `pool.put` →
  `apply_pending_switches` → flush → `drain_commands` (64) → flush → `push_pending` →
  housekeeping. `IterationStats { received, taken, would_block, commands }` (`:57-68`);
  `commands_pending()` (`:242-244`).
- `ShardThread::run` (`runner.rs:43-83`) treats `taken > 0 || commands > 0` as work (`:63`);
  `pending` at `:77`.
- `PublishedTrack` (`track.rs:23-36`) has no `remote_shards`, although note §7.1 lists it.
  `Subscription` (`subscription.rs:50-73`) holds `track: TrackIdx`, `pub_mid`, `clock_rate`.
- `Subscribe` (`commands.rs:203-261`) looks the track up locally **before** the source
  check, so a remote source gets `UnknownTrack` today, not `WrongShard` (`:212-222`).
  `WrongShard` (`command.rs:262-263`) is never tested.
- `request_keyframe` needs the publisher session's `srtp_out`, address and `out_ssrc_base`:
  it can only run on the publisher's shard.
- `Command` must stay ≤ 72 bytes (`command_stays_small`, `command.rs:295-300`); the new
  commands are small, `SubSpec` stays boxed.
- **Sizes change:** `PublishedTrack` grows by 8 B (`remote_shards`), `Subscription.track`
  becomes a two-way reference, and `MirrorTrack` is new. `lib.rs` `sizes` (`:63-70`) and
  `benches/memory.rs` report them; the 25 KB budget is re-checked (a subscriber's share of
  a mirror is at most one mirror per subscribed remote track).
- `request_keyframe` (`rtcp.rs:165-201`) sends nothing and does not arm the throttle while
  the publisher's layer SSRC is unknown (`:168-177`): tests of the throttle across shards
  must let the publisher's SSRC be learned (one RTP packet) first.
- Gauges and counters are published by housekeeping, once a second, and a parked shard wakes
  for it at most once a second: tests that wait for a gauge or `xs_in_flight` to return to 0
  poll for more than 2 s.
- `tests/support/mod.rs`: `shard(now)` (`:30`) builds with the default `ShardId(0)` and
  `sub_spec` (`:345-357`) hard-codes `source.shard = 0` (`:352`); `run` (`:40`) drains one
  shard. `MemIo` (`shard/io.rs:204-260`) is per shard, so several can run on one thread.

**Tests** (`tests/shard.rs`, 2-3 shards on `MemIo`, one thread, a `run_all` that iterates
every shard until all are drained):
- Publisher on A, subscribers on A and B: both get identical payloads with their own SSRC,
  seq and PT; A's pool is full again after the drain; `xs_tx == xs_rx == xs_returned`.
- Subscribers on B and C only: one hand-off per shard, not per subscriber.
- SR on A → translated SR + SDES on B with B's `ts_offset` and counters; after the
  publisher's SSRC is learned, PLI from B's subscriber → one PLI to A's publisher; five PLIs
  from B and C within 100 ms → one.
- Lend/push: a full ring with credit left, and credit exhausted with ring room: each drops
  with its counter and leaves `refs`/`in_flight` unchanged.
- Returns at the top of `iterate`: a burst that uses all credit, returned by the peer, is
  forwarded in the next iteration without `drop_xs_credit`.
- Unordered commands: `Subscribe` on B before `AddRemoteShard` on A (media dropped until
  then, keyframe after), and the reverse (A sends, B has no mirror: `drop_xs_no_track`,
  buffer returned); `KeyframeRequest` before `AddRemoteShard` ignored.
- `RemoveTrack` on A, then on B; `CloseSession` of the publisher; `CloseSession` of the
  subscriber while messages are in flight; mirror freed with its last subscription.
- Full ring and exhausted credit: drops counted, never blocking, recovery afterwards.
- `tests/alloc.rs`: a 2-shard case (publisher on A, 5 subscribers on A and 5 on B, SRs and
  PLIs across), 0 allocations, output = 10 × input.
- **Proptest** (3 shards): random subscriber/publisher operations turned into commands by a
  small model of the orchestrator's counting rule (2.4), random delivery order across shards
  (commands to different shards unordered, same shard in order), media and RTCP, and random
  shard iteration order. No panic; at quiescence every pool is full, every `in_flight` is 0,
  and the shards match the model (test-only accessors for `remote_shards` and mirrors).

**Checkpoint:** `cargo test -p nexus-dataplane` green, alloc test at 0; the rest of the
workspace green; Linux container run.

---

### 2.3 N shards on threads

**Goal:** `Dataplane::start` runs N shard threads connected by the mesh, and the config
accepts `shards > 1`.

**Files:** `crates/nexus-dataplane/src/{handle.rs, config.rs, sched.rs, shard/runner.rs}`,
`tests/loopback.rs`, `src/config/{dataplane.rs, tests.rs}`, `config/*.toml` (comments).

**Change:**
- **Two-phase start:** bind every socket, build every `Shard` and `Parker`, build the
  `XsMesh` and give each shard its ports and its peers' `Wake`s, then spawn. Today
  `Dataplane::start` (`handle.rs:176-198`) calls `spawn_shard` (`handle.rs:226-271`), which
  builds and spawns one shard at a time.
- **Limit:** `MAX_SHARDS_PHASE_1` (`config.rs:134`, checked at `:157` with "shards must be 1
  in Phase 1") goes; `shards` is checked against `ids::MAX_SHARDS` (64) and the port range
  (`:160-173`, already N-aware).
- **Pool size:** validated ≥ `RECV_BATCH + SEND_BATCH + (shards − 1) × XS_CREDIT`, so lent
  buffers can never starve a receive batch; the default follows the shard count (≈ 2 MB per
  shard at 1 shard, ≈ 8 MB at 4 with the starting constants). 2.6 revisits the constants.
- **Pinning:** shard i stays on `core_affinity::get_core_ids()[i]` (`sched.rs:7-25`); the
  warning at `config.rs:137-149` ("shard 0 on core 0") is reworded for N shards, and the
  config docs say which cores the shards take.
- `src/config/dataplane.rs:17` doc and the TOML comments (`shards = 1 # Must be 1 in Phase
  1`) updated; defaults stay `shards = 1` everywhere until 2.7 decides production's value.

**Code notes (audited 2026-09-29):**
- `Dataplane::start` already creates one event channel for every shard (`handle.rs:180`),
  binds `port + index` (`:233-236`, ephemeral per shard when the port is 0), and returns
  `Vec<ShardInfo>`; `DataplaneHandle::send(shard, cmd)` (`:285-295`), `stats(shard)`,
  `loads()` (`:309-317`) and `shutdown()` (`:326-344`) are per shard already.
- `src/config/dataplane.rs` already splits `max_webrtc_sessions` with `div_ceil(shards)`
  (`:67-70`) and passes the reserved ports (`:99-110`).
- Tests that assume one shard: `config.rs:260-263` (`shards: 2` refused),
  `src/config/tests.rs:136-138, 436-437`.
- Shutdown: a shard that stops while peers still hold its buffers is fine (the region is an
  `Arc`); messages still in rings at shutdown are dropped with the process.

**Tests:**
- `tests/loopback.rs`: 2 shards, publisher on shard 0 and subscriber on shard 1 through real
  sockets (media, SR, PLI across); 4 shards all parked, a message to a parked peer is handled
  within 10 ms (wake works); shutdown joins every shard within 100 ms.
- Config: `shards = 2..4` accepted, `shards = 65` refused, the range overlapping a reserved
  port refused, pool below the minimum refused.

**Checkpoint:** workspace green, Linux container run (threads, pinning, `LinuxIo`).

---

### 2.4 Control plane: placement and cross-shard subscriptions

**Goal:** the orchestrator places sessions on shards by room and keeps the publisher's shard
told which shards need each track.

**Files:** `crates/nexus-dataplane/src/placement.rs`, `src/orchestrator/{plane.rs,
negotiation.rs, subscription.rs, mod.rs, tracks.rs}`, `src/server.rs`,
`src/config/{dataplane.rs, tests.rs}`, `src/orchestrator/orchestrator_tests.rs`.

**Change:**
- **`RoomAffine`** (note §13.2). State, all counted by placement itself (`place` +1,
  `session_closed` −1), never read back from the 1 s stats:
  - `(room, shard) → sessions` and, per room, its **current shard**; `shard → sessions`
    (total placed).
  - `place(room)`: the room's current shard if it has fewer than `room_shard_max_sessions`
    of this room's sessions, is under the shard's `max_sessions`
    (`ceil(max_webrtc_sessions / shards)`, `src/config/dataplane.rs:67-85`) and under
    `room_shard_max_pps` (`ShardLoad::rx_pps`, the only stats input). Otherwise the
    least-loaded shard (placed sessions, then `rx_pps`) that is under its `max_sessions`
    becomes the room's current shard. A new room goes to the least-loaded shard. A shard at
    its `max_sessions` is never chosen; if all are, placement returns the least-loaded one
    and the shard's own limit refuses the session (`CommandRejected`, as today).
  - Earlier participants stay where they are; there is no migration.
  - Entries are removed at 0, so the maps are bounded by live sessions, not by `MAX_ROOMS`.
  - `REST DELETE /rooms/:id` touches no sessions and no placement state (sessions leave
    through their own cleanup).
  - Config: `dataplane.room_shard_max_sessions` (starting default **50**, so a large room
    spreads its fan-out over cores; with ≈ 2,500 per shard, a default tied to
    `max_sessions` would mean rooms never spill; tuned in 2.6) and
    `dataplane.room_shard_max_pps` (0 = off until 2.6 measures a value).
  - `server.rs:195` builds `RoomAffine` instead of `SingleShard`; `SingleShard` stays for
    tests.
- **Count leak on a failed create:** `Plane::create_session` returns `None` after `place`
  without `session_closed` when the transport table insert or the `CreateSession` push fails
  (`plane.rs:175-189`). Every failure path after `place` calls `session_closed`.
- **Per-(track, shard) subscription counts** in the orchestrator (in `TrackRegistry` next
  to `TrackInfo.shard`). **Counted on the slot's state change, not on push success:**
  - +1 when a slot becomes an on-shard subscription (`register_subscriptions`,
    `negotiation.rs:616-684`, push at `:664-671`); the first on a shard other than the
    track's → `AddRemoteShard` to the track's shard.
  - −1 when an on-shard slot leaves that state: `drop_subscriptions_except`
    (`:781-810`) marks the slot `Inactive` before pushing `Unsubscribe` and ignores a failed
    push (`:803-805`), so the count follows the slot, and the `Unsubscribe` goes through the
    retry list below.
  - −1 for each on-shard slot of a **subscriber that leaves**: `Plane::close_session` does
    not know the m-lines, and `NegotiationManager::cleanup_participant` removes the
    `NegotiationState` before calling it (`negotiation.rs:978`, `:991`). The decrement is
    done there, from the removed state's on-shard slots, before `close_session`. No
    `Unsubscribe` is needed: `CloseSession` removes the subscriptions (and so the mirror's
    last subscriber) on the subscriber's shard.
  - The last one on a shard → `RemoveRemoteShard` to the track's shard.
- **Track removal reaches every shard** (gap found in the audit): `handle_unpublish`
  (`mod.rs:324-367`) sends `RemoveTrack` to the publisher's shard only, and
  `forget_tracks` (`negotiation.rs:864`, `subscription.rs:190-207`) then marks the
  subscribers' m-lines inactive **without** `Unsubscribe`. With one shard that is correct
  (`RemoveTrack` drops the subscriptions); with mirrors it would leave them on the other
  shards. Fix: `RemoveTrack` is also sent to every shard with a count for the track, and the
  counts are cleared; the same for a publisher's `CloseSession` (its tracks,
  `negotiation.rs:972-994`).
- **Full queues: additive commands close, cleanup commands retry.** `Plane::push`
  (`plane.rs:157-166`) closes the participant and drops the command. That is right for
  additive commands (`CreateSession`, `AddTrack`, `Subscribe`, `AddRemoteShard`): the
  participant is torn down and nothing was added. For cleanup commands it leaks state on
  another shard (a mirror, a `remote_shards` bit, a subscription). So `Unsubscribe`,
  `RemoveRemoteShard` and `RemoveTrack` go through `Plane::push_cleanup`: on a full queue
  they join a bounded retry list, generalising `pending_close` (`plane.rs:204-229`, retried
  by the 1 s sweep), and never close the participant.
  - **Cancel instead of racing:** when a (track, shard) count goes 0 → 1 while a
    `RemoveRemoteShard` for that pair is still in the retry list, the pending remove is
    dropped and no `AddRemoteShard` is sent (the shard never lost the bit). Otherwise the
    retried remove could arrive after the new add and cut the new subscriber off.
  - `RemoveTrack` needs no such rule (track ids are never reused), nor does `Unsubscribe`
    (subscription ids are never reused).
  - A full retry list logs an error and leaks, as `pending_close` does today.
- A rejected `AddRemoteShard`/`RemoveRemoteShard`/`RemoveTrack` for an unknown track is
  ignored (race with removal). `WrongShard` stays an internal error
  (`connection.rs:132-139`).
- `ServerHandle::candidate_addrs` (shard 0's, `server.rs:69-72, 219`) is documented as
  such or becomes per shard for the tests.

**Code notes (audited 2026-09-29):**
- `place` is called once, in `Plane::create_session(participant, room)` (`plane.rs:171-176`,
  after `dataplane.loads()`), from `NegotiationManager::ensure_session`
  (`negotiation.rs:170-193`) with the participant's room. Publish and subscribe are refused
  without a room and a second `Join` is refused, so the room is known and fixed for the
  session's life. `session_closed` is called in `Plane::close_session` (`plane.rs:200`) with
  the same room.
- Commands are already routed per session (`TransportEntry.shard`, `transports.rs:174`),
  candidates are trickled from the session's shard (`negotiation.rs:1129-1154`), and
  `TrackInfo.shard` (`tracks.rs:24`) is the publisher's shard; `Subscribe` already carries
  `TrackRef { shard: info.shard, track }` (`negotiation.rs:652-655`).
- `SubscriptionManager` keeps only participant → tracks (`subscription.rs:33-35`): no shard,
  no counts.
- `FakeSink` in `orchestrator_tests.rs:1417-1439` and `QueueSink` in `benches/memory.rs:290-306`
  hard-code one shard, and `FakeSink::send` ignores `_shard` (`:1425`): it must record
  `(shard, command)` and support a full queue per shard.

**Tests** (`orchestrator_tests.rs`, `FakeSink` with N shards, recorded `(shard, command)`):
- `RoomAffine` unit tests: a room stays on one shard up to `room_shard_max_sessions`, then
  moves its current shard to the least-loaded; earlier participants stay; a new room goes to
  the least-loaded shard; a shard at `max_sessions` is skipped; a mass join of 100 in one
  tick spreads by placement's own counts; entries freed at 0; a failed `create_session`
  releases its placement.
- Cross-shard subscribe → `Subscribe` to B with a remote source and one `AddRemoteShard` to
  A; a second subscriber on B → no second `AddRemoteShard`; both unsubscribe →
  one `RemoveRemoteShard`.
- Unpublish and publisher leave → `RemoveTrack` to A and to every counted shard; subscriber
  leave → `RemoveRemoteShard` when it was the last on its shard.
- Full queue: a cleanup command waits in the retry list and is sent by the sweep, the
  participant is not closed; an additive command still closes it. Remove pending, then a new
  subscriber on the same shard → the pending remove is cancelled and no add is sent.
- Randomised sequence (subscribe, unsubscribe, unpublish, leave, full queues on/off): the
  recorded stream per (track, shard) is balanced: adds and removes alternate, and at the end
  every pair with a count has had one more add than remove.
- A scripted `Placement` for the exact-shard cases.

**Checkpoint:** workspace green; e2e green with `shards = 1` (placement is a no-op there).

---

### 2.5 E2E on several shards

**Goal:** exit criterion 1 with real webrtc-rs clients.

**Files:** `tests/e2e.rs`, `tests/e2e/harness.rs`.

**Change:**
- `test_config_shards(n)`; `start_server` no longer asserts one shard (`harness.rs:65`).
  Stats read through a helper that sums over shards (`e2e.rs:115`, `shard_stats` `:724-725`,
  `settled_shard_stats` `:647`); `ten_clients_audio_video`'s `sessions == TEN` (`:486`)
  becomes a sum.
- Participants are spread by real placement: `room_shard_max_sessions = 1` (or 2) in the
  test config, so a room's participants land on different shards. No test-only placement
  hook in the server.
- The four new tests of exit criterion 1, each asserting that the participants it needs
  apart really are on different shards (per-shard `sessions` gauges).
- The existing suite runs with `shards = 1` as today; `two_party_audio_video`,
  `sender_report_translation` and `keyframe_requests` also run with `shards = 2` and spread
  placement (shared bodies, two test functions).
- Candidates: each client already receives its own shard's candidates (signaling), so
  `candidate_is_announced_address` checks the port of the shard its session is on.

**Code notes (audited 2026-09-29):** `test_config` (`harness.rs:47-61`) binds media on
`0.0.0.0:0` (one ephemeral port per shard), API off, `shards = 1`. The 9 tests:
`two_party_audio_video`, `candidate_is_announced_address`,
`room_claim_confines_create_and_join`, `dtls_survives_lost_first_flight`,
`ten_clients_audio_video`, `resubscribe_no_srtp_index_reuse`, `address_change_mid_call`,
`sender_report_translation`, `keyframe_requests` (≈ 50 s).

**Checkpoint:** `cargo test --test e2e` green on macOS and in the Linux container; suite time
recorded (target: under 90 s).

---

### 2.6 `benches/dataplane.rs` and measurements

**Goal:** exit criteria 2, 3 and 5 measured on the VM; latency reported; `busy_poll_rounds`
and the cross-shard constants tuned.

**Files:** `benches/dataplane.rs` (new), `benches/common/mod.rs`, root `Cargo.toml`
(`[[bench]] name = "dataplane" harness = false`), `.github/workflows/ci.yml` (bench-smoke),
`scripts/ci-local.sh` (`run_linux`), `config/production.toml`, `architecture.md` Part 5.

**Change:**
- **Rig:** `Dataplane::start` with 1, 2 and 4 shards on real loopback sockets, shards on
  their own threads (unlike `real_path`, which calls `iterate` on the bench thread).
  Sessions set up as in `tests/loopback.rs` (STUN nomination, synthetic keys via
  `tests/support`).
- **Generators encrypt on the fly.** Replaying pre-encrypted packets cannot work: the
  shard's inbound SRTP replay protection drops every repeat. Each generator thread owns its
  publishers' `SrtpOutbound` contexts (not `Peer::protect_rtp`, which allocates), writes each
  packet with a fresh sequence number into a fixed buffer, protects it in place and sends
  with `sendmmsg`, paced to a target rate (saturation runs: unpaced).
- **Sinks** (`benches/common`): `recvmmsg` into fixed arrays on Linux (from `udp_floor`),
  with a thread count scaled to the expected rate (4 shards ≈ 2-3 M datagrams/s; today's 4
  drain threads call `recv` per datagram, `common/mod.rs:74-95`, and would be the
  bottleneck); `recv` stays for macOS smoke runs.
- **Scenarios**, AES-GCM, 1,200-byte video, 10 subscribers per published packet:
  - *local*: every room fits on one shard (no cross-shard traffic), N rooms per shard
    (exit criteria 2 and 3);
  - *cross*: every publisher's subscribers are spread over all shards, the worst case for
    D3 (exit criterion 3);
  - an AES-CM row for reference.
- **Throughput:** subscriber-packets/s per shard at saturation (from `ShardStats`
  `tx_datagrams` over a timed window), and the 1 → 2 → 4 scaling ratio. Drop counters and
  sink delivery are checked: a run with drops or < 99% delivery is marked invalid (as in
  `real_path`), and so is one where a sink or generator thread was saturated (its busy
  fraction is reported).
- **Allocations:** the counting allocator's gate in `real_path` is thread-local
  (`real_path.rs:76-117`), so allocations on shard threads (and generators) would not be
  counted. `dataplane.rs` counts **process-wide** during the steady-state window; generators
  and sinks are allocation-free by construction, so any allocation in the window is charged
  to the SFU (conservative). `tests/alloc.rs` stays the gate (exit criterion 4).
- **Latency, inside the SFU** (design §2), measured with a cargo feature `latency-probe` on
  `nexus-dataplane`, off by default:
  - with the feature, after the iteration's last flush the shard reads the clock once more
    and records `flush return − the iteration's now` into a fixed log₂-bucket histogram
    (weighted by the datagrams sent in that flush), published with the stats. The default
    build keeps one clock read per iteration;
  - the iteration's `now` is read before `recv_batch`, so the figure is an upper bound on
    "receive to `sendmmsg` return" for datagrams received in that iteration;
  - cross-shard packets also wait in a ring: with the feature, `XsMsg::Rtp` carries the
    origin iteration's `now` (the ≤ 24-byte assert applies to the default build only) and the
    receiving shard records `flush return − origin now` in a second histogram;
  - load: **250,000 subscriber-packets/s per shard, 50% of the design target**, not of the
    measured saturation; p50 and p99 reported for 1, 2 and 4 shards, local and cross.
- **Tuning:** `busy_poll_rounds` (0, 64, 256, 1,024: throughput, latency and idle CPU; note
  §3.3), media ring / `XS_CREDIT` / `XS_BUDGET`, `room_shard_max_sessions` /
  `room_shard_max_pps` (2.4); the chosen values go in `config/production.toml` and the
  constants.
- **CI:** a smoke run (short duration, 1 and 2 shards, without `latency-probe`) in
  `bench-smoke` and in `ci-local.sh run_linux`; it checks that the bench works, it does not
  gate on numbers (`ci.yml:95-97`, design §6). Timed runs on the ≈ 10 vCPU VM, each point
  repeated (median of 3), `udp_floor` in the same session (only ratios within one session
  are meaningful, architecture.md 5.1).
- If the `ArrayQueue` hand-off shows up as a measurable share of the cross-shard cost,
  replacing it with an SPSC ring is proposed here (owner's decision above).
- **Memory:** `benches/memory.rs` stays single-shard and per-participant (with 2.2's sizes);
  the dataplane bench also prints the fixed memory of 4 shards (pools, rings, batches).

**Code notes (audited 2026-09-29):**
- `benches/real_path.rs` (`:210-227` `loopback_shard`, `BenchIo` `:164-203`, counting
  allocator `:72-119`, `report`/`report_delivery` `:303-320`, `:492-511`) and
  `benches/common/mod.rs` (`Sinks`, 4 busy-spinning drain threads, `raise_fd_limit`) are the
  starting points; `tests/support` is included by `#[path]` (`real_path.rs:48-49`).
- Phase 1 measured (Linux arm64 VM, one bench thread, ingress injected): GCM video egress
  0.94-1.30 µs per subscriber, `sendmmsg` floor 0.51-0.82 µs; 500K/s per shard needs ≤ 2 µs
  per subscriber-packet including ingress (design §2).
- No latency code exists on the new path (`src/tracing.rs` `HotPathMetrics` and
  `nexus-metrics` `tracing_metrics.rs` are unused), and sinks only count datagrams; a
  timestamp in the payload cannot be read at the sinks anyway (each subscriber's copy is
  encrypted with its own key). Hence the in-shard probe.
- Core budget: 4 shards + 1-2 generators + 2-4 sink threads ≈ 8-10 runnable threads; the default
  6-vCPU VM cannot measure the 4-shard point, hence the ≈ 10 vCPU VM (owner's decision).
  `ci-local.sh` passes no `--cpus` (`:150-165`), so the container gets the whole VM.

**Checkpoint:** numbers recorded in architecture.md Part 5 and this plan; exit criteria 2 and
3 met, or a design revision with the measurements proposed to the owner.

---

### 2.7 Deploy, documents, browser check, merge

**Files:** `deploy/docker/{run.sh, Dockerfile}`, `config/*.toml`, `README.md`, `CLAUDE.md`,
`architecture.md`, `docs/dataplane-design.md` (revision log), `docs/design/dataplane-v1.md`
(a note pointing to the corrections below), this plan.

**Change:**
- **Docker:** `run.sh` publishes the range `MEDIA_PORT … MEDIA_PORT+SHARDS−1/udp` (today one
  port, `run.sh:26, 88`; the `MEDIA_PORT == 10000` rule with announced IPs, `:39-45`,
  becomes "host range = container range") and passes `NEXUS_SHARDS`; `Dockerfile:85-88`
  `EXPOSE` the default range.
- **Config:** `production.toml` shard count and `busy_poll_rounds` from 2.6 (the owner
  decides the shipped default); comments in every TOML.
- **Documents:** CLAUDE.md's e2e line says 8 tests; there are 9 today (and more after 2.5).
  README (one-shard statements at l.18, 33, 38, 218; `media_bind_addr` and
  `shards` at l.114-119; Docker port at l.185), CLAUDE.md (status, "Architecture (today)",
  `[dataplane]`, ports table as a range), `architecture.md` Parts 1-3 and 5 (process
  layout with N shards, the cross-shard path, numbers).
- **Design revision** entry (no D/R change expected): rings on `ArrayQueue`, stress + Miri
  instead of loom, the credit bound, mirror-track metadata in `SubSpec`, the keyframe
  ordering rule, placement counting its own sessions, the VM measurement and any target
  revision from 2.6.
- **Browser check** (owner): Chrome and Firefox, `shards = 2`, two participants forced onto
  different shards (`room_shard_max_sessions = 1`): media both ways, late joiner shows video
  (cross-shard PLI), unpublish/republish, leave/rejoin; versions and cipher recorded here.
- `scripts/ci-local.sh all` on the commit to merge, summary in the session log; merge
  `phase-2` into `main`; CLAUDE.md names Phase 3 as current, its plan not written yet.

**Checkpoint:** every exit criterion checked off in the Status table; merged.

---

## Corrections to the design note

Facts in `docs/design/dataplane-v1.md` the audit or the owner's decisions changed. None
changes a decision (D1-D10, R1-R9).

| Note | Says | Plan |
|------|------|------|
| §7.1 | `PublishedTrack::remote_shards: ShardMask`, "always empty in Phase 1" | Not in the code (`track.rs:23-36`); added in 2.2 |
| §13.4 | SPSC ring from `src/worker/spsc.rs` | `ArrayQueue` per ordered pair (owner); `spsc.rs` was not generic, unpadded, single-thread tested only |
| §13.4 item 6 | `loom` model of one pair | Multi-thread stress test + Miri (owner); `loom` is not in the lock file |
| §13.4 item 7 | Return ring capacity = media capacity + `XS_BUDGET`, so it cannot fill | Does not bound what is outstanding (the owner can keep lending while returns wait). A per-peer credit (`in_flight[j] < XS_CREDIT`) bounds it; return capacity = `XS_CREDIT` |
| §13.4 | `Subscribe{source: TrackRef}` is all the subscriber's shard needs | It also needs the track's clock rate, publisher `mid` id and cname (read from the local track today, `commands.rs:247-248`); carried in `SubSpec`, kept in a mirror track |
| §12.3, §13.4 | Subscriber's shard sends `KeyframeRequest`; commands unordered is safe | A request that arrives before `AddRemoteShard` yields a keyframe the new shard never gets, and the throttle suppresses the next. `AddRemoteShard` requests a keyframe; requests from shards not in `remote_shards` are ignored |
| §13.2 | `RoomAffine` decides from `ShardLoad` (stats) | Stats are published once a second; placement counts its own sessions and uses stats only for `rx_pps` |
| §6.5 / §13.4 | Track removal: `RemoveTrack` to the publisher's shard | With mirrors, `RemoveTrack` also goes to every shard with subscriptions to the track: the orchestrator marks subscriber m-lines inactive without `Unsubscribe` (`forget_tracks`) |
| §2 targets | Linux arm64 and x86_64 | Linux arm64 in the ≈ 10 vCPU VM (owner); x86_64 at release |
| §2 latency | "Timestamp at receive vs `sendmmsg` return" | Receive time = the iteration's `now`, read before `recvmmsg` (an upper bound), recorded at the flush's return by the off-by-default `latency-probe` feature; cross-shard packets carry their origin iteration's `now`. No per-datagram receive timestamp (`SO_TIMESTAMP`) |
| §6.4 / §13.4 | A full command queue fails the orchestrator operation (note §5.3) | Right for additive commands; cleanup commands (`Unsubscribe`, `RemoveRemoteShard`, `RemoveTrack` to other shards) are retried by the sweep instead, or state on another shard leaks (2.4) |
| §10.3 | Pool buffers are only touched by their shard | Peers read lent buffers, so the owner forms per-buffer references only, never one over the whole region (2.1) |

## Risks for this phase

| Risk | Mitigation |
|------|------------|
| The VM (≈ 10 vCPU, shared with macOS) is noisy and small for 4 shards plus load generators | Ratios within one session only; `udp_floor` in the same session; median of 3 runs; if the 4-shard point is load-generator bound, say so and report 1→2→3 as well |
| The harness, not the SFU, is the limit: 4 shards ≈ 2-3 M datagrams/s into the sinks, plus on-the-fly encryption in the generators | Sinks on `recvmmsg` with a scaled thread count; generator and sink busy fractions reported, and a saturated one marks the run invalid |
| M2 Pro efficiency cores: VM vCPUs are scheduled by macOS onto P- or E-cores, so a shard can run at a different speed from run to run | Repeat runs and report the spread; compare shard counts within one session; state the host's P/E split with the numbers; real hardware at release |
| x86_64 not measured | Owner's decision: release item |
| `ArrayQueue` (MPMC) costs more than an SPSC ring | One hand-off per (packet, shard), not per subscriber: small next to 10 encrypts; 2.6 measures it and a custom ring is proposed only if it matters |
| The shared region's `unsafe` is wrong in a way the stress test misses | Ownership rule enforced by `refs`/`in_flight` asserts in debug; Miri on the hand-off; one module only |
| Accounting bugs between orchestrator counts and shard state leak mirrors, subscriptions or buffers | Proptest with leak checks (2.2), orchestrator command tests (2.4), e2e gauges back to 0 (2.5) |
| Lent buffers starve a shard's receive batch | Pool size validated against `(shards − 1) × XS_CREDIT` (2.3); `drop_pool_empty` counted |
| A hot room (one publisher, many viewers) keeps all decrypts on one shard | Accepted by design §7 |
| Port range awkward behind Docker/Kubernetes/firewalls | Documented range (2.7); single-port mode stays after v1 (design §7) |
| Miri needs nightly and may not support every crate used by the test | The hand-off test uses only `pool.rs` and `ArrayQueue`; run locally, recorded in the session log |

## Status

| Part | State | Commits | Notes |
|------|-------|---------|-------|
| 2.1 Shared pool region, `XsMsg`, mesh | Not started | | |
| 2.2 Shard: remote fan-out, mirrors, cross-shard RTCP | Not started | | |
| 2.3 N shards on threads | Not started | | |
| 2.4 Control plane: placement, cross-shard subscriptions | Not started | | |
| 2.5 E2E on several shards | Not started | | |
| 2.6 `benches/dataplane.rs`, measurements, tuning | Not started | | |
| 2.7 Deploy, documents, browser check, merge | Not started | | |

Exit criteria: 1 ☐ e2e across shards · 2 ☐ 500K/shard · 3 ☐ 0.8× scaling · 4 ☐ 0
allocations · 5 ☐ memory · 6 ☐ no panic, no leak · 7 ☐ browsers · 8 ☐ documents.

### Session log

Add one line per working session: date, part, what was done, what is left.

- 2026-09-29: plan written from design §5 and note §13 (with §3.3, §10, §12); branch
  `phase-2` created from `75fcdd9`; code notes audited against that commit (data plane,
  control plane, benches/CI). Owner's decisions: `ArrayQueue` rings, stress + Miri instead
  of loom, measurements on the ≈ 10 vCPU Linux arm64 VM. Found: `remote_shards` missing,
  the return-ring bound in note §13.4, the keyframe/`AddRemoteShard` ordering, and the
  track-removal gap for mirrors (2.4). Not committed; waiting for review. Next: 2.1.
- 2026-09-29: plan revised after the owner's review (16 points), not committed. Blockers:
  2.6 generators encrypt on the fly (replay protection drops replays; allocations counted
  process-wide because the `real_path` gate is thread-local); latency measured inside the
  shard with an off-by-default `latency-probe` feature at 250K/s per shard (50% of the
  target), corrections row added; 2.4 cleanup commands go through a retry list (with
  cancellation of a pending `RemoveRemoteShard` on re-add), only additive commands close the
  participant. Also: per-buffer references in the shared pool, lend only after local
  fan-out, check-then-lend-then-push, returns drained at the top of `iterate`, one wake per
  peer after a drain, mirror re-parse and split borrows, sizes and memory bench in 2.2,
  counting on slot state, decrement in `cleanup_participant`, `session_closed` on failed
  creates, spill rules (room cap 50, shard `max_sessions`), `recvmmsg` sinks, criteria 2/3
  scenarios, x86_64 emulated, criterion 6 agreement check, `FakeSink` recording shards.
  Waiting for review. Next: 2.1.
