# Phase 2 — Multiple shards

**State: in progress** (plan written 2026-09-29, audited against `75fcdd9` the same day, revised the same day after
the owner's review; 2.1 detailed the same day from a code analysis, with the owner's `Loan`
decision and a process-unique region id; 2.1 implemented and committed the same day,
`28d9cdf`; 2.2 implemented the same day, not committed, waiting for review).

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
| Peer access to a lent buffer | `lend` returns a move-only `Loan` (12 B: index, process-unique region id, owner, peer; private fields, not `Copy`/`Clone`); a peer reads through `&Loan` and returns it by moving it into the return ring, so reading after the return does not compile. `XsMsg` carries the `Loan` and is not `Copy` | `XsMsg: Copy` with a `BufRef` and a safe `slice(buf, len)` any code could call on any handle, including one already returned (note §13.4) |
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
     `tracks` and `subscriptions` gauges and `xs_in_flight` (loans outstanding) return to 0;
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
per-peer credit, a move-only `Loan` for each lent buffer, the message type and the ring mesh.

**Files:** `crates/nexus-dataplane/src/{pool.rs, xs.rs (new), ids.rs, lib.rs}`,
`crates/nexus-dataplane/tests/pool_handoff.rs` (new). No manifest change (`crossbeam-queue`
is already a dependency; crate `tests/` files are auto-discovered) and **no caller change**:
`take`, `put`, `buf`, `buf_mut`, `pair_mut`, `available` and `capacity` keep their signatures.

**Change — `pool.rs`:**
- **`PoolRegion { id: u32, shard: ShardId, cells: Box<[UnsafeCell<[u8; BUF_SIZE]>]> }`**:
  one allocation at startup (`iter::repeat_with(..).take(count).collect()`; the pages are
  touched eagerly, 2 MB at the default), shared as `Arc<PoolRegion>`. `Sync` by an `unsafe
  impl` with the safety argument below. **`id` is process-unique**, taken from a global
  `AtomicU32` (`assert!` that it does not wrap): a `ShardId` does not identify a region,
  because several pools in one process share `ShardId(0)` (each e2e test's in-process server,
  unit tests), so a `Loan` from one would otherwise pass the checks of another — a read of a
  cell its owner writes, or an early free, from safe `pub` code. Methods: `id()`, `shard()`,
  `len()`, and `read<'a>(&'a self, loan: &'a Loan, len: usize) -> &'a [u8]`, which
  `assert!`s `loan.region == self.id` and `len <= BUF_SIZE` (soundness guards, so hard
  asserts). The slice borrows the `Loan`, so it cannot outlive the loan's return.
- **`Loan { index: u32, region: u32, owner: ShardId, peer: ShardId }`** (12 B, align 4):
  `#[must_use]`, `Debug` only,
  no `Clone`, `Copy` or `Drop`, private fields; only `BufferPool::lend` makes one. Accessors
  `buf() -> BufRef`, `owner()`, `peer()`. A `Loan` dropped without being returned leaks its buffer (a bug
  the pool-full checks catch), never undefined behaviour.
- **`BufferPool`** becomes `{ shard, region: Arc<PoolRegion>, free: Vec<u32>, state: Box<[u16]>,
  in_flight: [u32; MAX_SHARDS], lent: u32 }`, where each buffer's `state` holds `refs` (the loan
  count, low 15 bits) and `held` (top bit). `state` and `in_flight` are read and written only
  by the owner (note §13.4 item 2). One word per buffer keeps `take` and `put` to one load,
  compare and store: `LinuxIo::recv_batch` takes 64 buffers and puts back the unused ones every
  iteration, so these two run ≈ 128 times per iteration (a separate `held: Box<[bool]>` cost
  ≈ 180 ns per ingress iteration, see the session log).
  - **Freeing does not depend on call order** (review, 2026-09-29): `held` says a local holder
    (ingress, a send buffer) has the buffer, from `take` to `put`/`put_if_unshared`. A buffer
    goes back on the free stack when it is neither held nor lent, by whichever of the holder
    or the last `release` comes last (`free_if_done`). Without it, a return handled between
    `lend` and `put_if_unshared` would free the buffer at `refs == 0` and the holder would
    push the index a second time (one buffer handed out twice). `held` replaces the debug-only
    `taken` and makes the double-free check a hard `assert!`.
  - `take`: `assert!(state == 0)` (hard, so a corrupt free stack fails near the cause), sets
    `held`. `put`: one compare `state == HELD`, else a cold panic naming the case ("put of a
    lent buffer" or "buffer returned twice"), then `state = 0` and push.
  - `buf(&self, buf) -> &[u8]`: a shared reference to one cell (the owner may read a lent
    buffer).
  - `buf_mut(&mut self, buf) -> &mut [u8]`: `assert!(refs[i] == 0, "write to a lent buffer")`,
    then a reference to that cell only.
  - `pair_mut(read, write)`: two references built from two different cells (`assert!(read !=
    write)`), the write side with the same `refs == 0` assert; the read side may be lent. **No
    reference ever spans the whole region** (today's `split_at_mut` over `memory`,
    `pool.rs:98-117`, goes).
  - `can_lend(peer)`: `in_flight[peer] < XS_CREDIT`.
  - `lend(&mut self, buf, peer) -> Loan`: `assert!(peer != self.shard)`,
    `assert!(can_lend(peer))` (the credit is what keeps the return ring from filling) and
    `assert!(held)` (only the holder lends), then `refs += 1`, `in_flight[peer] += 1`.
  - `unlend(&mut self, loan)`: undoes `lend` for a push that failed (2.2). `assert!(loan.region
    == region.id)`. The holder still has the buffer, so it is not freed here
    (`debug_assert!`); the holder's `put_if_unshared` frees it.
  - `release(&mut self, loan, from: ShardId) -> bool`: a returned loan. `assert!(loan.region ==
    region.id)`, `debug_assert!(loan.peer == from)` (return from the wrong peer), `refs -= 1`,
    `in_flight -= 1`, freed if neither lent nor held; returns whether it freed the buffer.
  - `put_if_unshared(buf) -> bool`: ends the hold (`assert!(held)`, "buffer returned twice");
    frees the buffer if it is not lent, otherwise the last `release` does.
  - `in_flight(peer)`, `lent_total()` (2.2's `xs_in_flight` gauge), `region() -> Arc<PoolRegion>`
    (startup clone for the mesh).
- **`unsafe` stays local:** `#[allow(unsafe_code)]` only on the `unsafe impl Sync` and on the
  few fns that call `UnsafeCell::get` (`buf`, `buf_mut`, `pair_mut`, `PoolRegion::read`), each
  block with a `// SAFETY:` comment. The crate root keeps `#![deny(unsafe_code)]`.
- `BufRef`'s doc ("Phase 2 adds the owner-local refcount") says where the refcount lives and
  that cross-shard handles are `Loan`s.
- **Safety argument** (written at the top of `pool.rs`):
  1. Only the owner forms `&mut` into its region, one cell at a time, and only for a cell with
     `refs == 0` (asserted); `&mut self` on `BufferPool` rules out two local `&mut` to one cell.
  2. Peers form `&[u8]` only through `read(&Loan)`. A `Loan` exists only between `lend` and
     `release`/`unlend`, so `refs > 0` while any peer can read. A `Loan` names its region by
     the process-unique `id`, and `read`, `release` and `unlend` assert it, so a loan from
     another pool (even one with the same `ShardId`) can neither read this region nor change
     its counts.
  3. Owner writes → `lend` → `ArrayQueue::push` (Release) → peer `pop` (Acquire) → reads; the
     reads end with the borrow of the `Loan` → return `push` (Release) → owner `pop` (Acquire)
     → `release` → `put` → next writes. Every write is ordered after every peer read of the
     previous use.
  4. `in_flight[j]` counts every loan of the owner's that j holds, has queued or is returning,
     and the return ring j→owner has capacity `XS_CREDIT`, so it cannot fill. The count is per
     `loan.peer`, so `give_back` asserts `loan.peer == self.shard` (a loan given back by
     another shard would go into a queue its credit does not bound) and `assert!`s the push
     (a full return ring would leak a buffer).
- **Lend only after local fan-out** (the rule 2.2 follows): the ingress buffer is lent after
  the local subscribers are served; from then on the owner only reads it until `release`
  brings `refs` to 0. Nothing writes to a lent buffer (the plaintext is final after unprotect).

**Change — `xs.rs` (new, `pub mod xs`):**
- **`XsMsg`** (`Debug`, not `Copy`: it carries a `Loan`):
  `Rtp { loan: Loan, len: u16, track: TrackId, layer: u8 }`,
  `SenderReport { track: TrackId, layer: u8, ntp: u64, rtp: u32 }`,
  `KeyframeRequest { track: TrackId, layer: u8, from: ShardId }`.
  `const _: () = assert!(size_of::<XsMsg>() <= 24)` on the default build (layout: tag, layer,
  len in 4 B, `Loan` at 4..16, `TrackId` at 16; 2.6's `latency-probe` field is exempt).
  `give_back` routes a `Loan` by its `owner` (a mesh holds one region per shard).
- **Constants:** `XS_RING = 1_024` (media ring), `XS_CREDIT = 1_024` (per-peer credit and
  return-ring capacity), `XS_BUDGET = 256` (messages per peer per iteration, 2.2). `const`
  asserts `XS_BUDGET <= XS_RING`; `refs` stays `u16` (`lend` asserts it does not overflow;
  the protocol lends a buffer at most once per peer, ≤ 63). 2.6 tunes the values.
- **`XsMesh::build(regions: &[Arc<PoolRegion>]) -> Vec<XsPorts>`**: asserts `1 <= n <=
  MAX_SHARDS` and `regions[i].shard() == i`; for every ordered pair i ≠ j one media
  `ArrayQueue<XsMsg>` i→j (`XS_RING`) and one return `ArrayQueue<Loan>` j→i (`XS_CREDIT`).
- **`XsPorts { shard, peers: Box<[Option<PeerPorts>]> }`**, indexed by shard index, `None`
  for itself; `PeerPorts` holds `media_tx`, `media_rx`, `return_tx`, `return_rx` (`Arc`s) and
  the peer's `Arc<PoolRegion>`. Methods: `shard()`, `peer_ids()`, `has_room(peer)` (this shard
  is the ring's only producer, so room seen stays room until its push),
  `send(peer, msg) -> Result<(), XsMsg>` (the message comes back so the caller can `unlend`),
  `recv(peer) -> Option<XsMsg>`, `region(peer) -> &PoolRegion`, `give_back(loan)` (routed by
  `loan.owner`; asserts it is not an own loan and that `loan.peer` is this shard), `take_return(peer) -> Option<Loan>`. The peers' `Wake`s and an
  `inbound_pending()` for the runner come with 2.2/2.3.
- `ids.rs`: `ShardId` derives `PartialOrd, Ord`; `MAX_SHARDS` stays 64 (a `ShardMask` is a
  `u64`). `lib.rs`: `pub mod xs;`, re-exports `Loan`, `PoolRegion`, `XsMsg`, `XsMesh`,
  `XsPorts` and the `XS_*` constants.

**Code notes (audited 2026-09-29):**
- `BufferPool` today (`pool.rs:20-27`) is `{ shard, memory: Vec<u8>, free: Vec<u32>, taken
  (debug) }`: one `Vec<u8>` of `count × BUF_SIZE`, LIFO free stack, no refcount, no `unsafe`.
  `take` `:57`, `put` `:71` (debug asserts owner and double free; hard `assert!` on stack
  overflow), `buf` `:85`, `buf_mut` `:91`, `pair_mut` `:98` (safe `split_at_mut`).
- **Callers, unchanged by 2.1:** `shard/ingress.rs` (`buf` for classify/parse, `buf_mut` for
  unprotect in place `:282`, `:342`, `pair_mut` for the rewrite `:79`, `:389`), `shard/rtcp.rs`
  and `shard/commands.rs` (take + `buf_mut` + put), `shard/mod.rs:192` (`put` after
  `handle_datagram`, still right because nothing lends until 2.2, which switches it to
  `put_if_unshared`), the three `DatagramIo` backends (`io/{portable,linux}.rs`, `MemIo` in
  `io.rs`), `io/conformance.rs`, `runner.rs` tests, `benches/real_path.rs` (`BenchIo`).
- `LinuxIo` keeps raw pointers from `buf_mut` in its iovecs (`arm_rx` `linux.rs:97`, `arm_tx`
  `:116`); those are receive slots and send buffers, never lent, so the `refs == 0` assert
  holds and the kernel's writes never touch a lent cell.
- The new `refs` asserts in `buf_mut`/`pair_mut`/`put` are on the per-packet path (one
  owner-local compare each): `real_path` is measured before and after (PR checklist).
- The deleted `src/worker/spsc.rs` (last at `372cbcd^`, 481 lines) was `SpscChannel<N>` over
  `UnsafeCell<[Option<PacketSlot>; N]>`, head/tail `AtomicU32` without padding or cached
  indices, not generic, 8 single-thread tests. Not used (owner's decision).
- `crossbeam-queue = "0.3"` (lock: 0.3.12, `crossbeam-utils` 0.8.21) is already a dependency,
  used for the command `ArrayQueue` (`shard/mod.rs:38`, capacity 4,096). Its push/pop give
  the Release/Acquire ordering of the safety argument; crossbeam runs under Miri.
  `ArrayQueue` slots carry a stamp: ≈ 32 B per `XsMsg`, 24 B per `Loan`, so ≈ 56 KB per
  ordered pair at the starting capacities (see 2.3 on growth with n).
- `#![deny(unsafe_code)]` is at `lib.rs:16`; the only `#[allow(unsafe_code)]` is
  `shard/io.rs:19` (`mod linux`).
- `lib.rs` `sizes` (`:63-70`) feed the memory bench; 2.1 does not change them (2.2 does).
- `TrackId` is a monotonic `u64` from the orchestrator's counter, never 0 and never reused
  (`src/orchestrator/ids.rs:40`, `bump` `:48-53`), so a late message naming a removed track
  can never be taken for a new one.
- **Miri:** `rustup toolchain install nightly --component miri` (done 2026-09-29, nightly
  `c1070d693 2026-09-28`). `+nightly` overrides `rust-toolchain.toml`. Nightly deprecates
  `AtomicU32::fetch_update` (renamed `try_update`), which trips `#![deny(warnings)]`, so
  every Miri run uses `RUSTFLAGS=--cap-lints=warn`; the pinned 1.83 build keeps
  `fetch_update`.

**Tests:**
- Unit, `pool.rs`:
  - lend → release cycle: `refs`, `in_flight`, `available`;
  - `can_lend` false at `XS_CREDIT` (pool of `XS_CREDIT + 1`, one loan per buffer);
  - `unlend` restores `refs` and `in_flight` and does not free;
  - a buffer lent to two peers is freed at the second `release`, not the first;
  - `put_if_unshared` true when unshared, false when lent (then `release` frees it);
  - order independence: lend → release → `put_if_unshared` and lend → `put_if_unshared` →
    release each free the buffer exactly once (all buffers then taken, none twice); `lend`
    after the holder put the buffer back panics;
  - `put`, `buf_mut` and the write side of `pair_mut` on a lent buffer panic; `pair_mut`
    whose read side is lent works; `lend` to its own shard panics;
  - `release` from the wrong peer is caught (`cfg(debug_assertions)`);
  - a `Loan` from another pool **with the same `ShardId`** panics in `read`, `release` and
    `unlend` (region id);
  - aliasing on one thread: a `read(&loan)` slice held while `pair_mut` writes two other
    buffers (Miri checks it).
- Unit, `xs.rs`: `XsMsg` ≤ 24 B; mesh wiring for n = 1..4 (every ordered pair delivers media
  and returns, no self ports, n = 1 has no peers); a full media ring hands the message back
  and `unlend` leaves the counters as before; `give_back` lands in the owner's return ring;
  `give_back` of an own loan, and of a loan lent to another shard, panic.
- **`tests/pool_handoff.rs`** (on `XsMesh::build`, owner shard 0, reader shards 1..=3):
  - owner thread: drain every return ring (`release`) → `take` (none: go round) → write a
    canary (buffer index, generation, length, a fill derived from the generation, random
    length) → lend to a random subset of readers where `can_lend && has_room` → `send` (an
    `Err` is `unlend`ed and counted) → `put_if_unshared`. Stops after `HANDOFFS` loans and all
    returns;
  - reader threads: `recv` → `read` → check header and body (the body compared with `==`
    against a static pattern, i.e. memcmp, so the debug build stays fast) → `give_back`.
    Readers that hold loans (per 8, per 64, up to the credit) keep each loan's generation and
    length, yield now and then while holding, and check the canary **again** before
    `give_back`, so an owner that reuses a buffer early is caught outside Miri too. The
    no-credit and empty-pool paths run;
  - a reader's panic sets an abort flag the owner checks every round, and the owner's end
    (or panic) sets `done`, so a failure stops both sides at once;
  - end: 0 mismatches, the owner's pool full, every `in_flight` 0, loans sent = received =
    returned. Every loop has an iteration cap and a deadline `assert!`, so a bug fails the
    test instead of hanging it;
  - `HANDOFFS` = 10⁶, pool 64 buffers; under `cfg(miri)` 100 hand-offs, one reader, pool 8.
    Target ≤ 10 s in a debug `cargo test`.
- **Miri** (nightly, local; command, nightly version, duration and result in the session log):
  `cargo +nightly miri test -p nexus-dataplane --test pool_handoff` and
  `cargo +nightly miri test -p nexus-dataplane --lib -- pool:: xs::`. If time allows, the
  hand-off test again with `MIRIFLAGS=-Zmiri-many-seeds=0..16` (more schedules).

**Checkpoint:** `cargo test -p nexus-dataplane` green and the workspace green (fmt, clippy
`-D warnings`); Miri clean; `real_path` before/after in the Linux container, in the session
log; `scripts/ci-local.sh` summary in the session log; Status table and session log updated;
not committed, stopped for review.

---

### 2.2 Shard: remote fan-out, mirror tracks, cross-shard RTCP

**Goal:** a shard that forwards to subscribers on other shards and serves subscriptions to
tracks published elsewhere, driven entirely through `MemIo` with several shards iterated on
one thread.

**Files:** `crates/nexus-dataplane/src/{command.rs, track.rs, subscription.rs, session.rs,
xs.rs, lib.rs (sizes), rewrite.rs (test fixture), shard/{mod.rs, ingress.rs, commands.rs,
rtcp.rs, runner.rs, stats.rs, housekeeping.rs, xs.rs (new)}}`, `tests/{support/mod.rs,
shard.rs, alloc.rs}`, `benches/memory.rs` (new structure sizes reported; budget re-checked),
`benches/real_path.rs` (`SubSpec.pub_mid`). Found while implementing: `SubSpec`'s other
constructor, `src/orchestrator/sdp_params.rs` (+ its tests), fills the three new fields, and
the two new gauges need `crates/nexus-metrics/src/prometheus.rs` (+ its integration test).

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
  **Deferral** (2.2 review): the reverse order races too. `AddRemoteShard` sends a PLI and
  arms the throttle, the keyframe reaches the new shard before its mirror exists (dropped),
  and the new shard's own request then falls inside the window. So a throttled request is
  not dropped: the track keeps one `keyframe_pending`, sent as one PLI when the window
  ends. It is checked on each of the track's packets and by housekeeping (so it goes out
  within 1 s for a paused publisher), costs one load per packet while none is pending, and
  is counted in `keyframe_deferred`.
- **Counters:** `xs_tx`, `xs_rx`, `xs_returned`, `drop_xs_full`, `drop_xs_credit`,
  `drop_xs_no_track` (also a hand-off from a shard that is not the mirror's source), and
  (added while implementing) `drop_xs_malformed` (a hand-off whose header does not parse,
  a sender bug), `xs_keyframe_ignored` (the ordering rule) and `keyframe_deferred`. They
  reach Prometheus through `ShardCounters::NAMES` with no exporter change. The gauges
  `mirrors` and `xs_in_flight` (loans outstanding, summed over peers: one buffer lent to 3
  peers counts 3; `BufferPool::lent_total`) are listed field by field in
  `Gauges`/`ShardStats` and in the exporter, which gains two gauge families.

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
  shard at 1 shard, ≈ 7 MB at 4 with the starting constants). 2.6 revisits the constants.
- **Fixed memory grows with n²** (found while detailing 2.1): the pool minimum is
  `(n − 1) × XS_CREDIT` buffers per shard and the mesh has n(n − 1) pairs of rings (≈ 56 KB
  per pair). At 4 shards that is ≈ 7 MB of pool per shard and ≈ 0.7 MB of rings; at
  `MAX_SHARDS` = 64 it would be ≈ 126 MB of pool per shard (≈ 8 GB in total) and ≈ 225 MB of
  rings. So `shards` is validated against a practical bound (e.g. the core count, with a
  clear error), or `XS_CREDIT` is scaled down with n; `Dataplane::start` logs the fixed
  memory it allocates.
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
  - **Per-shard order** (review note, 2026-09-29): before any push to shard s, additive or
    cleanup, `Plane` first sends s's queued cleanup commands, oldest first (the retry list
    absorbs `pending_close`, so `CloseSession` follows the same rule). If one still does not
    fit, the new command is never sent ahead of it: a cleanup command joins the list behind
    it, an additive command closes its participant as today. The list is FIFO per shard and
    the 1 s sweep keeps that order.
- A rejected `AddRemoteShard`/`RemoveRemoteShard`/`RemoveTrack` for an unknown track is
  ignored (race with removal), and so is a rejected `Unsubscribe` for an unknown subscription
  (it may be retried after `CloseSession` or `RemoveTrack` removed the subscription). Both
  already hold: `connection.rs:120-127` returns early for `UnknownSession`, `UnknownTrack`
  and `UnknownSubscription`; keep it. `WrongShard` stays an internal error
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
- Per-shard order: a cleanup command queued for B, then a `Subscribe` to B → the recorded
  stream has the cleanup first; with B's queue still full, the `Subscribe` closes its
  participant and the cleanup stays queued ahead. A late `Unsubscribe` rejected with
  `UnknownSubscription` closes no one.
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
| §13.4 | `XsMsg` `Copy`, ≤ 32 bytes, carrying a `BufRef`; peers read `region.slice(buf, len)` | A safe read by `BufRef` cannot stop a peer reading a buffer it already returned (a data race). `lend` returns a move-only 12-byte `Loan` naming its region by a process-unique id (a `ShardId` repeats across pools in one process), peers read through `&Loan` and return it by move; `XsMsg` is not `Copy`, ≤ 24 bytes (owner, 2.1) |
| §13.4 item 6 | `loom` model of one pair | Multi-thread stress test + Miri (owner); `loom` is not in the lock file |
| §13.4 item 7 | Return ring capacity = media capacity + `XS_BUDGET`, so it cannot fill | Does not bound what is outstanding (the owner can keep lending while returns wait). A per-peer credit (`in_flight[j] < XS_CREDIT`) bounds it; return capacity = `XS_CREDIT` |
| §13.4 | `Subscribe{source: TrackRef}` is all the subscriber's shard needs | It also needs the track's clock rate, publisher `mid` id and cname (read from the local track today, `commands.rs:247-248`); carried in `SubSpec`, kept in a mirror track |
| §12.3, §13.4 | Subscriber's shard sends `KeyframeRequest`; commands unordered is safe | A request that arrives before `AddRemoteShard` yields a keyframe the new shard never gets, and the throttle suppresses the next. `AddRemoteShard` requests a keyframe; requests from shards not in `remote_shards` are ignored |
| §12.3 | Keyframe requests inside the 500 ms window are suppressed | They are deferred: one pending request per track, sent when the window ends (a new shard's request right after `AddRemoteShard`'s PLI would otherwise wait for the client's next PLI) (2.2 review) |
| §13.2 | `RoomAffine` decides from `ShardLoad` (stats) | Stats are published once a second; placement counts its own sessions and uses stats only for `rx_pps` |
| §6.5 / §13.4 | Track removal: `RemoveTrack` to the publisher's shard | With mirrors, `RemoveTrack` also goes to every shard with subscriptions to the track: the orchestrator marks subscriber m-lines inactive without `Unsubscribe` (`forget_tracks`) |
| §2 targets | Linux arm64 and x86_64 | Linux arm64 in the ≈ 10 vCPU VM (owner); x86_64 at release |
| §2 latency | "Timestamp at receive vs `sendmmsg` return" | Receive time = the iteration's `now`, read before `recvmmsg` (an upper bound), recorded at the flush's return by the off-by-default `latency-probe` feature; cross-shard packets carry their origin iteration's `now`. No per-datagram receive timestamp (`SO_TIMESTAMP`) |
| §6.4 / §13.4 | A full command queue fails the orchestrator operation (note §5.3) | Right for additive commands; cleanup commands (`Unsubscribe`, `RemoveRemoteShard`, `RemoveTrack` to other shards) are retried by the sweep instead, or state on another shard leaks (2.4) |
| Plan 2.2 | Gauges reach Prometheus with no exporter change | Only counters do (`ShardCounters::NAMES`); `mirrors` and `xs_in_flight` are added to `Gauges`, `ShardStats` and `nexus-metrics`' exporter (2.2) |
| Plan 2.2 tests | "Credit exhausted with ring room" on shards iterated on one thread | Cannot happen there: `XS_CREDIT == XS_RING` and a shard returns each loan in the drain that received it, so credit ends exactly when the ring fills. The test holds the peer's `XsPorts` itself (a scripted peer that keeps loans); "full ring with credit left" fills the ring with `SenderReport`s (2.2) |
| Plan 2.2 | Local `Subscribe` reads clock rate and `mid` id from the track | The `SubSpec` carries them (and the cname) for every subscription; a local `Subscribe` whose description differs from the track's is refused with `InvalidSpec`, so every single-shard test and e2e run checks what the orchestrator fills in (2.2) |
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
| Miri needs nightly and may not support every crate used by the test | The hand-off test uses only `pool.rs`, `xs.rs` and `ArrayQueue`; run locally, recorded in the session log. Nightly and the `miri` component are not installed yet; `RUSTFLAGS=--cap-lints=warn` for the Miri run if a nightly-only lint trips `deny(warnings)` |
| Fixed memory (pools, rings) grows with n² | 2.3 bounds `shards` or scales `XS_CREDIT` with n and logs the fixed memory; 2.6 reports it for 4 shards |
| The `refs == 0` asserts added to `buf_mut`/`pair_mut`/`put` cost on the per-packet path | One owner-local compare each; `real_path` before and after in 2.1 |

## Status

| Part | State | Commits | Notes |
|------|-------|---------|-------|
| 2.1 Shared pool region, `XsMsg`, mesh | Done | `28d9cdf` | `Loan` with region id; freeing independent of call order (`held`); stress test and Miri clean |
| 2.2 Shard: remote fan-out, mirrors, cross-shard RTCP | Done, not committed (review fixes, second review) | | Mirrors, lend after local fan-out, returns at the top of `iterate`; alloc test 0 on 2 shards; 3-shard proptest agrees with the counting model |
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
- 2026-09-29: 2.1 detailed from a code analysis (every pool caller, the Linux iovecs, the
  soundness of peer reads). Owner's decision: a move-only `Loan` instead of a `Copy`
  `XsMsg` with a `BufRef`. Added: `refs == 0` asserts on `buf_mut`/`pair_mut`/`put` (a
  `real_path` check), per-buffer cells and the safety argument, the `XsPorts` API, the
  stress-test design and the Miri commands (nightly not installed yet); 2.3 note on fixed
  memory growing with n²; review note carried into 2.4 (per-shard order: queued cleanup
  before any push; a rejected `Unsubscribe` for an unknown subscription is ignored, already
  so in `connection.rs`). Not committed. Next: implement 2.1.
- 2026-09-29: plan fix before 2.1 (owner's review): a `ShardId` does not identify a region
  (every in-process server and unit test has a `ShardId(0)` pool), so `PoolRegion` gets a
  process-unique `id` (global `AtomicU32`, no wrap) and `Loan` carries it (12 B);
  `read`/`release`/`unlend` assert it. **2.1 implemented, not committed:** `pool.rs`
  (`PoolRegion` with one `UnsafeCell` per buffer, `Loan`, `refs`/`in_flight`/credit,
  `can_lend`/`lend`/`unlend`/`release`/`put_if_unshared`, `refs == 0` asserts on
  `put`/`buf_mut`/`pair_mut`, safety argument; `#[allow(unsafe_code)]` on the `Sync` impl and
  four fns), `xs.rs` (`XsMsg` ≤ 24 B, const-asserted; `XS_RING`/`XS_CREDIT`/`XS_BUDGET`;
  `XsMesh::build`, `XsPorts`), `ShardId: Ord`, re-exports. No caller changed. Also added:
  `PoolRegion::is_empty` (clippy). Tests: 18 unit tests in `pool.rs` (among them a same-`ShardId`
  loan from another pool panicking in `read`, `release` and `unlend`), 4 in `xs.rs`;
  `tests/pool_handoff.rs`: 10⁶ hand-offs to 3 readers (return at once, per 8, per 64) and
  2 × 10⁵ with the credit exhausted (140,576 lends refused for credit), 0 mismatches, pool
  full; 0.6-0.8 s in debug. Readers stop if the owner panics (a drop guard), so a failure
  does not wait out the 120 s deadline. Mutation check: an early free (refs set to 0 in
  `release`) fails the test at once through the pool's own asserts, also with the `refs`
  asserts removed (free-stack bound). **Miri** (nightly 2026-09-28, `RUSTFLAGS=--cap-lints=warn`):
  `cargo +nightly miri test -p nexus-dataplane --test pool_handoff` clean (100 hand-offs,
  one reader, 16 s; the credit variant is ignored under Miri); `--lib -- pool:: xs::` 20 passed,
  2 ignored (2 MB pools), 33 s; `MIRIFLAGS=-Zmiri-many-seeds=0..16` on the hand-off test:
  16 seeds clean, 324 s. **`real_path`** (Linux arm64 container, HEAD vs the working tree,
  medians): pool paths −31% to +6% (e.g. GCM video with 100 subscribers 104.5 → 102.9 µs,
  ingress GCM video 800 → 819 ns, CM video with 1 subscriber 3.12 → 3.31 µs). Benches that do
  not touch the pool moved by as much (SRTP unprotect GCM audio +19%), so the change is within
  run-to-run noise; 0 allocations per packet in every case. **ci-local** (`e399329` + 6
  uncommitted or untracked paths, macos + linux-arm64): all PASS, `cargo test --workspace`
  1,490 (macOS) / 1,496 (Linux) passed, bench smoke and memory budget 25 KB PASS. Next:
  owner's review of 2.1, then commit; then 2.2.
- 2026-09-29: 2.1 review fixes, not committed. (1) **Freeing independent of call order:**
  each buffer's `state: u16` holds its loan count and a `HELD` bit (a local holder has it,
  `take` to `put`/`put_if_unshared`; replaces the debug-only `taken`), and a buffer goes back
  on the free stack when its state is 0, by whichever of the holder or the last `release`
  comes last. Before, a return handled between `lend` and `put_if_unshared` freed at
  `refs == 0` and the holder pushed the index again. `lend` asserts `HELD`; `unlend` cannot
  free (debug-asserted); a double put is a hard `assert!`. Tests: lend → release →
  `put_if_unshared` and lend → `put_if_unshared` → release each free once (every buffer then
  taken, none twice); `lend` after the holder's put panics. (2) `XsPorts::give_back` asserts
  `loan.peer() == self.shard` (the return-queue bound counts credit per peer); tests for a
  loan lent elsewhere and an own loan. (3) `pool_handoff.rs`: holding readers keep each loan's
  generation and length, yield every 4 receipts while holding, and re-check the canary
  before `give_back`. Mutation check with the pool's asserts removed and `release` freeing
  early: the canaries alone report 854,038 mismatches. Nits: `take` hard-asserts
  `state == 0`; a reader's panic sets an abort flag the owner checks every round; the plan
  lists `owner()` among `Loan`'s accessors; safety point 4 and the plan text updated.
  **Hot-path cost:** a first version with a separate `held: Box<[bool]>` cost ≈ +16% on
  `ingress/gcm/video` (medians of 3 alternating runs, 1,149 → 1,334 ns) because
  `LinuxIo::recv_batch` takes 64 buffers and puts the unused ones back every iteration
  (≈ 128 pool operations per one-datagram iteration). Folding `HELD` into the loan-count word
  (one load, compare and store in `take` and `put`, the failed `put` check in a `#[cold]` fn)
  brought it to +2-6%: `real_path` in the Linux arm64 container, base and new alternating, 3
  runs each on a loaded host (load ≈ 8), medians: ingress GCM video 1,159 → 1,185 ns, GCM
  audio 925 → 970, CM video 1,760 → 1,818, CM audio 1,020 → 1,081; egress GCM video /1
  3,015 → 3,182, /10 16,241 → 18,172, /100 145,750 → 144,460, /500 627,220 → 657,440 (base
  itself varies 15.9-17.8 µs at /10 across its 3 runs); SRTP control 405 → 407 ns. A full
  run earlier in the session was ≈ 40% slower on every bench, SRTP included (host load), and
  is discarded. 0 allocations per packet throughout. **Proposal (2.6, not done):**
  `LinuxIo` could keep its armed receive buffers across iterations instead of taking and
  putting back 63 per call, which removes most of that per-iteration pool cost (before and
  after this change). Results on the final tree: `cargo test -p nexus-dataplane` green (lib
  80, `pool_handoff` 2 in 0.6 s: 10⁶ hand-offs, 0 mismatches; credit variant ≈ 170,000 lends
  refused for credit); clippy and fmt clean. **Miri** (nightly 2026-09-28,
  `RUSTFLAGS=--cap-lints=warn`): `--test pool_handoff` clean (14 s); `--lib -- pool:: xs::`
  25 passed, 2 ignored (39 s); `MIRIFLAGS=-Zmiri-many-seeds=0..16` 16 seeds tried, 16 `ok`
  (331 s). **ci-local** (`e399329` + 6 uncommitted or untracked paths, macos + linux-arm64):
  all PASS, `cargo test --workspace` 1,495 (macOS) / 1,501 (Linux), bench smoke and memory
  budget 25 KB PASS. Next: owner's review, then commit; then 2.2.
- 2026-09-29: 2.1 committed (`28d9cdf`); Status set to Done. **2.2 implemented, not
  committed.** `AddRemoteShard`/`RemoveRemoteShard`; `PublishedTrack.remote_shards`;
  `MirrorTrack` (freed with its last subscription or by `RemoveTrack`) and `SubTrack`
  (local or mirror); `SubSpec` carries `clock_rate`, `pub_mid`, `cname` (filled by
  `sdp_params::sub_spec`), and a local `Subscribe` that describes the track differently is
  refused with `InvalidSpec`. New `shard/xs.rs`: `drain_returns` at the top of `iterate`,
  `lend_to_remotes` after the local fan-out (credit, then room, then lend and send; `unlend`
  on `Err`), `drain_cross_shard` after the commands (≤ `XS_BUDGET` per peer; the ports moved
  out for the drain so `forward` reads a peer's slice, `Src::{Local, Peer}`), SRs translated
  on the mirror's shard, `KeyframeRequest` ignored from a shard not in `remote_shards`, and
  `AddRemoteShard` asking for a keyframe; one wake per peer per iteration (`wake_mask`,
  `attach_peer_wakes` for 2.3). Ingress buffers go back with `put_if_unshared`. Runner:
  cross-shard work counts as work, `xs_pending` before parking. Counters `xs_tx`, `xs_rx`,
  `xs_returned`, `drop_xs_full`, `drop_xs_credit`, `drop_xs_no_track`, `drop_xs_malformed`,
  `xs_keyframe_ignored`; gauges `mirrors`, `xs_in_flight` (exporter extended; corrections
  table). **Tests:** 14 new in `tests/shard.rs` (2-3 shards on one thread; a scripted peer
  holding shard 1's `XsPorts` for the full-queue and exhausted-credit cases, see the
  corrections table), among them a 3-shard proptest (128 cases, < 200 operations, ≈ 1 s):
  an orchestrator model counts per (track, shard), delivers per-shard FIFOs in a random
  interleaving and iterates shards in random order; at quiescence every pool is full, no
  loan is out, `remote_shards` and mirrors match the model, and one marked packet per live
  track reaches exactly the live subscriptions with their SSRCs. Mutation checks, each
  caught: `RemoveRemoteShard` a no-op (proptest), returns drained after ingress (credit
  test), `put` instead of `put_if_unshared` (10 tests panic), keyframe requests accepted
  from any shard (ordering test), a loan not given back without a mirror (3 tests).
  `tests/alloc.rs` runs 1 and 2 shards (5 subscribers on each, SRs and PLIs across), GCM and
  CM: 0 allocations, output = 10 × input, 10,000 hand-offs returned per case. The new
  `InvalidSpec` check found `benches/real_path.rs` subscribing to 90 kHz video with a 48 kHz
  spec (fixed). **Sizes:** `PublishedTrack` 384 → 392 B, `Subscription` 120 B (unchanged,
  padding), `MirrorTrack` 296 B. `benches/memory.rs` adds the worst-case mirror share
  (10 subscribed tracks, one subscriber per mirror: 3.2 KB) to the checked figure: 17.3 KB
  + 264 B + 3.2 KB = **20.8 KB ≤ 25 KB**. **`real_path`** (Linux arm64 container, HEAD vs
  the working tree): a first 3 × 3 run on a loaded host (load ≈ 8) showed ingress +33-37% in
  the new tree's runs 2-3 only (its run 1 matched base), so it was repeated for ingress with
  5 alternations at load 1-2.4; medians: GCM audio 700 → 678 ns, GCM video 837 → 882, CM
  audio 753 → 786, CM video 1,286 → 1,316 (−3% to +5%, as in 2.1). Egress from the 3 × 3
  run: /10-/500 within ±5% (e.g. GCM video /100 109.3 → 109.7 µs), /1 +5% to +22% with base
  itself spreading as much (GCM audio /1 base 1.84-2.31 µs); 0 allocations per packet
  throughout. **ci-local** (`28d9cdf` + 26 uncommitted or untracked paths, macos +
  linux-arm64): all PASS, `cargo test --workspace` 1,512 (macOS) / 1,518 (Linux), bench
  smoke and memory budget 25 KB PASS (the 26th path was `shard.proptest-regressions`, seeds
  from the mutation runs, reverted afterwards). Not tested yet: the wakes
  (`attach_peer_wakes`, `wake_peers`) and the runner's park check on `xs_pending`, which need
  threads (2.3's `tests/loopback.rs`). Next: owner's review of 2.2, then
  commit; then 2.3.
- 2026-09-29: 2.2 review fixes, not committed. (1) **Keyframe throttle race:** a request
  inside the 500 ms window is deferred, not dropped (`PublishedTrack.keyframe_pending`, one
  per track; `deferred_keyframe` on each of the track's packets and in housekeeping, which
  now flushes before publishing the stats; counter `keyframe_deferred`). Tests: the race on
  `MemIo` (`AddRemoteShard` before B's `Subscribe`, the keyframe dropped at B, B's request
  deferred, exactly one PLI after the window with no media, sent by the sweep); the
  throttle tests exact (5 within 100 ms → one now, one deferred with the first packet after
  the window, not before; single shard: 5 requests, 4 throttled, 1 deferred); a mutation
  that never sets the flag fails all three. e2e `keyframe_requests`: one PLI of the burst at
  once, the deferred one 563 ms after it, counters +4 throttled, +1 deferred, +2 requests.
  `tests/alloc.rs`: deferred PLIs sent inside the measured window, 0 allocations; its exact
  "PLI + FIR = requests + throttled" becomes a range (+ deferrals, + one pending per track
  from the warm-up). A first version flushed the sweep's PLIs after the stats were
  published, and `tests/loopback.rs` `burst_larger_than_the_send_batch` saw 751 of 750
  (a PLI counted in `keyframe_requests` but not yet in `tx_datagrams`); fixed in the shard,
  the test unchanged. (2) **`xs_in_flight` = loans outstanding** (one buffer lent to 3
  peers counts 3, `BufferPool::lent_total`), in the gauge docs, `ShardSnapshot`, the
  Prometheus help and this plan. Nits: the cross-shard SR test sends publisher counters
  (77, 9,999) so B's (3, 150) are checked; the proptest asserts no rejection at all (the
  model's per-shard order makes none possible, comment) and is a hand-written `TestRunner`
  that also asserts, after all cases, that ≥ 1/8 handed packets across shards and ≥ 1/8
  ended with mirrors (measured 89-95 and 57-75 of 128); `benches/memory.rs` counts a mirror
  as slab slot 304 + id-map entry 16 + subscriber list 32 B (`sizes::MIRROR_TRACK_SLOT`,
  `MIRROR_ID_ENTRY`, `slab::slot_size`); `mirror_rtp` drops (`drop_xs_no_track`) a hand-off
  from a peer that is not the mirror's source in release builds too; a keyframe request
  names its requester by the queue it came on, `from` only checked; `drain_cross_shard`
  says nothing in it may send to a peer. **Sizes:** `PublishedTrack` 400 B (the flag),
  checked memory 17.3 KB + 264 B + mirrors 3.4 KB = **21.0 KB ≤ 25 KB**. **ci-local**
  (`28d9cdf` + 27 uncommitted or untracked paths, macos + linux-arm64): all PASS,
  `cargo test --workspace` 1,513 (macOS) / 1,519 (Linux), e2e included, bench smoke and
  memory budget 25 KB PASS. Next: owner's review, then commit; then 2.3.
