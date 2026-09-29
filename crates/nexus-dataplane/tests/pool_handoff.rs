//! Cross-shard buffer hand-off under real threads (plan 2.1): an owner shard
//! writes a canary into a pool buffer, lends it to reader shards over the
//! mesh, and reuses it only after every reader gave it back. A reader that
//! sees a canary change under it, or an owner that reuses a buffer too early,
//! shows up as a mismatch.
//!
//! Miri runs the reduced sizes (`cfg(miri)`):
//! `cargo +nightly miri test -p nexus-dataplane --test pool_handoff`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use nexus_dataplane::{
    BufRef, BufferPool, Loan, ShardId, TrackId, XsMesh, XsMsg, XsPorts, BUF_SIZE, XS_CREDIT,
};

/// Buffer index, generation and length at the start of every packet.
const HEADER: usize = 16;
/// Body bytes: `PATTERN[offset..]`, the offset set by the generation.
static PATTERN: [u8; 2 * BUF_SIZE] = pattern();
/// Loop rounds between deadline checks.
const CHECK_EVERY: u64 = 4_096;
const DEADLINE: Duration = Duration::from_secs(if cfg!(miri) { 3_600 } else { 120 });
/// Upper bound on rounds of any loop (with the deadline, a bug fails, never hangs).
const MAX_ROUNDS: u64 = 1 << 40;

const fn pattern() -> [u8; 2 * BUF_SIZE] {
    let mut p = [0u8; 2 * BUF_SIZE];
    let mut i = 0;
    while i < p.len() {
        p[i] = (i % 251) as u8;
        i += 1;
    }
    p
}

/// When a reader gives its loans back.
#[derive(Clone, Copy)]
enum Give {
    /// At once.
    Each,
    /// When it holds this many, or its queue is empty.
    Batch(usize),
    /// Only when it holds the whole credit, or the owner is done.
    AtCredit,
}

struct Run {
    handoffs: u64,
    pool: u32,
    readers: Vec<Give>,
}

#[derive(Default)]
struct OwnerStats {
    lent: u64,
    returned: u64,
    no_credit: u64,
    no_buffer: u64,
}

/// Sets the flag when dropped.
struct SetOnDrop<'a>(&'a AtomicBool);

impl Drop for SetOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Sets the flag when dropped during a panic.
struct SetOnPanic<'a>(&'a AtomicBool);

impl Drop for SetOnPanic<'_> {
    fn drop(&mut self) {
        if thread::panicking() {
            self.0.store(true, Ordering::Release);
        }
    }
}

/// Small xorshift; the test needs spread, not quality.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn body_offset(generation: u64) -> usize {
    (generation % 251) as usize
}

fn write_canary(bytes: &mut [u8], buf: BufRef, generation: u64, len: usize) {
    assert!((HEADER..=BUF_SIZE).contains(&len));
    bytes[..4].copy_from_slice(&buf.index.to_le_bytes());
    bytes[4..12].copy_from_slice(&generation.to_le_bytes());
    bytes[12..16].copy_from_slice(&(len as u32).to_le_bytes());
    let offset = body_offset(generation);
    bytes[HEADER..len].copy_from_slice(&PATTERN[offset..offset + len - HEADER]);
}

fn canary_ok(bytes: &[u8], buf: BufRef, generation: u64) -> bool {
    let len = bytes.len();
    let offset = body_offset(generation);
    len >= HEADER
        && bytes[..4] == buf.index.to_le_bytes()
        && bytes[4..12] == generation.to_le_bytes()
        && bytes[12..16] == (len as u32).to_le_bytes()
        && bytes[HEADER..] == PATTERN[offset..offset + len - HEADER]
}

fn check_deadline(round: u64, start: Instant, who: &str) {
    assert!(round < MAX_ROUNDS, "{who}: too many rounds");
    if round % CHECK_EVERY == 0 {
        assert!(start.elapsed() < DEADLINE, "{who}: deadline passed");
    }
}

fn run(config: Run) {
    let readers = config.readers.len();
    assert!((1..=8).contains(&readers));
    let mut owner_pool = BufferPool::new(ShardId::new(0), config.pool);
    let reader_pools: Vec<_> = (1..=readers)
        .map(|i| BufferPool::new(ShardId::new(i as u8), 1))
        .collect();
    let mut regions = vec![owner_pool.region()];
    regions.extend(reader_pools.iter().map(BufferPool::region));
    let mut ports = XsMesh::build(&regions).into_iter();
    let owner_ports = ports.next().unwrap();
    let done = AtomicBool::new(false);
    let abort = AtomicBool::new(false);
    let mismatches = AtomicU64::new(0);

    let (stats, received) = thread::scope(|scope| {
        let handles: Vec<_> = ports
            .zip(&config.readers)
            .map(|(p, &give)| {
                let (done, abort, mismatches) = (&done, &abort, &mismatches);
                scope.spawn(move || {
                    // A reader's panic stops the owner at its next round.
                    let _abort = SetOnPanic(abort);
                    reader(&p, give, done, mismatches)
                })
            })
            .collect();
        let stats = {
            // Also on a panic, so the readers stop instead of waiting out the deadline.
            let _stop = SetOnDrop(&done);
            owner(&mut owner_pool, &owner_ports, &config, &done, &abort)
        };
        let received: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        (stats, received)
    });

    assert_eq!(mismatches.load(Ordering::Relaxed), 0, "canary mismatches");
    assert_eq!(stats.lent, config.handoffs);
    assert_eq!((received, stats.returned), (stats.lent, stats.lent));
    assert_eq!(owner_pool.available(), config.pool as usize);
    assert_eq!(owner_pool.lent_total(), 0);
    for peer in owner_ports.peer_ids() {
        assert_eq!(owner_pool.in_flight(peer), 0);
    }
    if matches!(config.readers[..], [Give::AtCredit]) && !cfg!(miri) {
        assert!(stats.no_credit > 0, "the credit never ran out");
    }
    println!(
        "{} hand-offs, {} without credit, {} with the pool empty",
        stats.lent, stats.no_credit, stats.no_buffer
    );
}

/// The owner: take, write, lend to a random subset of readers, put if
/// nobody took it; drain returns every round.
fn owner(
    pool: &mut BufferPool,
    ports: &XsPorts,
    config: &Run,
    done: &AtomicBool,
    abort: &AtomicBool,
) -> OwnerStats {
    let peers: Vec<ShardId> = ports.peer_ids().collect();
    let mut generations = vec![0u64; config.pool as usize];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut stats = OwnerStats::default();
    let start = Instant::now();
    for round in 0.. {
        check_deadline(round, start, "owner");
        assert!(!abort.load(Ordering::Relaxed), "a reader panicked");
        drain_returns(pool, ports, &peers, &mut stats);
        if stats.lent >= config.handoffs {
            done.store(true, Ordering::Release);
            if pool.lent_total() == 0 {
                break;
            }
            thread::yield_now();
            continue;
        }
        let Some(buf) = pool.take() else {
            stats.no_buffer += 1;
            thread::yield_now();
            continue;
        };
        let generation = &mut generations[buf.index as usize];
        *generation += 1;
        let (generation, random) = (*generation, rng.next());
        let len = HEADER + (random as usize >> 8) % (BUF_SIZE - HEADER + 1);
        write_canary(pool.buf_mut(buf), buf, generation, len);
        let mask = (random & ((1 << peers.len()) - 1)).max(1);
        for (i, &peer) in peers.iter().enumerate() {
            if mask & (1 << i) != 0 && stats.lent < config.handoffs {
                lend_one(pool, ports, buf, peer, generation, len, &mut stats);
            }
        }
        pool.put_if_unshared(buf);
    }
    stats
}

fn lend_one(
    pool: &mut BufferPool,
    ports: &XsPorts,
    buf: BufRef,
    peer: ShardId,
    generation: u64,
    len: usize,
    stats: &mut OwnerStats,
) {
    if !pool.can_lend(peer) {
        stats.no_credit += 1;
        return;
    }
    if !ports.has_room(peer) {
        return;
    }
    let loan = pool.lend(buf, peer);
    let msg = XsMsg::Rtp {
        loan,
        len: len as u16,
        track: TrackId::new(generation),
        layer: 0,
    };
    match ports.send(peer, msg) {
        Ok(()) => stats.lent += 1,
        Err(XsMsg::Rtp { loan, .. }) => pool.unlend(loan),
        Err(other) => panic!("send handed back another message: {other:?}"),
    }
}

fn drain_returns(
    pool: &mut BufferPool,
    ports: &XsPorts,
    peers: &[ShardId],
    stats: &mut OwnerStats,
) {
    for &peer in peers {
        for _ in 0..XS_CREDIT {
            let Some(loan) = ports.take_return(peer) else {
                break;
            };
            pool.release(loan, peer);
            stats.returned += 1;
        }
    }
}

/// A loan a reader holds, with what it must still read.
struct Held {
    loan: Loan,
    generation: u64,
    len: usize,
}

/// One reader thread's state.
struct Reader<'a> {
    ports: &'a XsPorts,
    give: Give,
    held: Vec<Held>,
    mismatches: &'a AtomicU64,
}

/// A reader: check each lent packet's canary, hold loans as `give` says
/// (yielding now and then, so the owner runs meanwhile), check them again
/// and give them back. Returns the packets it received.
fn reader(ports: &XsPorts, give: Give, done: &AtomicBool, mismatches: &AtomicU64) -> u64 {
    let owner = ShardId::new(0);
    let mut r = Reader {
        ports,
        give,
        held: Vec::with_capacity(XS_CREDIT as usize),
        mismatches,
    };
    let mut received = 0u64;
    let start = Instant::now();
    for round in 0.. {
        check_deadline(round, start, "reader");
        if let Some(msg) = ports.recv(owner) {
            r.receive(msg);
            received += 1;
            let full = match give {
                Give::Each => true,
                Give::Batch(n) => r.held.len() >= n,
                Give::AtCredit => r.held.len() >= XS_CREDIT as usize,
            };
            if full {
                r.give_all();
            } else if received % 4 == 0 {
                thread::yield_now();
            }
            continue;
        }
        // Everything sent before `done` is visible after it (Release/Acquire).
        if done.load(Ordering::Acquire) {
            while let Some(msg) = ports.recv(owner) {
                r.receive(msg);
                received += 1;
            }
            r.give_all();
            break;
        }
        if !matches!(give, Give::AtCredit) {
            r.give_all();
        }
        thread::yield_now();
    }
    received
}

impl Reader<'_> {
    fn receive(&mut self, msg: XsMsg) {
        let XsMsg::Rtp {
            loan, len, track, ..
        } = msg
        else {
            panic!("unexpected message {msg:?}");
        };
        let held = Held {
            loan,
            generation: track.get(),
            len: usize::from(len),
        };
        self.check(&held);
        assert!(
            self.held.len() < self.held.capacity(),
            "reader holds more than the credit"
        );
        self.held.push(held);
    }

    /// The canary is still the one written before the loan was made.
    fn check(&self, held: &Held) {
        let region = self.ports.region(held.loan.owner());
        let bytes = region.read(&held.loan, held.len);
        if !canary_ok(bytes, held.loan.buf(), held.generation) {
            self.mismatches.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Checks every held loan again (the owner must not have reused its
    /// buffer meanwhile), then gives it back.
    fn give_all(&mut self) {
        let mut held = std::mem::take(&mut self.held);
        for h in held.drain(..) {
            if !matches!(self.give, Give::Each) {
                self.check(&h);
            }
            self.ports.give_back(h.loan);
        }
        self.held = held;
    }
}

#[test]
fn handoff_to_readers() {
    let readers = if cfg!(miri) {
        vec![Give::Batch(4)]
    } else {
        vec![Give::Each, Give::Batch(8), Give::Batch(64)]
    };
    run(Run {
        handoffs: if cfg!(miri) { 100 } else { 1_000_000 },
        pool: if cfg!(miri) { 8 } else { 64 },
        readers,
    });
}

#[test]
#[cfg_attr(miri, ignore)] // needs a pool larger than the credit (2 MB+)
fn handoff_until_the_credit_runs_out() {
    run(Run {
        handoffs: 200_000,
        pool: 2 * XS_CREDIT,
        readers: vec![Give::AtCredit],
    });
}
