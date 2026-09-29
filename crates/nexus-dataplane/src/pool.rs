//! The shard's buffer pool (note §10.3): one allocation at startup, a free
//! stack of indices, no allocation after that.
//!
//! Phase 2 (plan 2.1) lends buffers to other shards: the pool's bytes live in
//! a [`PoolRegion`] that peers hold as an `Arc`, and a buffer lent to a peer
//! travels as a move-only [`Loan`] until the peer gives it back.
//!
//! # Safety argument
//!
//! The region is `Sync` and hands out references into `UnsafeCell`s. It is
//! sound because:
//!
//! 1. Only the owning [`BufferPool`] forms `&mut` into its region, one cell at
//!    a time, and only for a cell with no loan (`refs`, the loan count in
//!    `BufferPool::state`, is 0; a hard `assert!`). Its
//!    `&mut self` rules out two local `&mut` to one cell, or a `&mut` next to
//!    one of its own `&`.
//! 2. Peers form `&[u8]` only through [`PoolRegion::read`], which needs a
//!    `&Loan`. A `Loan` exists only between [`BufferPool::lend`] and
//!    [`BufferPool::release`] / [`BufferPool::unlend`], so `refs > 0` while
//!    any peer can read. A `Loan` names its region by a process-unique id,
//!    and `read`, `release` and `unlend` assert it, so a loan from another
//!    pool (even one with the same `ShardId`) can neither read this region
//!    nor change its counts.
//! 3. Owner writes → `lend` → queue push (Release) → peer pop (Acquire) →
//!    reads. The reads end with the borrow of the `Loan`; the peer then moves
//!    it into the return queue (Release) → owner pop (Acquire) → `release` →
//!    `put` → next writes. Every write is ordered after every peer read of the
//!    previous use.
//! 4. `in_flight[j]` counts every loan the peer j holds, has queued or is
//!    returning; it stays below `XS_CREDIT`, the return queue's capacity, so
//!    that queue never fills. The count is per `loan.peer`, so
//!    `XsPorts::give_back` asserts that the loan was lent to the giving shard,
//!    and that the push succeeds.
//!
//! A buffer goes back on the free stack only when it is neither held locally
//! (`take` to `put`/`put_if_unshared`) nor lent, whichever ends last; so the
//! order of a return and the holder's put never frees it twice.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::ids::{ShardId, MAX_SHARDS};
use crate::xs::XS_CREDIT;

/// Size of every pool buffer: a 1,500-byte datagram plus header growth from
/// the rewrite and the SRTP/SRTCP trailer.
pub const BUF_SIZE: usize = 2_048;

/// Next region id; 0 is never used.
static NEXT_REGION: AtomicU32 = AtomicU32::new(1);

/// A process-unique region id (startup only).
fn next_region_id() -> u32 {
    let id = NEXT_REGION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("pool region ids exhausted");
    assert!(id != 0);
    id
}

/// Handle to one buffer of the local pool. Its refcount lives in the pool;
/// a buffer lent to another shard travels as a [`Loan`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufRef {
    /// Owning shard.
    pub shard: ShardId,
    /// Buffer index in the owner's pool.
    pub index: u32,
}

/// One buffer lent to a peer shard. Made only by [`BufferPool::lend`]; not
/// `Clone`, so reading it ([`PoolRegion::read`]) ends when it is given back.
/// A loan dropped without being returned leaks its buffer.
#[must_use = "a loan must go back to its owner, or its buffer leaks"]
#[derive(Debug)]
pub struct Loan {
    index: u32,
    region: u32,
    owner: ShardId,
    peer: ShardId,
}

impl Loan {
    /// The buffer, as the owner names it.
    pub fn buf(&self) -> BufRef {
        BufRef {
            shard: self.owner,
            index: self.index,
        }
    }

    /// The owning shard.
    pub fn owner(&self) -> ShardId {
        self.owner
    }

    /// The shard it is lent to.
    pub fn peer(&self) -> ShardId {
        self.peer
    }
}

/// A pool's bytes, one `UnsafeCell` per buffer, readable by peers through a
/// [`Loan`] (see the safety argument above).
pub struct PoolRegion {
    id: u32,
    shard: ShardId,
    cells: Box<[UnsafeCell<[u8; BUF_SIZE]>]>,
}

// SAFETY: the owner writes a cell only while no loan of it exists, and peers
// read a cell only through a loan (points 1-3 of the module's argument).
#[allow(unsafe_code)]
unsafe impl Sync for PoolRegion {}

impl PoolRegion {
    fn new(shard: ShardId, count: u32) -> Self {
        let cells: Box<[_]> = std::iter::repeat_with(|| UnsafeCell::new([0u8; BUF_SIZE]))
            .take(count as usize)
            .collect();
        assert!(cells.len() == count as usize);
        Self {
            id: next_region_id(),
            shard,
            cells,
        }
    }

    /// Process-unique id.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Owning shard.
    pub fn shard(&self) -> ShardId {
        self.shard
    }

    /// Buffers in the region.
    pub fn len(&self) -> usize {
        self.cells.len()
    }

    /// Never true: a pool has at least one buffer.
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// The first `len` bytes of a lent buffer. Panics on a loan of another
    /// region.
    #[allow(unsafe_code)]
    pub fn read<'a>(&'a self, loan: &'a Loan, len: usize) -> &'a [u8] {
        assert!(loan.region == self.id, "loan of another pool region");
        assert!(len <= BUF_SIZE);
        let cell = self.cell(loan.index);
        // SAFETY: the loan keeps `refs > 0`, so the owner forms no `&mut` to
        // this cell while the returned slice (which borrows the loan) lives.
        let bytes = unsafe { &*cell };
        &bytes[..len]
    }

    /// Pointer to one cell; bounds-checked.
    fn cell(&self, index: u32) -> *mut [u8; BUF_SIZE] {
        self.cells[index as usize].get()
    }
}

/// Fixed pool of `BUF_SIZE` buffers with owner-local refcounts for lending.
pub struct BufferPool {
    shard: ShardId,
    region: Arc<PoolRegion>,
    free: Vec<u32>,
    /// Per buffer, owner-local (note §13.4 item 2): the loans outstanding
    /// (`LOANS` bits) and whether a local holder has it (`HELD`, from `take`
    /// to `put`/`put_if_unshared`). A buffer goes back on the free stack when
    /// its state is 0, by whichever of the holder or the last loan ends last.
    /// One word, so `take` and `put` are one load, compare and store.
    state: Box<[u16]>,
    /// Loans outstanding per peer.
    in_flight: [u32; MAX_SHARDS],
    /// Sum of `in_flight`.
    lent: u32,
}

/// `BufferPool::state`: a local holder has the buffer.
const HELD: u16 = 1 << 15;
/// `BufferPool::state`: loans outstanding.
const LOANS: u16 = HELD - 1;

/// The failed check of `put`, off the hot path.
#[cold]
#[inline(never)]
fn put_refused(state: u16) -> ! {
    if state & LOANS != 0 {
        panic!("put of a lent buffer");
    }
    panic!("buffer returned twice");
}

impl BufferPool {
    /// Allocates `count` buffers (startup only).
    pub fn new(shard: ShardId, count: u32) -> Self {
        assert!(count > 0);
        let free: Vec<u32> = (0..count).rev().collect();
        let pool = Self {
            shard,
            region: Arc::new(PoolRegion::new(shard, count)),
            free,
            state: vec![0; count as usize].into_boxed_slice(),
            in_flight: [0; MAX_SHARDS],
            lent: 0,
        };
        assert!(pool.available() == count as usize);
        pool
    }

    /// Buffers in the pool.
    pub fn capacity(&self) -> usize {
        self.region.len()
    }

    /// Buffers not handed out.
    pub fn available(&self) -> usize {
        self.free.len()
    }

    /// The region, for peers (startup only).
    pub fn region(&self) -> Arc<PoolRegion> {
        Arc::clone(&self.region)
    }

    /// Takes a buffer; `None` when the pool is empty.
    pub fn take(&mut self) -> Option<BufRef> {
        let index = self.free.pop()?;
        let state = &mut self.state[index as usize];
        assert!(*state == 0, "free buffer in use");
        *state = HELD;
        Some(BufRef {
            shard: self.shard,
            index,
        })
    }

    /// Returns a buffer taken from this pool; it must not be lent.
    pub fn put(&mut self, buf: BufRef) {
        debug_assert!(buf.shard == self.shard);
        let state = &mut self.state[buf.index as usize];
        if *state != HELD {
            put_refused(*state);
        }
        *state = 0;
        self.push_free(buf.index);
    }

    /// Ends the local hold on `buf`: frees it unless it is lent, and then the
    /// last loan to end frees it. Says whether it freed the buffer.
    pub fn put_if_unshared(&mut self, buf: BufRef) -> bool {
        debug_assert!(buf.shard == self.shard);
        let state = &mut self.state[buf.index as usize];
        assert!(*state & HELD != 0, "buffer returned twice");
        *state &= !HELD;
        self.free_if_done(buf.index)
    }

    /// The buffer's bytes (the owner may read a lent buffer).
    #[allow(unsafe_code)]
    pub fn buf(&self, buf: BufRef) -> &[u8] {
        debug_assert!(buf.shard == self.shard);
        let cell = self.region.cell(buf.index);
        // SAFETY: `&self` excludes this pool's `&mut` (point 1); peers only read.
        unsafe { &*cell }
    }

    /// The buffer's bytes, writable; panics if the buffer is lent.
    #[allow(unsafe_code)]
    pub fn buf_mut(&mut self, buf: BufRef) -> &mut [u8] {
        debug_assert!(buf.shard == self.shard);
        self.assert_writable(buf);
        let cell = self.region.cell(buf.index);
        // SAFETY: not lent, so no peer reads it (point 2); `&mut self`
        // excludes any other reference this pool made (point 1).
        unsafe { &mut *cell }
    }

    /// One buffer to read and another to write, e.g. an ingress packet and
    /// the send buffer it is rewritten into. The written one must not be lent.
    #[allow(unsafe_code)]
    pub fn pair_mut(&mut self, read: BufRef, write: BufRef) -> (&[u8], &mut [u8]) {
        assert!(read.index != write.index);
        debug_assert!(read.shard == self.shard && write.shard == self.shard);
        self.assert_writable(write);
        let (r, w) = (self.region.cell(read.index), self.region.cell(write.index));
        // SAFETY: two different cells; `write` is not lent and `&mut self`
        // excludes other references this pool made; `read` is only read.
        unsafe { (&*r, &mut *w) }
    }

    /// The owner may lend another buffer to `peer`.
    pub fn can_lend(&self, peer: ShardId) -> bool {
        self.in_flight[usize::from(peer.index())] < XS_CREDIT
    }

    /// Lends `buf` to `peer`; the caller has checked [`Self::can_lend`].
    pub fn lend(&mut self, buf: BufRef, peer: ShardId) -> Loan {
        debug_assert!(buf.shard == self.shard);
        assert!(peer != self.shard, "lend to its own shard");
        assert!(self.can_lend(peer), "no credit left for the peer");
        let state = &mut self.state[buf.index as usize];
        assert!(*state & HELD != 0, "lend of a buffer not held");
        assert!(*state & LOANS < LOANS);
        *state += 1;
        self.in_flight[usize::from(peer.index())] += 1;
        self.lent += 1;
        Loan {
            index: buf.index,
            region: self.region.id,
            owner: self.shard,
            peer,
        }
    }

    /// Undoes a `lend` whose message was not sent (the holder still has the
    /// buffer, so it is not freed here).
    pub fn unlend(&mut self, loan: Loan) {
        let buf = self.end_loan(loan);
        let freed = self.free_if_done(buf.index);
        debug_assert!(!freed, "unlend after the holder put the buffer back");
    }

    /// A loan given back by `from`: frees the buffer if it was the last loan
    /// and no local holder has it; says whether it did.
    pub fn release(&mut self, loan: Loan, from: ShardId) -> bool {
        debug_assert!(loan.peer == from, "loan returned by the wrong peer");
        let buf = self.end_loan(loan);
        self.free_if_done(buf.index)
    }

    /// Loans outstanding to `peer`.
    pub fn in_flight(&self, peer: ShardId) -> u32 {
        self.in_flight[usize::from(peer.index())]
    }

    /// Loans outstanding to all peers.
    pub fn lent_total(&self) -> u32 {
        self.lent
    }

    /// Ends one loan: its buffer's refcount and its peer's count go down.
    fn end_loan(&mut self, loan: Loan) -> BufRef {
        assert!(loan.region == self.region.id, "loan of another pool region");
        debug_assert!(loan.owner == self.shard);
        let peer = usize::from(loan.peer.index());
        let state = &mut self.state[loan.index as usize];
        assert!(*state & LOANS > 0 && self.in_flight[peer] > 0 && self.lent > 0);
        *state -= 1;
        self.in_flight[peer] -= 1;
        self.lent -= 1;
        loan.buf()
    }

    /// Pushes the buffer on the free stack once it is neither held nor lent.
    fn free_if_done(&mut self, index: u32) -> bool {
        let done = self.state[index as usize] == 0;
        if done {
            self.push_free(index);
        }
        done
    }

    /// Pushes a buffer whose state just became 0 on the free stack.
    fn push_free(&mut self, index: u32) {
        // Never grows: the stack was allocated for every index, and a buffer
        // is pushed only on its transition to state 0.
        assert!(self.free.len() < self.capacity());
        self.free.push(index);
    }

    /// Soundness guard for every `&mut` into the region (point 1).
    fn assert_writable(&self, buf: BufRef) {
        let lent = self.state[buf.index as usize] & LOANS != 0;
        assert!(!lent, "write to a lent buffer");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shard(i: u8) -> ShardId {
        ShardId::new(i)
    }

    #[test]
    fn take_until_empty_then_put_back() {
        let mut pool = BufferPool::new(shard(0), 3);
        let bufs: Vec<_> = (0..3).map(|_| pool.take().unwrap()).collect();
        assert!(pool.take().is_none());
        for b in bufs {
            pool.put(b);
        }
        assert_eq!(pool.available(), 3);
    }

    #[test]
    #[should_panic(expected = "buffer returned twice")]
    fn double_free_is_caught() {
        let mut pool = BufferPool::new(shard(0), 2);
        let b = pool.take().unwrap();
        pool.put(b);
        pool.put(b);
    }

    #[test]
    fn pair_mut_gives_the_right_buffers() {
        let mut pool = BufferPool::new(shard(0), 4);
        let a = pool.take().unwrap();
        let b = pool.take().unwrap();
        pool.buf_mut(a)[0] = 1;
        pool.buf_mut(b)[0] = 2;
        for (r, w) in [(a, b), (b, a)] {
            let expected = pool.buf(r)[0];
            let (read, write) = pool.pair_mut(r, w);
            assert_eq!(read[0], expected);
            write[1] = 9;
            assert_eq!(read.len(), BUF_SIZE);
            assert_eq!(write.len(), BUF_SIZE);
        }
        assert_eq!(pool.buf(a)[1], 9);
        assert_eq!(pool.buf(b)[1], 9);
    }

    #[test]
    fn region_ids_are_unique() {
        let a = BufferPool::new(shard(0), 1);
        let b = BufferPool::new(shard(0), 1);
        assert_ne!(a.region().id(), b.region().id());
        assert_ne!(a.region().id(), 0);
    }

    #[test]
    fn lend_then_release_frees_the_buffer() {
        let mut pool = BufferPool::new(shard(0), 2);
        let buf = pool.take().unwrap();
        pool.buf_mut(buf)[..3].copy_from_slice(b"abc");
        let loan = pool.lend(buf, shard(1));
        assert_eq!(
            (loan.buf(), loan.owner(), loan.peer()),
            (buf, shard(0), shard(1))
        );
        assert_eq!((pool.in_flight(shard(1)), pool.lent_total()), (1, 1));
        assert!(!pool.put_if_unshared(buf));
        assert_eq!(pool.region().read(&loan, 3), b"abc");
        assert!(pool.release(loan, shard(1)));
        assert_eq!((pool.in_flight(shard(1)), pool.lent_total()), (0, 0));
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn released_at_the_last_loan_only() {
        let mut pool = BufferPool::new(shard(0), 1);
        let buf = pool.take().unwrap();
        let one = pool.lend(buf, shard(1));
        let two = pool.lend(buf, shard(2));
        assert!(!pool.put_if_unshared(buf));
        assert!(!pool.release(two, shard(2)));
        assert_eq!(pool.available(), 0);
        assert!(pool.release(one, shard(1)));
        assert_eq!(pool.available(), 1);
    }

    /// Takes every buffer and checks that none comes out twice.
    fn assert_free_stack_distinct(pool: &mut BufferPool) {
        let mut seen = vec![false; pool.capacity()];
        let bufs: Vec<_> = std::iter::from_fn(|| pool.take()).collect();
        for b in &bufs {
            assert!(
                !std::mem::replace(&mut seen[b.index as usize], true),
                "freed twice"
            );
        }
        assert_eq!(bufs.len(), pool.capacity());
        for b in bufs {
            pool.put(b);
        }
    }

    #[test]
    fn released_while_held_frees_once_at_the_holder() {
        let mut pool = BufferPool::new(shard(0), 2);
        let buf = pool.take().unwrap();
        let loan = pool.lend(buf, shard(1));
        // The peer returns it before the holder is done with it.
        assert!(!pool.release(loan, shard(1)));
        assert_eq!(pool.available(), 1);
        assert!(pool.put_if_unshared(buf));
        assert_eq!(pool.available(), 2);
        assert_free_stack_distinct(&mut pool);
    }

    #[test]
    fn held_then_released_frees_once_at_the_loan() {
        let mut pool = BufferPool::new(shard(0), 2);
        let buf = pool.take().unwrap();
        let loan = pool.lend(buf, shard(1));
        assert!(!pool.put_if_unshared(buf));
        assert_eq!(pool.available(), 1);
        assert!(pool.release(loan, shard(1)));
        assert_eq!(pool.available(), 2);
        assert_free_stack_distinct(&mut pool);
    }

    #[test]
    #[should_panic(expected = "not held")]
    fn lend_after_the_holder_put_it_back_panics() {
        let (mut pool, buf, _loan) = lent_pool();
        assert!(!pool.put_if_unshared(buf));
        let _ = pool.lend(buf, shard(2));
    }

    #[test]
    fn unlend_restores_the_counts_without_freeing() {
        let mut pool = BufferPool::new(shard(0), 1);
        let buf = pool.take().unwrap();
        let loan = pool.lend(buf, shard(3));
        pool.unlend(loan);
        assert_eq!((pool.in_flight(shard(3)), pool.lent_total()), (0, 0));
        assert_eq!(pool.available(), 0);
        pool.buf_mut(buf)[0] = 1;
        assert!(pool.put_if_unshared(buf));
        assert_eq!(pool.available(), 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // 2 MB of cells: slow under Miri
    fn credit_runs_out_at_xs_credit() {
        let mut pool = BufferPool::new(shard(0), XS_CREDIT + 1);
        let peer = shard(1);
        let mut loans = Vec::new();
        while pool.can_lend(peer) {
            let buf = pool.take().unwrap();
            loans.push(pool.lend(buf, peer));
            assert!(!pool.put_if_unshared(buf));
        }
        assert_eq!(loans.len() as u32, XS_CREDIT);
        assert!(pool.can_lend(shard(2)));
        let back = loans.pop().unwrap();
        pool.release(back, peer);
        assert!(pool.can_lend(peer));
        for loan in loans {
            pool.release(loan, peer);
        }
        assert_eq!(pool.available(), (XS_CREDIT + 1) as usize);
    }

    #[test]
    #[should_panic(expected = "no credit left")]
    #[cfg_attr(miri, ignore)] // 2 MB of cells: slow under Miri
    fn lend_without_credit_panics() {
        let mut pool = BufferPool::new(shard(0), XS_CREDIT + 1);
        let mut loans = Vec::new();
        for _ in 0..=XS_CREDIT {
            let buf = pool.take().unwrap();
            loans.push(pool.lend(buf, shard(1)));
        }
    }

    fn lent_pool() -> (BufferPool, BufRef, Loan) {
        let mut pool = BufferPool::new(shard(0), 3);
        let buf = pool.take().unwrap();
        let loan = pool.lend(buf, shard(1));
        (pool, buf, loan)
    }

    #[test]
    #[should_panic(expected = "put of a lent buffer")]
    fn put_of_a_lent_buffer_panics() {
        let (mut pool, buf, _loan) = lent_pool();
        pool.put(buf);
    }

    #[test]
    #[should_panic(expected = "write to a lent buffer")]
    fn buf_mut_of_a_lent_buffer_panics() {
        let (mut pool, buf, _loan) = lent_pool();
        pool.buf_mut(buf)[0] = 1;
    }

    #[test]
    #[should_panic(expected = "write to a lent buffer")]
    fn pair_mut_writing_a_lent_buffer_panics() {
        let (mut pool, buf, _loan) = lent_pool();
        let other = pool.take().unwrap();
        let _ = pool.pair_mut(other, buf);
    }

    #[test]
    #[should_panic(expected = "lend to its own shard")]
    fn lend_to_itself_panics() {
        let mut pool = BufferPool::new(shard(2), 1);
        let buf = pool.take().unwrap();
        let _ = pool.lend(buf, shard(2));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "wrong peer")]
    fn release_from_the_wrong_peer_is_caught() {
        let (mut pool, _, loan) = lent_pool();
        pool.release(loan, shard(2));
    }

    #[test]
    #[should_panic(expected = "another pool region")]
    fn read_with_a_loan_of_another_pool_panics() {
        let (_pool, _, loan) = lent_pool();
        let other = BufferPool::new(shard(0), 3);
        let _ = other.region().read(&loan, 1);
    }

    #[test]
    #[should_panic(expected = "another pool region")]
    fn release_of_a_loan_of_another_pool_panics() {
        let (_pool, _, loan) = lent_pool();
        let mut other = BufferPool::new(shard(0), 3);
        let buf = other.take().unwrap();
        let _held = other.lend(buf, shard(1));
        other.release(loan, shard(1));
    }

    #[test]
    #[should_panic(expected = "another pool region")]
    fn unlend_of_a_loan_of_another_pool_panics() {
        let (_pool, _, loan) = lent_pool();
        let mut other = BufferPool::new(shard(0), 3);
        let buf = other.take().unwrap();
        let _held = other.lend(buf, shard(1));
        other.unlend(loan);
    }

    #[test]
    fn owner_writes_others_while_a_peer_reads_a_loan() {
        let mut pool = BufferPool::new(shard(0), 3);
        let lent = pool.take().unwrap();
        pool.buf_mut(lent)[..4].copy_from_slice(b"lent");
        let loan = pool.lend(lent, shard(1));
        let region = pool.region();
        let seen = region.read(&loan, 4);
        let (a, b) = (pool.take().unwrap(), pool.take().unwrap());
        pool.buf_mut(a)[0] = 7;
        let (read_lent, write) = pool.pair_mut(lent, b);
        write[..4].copy_from_slice(&read_lent[..4]);
        assert_eq!(seen, b"lent");
        assert_eq!(&pool.buf(b)[..4], b"lent");
        assert!(!pool.put_if_unshared(lent));
        assert!(pool.release(loan, shard(1)));
        pool.put(a);
        pool.put(b);
        assert_eq!(pool.available(), 3);
    }
}
