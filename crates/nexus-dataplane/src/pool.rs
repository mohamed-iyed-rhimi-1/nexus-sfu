//! The shard's buffer pool (note §10.3): one allocation at startup, a free
//! stack of indices, no allocation after that.

use crate::ids::ShardId;

/// Size of every pool buffer: a 1,500-byte datagram plus header growth from
/// the rewrite and the SRTP/SRTCP trailer.
pub const BUF_SIZE: usize = 2_048;

/// Handle to one pool buffer. Phase 2 adds the owner-local refcount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufRef {
    /// Owning shard.
    pub shard: ShardId,
    /// Buffer index in the owner's pool.
    pub index: u32,
}

/// Fixed pool of `BUF_SIZE` buffers.
pub struct BufferPool {
    shard: ShardId,
    memory: Vec<u8>,
    free: Vec<u32>,
    /// Debug builds: which buffers are out, to catch double frees.
    #[cfg(debug_assertions)]
    taken: Vec<bool>,
}

impl BufferPool {
    /// Allocates `count` buffers (startup only).
    pub fn new(shard: ShardId, count: u32) -> Self {
        assert!(count > 0);
        let memory = vec![0u8; count as usize * BUF_SIZE];
        let free: Vec<u32> = (0..count).rev().collect();
        let pool = Self {
            shard,
            memory,
            free,
            #[cfg(debug_assertions)]
            taken: vec![false; count as usize],
        };
        assert!(pool.available() == count as usize);
        pool
    }

    /// Buffers in the pool.
    pub fn capacity(&self) -> usize {
        self.memory.len() / BUF_SIZE
    }

    /// Buffers not handed out.
    pub fn available(&self) -> usize {
        self.free.len()
    }

    /// Takes a buffer; `None` when the pool is empty.
    pub fn take(&mut self) -> Option<BufRef> {
        let index = self.free.pop()?;
        #[cfg(debug_assertions)]
        {
            debug_assert!(!self.taken[index as usize]);
            self.taken[index as usize] = true;
        }
        Some(BufRef {
            shard: self.shard,
            index,
        })
    }

    /// Returns a buffer taken from this pool.
    pub fn put(&mut self, buf: BufRef) {
        debug_assert!(buf.shard == self.shard);
        debug_assert!((buf.index as usize) < self.capacity());
        #[cfg(debug_assertions)]
        {
            debug_assert!(self.taken[buf.index as usize], "buffer returned twice");
            self.taken[buf.index as usize] = false;
        }
        // Never grows: the stack was allocated for every index.
        assert!(self.free.len() < self.capacity());
        self.free.push(buf.index);
    }

    /// The buffer's bytes.
    pub fn buf(&self, buf: BufRef) -> &[u8] {
        let start = buf.index as usize * BUF_SIZE;
        &self.memory[start..start + BUF_SIZE]
    }

    /// The buffer's bytes, writable.
    pub fn buf_mut(&mut self, buf: BufRef) -> &mut [u8] {
        let start = buf.index as usize * BUF_SIZE;
        &mut self.memory[start..start + BUF_SIZE]
    }

    /// One buffer to read and another to write, e.g. an ingress packet and
    /// the send buffer it is rewritten into.
    pub fn pair_mut(&mut self, read: BufRef, write: BufRef) -> (&[u8], &mut [u8]) {
        assert!(read.index != write.index);
        let (r, w) = (read.index as usize, write.index as usize);
        if r < w {
            let (low, high) = self.memory.split_at_mut(w * BUF_SIZE);
            (
                &low[r * BUF_SIZE..(r + 1) * BUF_SIZE],
                &mut high[..BUF_SIZE],
            )
        } else {
            let (low, high) = self.memory.split_at_mut(r * BUF_SIZE);
            (
                &high[..BUF_SIZE],
                &mut low[w * BUF_SIZE..(w + 1) * BUF_SIZE],
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_until_empty_then_put_back() {
        let mut pool = BufferPool::new(ShardId::new(0), 3);
        let bufs: Vec<_> = (0..3).map(|_| pool.take().unwrap()).collect();
        assert!(pool.take().is_none());
        for b in bufs {
            pool.put(b);
        }
        assert_eq!(pool.available(), 3);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "buffer returned twice")]
    fn double_free_is_caught() {
        let mut pool = BufferPool::new(ShardId::new(0), 2);
        let b = pool.take().unwrap();
        pool.put(b);
        pool.put(b);
    }

    #[test]
    fn pair_mut_gives_the_right_buffers() {
        let mut pool = BufferPool::new(ShardId::new(0), 4);
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
}
