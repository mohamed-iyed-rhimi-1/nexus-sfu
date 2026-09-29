//! Cross-shard messages and the queue mesh (note §13.4, plan 2.1).
//!
//! Every ordered shard pair (i, j) has a media queue i → j carrying
//! [`XsMsg`] and a return queue j → i carrying i's [`Loan`]s back. Each queue
//! has one producer and one consumer. A shard never waits on a peer: a full
//! media queue is the caller's drop, and a return queue cannot fill (the
//! per-peer credit, `pool.rs` point 4).

use std::sync::Arc;

use crossbeam_queue::ArrayQueue;

use crate::ids::{ShardId, TrackId, MAX_SHARDS};
use crate::pool::{Loan, PoolRegion};

/// Capacity of each media queue.
pub const XS_RING: usize = 1_024;
/// Loans a shard may have outstanding to one peer; also the capacity of each
/// return queue, which therefore never fills.
pub const XS_CREDIT: u32 = 1_024;
/// Messages a shard handles from one peer per iteration.
pub const XS_BUDGET: usize = 256;

const _: () = assert!(XS_BUDGET <= XS_RING);
const _: () = assert!(std::mem::size_of::<XsMsg>() <= 24);

/// One message from a shard to a peer.
#[derive(Debug)]
pub enum XsMsg {
    /// A decrypted RTP packet of a local track, lent to the peer.
    Rtp {
        /// The buffer; go back through the return queue.
        loan: Loan,
        /// Packet length.
        len: u16,
        /// The published track.
        track: TrackId,
        /// Simulcast layer.
        layer: u8,
    },
    /// A publisher's sender report, for translation on the peer.
    SenderReport {
        /// The published track.
        track: TrackId,
        /// Simulcast layer.
        layer: u8,
        /// NTP timestamp.
        ntp: u64,
        /// RTP timestamp.
        rtp: u32,
    },
    /// A subscriber on shard `from` wants a keyframe of the track.
    KeyframeRequest {
        /// The published track.
        track: TrackId,
        /// Simulcast layer.
        layer: u8,
        /// The requesting shard.
        from: ShardId,
    },
}

type Queue<T> = Arc<ArrayQueue<T>>;

/// One shard's ends of the queues it shares with one peer.
struct PeerPorts {
    /// This shard → peer.
    media_tx: Queue<XsMsg>,
    /// Peer → this shard.
    media_rx: Queue<XsMsg>,
    /// The peer's loans, going back to it.
    return_tx: Queue<Loan>,
    /// This shard's loans, coming back from the peer.
    return_rx: Queue<Loan>,
    /// The peer's pool, read through its loans.
    region: Arc<PoolRegion>,
}

/// A shard's ends of the mesh, one entry per peer.
pub struct XsPorts {
    shard: ShardId,
    /// Indexed by shard index; `None` for this shard.
    peers: Box<[Option<PeerPorts>]>,
}

/// Builds the mesh.
pub struct XsMesh;

impl XsMesh {
    /// One [`XsPorts`] per shard, where `regions[i]` is shard i's pool region
    /// (startup only).
    pub fn build(regions: &[Arc<PoolRegion>]) -> Vec<XsPorts> {
        let n = regions.len();
        assert!((1..=MAX_SHARDS).contains(&n));
        for (i, region) in regions.iter().enumerate() {
            assert!(
                usize::from(region.shard().index()) == i,
                "regions out of order"
            );
        }
        // media[i][j]: i → j. returns[i][j]: i's loans coming back from j.
        let media = queues::<XsMsg>(n, XS_RING);
        let returns = queues::<Loan>(n, XS_CREDIT as usize);
        let ports: Vec<XsPorts> = (0..n)
            .map(|i| XsPorts {
                shard: ShardId::new(i as u8),
                peers: (0..n)
                    .map(|j| {
                        (i != j).then(|| PeerPorts {
                            media_tx: pick(&media, i, j),
                            media_rx: pick(&media, j, i),
                            return_tx: pick(&returns, j, i),
                            return_rx: pick(&returns, i, j),
                            region: Arc::clone(&regions[j]),
                        })
                    })
                    .collect(),
            })
            .collect();
        assert!(ports.len() == n);
        ports
    }
}

/// An n × n table of queues, without the diagonal.
fn queues<T>(n: usize, capacity: usize) -> Vec<Vec<Option<Queue<T>>>> {
    (0..n)
        .map(|i| {
            (0..n)
                .map(|j| (i != j).then(|| Arc::new(ArrayQueue::new(capacity))))
                .collect()
        })
        .collect()
}

fn pick<T>(table: &[Vec<Option<Queue<T>>>], i: usize, j: usize) -> Queue<T> {
    Arc::clone(table[i][j].as_ref().expect("no queue on the diagonal"))
}

impl XsPorts {
    /// The shard these ports belong to.
    pub fn shard(&self) -> ShardId {
        self.shard
    }

    /// The other shards.
    pub fn peer_ids(&self) -> impl Iterator<Item = ShardId> + '_ {
        self.peers
            .iter()
            .enumerate()
            .filter(|(_, p)| p.is_some())
            .map(|(i, _)| ShardId::new(i as u8))
    }

    /// `shard` is a peer of this shard (in the mesh and not itself).
    pub fn is_peer(&self, shard: ShardId) -> bool {
        self.peers
            .get(usize::from(shard.index()))
            .is_some_and(Option::is_some)
    }

    /// A message or a returned loan waits in a queue toward this shard
    /// (checked before parking; ≤ 2 × 63 loads).
    pub fn inbound_pending(&self) -> bool {
        self.peers
            .iter()
            .flatten()
            .any(|p| !p.media_rx.is_empty() || !p.return_rx.is_empty())
    }

    /// The media queue to `peer` has room. This shard is its only producer,
    /// so the room is still there at its next `send`.
    pub fn has_room(&self, peer: ShardId) -> bool {
        !self.peer(peer).media_tx.is_full()
    }

    /// Sends `msg` to `peer`; a full queue hands it back (to `unlend` its loan).
    pub fn send(&self, peer: ShardId, msg: XsMsg) -> Result<(), XsMsg> {
        self.peer(peer).media_tx.push(msg)
    }

    /// The next message from `peer`.
    pub fn recv(&self, peer: ShardId) -> Option<XsMsg> {
        self.peer(peer).media_rx.pop()
    }

    /// `peer`'s pool region, to read its loans.
    pub fn region(&self, peer: ShardId) -> &PoolRegion {
        &self.peer(peer).region
    }

    /// Gives a loan lent to this shard back to its owner. The return queue
    /// cannot be full: the owner's credit for this shard bounds the loans in
    /// it (`pool.rs` point 4), which holds only for loans lent to this shard.
    /// A full queue would leak a buffer, so it panics.
    pub fn give_back(&self, loan: Loan) {
        let owner = loan.owner();
        assert!(owner != self.shard, "give_back of an own loan");
        assert!(
            loan.peer() == self.shard,
            "give_back of a loan lent to another shard"
        );
        let pushed = self.peer(owner).return_tx.push(loan);
        assert!(pushed.is_ok(), "return queue full: a buffer would leak");
    }

    /// The next of this shard's loans that `peer` gave back.
    pub fn take_return(&self, peer: ShardId) -> Option<Loan> {
        self.peer(peer).return_rx.pop()
    }

    fn peer(&self, peer: ShardId) -> &PeerPorts {
        self.peers[usize::from(peer.index())]
            .as_ref()
            .expect("not a peer of this shard")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::BufferPool;

    fn pools(n: u8) -> (Vec<BufferPool>, Vec<XsPorts>) {
        let pools: Vec<_> = (0..n)
            .map(|i| BufferPool::new(ShardId::new(i), 4))
            .collect();
        let regions: Vec<_> = pools.iter().map(BufferPool::region).collect();
        let ports = XsMesh::build(&regions);
        (pools, ports)
    }

    #[test]
    fn message_fits_24_bytes() {
        assert!(std::mem::size_of::<XsMsg>() <= 24);
        assert_eq!(std::mem::size_of::<Loan>(), 12);
    }

    #[test]
    fn every_ordered_pair_is_wired() {
        for n in 1..=4u8 {
            let (mut pools, ports) = pools(n);
            for (i, p) in ports.iter().enumerate() {
                assert_eq!(p.shard(), ShardId::new(i as u8));
                let peers: Vec<_> = p.peer_ids().collect();
                assert_eq!(peers.len(), n as usize - 1);
                assert!(!peers.contains(&p.shard()));
            }
            for i in 0..n {
                for j in (0..n).filter(|&j| j != i) {
                    let (si, sj) = (ShardId::new(i), ShardId::new(j));
                    let pool = &mut pools[usize::from(i)];
                    let buf = pool.take().unwrap();
                    pool.buf_mut(buf)[0] = 10 * i + j;
                    let loan = pool.lend(buf, sj);
                    assert!(!pool.put_if_unshared(buf));
                    let track = TrackId::new(u64::from(i) + 1);
                    let msg = XsMsg::Rtp {
                        loan,
                        len: 1,
                        track,
                        layer: 0,
                    };
                    ports[usize::from(i)].send(sj, msg).unwrap();
                    let at_j = &ports[usize::from(j)];
                    let Some(XsMsg::Rtp { loan, len, .. }) = at_j.recv(si) else {
                        panic!("no message from {i} at {j}");
                    };
                    assert_eq!(at_j.region(si).read(&loan, len.into()), &[10 * i + j]);
                    at_j.give_back(loan);
                    let back = ports[usize::from(i)].take_return(sj).unwrap();
                    assert!(pools[usize::from(i)].release(back, sj));
                }
            }
            assert!(pools
                .iter()
                .all(|p| p.available() == 4 && p.lent_total() == 0));
        }
    }

    #[test]
    fn full_media_queue_hands_the_message_back() {
        let (mut pools, ports) = pools(2);
        let peer = ShardId::new(1);
        let pool = &mut pools[0];
        let buf = pool.take().unwrap();
        for _ in 0..XS_RING {
            let msg = XsMsg::KeyframeRequest {
                track: TrackId::new(1),
                layer: 0,
                from: ShardId::new(0),
            };
            ports[0].send(peer, msg).unwrap();
        }
        assert!(!ports[0].has_room(peer));
        let loan = pool.lend(buf, peer);
        let msg = XsMsg::Rtp {
            loan,
            len: 1,
            track: TrackId::new(1),
            layer: 0,
        };
        let Err(XsMsg::Rtp { loan, .. }) = ports[0].send(peer, msg) else {
            panic!("a full queue took the message");
        };
        pool.unlend(loan);
        assert_eq!((pool.in_flight(peer), pool.lent_total()), (0, 0));
        assert!(pool.put_if_unshared(buf));
    }

    /// Shard 0 lends a buffer to `to`; returns the pools, ports and loan.
    fn lent_to(to: u8) -> (Vec<BufferPool>, Vec<XsPorts>, Loan) {
        let (mut pools, ports) = pools(3);
        let buf = pools[0].take().unwrap();
        let loan = pools[0].lend(buf, ShardId::new(to));
        (pools, ports, loan)
    }

    #[test]
    #[should_panic(expected = "lent to another shard")]
    fn give_back_of_a_loan_lent_elsewhere_panics() {
        let (_pools, ports, loan) = lent_to(2);
        ports[1].give_back(loan);
    }

    #[test]
    #[should_panic(expected = "own loan")]
    fn give_back_of_an_own_loan_panics() {
        let (_pools, ports, loan) = lent_to(1);
        ports[0].give_back(loan);
    }

    #[test]
    fn inbound_pending_sees_media_and_returns() {
        let (mut pools, ports) = pools(3);
        let (s0, s1) = (ShardId::new(0), ShardId::new(1));
        assert!(ports.iter().all(|p| !p.inbound_pending()));
        assert!(ports[0].is_peer(s1) && !ports[0].is_peer(s0));
        assert!(!ports[0].is_peer(ShardId::new(5)));
        let buf = pools[0].take().unwrap();
        let loan = pools[0].lend(buf, s1);
        let msg = XsMsg::Rtp {
            loan,
            len: 1,
            track: TrackId::new(1),
            layer: 0,
        };
        ports[0].send(s1, msg).unwrap();
        assert!(ports[1].inbound_pending());
        assert!(!ports[0].inbound_pending() && !ports[2].inbound_pending());
        let Some(XsMsg::Rtp { loan, .. }) = ports[1].recv(s0) else {
            panic!("no message");
        };
        assert!(!ports[1].inbound_pending());
        ports[1].give_back(loan);
        assert!(ports[0].inbound_pending(), "a return is inbound work");
        let back = ports[0].take_return(s1).unwrap();
        assert!(!pools[0].release(back, s1));
        assert!(pools[0].put_if_unshared(buf));
        assert!(ports.iter().all(|p| !p.inbound_pending()));
    }

    #[test]
    #[should_panic(expected = "not a peer")]
    fn no_queue_to_itself() {
        let (_pools, ports) = pools(2);
        let _ = ports[0].has_room(ShardId::new(0));
    }
}
