//! Packet loss injection on a client's own UDP socket.
//!
//! The client's ICE agent runs over a [`LossyUdpConn`] (webrtc-rs UDP mux),
//! which drops datagrams by rule before they are sent or after they are
//! received. Loss sits on the client side of the path, so every packet
//! between the client and the SFU passes through it, whichever candidate
//! pair ICE selects; no address rewriting or root privileges are needed.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::net::UdpSocket;
use webrtc::util::Conn;

/// Most rules per connection.
pub const MAX_RULES: usize = 16;

/// Direction of a datagram, seen from the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// SFU → client.
    Inbound,
    /// Client → SFU.
    Outbound,
}

/// Datagram class by first byte (RFC 7983).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketClass {
    Stun,
    Dtls,
    /// RTP or RTCP.
    Media,
    Other,
}

impl PacketClass {
    /// Classify a datagram by its first byte.
    pub fn of(datagram: &[u8]) -> Self {
        match datagram.first() {
            Some(0..=3) => Self::Stun,
            Some(20..=63) => Self::Dtls,
            Some(128..=191) => Self::Media,
            _ => Self::Other,
        }
    }
}

/// Drop datagrams of one class and direction: let `skip` through, then drop
/// the next `drop` (u64::MAX: all), each also subject to `rate_permille`.
#[derive(Clone, Debug)]
pub struct LossRule {
    pub direction: Direction,
    pub class: PacketClass,
    pub skip: u64,
    pub drop: u64,
    /// Of the datagrams in the drop window, drop this many per 1000
    /// (1000: every one).
    pub rate_permille: u32,
}

impl LossRule {
    /// Drop the first `count` datagrams of `class` in `direction`.
    pub fn first(direction: Direction, class: PacketClass, count: u64) -> Self {
        Self {
            direction,
            class,
            skip: 0,
            drop: count,
            rate_permille: 1000,
        }
    }
}

#[derive(Debug)]
struct RuleState {
    rule: LossRule,
    seen: u64,
    dropped: u64,
}

/// Rules shared between a test and the client's socket. Rules can be added
/// while the client runs.
#[derive(Debug, Default)]
pub struct LossRules {
    rules: Mutex<Vec<RuleState>>,
    dropped_total: AtomicU64,
    passed_total: AtomicU64,
    /// Deterministic generator state for `rate_permille`.
    rng: AtomicU64,
}

impl LossRules {
    /// A rule set with no rules (nothing is dropped).
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            rng: AtomicU64::new(0x9E37_79B9_7F4A_7C15),
            ..Default::default()
        })
    }

    /// Add a rule.
    pub fn add(&self, rule: LossRule) {
        assert!(rule.rate_permille <= 1000, "rate is per mille");
        let mut rules = self.rules.lock().expect("loss rules lock");
        assert!(rules.len() < MAX_RULES, "too many loss rules");
        rules.push(RuleState {
            rule,
            seen: 0,
            dropped: 0,
        });
    }

    /// Datagrams dropped so far, by rule index.
    pub fn dropped_by_rule(&self) -> Vec<u64> {
        let rules = self.rules.lock().expect("loss rules lock");
        rules.iter().map(|r| r.dropped).collect()
    }

    /// Datagrams dropped and passed so far.
    pub fn totals(&self) -> (u64, u64) {
        (
            self.dropped_total.load(Ordering::Relaxed),
            self.passed_total.load(Ordering::Relaxed),
        )
    }

    /// Decide whether to drop `datagram` travelling in `direction`.
    pub fn should_drop(&self, direction: Direction, datagram: &[u8]) -> bool {
        let class = PacketClass::of(datagram);
        let mut drop = false;
        let mut rules = self.rules.lock().expect("loss rules lock");
        for state in rules.iter_mut() {
            if state.rule.direction != direction || state.rule.class != class {
                continue;
            }
            state.seen += 1;
            let index = state.seen - 1;
            let in_window = index >= state.rule.skip && index - state.rule.skip < state.rule.drop;
            if in_window && self.roll(state.rule.rate_permille) {
                state.dropped += 1;
                drop = true;
            }
        }
        let counter = if drop {
            &self.dropped_total
        } else {
            &self.passed_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
        drop
    }

    fn roll(&self, rate_permille: u32) -> bool {
        if rate_permille >= 1000 {
            return true;
        }
        // xorshift64: reproducible across runs.
        let mut x = self.rng.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng.store(x, Ordering::Relaxed);
        (x % 1000) < rate_permille as u64
    }
}

/// A UDP socket that applies [`LossRules`] to everything it sends and
/// receives.
pub struct LossyUdpConn {
    socket: UdpSocket,
    rules: Arc<LossRules>,
}

impl LossyUdpConn {
    /// Bind `addr` (use `0.0.0.0:0`: webrtc-rs advertises each interface
    /// address with this socket's port).
    pub async fn bind(addr: SocketAddr, rules: Arc<LossRules>) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self { socket, rules })
    }
}

#[async_trait]
impl Conn for LossyUdpConn {
    async fn connect(&self, addr: SocketAddr) -> webrtc::util::Result<()> {
        Ok(self.socket.connect(addr).await?)
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc::util::Result<usize> {
        let (n, _) = self.recv_from(buf).await?;
        Ok(n)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc::util::Result<(usize, SocketAddr)> {
        // Bounded only by the peer: every dropped datagram was received.
        loop {
            let (n, from) = self.socket.recv_from(buf).await?;
            if !self.rules.should_drop(Direction::Inbound, &buf[..n]) {
                return Ok((n, from));
            }
        }
    }

    async fn send(&self, buf: &[u8]) -> webrtc::util::Result<usize> {
        if self.rules.should_drop(Direction::Outbound, buf) {
            return Ok(buf.len());
        }
        Ok(self.socket.send(buf).await?)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc::util::Result<usize> {
        if self.rules.should_drop(Direction::Outbound, buf) {
            // Report success, as a lossy network would.
            return Ok(buf.len());
        }
        Ok(self.socket.send_to(buf, target).await?)
    }

    fn local_addr(&self) -> webrtc::util::Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }

    async fn close(&self) -> webrtc::util::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_n_by_class_and_direction() {
        let rules = LossRules::new();
        rules.add(LossRule::first(Direction::Inbound, PacketClass::Dtls, 2));
        let dtls = [22u8, 0xfe, 0xfd];
        let rtp = [0x80u8, 96];
        assert!(!rules.should_drop(Direction::Outbound, &dtls));
        assert!(!rules.should_drop(Direction::Inbound, &rtp));
        assert!(rules.should_drop(Direction::Inbound, &dtls));
        assert!(rules.should_drop(Direction::Inbound, &dtls));
        assert!(!rules.should_drop(Direction::Inbound, &dtls));
        assert_eq!(rules.dropped_by_rule(), vec![2]);
    }

    #[test]
    fn test_rate_is_roughly_honoured() {
        let rules = LossRules::new();
        rules.add(LossRule {
            direction: Direction::Inbound,
            class: PacketClass::Media,
            skip: 0,
            drop: u64::MAX,
            rate_permille: 100,
        });
        let dropped = (0..10_000)
            .filter(|_| rules.should_drop(Direction::Inbound, &[0x80]))
            .count();
        assert!((800..1200).contains(&dropped), "{dropped}");
    }

    #[test]
    fn test_classification() {
        assert_eq!(PacketClass::of(&[0]), PacketClass::Stun);
        assert_eq!(PacketClass::of(&[22]), PacketClass::Dtls);
        assert_eq!(PacketClass::of(&[0x80]), PacketClass::Media);
        assert_eq!(PacketClass::of(&[]), PacketClass::Other);
    }
}
