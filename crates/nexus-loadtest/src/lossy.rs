//! Packet loss injection on a client's own UDP socket.
//!
//! The client's ICE agent runs over a [`LossyUdpConn`] (webrtc-rs UDP mux),
//! which drops datagrams by rule before they are sent or after they are
//! received. Loss sits on the client side of the path, so every packet
//! between the client and the SFU passes through it, whichever candidate
//! pair ICE selects; no address rewriting or root privileges are needed.
//!
//! [`LossRules::rebind`] moves the connection to a new local port while ICE
//! keeps running, which is what a NAT rebinding looks like to the SFU.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
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
    /// Leading bytes of the first datagram this rule dropped.
    first_dropped: Option<Vec<u8>>,
}

/// Bytes of a dropped datagram kept by [`LossRules::first_dropped`].
const DROPPED_SAMPLE_BYTES: usize = 32;

/// Trailer bytes an SRTCP tap entry keeps: enough for E+index before a 10-byte
/// AES-CM tag, and for E+index after a GCM tag.
const SRTCP_TRAILER: usize = 14;

/// Where SRTCP carries its E flag and index (RFC 3711 §3.4, RFC 7714 §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrtcpLayout {
    /// AEAD: E+index is the last word, after the tag.
    Gcm,
    /// AES_CM_128_HMAC_SHA1_80: E+index precedes the 10-byte tag.
    AesCm80,
}

/// One inbound SRTP or SRTCP datagram, from its cleartext fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TapEntry {
    Srtp {
        ssrc: u32,
        seq: u16,
    },
    Srtcp {
        sender_ssrc: u32,
        /// The datagram's last bytes; see [`TapEntry::srtcp_e_index`].
        trailer: [u8; SRTCP_TRAILER],
    },
}

impl TapEntry {
    /// Classify a datagram: SRTP (RTP version 2, not an RTCP packet type) or
    /// SRTCP (packet type 192-223, RFC 5761). Anything else, or too short, is `None`.
    pub fn of(datagram: &[u8]) -> Option<Self> {
        if datagram.len() < 12 || datagram[0] >> 6 != 2 {
            return None;
        }
        let word = |at: usize| u32::from_be_bytes(datagram[at..at + 4].try_into().unwrap());
        if (192..=223).contains(&datagram[1]) {
            // 8-byte header, E+index, a 10-byte tag at least.
            if datagram.len() < 8 + 4 + 10 {
                return None;
            }
            let mut trailer = [0u8; SRTCP_TRAILER];
            trailer.copy_from_slice(&datagram[datagram.len() - SRTCP_TRAILER..]);
            return Some(Self::Srtcp {
                sender_ssrc: word(4),
                trailer,
            });
        }
        Some(Self::Srtp {
            ssrc: word(8),
            seq: u16::from_be_bytes([datagram[2], datagram[3]]),
        })
    }

    /// The E+index word of an SRTCP entry under `layout` (E is the top bit).
    pub fn srtcp_e_index(&self, layout: SrtcpLayout) -> Option<u32> {
        let Self::Srtcp { trailer, .. } = self else {
            return None;
        };
        let at = match layout {
            SrtcpLayout::Gcm => SRTCP_TRAILER - 4,
            SrtcpLayout::AesCm80 => 0,
        };
        Some(u32::from_be_bytes(trailer[at..at + 4].try_into().unwrap()))
    }
}

/// Most round boundaries a tap records.
pub const MAX_TAP_MARKS: usize = 64;

/// Bounded record of inbound media datagrams that passed the rules.
#[derive(Debug, Default)]
struct Tap {
    entries: Vec<TapEntry>,
    capacity: usize,
    overflow: u64,
    /// Entry counts at each [`LossRules::mark_tap`].
    marks: Vec<usize>,
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
    /// Inbound SRTP/SRTCP record, once enabled.
    tap: Mutex<Option<Tap>>,
    /// The socket of the connection these rules apply to, once bound.
    slot: Mutex<Option<Arc<SocketSlot>>>,
}

/// Most sockets a connection is rebound to.
pub const MAX_REBINDS: usize = 8;

/// The connection's current socket, swappable while receives are pending.
#[derive(Debug)]
struct SocketSlot {
    socket: ArcSwap<UdpSocket>,
    /// Wakes pending receives after a swap.
    swapped: Notify,
    /// Sockets rebound away from, kept open: datagrams to an old port are
    /// counted and discarded, as behind a NAT whose mapping changed.
    retired: Mutex<Vec<Arc<UdpSocket>>>,
    /// Datagrams that reached a retired socket, and when the last one did.
    retired_rx: Mutex<(u64, Option<std::time::Instant>)>,
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
            first_dropped: None,
        });
    }

    /// Datagrams dropped so far, by rule index.
    pub fn dropped_by_rule(&self) -> Vec<u64> {
        let rules = self.rules.lock().expect("loss rules lock");
        rules.iter().map(|r| r.dropped).collect()
    }

    /// Leading bytes (up to 32) of the first datagram rule `index` dropped,
    /// so a test can check it dropped what it meant to.
    pub fn first_dropped(&self, index: usize) -> Option<Vec<u8>> {
        let rules = self.rules.lock().expect("loss rules lock");
        rules.get(index).and_then(|r| r.first_dropped.clone())
    }

    /// Datagrams dropped and passed so far.
    pub fn totals(&self) -> (u64, u64) {
        (
            self.dropped_total.load(Ordering::Relaxed),
            self.passed_total.load(Ordering::Relaxed),
        )
    }

    /// Record every inbound SRTP and SRTCP datagram that is not dropped, up to
    /// `capacity` entries (later ones are counted in [`LossRules::tap`]).
    pub fn enable_tap(&self, capacity: usize) {
        assert!(capacity > 0);
        let mut tap = self.tap.lock().expect("tap lock");
        assert!(tap.is_none(), "tap already enabled");
        *tap = Some(Tap {
            entries: Vec::with_capacity(capacity),
            capacity,
            overflow: 0,
            marks: Vec::new(),
        });
    }

    /// The tap's entries in arrival order, and how many did not fit.
    pub fn tap(&self) -> (Vec<TapEntry>, u64) {
        let tap = self.tap.lock().expect("tap lock");
        tap.as_ref()
            .map_or((Vec::new(), 0), |t| (t.entries.clone(), t.overflow))
    }

    /// Start a new round: entries recorded from now on belong to it (see
    /// [`LossRules::tap_rounds`]).
    pub fn mark_tap(&self) {
        let mut tap = self.tap.lock().expect("tap lock");
        let tap = tap.as_mut().expect("tap enabled");
        assert!(tap.marks.len() < MAX_TAP_MARKS, "too many tap marks");
        assert_eq!(tap.overflow, 0, "rounds of a full tap are meaningless");
        tap.marks.push(tap.entries.len());
    }

    /// The tap's entries split at the marks: element 0 is what arrived before
    /// the first mark, element i what arrived from mark i on.
    pub fn tap_rounds(&self) -> Vec<Vec<TapEntry>> {
        let tap = self.tap.lock().expect("tap lock");
        let Some(tap) = tap.as_ref() else {
            return Vec::new();
        };
        let mut bounds = vec![0];
        bounds.extend(&tap.marks);
        bounds.push(tap.entries.len());
        bounds
            .windows(2)
            .map(|w| tap.entries[w[0]..w[1]].to_vec())
            .collect()
    }

    fn record_inbound(&self, datagram: &[u8]) {
        let mut tap = self.tap.lock().expect("tap lock");
        let Some(tap) = tap.as_mut() else {
            return;
        };
        let Some(entry) = TapEntry::of(datagram) else {
            return;
        };
        if tap.entries.len() < tap.capacity {
            tap.entries.push(entry);
        } else {
            tap.overflow += 1;
        }
    }

    /// Move the connection to a fresh socket on a new local port (NAT
    /// rebinding): later sends leave from it and pending receives move to it.
    /// ICE is not told; its candidate keeps the old port. Returns the new
    /// local address.
    pub async fn rebind(&self) -> std::io::Result<SocketAddr> {
        let slot = self.slot.lock().expect("slot lock").clone();
        let slot = slot.expect("rebind needs a bound LossyUdpConn");
        let socket = Arc::new(UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?);
        let local = socket.local_addr()?;
        let old = {
            let mut retired = slot.retired.lock().expect("retired lock");
            assert!(retired.len() < MAX_REBINDS, "too many rebinds");
            let old = slot.socket.swap(socket);
            retired.push(Arc::clone(&old));
            old
        };
        slot.swapped.notify_waiters();
        // Count what still arrives at the old port; ends with the runtime.
        let counter = Arc::clone(&slot);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while old.recv_from(&mut buf).await.is_ok() {
                let mut rx = counter.retired_rx.lock().expect("retired rx lock");
                *rx = (rx.0 + 1, Some(std::time::Instant::now()));
            }
        });
        Ok(local)
    }

    /// Datagrams that arrived at a port the connection was rebound away from,
    /// and when the last one arrived.
    pub fn retired_received(&self) -> (u64, Option<std::time::Instant>) {
        let slot = self.slot.lock().expect("slot lock").clone();
        slot.map_or((0, None), |s| {
            *s.retired_rx.lock().expect("retired rx lock")
        })
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
                if state.first_dropped.is_none() {
                    let len = datagram.len().min(DROPPED_SAMPLE_BYTES);
                    state.first_dropped = Some(datagram[..len].to_vec());
                }
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
    slot: Arc<SocketSlot>,
    rules: Arc<LossRules>,
}

impl LossyUdpConn {
    /// Bind `addr` (use `0.0.0.0:0`: webrtc-rs advertises each interface
    /// address with this socket's port). One connection per rule set.
    pub async fn bind(addr: SocketAddr, rules: Arc<LossRules>) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let slot = Arc::new(SocketSlot {
            socket: ArcSwap::from_pointee(socket),
            swapped: Notify::new(),
            retired: Mutex::new(Vec::new()),
            retired_rx: Mutex::new((0, None)),
        });
        let mut registered = rules.slot.lock().expect("slot lock");
        assert!(registered.is_none(), "one connection per LossRules");
        *registered = Some(Arc::clone(&slot));
        drop(registered);
        Ok(Self { slot, rules })
    }

    fn socket(&self) -> Arc<UdpSocket> {
        self.slot.socket.load_full()
    }

    /// One datagram from the current socket; `None` if the socket was swapped
    /// while waiting (the caller retries on the new one).
    async fn recv_current(&self, buf: &mut [u8]) -> Option<std::io::Result<(usize, SocketAddr)>> {
        let notified = self.slot.swapped.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let socket = self.socket();
        if !Arc::ptr_eq(&socket, &self.slot.socket.load()) {
            return None; // swapped before the notification was armed
        }
        tokio::select! {
            received = socket.recv_from(buf) => Some(received),
            _ = &mut notified => None,
        }
    }
}

#[async_trait]
impl Conn for LossyUdpConn {
    async fn connect(&self, addr: SocketAddr) -> webrtc::util::Result<()> {
        Ok(self.socket().connect(addr).await?)
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc::util::Result<usize> {
        let (n, _) = self.recv_from(buf).await?;
        Ok(n)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc::util::Result<(usize, SocketAddr)> {
        // Bounded only by the peer (every dropped datagram was received) and
        // by MAX_REBINDS swaps. A swap never surfaces as an error: webrtc-ice's
        // UDP mux stops for good on any receive error but a timeout.
        loop {
            let Some(received) = self.recv_current(buf).await else {
                continue;
            };
            let (n, from) = received?;
            if !self.rules.should_drop(Direction::Inbound, &buf[..n]) {
                self.rules.record_inbound(&buf[..n]);
                return Ok((n, from));
            }
        }
    }

    async fn send(&self, buf: &[u8]) -> webrtc::util::Result<usize> {
        if self.rules.should_drop(Direction::Outbound, buf) {
            return Ok(buf.len());
        }
        Ok(self.socket().send(buf).await?)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc::util::Result<usize> {
        if self.rules.should_drop(Direction::Outbound, buf) {
            // Report success, as a lossy network would.
            return Ok(buf.len());
        }
        Ok(self.socket().send_to(buf, target).await?)
    }

    fn local_addr(&self) -> webrtc::util::Result<SocketAddr> {
        Ok(self.socket().local_addr()?)
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

    fn srtcp(len: usize) -> Vec<u8> {
        let mut d = vec![0u8; len];
        d[0] = 0x80;
        d[1] = 200; // SR
        d[4..8].copy_from_slice(&0xAABB_CCDDu32.to_be_bytes());
        d
    }

    #[test]
    fn tap_entry_parses_srtp_and_srtcp() {
        let mut rtp = vec![0u8; 20];
        rtp[0] = 0x80;
        rtp[1] = 96;
        rtp[2..4].copy_from_slice(&513u16.to_be_bytes());
        rtp[8..12].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        assert_eq!(
            TapEntry::of(&rtp),
            Some(TapEntry::Srtp {
                ssrc: 0x0102_0304,
                seq: 513
            })
        );

        // GCM: ... tag(16) | E+index.
        let mut gcm = srtcp(8 + 28 + 16 + 4);
        let n = gcm.len();
        gcm[n - 4..].copy_from_slice(&0x8000_0007u32.to_be_bytes());
        let entry = TapEntry::of(&gcm).unwrap();
        assert!(matches!(
            entry,
            TapEntry::Srtcp {
                sender_ssrc: 0xAABB_CCDD,
                ..
            }
        ));
        assert_eq!(entry.srtcp_e_index(SrtcpLayout::Gcm), Some(0x8000_0007));

        // AES-CM: ... | E+index | tag(10).
        let mut cm = srtcp(8 + 28 + 4 + 10);
        let n = cm.len();
        cm[n - 14..n - 10].copy_from_slice(&0x8000_0009u32.to_be_bytes());
        let entry = TapEntry::of(&cm).unwrap();
        assert_eq!(entry.srtcp_e_index(SrtcpLayout::AesCm80), Some(0x8000_0009));
    }

    #[test]
    fn tap_entry_refuses_what_is_not_srtp() {
        assert_eq!(TapEntry::of(&[]), None);
        assert_eq!(
            TapEntry::of(&[0x80; 11]),
            None,
            "shorter than an RTP header"
        );
        assert_eq!(TapEntry::of(&[0x00; 20]), None, "STUN");
        assert_eq!(TapEntry::of(&[22; 20]), None, "DTLS");
        assert_eq!(
            TapEntry::of(&srtcp(21)),
            None,
            "SRTCP without room for a tag"
        );
        let rtp = TapEntry::Srtp { ssrc: 1, seq: 1 };
        assert_eq!(rtp.srtcp_e_index(SrtcpLayout::Gcm), None);
    }

    #[test]
    fn tap_is_bounded_and_records_media_only() {
        let rules = LossRules::new();
        assert_eq!(rules.tap(), (Vec::new(), 0), "off until enabled");
        rules.enable_tap(2);
        let rtp = [0x80u8, 96, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5];
        for _ in 0..3 {
            rules.record_inbound(&rtp);
        }
        rules.record_inbound(&[0u8; 20]); // STUN: not recorded, not counted
        let (entries, overflow) = rules.tap();
        assert_eq!((entries.len(), overflow), (2, 1));
    }

    #[tokio::test]
    async fn rebind_moves_a_pending_receive_and_the_source_port() {
        let rules = LossRules::new();
        let conn = Arc::new(
            LossyUdpConn::bind("127.0.0.1:0".parse().unwrap(), Arc::clone(&rules))
                .await
                .unwrap(),
        );
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let old = conn.local_addr().unwrap();

        // A receive pending on the old socket when the swap happens.
        let receiver = Arc::clone(&conn);
        let pending = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let (n, from) = receiver.recv_from(&mut buf).await.unwrap();
            (buf[..n].to_vec(), from)
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let new = rules.rebind().await.unwrap();
        assert_ne!(new.port(), old.port());
        assert_eq!(conn.local_addr().unwrap().port(), new.port());

        // Sent to the old port: never delivered, only counted. To the new
        // one: delivered.
        peer.send_to(b"old", ("127.0.0.1", old.port()))
            .await
            .unwrap();
        peer.send_to(b"new", ("127.0.0.1", new.port()))
            .await
            .unwrap();
        let (data, from) = pending.await.unwrap();
        assert_eq!((data.as_slice(), from), (&b"new"[..], peer_addr));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while rules.retired_received().0 == 0 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(rules.retired_received().0, 1);

        // Sends leave from the new port.
        conn.send_to(b"hi", peer_addr).await.unwrap();
        let mut buf = [0u8; 16];
        let (_, from) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(from.port(), new.port());
    }

    #[test]
    fn tap_rounds_split_at_the_marks() {
        let rules = LossRules::new();
        rules.enable_tap(16);
        let rtp = |seq: u8| [0x80u8, 96, 0, seq, 0, 0, 0, 0, 0, 0, 0, 5];
        rules.record_inbound(&rtp(1));
        rules.mark_tap();
        rules.mark_tap(); // an empty round
        rules.record_inbound(&rtp(2));
        rules.record_inbound(&rtp(3));
        let sizes: Vec<usize> = rules.tap_rounds().iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![1, 0, 2]);
    }

    #[test]
    fn test_classification() {
        assert_eq!(PacketClass::of(&[0]), PacketClass::Stun);
        assert_eq!(PacketClass::of(&[22]), PacketClass::Dtls);
        assert_eq!(PacketClass::of(&[0x80]), PacketClass::Media);
        assert_eq!(PacketClass::of(&[]), PacketClass::Other);
    }
}
