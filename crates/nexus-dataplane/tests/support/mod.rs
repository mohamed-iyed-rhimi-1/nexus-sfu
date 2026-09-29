//! Scripted peers for driving a shard on `MemIo` (shared by `shard.rs` and
//! `alloc.rs`). Each peer uses `SrtpContext` as its own SRTP and builds STUN
//! with `nexus-transport`'s helpers.

#![allow(dead_code)] // each test binary uses a subset

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use nexus_core::MediaKind;
use nexus_dataplane::{
    CnameValue, CodecParams, Command, Event, ExtIds, ExtMap, IceParams, MemIo, MidValue, PtMap,
    SessionId, Shard, ShardConfig, ShardId, SrtpInstall, SubSpec, SubscriptionId, TrackId,
    TrackRef, TrackSpec, XsMesh,
};
use nexus_transport::ice::stun::{
    create_binding_request, generate_transaction_id, sign_message, STUN_MAGIC_COOKIE,
};
use nexus_transport::srtp::{KeyMaterial, ProtectionProfile, SrtpContext, SrtpPolicy};

/// The shard type the tests drive.
pub type TestShard = Shard<MemIo, Vec<Event>>;

/// Publisher's audio PT in the tests.
pub const PUB_PT: u8 = 111;
/// Subscriber's PT for the same codec (remapped by the negotiator).
pub const SUB_PT: u8 = 100;

/// A shard on `MemIo` with test settings.
pub fn shard(now: Instant) -> TestShard {
    shard_on(ShardId::new(0), 512, now)
}

/// Shard `id` on `MemIo` with test settings and `pool` buffers.
pub fn shard_on(id: ShardId, pool: u32, now: Instant) -> TestShard {
    let config = ShardConfig {
        shard: id,
        pool_buffers: pool,
        max_sessions: 64,
        ..Default::default()
    };
    Shard::new(config, MemIo::new(), Vec::new(), now).expect("valid config")
}

/// `n` shards connected by a cross-shard mesh, each with `pool` buffers.
pub fn mesh(n: u8, pool: u32, now: Instant) -> Vec<TestShard> {
    let mut shards: Vec<TestShard> = (0..n)
        .map(|i| shard_on(ShardId::new(i), pool, now))
        .collect();
    let regions: Vec<_> = shards.iter().map(TestShard::pool_region).collect();
    for (shard, ports) in shards.iter_mut().zip(XsMesh::build(&regions)) {
        shard.attach_xs(ports);
    }
    shards
}

/// Iterates every shard, in order, until none has inbound datagrams,
/// commands or cross-shard work left.
pub fn run_all(shards: &mut [TestShard], now: Instant) {
    for _ in 0..1_000 {
        let mut busy = false;
        for shard in shards.iter_mut() {
            let stats = shard.iterate(now);
            busy |= stats.received > 0 || stats.commands > 0 || stats.cross_shard > 0;
        }
        let idle = shards
            .iter()
            .all(|s| s.io().inbound_len() == 0 && !s.commands_pending() && !s.xs_pending());
        if idle && !busy {
            return;
        }
    }
    panic!("shards did not drain");
}

/// Iterates until inbound datagrams and commands are drained.
pub fn run(shard: &mut TestShard, now: Instant) {
    for _ in 0..1_000 {
        let stats = shard.iterate(now);
        if shard.io().inbound_len() == 0 && stats.commands == 0 && stats.received == 0 {
            return;
        }
    }
    panic!("shard did not drain");
}

/// Pushes a command, which must fit the queue.
pub fn command(shard: &mut TestShard, command: Command) {
    assert!(shard.push_command(command).is_ok(), "command queue full");
}

/// Takes the events emitted so far.
pub fn events(shard: &mut TestShard) -> Vec<Event> {
    std::mem::take(shard.events_mut())
}

/// Key material from a label (deterministic, distinct per label).
pub fn key(profile: ProtectionProfile, label: u64) -> KeyMaterial {
    let len = profile.key_len() + profile.salt_len();
    let bytes: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ (label as u8).wrapping_mul(97) ^ (label >> 8) as u8)
        .collect();
    KeyMaterial::from_dtls_export(&bytes, profile).expect("key material")
}

/// A remote participant: its SFU session's credentials and SRTP contexts.
pub struct Peer {
    /// Session id.
    pub id: SessionId,
    /// The peer's address.
    pub addr: SocketAddr,
    /// The session's local ICE credentials.
    pub ice: IceParams,
    /// The session's out SSRC base (and RTCP SSRC).
    pub base: u32,
    /// Profile.
    pub profile: ProtectionProfile,
    next_offset: u32,
    tx: SrtpContext,
    rx: SrtpContext,
}

impl Peer {
    /// Peer number `n` at `addr`.
    pub fn new(n: u64, addr: &str, profile: ProtectionProfile) -> Self {
        let mut ice = IceParams {
            local_ufrag: [0; 16],
            local_pwd: [0; 32],
        };
        ice.local_ufrag
            .copy_from_slice(format!("ufrag{n:011}").as_bytes());
        ice.local_pwd
            .copy_from_slice(format!("password{n:024}").as_bytes());
        let policy = SrtpPolicy {
            profile,
            ..SrtpPolicy::default()
        };
        Self {
            id: SessionId::new(n),
            addr: addr.parse().expect("address"),
            ice,
            base: 0x1000_0000u32.wrapping_mul(n as u32).wrapping_add(0x55),
            profile,
            next_offset: 1,
            tx: SrtpContext::new(&key(profile, 2 * n), policy).expect("tx"),
            rx: SrtpContext::new(&key(profile, 2 * n + 1), policy).expect("rx"),
        }
    }

    /// `CreateSession` for this peer.
    pub fn create(&self) -> Command {
        Command::CreateSession {
            id: self.id,
            ice: self.ice,
            out_ssrc_base: self.base,
        }
    }

    /// `InstallSrtp`: the SFU writes with the peer's rx key and reads with
    /// its tx key.
    pub fn install(&self) -> Command {
        let n = self.id.get();
        let keys = SrtpInstall {
            local: key(self.profile, 2 * n + 1),
            remote: key(self.profile, 2 * n),
        };
        Command::InstallSrtp {
            id: self.id,
            keys: Box::new(keys),
        }
    }

    /// The next out SSRC from this session's allocator.
    pub fn next_out_ssrc(&mut self) -> u32 {
        let ssrc = self.base.wrapping_add(self.next_offset);
        self.next_offset += 1;
        ssrc
    }

    /// A signed binding request for this session.
    pub fn binding_request(&self, use_candidate: bool) -> Vec<u8> {
        binding_request(&self.ice.local_ufrag, &self.ice.local_pwd, use_candidate)
    }

    /// An SRTP packet from this peer.
    pub fn rtp(&mut self, ssrc: u32, seq: u16, ts: u32, payload: &[u8]) -> Vec<u8> {
        let mut buf = rtp_packet(ssrc, seq, ts, PUB_PT, payload);
        let len = buf.len();
        buf.resize(len + 64, 0);
        let n = self.tx.protect_rtp(&mut buf, len).expect("protect");
        buf.truncate(n);
        buf
    }

    /// Protects a plain RTP packet built by the test.
    pub fn protect_rtp(&mut self, plain: &[u8]) -> Vec<u8> {
        let mut buf = plain.to_vec();
        buf.resize(plain.len() + 64, 0);
        let n = self.tx.protect_rtp(&mut buf, plain.len()).expect("protect");
        buf.truncate(n);
        buf
    }

    /// Protects a plain RTP packet; `None` if this peer's SRTP refuses it.
    pub fn try_protect_rtp(&mut self, plain: &[u8]) -> Option<Vec<u8>> {
        let mut buf = plain.to_vec();
        buf.resize(plain.len() + 64, 0);
        let n = self.tx.protect_rtp(&mut buf, plain.len()).ok()?;
        buf.truncate(n);
        Some(buf)
    }

    /// Protects a plain RTCP packet; `None` if this peer's SRTP refuses it.
    pub fn try_protect_rtcp(&mut self, plain: &[u8]) -> Option<Vec<u8>> {
        let mut buf = plain.to_vec();
        buf.resize(plain.len() + 64, 0);
        let n = self.tx.protect_rtcp(&mut buf, plain.len()).ok()?;
        buf.truncate(n);
        Some(buf)
    }

    /// Decrypts SRTCP the SFU sent to this peer.
    pub fn open_rtcp(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let mut buf = data.to_vec();
        let n = self.rx.unprotect_rtcp(&mut buf, data.len()).ok()?;
        buf.truncate(n);
        Some(buf)
    }

    /// An SRTCP packet from this peer.
    pub fn rtcp(&mut self, plain: &[u8]) -> Vec<u8> {
        let mut buf = plain.to_vec();
        buf.resize(plain.len() + 64, 0);
        let n = self
            .tx
            .protect_rtcp(&mut buf, plain.len())
            .expect("protect");
        buf.truncate(n);
        buf
    }

    /// Decrypts SRTP the SFU sent to this peer.
    pub fn open_rtp(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let mut buf = data.to_vec();
        let n = self.rx.unprotect_rtp(&mut buf, data.len()).ok()?;
        buf.truncate(n);
        Some(buf)
    }
}

/// A plain RTP packet.
pub fn rtp_packet(ssrc: u32, seq: u16, ts: u32, pt: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x80, pt];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ts.to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// A plain RTP packet with a one-byte-form extension block of `elements`
/// (id, data), padded to 32 bits.
pub fn rtp_with_ext(
    ssrc: u32,
    seq: u16,
    ts: u32,
    elements: &[(u8, &[u8])],
    payload: &[u8],
) -> Vec<u8> {
    let mut block = Vec::new();
    for (id, data) in elements {
        block.push((id << 4) | (data.len() as u8 - 1));
        block.extend_from_slice(data);
    }
    block.resize(block.len().div_ceil(4) * 4, 0);
    let mut p = rtp_packet(ssrc, seq, ts, PUB_PT, &[]);
    p[0] |= 0x10;
    p.extend_from_slice(&0xBEDEu16.to_be_bytes());
    p.extend_from_slice(&((block.len() / 4) as u16).to_be_bytes());
    p.extend_from_slice(&block);
    p.extend_from_slice(payload);
    p
}

/// An SR (no report blocks).
pub fn sender_report(ssrc: u32, ntp: u64, rtp: u32, packets: u32, octets: u32) -> Vec<u8> {
    let mut p = vec![0x80, 200, 0, 6];
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(&ntp.to_be_bytes());
    p.extend_from_slice(&rtp.to_be_bytes());
    p.extend_from_slice(&packets.to_be_bytes());
    p.extend_from_slice(&octets.to_be_bytes());
    p
}

/// A PLI.
pub fn pli(sender: u32, media: u32) -> Vec<u8> {
    let mut p = vec![0x81, 206, 0, 2];
    p.extend_from_slice(&sender.to_be_bytes());
    p.extend_from_slice(&media.to_be_bytes());
    p
}

/// A FIR with one entry for `media`.
pub fn fir(sender: u32, media: u32) -> Vec<u8> {
    let mut p = vec![0x84, 206, 0, 4];
    p.extend_from_slice(&sender.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&media.to_be_bytes());
    p.extend_from_slice(&[1, 0, 0, 0]);
    p
}

/// An RR with no report blocks.
pub fn receiver_report(sender: u32) -> Vec<u8> {
    let mut p = vec![0x80, 201, 0, 1];
    p.extend_from_slice(&sender.to_be_bytes());
    p
}

/// A generic NACK for one packet.
pub fn nack(sender: u32, media: u32, seq: u16) -> Vec<u8> {
    let mut p = vec![0x81, 205, 0, 3];
    p.extend_from_slice(&sender.to_be_bytes());
    p.extend_from_slice(&media.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p
}

/// A binding request built with `create_binding_request` (controlling).
pub fn binding_request(ufrag: &[u8; 16], pwd: &[u8; 32], use_candidate: bool) -> Vec<u8> {
    let user = format!(
        "{}:remote",
        std::str::from_utf8(ufrag).expect("ascii ufrag")
    );
    let pwd = std::str::from_utf8(pwd).expect("ascii password");
    let mut buf = [0u8; 576];
    // A fresh transaction id per request, as ICE agents do (the shard
    // refuses address changes on repeated ids).
    let tid = generate_transaction_id();
    let len = create_binding_request(&mut buf, &tid, &user, 100, true, 42, use_candidate, pwd);
    buf[..len].to_vec()
}

/// A binding request with a raw USERNAME and `unknown` extra attributes
/// before it, signed with `pwd`.
pub fn raw_binding_request(username: &[u8], pwd: &[u8], unknown: usize) -> Vec<u8> {
    let mut msg = vec![0x00, 0x01, 0, 0];
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&generate_transaction_id());
    for _ in 0..unknown {
        msg.extend_from_slice(&[0x80, 0x99, 0, 0]);
    }
    msg.extend_from_slice(&0x0006u16.to_be_bytes());
    msg.extend_from_slice(&(username.len() as u16).to_be_bytes());
    msg.extend_from_slice(username);
    msg.resize(msg.len().div_ceil(4) * 4, 0);
    let body = msg.len();
    msg.resize(body + 64, 0);
    let len = sign_message(&mut msg, body, pwd);
    msg.truncate(len);
    msg
}

/// A track spec with a known SSRC.
pub fn track_spec(ssrc: Option<u32>, mid: &[u8]) -> Box<TrackSpec> {
    Box::new(TrackSpec {
        kind: MediaKind::Audio,
        mid: MidValue::new(mid).expect("mid"),
        ssrc,
        codec: CodecParams {
            pt: PUB_PT,
            clock_rate: 48_000,
        },
        ext: ExtIds::default(),
        cname: CnameValue::new(b"publisher-cname").expect("cname"),
    })
}

/// A subscription spec mapping `PUB_PT` → `SUB_PT` for a track of shard 0
/// described by `track_spec` (no extensions).
pub fn sub_spec(out_ssrc: u32, track: TrackId) -> Box<SubSpec> {
    let source = TrackRef {
        shard: ShardId::new(0),
        track,
    };
    sub_spec_from(out_ssrc, source)
}

/// `sub_spec` for a track published on `source.shard`.
pub fn sub_spec_from(out_ssrc: u32, source: TrackRef) -> Box<SubSpec> {
    let track = track_spec(None, b"0");
    Box::new(SubSpec {
        out_ssrc,
        mid: MidValue::new(b"s0").expect("mid"),
        pt_map: PtMap::new(&[(PUB_PT, SUB_PT)]).expect("pt map"),
        ext_map: ExtMap::default(),
        source,
        clock_rate: track.codec.clock_rate,
        pub_mid: track.ext.mid,
        cname: track.cname,
    })
}

/// Creates the peer's session, nominates its address and installs SRTP.
pub fn connect(shard: &mut TestShard, peer: &Peer, now: Instant) {
    command(shard, peer.create());
    run(shard, now);
    shard
        .io_mut()
        .push_inbound(peer.addr, peer.binding_request(true));
    command(shard, peer.install());
    run(shard, now);
    assert_eq!(shard.session_addr(peer.id), Some(peer.addr));
    shard.io_mut().clear_outbound();
}

/// Subscribes `peer` to `track` with its next out SSRC; returns the SSRC.
pub fn subscribe(
    shard: &mut TestShard,
    peer: &mut Peer,
    sub: u64,
    track: TrackId,
    now: Instant,
) -> u32 {
    let out = peer.next_out_ssrc();
    command(
        shard,
        Command::Subscribe {
            id: peer.id,
            sub: SubscriptionId::new(sub),
            track,
            spec: sub_spec(out, track),
        },
    );
    run(shard, now);
    out
}

/// Datagrams captured for `addr`, and clears the capture.
pub fn sent_to(shard: &mut TestShard, addr: SocketAddr) -> Vec<Vec<u8>> {
    shard
        .io_mut()
        .take_outbound()
        .into_iter()
        .filter(|(a, _)| *a == addr)
        .map(|(_, b)| b)
        .collect()
}

/// `now + ms`.
pub fn at(now: Instant, ms: u64) -> Instant {
    now + Duration::from_millis(ms)
}
