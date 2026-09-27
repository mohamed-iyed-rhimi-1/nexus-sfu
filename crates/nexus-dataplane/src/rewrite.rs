//! RTP header rewrite into a send buffer (note §11.4).
//!
//! One pass: the fixed header (mapped PT, seq/ts offsets, out SSRC), the
//! CSRCs, the extensions mapped to the subscriber's IDs in the one-byte form
//! (the publisher's `mid` dropped, the subscriber's appended), then the
//! payload copied once.
//!
//! `rewrite` does not change the subscription: it returns an `Advance` that
//! the caller `commit`s only once the packet was protected, so a packet that
//! is never sent does not start the stream or move `last_out_*`.
//!
//! Offsets are constant while every accepted packet is forwarded, so the
//! output seq deltas equal the input deltas the publisher's inbound SRTP
//! accepted. When forwarding to a subscriber pauses (no address, empty pool,
//! unmapped PT) the input can move 2^15 or more past the last packet sent,
//! and the outbound RFC 3711 estimate would refuse every later packet (1.1's
//! precondition). The offsets are therefore rebased, so the next packet
//! continues right after the last one the subscriber received, when:
//! - the input is more than `REBASE_GAP` ahead of the last forwarded packet;
//! - the input is more than `REORDER_LIMIT` behind it: inbound SRTP refuses
//!   packets that old, so the input moved on (by 2^15 or more) meanwhile,
//!   and without a rebase the output would sit behind what was sent;
//! - `REBASE_IDLE` passed since the last forwarded packet: over a long pause
//!   the input seq can wrap and look like a small step.

use std::time::{Duration, Instant};

use nexus_media::rtp::RtpHeader;

use crate::ext::{self, MAX_ONE_BYTE_LEN};
use crate::rng::Rng;
use crate::subscription::{RewriteState, Subscription};

/// Input seq distance from the last forwarded packet beyond which the
/// offsets are rebased. Far above loss bursts and reordering (inbound SRTP
/// refuses packets more than 64 behind), far below 2^15.
pub const REBASE_GAP: u16 = 1 << 14;

/// Deepest reordering that reaches the rewrite: inbound SRTP refuses
/// packets more than its 64-packet replay window behind.
pub const REORDER_LIMIT: u16 = 64;

/// A pause in forwarding this long rebases, whatever the seq delta: the
/// input would need > 13,000 packets/s to wrap into a small step within it.
pub const REBASE_IDLE: Duration = Duration::from_secs(5);

/// Why a packet was not rewritten.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewriteError {
    /// The publisher PT is not in the subscription's map.
    UnmappedPt,
    /// The output does not fit the send buffer.
    TooLarge,
}

/// The rewrite state a packet was written with; applied by `commit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Advance {
    seq_offset: u16,
    ts_offset: u32,
    in_seq: u16,
    out_seq: u16,
    out_ts: u32,
    /// The offsets were rebased after a gap.
    pub rebased: bool,
}

/// Rewrites the decrypted packet `src` (parsed as `hdr`) for `sub` into
/// `dst`. The caller leaves room for the SRTP trailer outside `dst`. Returns
/// the RTP length and the state to `commit` once the packet is protected.
pub fn rewrite(
    src: &[u8],
    hdr: &RtpHeader,
    sub: &Subscription,
    rng: &mut Rng,
    now: Instant,
    dst: &mut [u8],
) -> Result<(usize, Advance), RewriteError> {
    debug_assert!(src.len() >= hdr.header_len_bytes as usize);
    let pt = sub
        .pt_map
        .map(hdr.payload_type)
        .ok_or(RewriteError::UnmappedPt)?;
    let csrc_end = 12 + 4 * hdr.csrc_count as usize;
    if csrc_end > dst.len() {
        return Err(RewriteError::TooLarge);
    }
    dst[12..csrc_end].copy_from_slice(&src[12..csrc_end]);
    let header_end = write_extensions(src, hdr, sub, dst, csrc_end)?;

    let payload = &src[hdr.header_len_bytes as usize..]; // padding included
    let out_len = header_end + payload.len();
    if out_len > dst.len() {
        return Err(RewriteError::TooLarge);
    }
    dst[header_end..out_len].copy_from_slice(payload);

    let (seq_offset, ts_offset, rebased) = offsets(&sub.rewrite, hdr, sub.clock_rate, rng, now);
    let seq = hdr.sequence_number.wrapping_add(seq_offset);
    let ts = hdr.timestamp.wrapping_add(ts_offset);
    let x = if header_end > csrc_end { 0x10 } else { 0 };
    // V=2, P kept, X if extensions were written, CC kept.
    dst[0] = 0x80 | (src[0] & 0x20) | x | hdr.csrc_count;
    dst[1] = (src[1] & 0x80) | pt;
    dst[2..4].copy_from_slice(&seq.to_be_bytes());
    dst[4..8].copy_from_slice(&ts.to_be_bytes());
    dst[8..12].copy_from_slice(&sub.rewrite.out_ssrc.to_be_bytes());
    let advance = Advance {
        seq_offset,
        ts_offset,
        in_seq: hdr.sequence_number,
        out_seq: seq,
        out_ts: ts,
        rebased,
    };
    Ok((out_len, advance))
}

/// Applies the state of a packet that was protected and queued.
pub fn commit(state: &mut RewriteState, advance: Advance, now: Instant) {
    let newer = !state.started
        || advance.rebased
        || (advance.out_seq.wrapping_sub(state.last_out_seq) as i16) > 0;
    state.seq_offset = advance.seq_offset;
    state.ts_offset = advance.ts_offset;
    state.started = true;
    if newer {
        state.last_out_seq = advance.out_seq;
        state.last_out_ts = advance.out_ts;
        state.last_out_at = Some(now);
        state.last_in_seq = advance.in_seq;
    }
    debug_assert!(state.last_out_at.is_some());
}

/// The offsets for this packet: random ones for the first packet (RFC 3550
/// §5.1), rebased ones after a gap (module doc), else the current.
fn offsets(
    state: &RewriteState,
    hdr: &RtpHeader,
    clock_rate: u32,
    rng: &mut Rng,
    now: Instant,
) -> (u16, u32, bool) {
    if !state.started {
        let r = rng.next_u64();
        let seq_offset = (r as u16).wrapping_sub(hdr.sequence_number);
        let ts_offset = ((r >> 32) as u32).wrapping_sub(hdr.timestamp);
        return (seq_offset, ts_offset, false);
    }
    let delta = hdr.sequence_number.wrapping_sub(state.last_in_seq) as i16;
    let idle = state
        .last_out_at
        .is_some_and(|at| now.saturating_duration_since(at) >= REBASE_IDLE);
    let in_step = (-(REORDER_LIMIT as i16)..=REBASE_GAP as i16).contains(&delta);
    if in_step && !idle {
        return (state.seq_offset, state.ts_offset, false);
    }
    // Continue after the last packet sent; the timestamp advances by the
    // wall time since then (note §11.5's rebase rule).
    let elapsed = state
        .last_out_at
        .map_or(0, |at| now.saturating_duration_since(at).as_millis());
    let step = (elapsed as u64).saturating_mul(u64::from(clock_rate)) / 1_000;
    let seq_offset = state
        .last_out_seq
        .wrapping_add(1)
        .wrapping_sub(hdr.sequence_number);
    let ts_offset = state
        .last_out_ts
        .wrapping_add(step.max(1) as u32)
        .wrapping_sub(hdr.timestamp);
    (seq_offset, ts_offset, true)
}

/// Writes the mapped extension block at `at` in the one-byte form; returns
/// its end (`at` itself when no element is written, and X stays clear).
fn write_extensions(
    src: &[u8],
    hdr: &RtpHeader,
    sub: &Subscription,
    dst: &mut [u8],
    at: usize,
) -> Result<usize, RewriteError> {
    let block = at + 4;
    let mut end = block;
    // Bounded by ext::MAX_ELEMENTS.
    for element in ext::elements(src, hdr) {
        let id = element.id as usize;
        let len = element.data.len();
        if element.id == sub.pub_mid || id >= sub.ext_map.map.len() || len > MAX_ONE_BYTE_LEN {
            continue;
        }
        let to = sub.ext_map.map[id];
        if to == 0 || len == 0 {
            continue;
        }
        end = write_element(dst, end, to, element.data)?;
    }
    if sub.ext_map.mid != 0 {
        end = write_element(dst, end, sub.ext_map.mid, sub.mid.as_bytes())?;
    }
    if end == block {
        return Ok(at);
    }
    let padded = block + (end - block).div_ceil(4) * 4;
    if padded > dst.len() {
        return Err(RewriteError::TooLarge);
    }
    dst[end..padded].fill(0);
    dst[at..at + 2].copy_from_slice(&0xBEDEu16.to_be_bytes());
    dst[at + 2..at + 4].copy_from_slice(&(((padded - block) / 4) as u16).to_be_bytes());
    Ok(padded)
}

/// Writes one one-byte-form element at `at`; returns its end.
fn write_element(dst: &mut [u8], at: usize, id: u8, data: &[u8]) -> Result<usize, RewriteError> {
    debug_assert!((1..=14).contains(&id) && (1..=MAX_ONE_BYTE_LEN).contains(&data.len()));
    let end = at + 1 + data.len();
    if end > dst.len() {
        return Err(RewriteError::TooLarge);
    }
    dst[at] = (id << 4) | (data.len() as u8 - 1);
    dst[at + 1..end].copy_from_slice(data);
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{ExtMap, PtMap};
    use crate::ids::{MidValue, SubscriptionId};
    use crate::slab::Key;

    /// Builds an RTP packet; `ext` is (profile, block) with the block a
    /// multiple of 4 bytes.
    fn packet(
        seq: u16,
        ts: u32,
        pt: u8,
        csrcs: &[u32],
        ext: Option<(u16, &[u8])>,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut p = vec![0x80 | csrcs.len() as u8, pt];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ts.to_be_bytes());
        p.extend_from_slice(&0x1111_2222u32.to_be_bytes());
        for c in csrcs {
            p.extend_from_slice(&c.to_be_bytes());
        }
        if let Some((profile, block)) = ext {
            assert!(block.len() % 4 == 0);
            p[0] |= 0x10;
            p.extend_from_slice(&profile.to_be_bytes());
            p.extend_from_slice(&((block.len() / 4) as u16).to_be_bytes());
            p.extend_from_slice(block);
        }
        p.extend_from_slice(payload);
        p
    }

    /// Publisher ids: mid 1, audio level 2, orientation 3. Subscriber maps
    /// audio level to 5, drops orientation; `sub_mid` is its mid id.
    fn subscription(sub_mid: u8) -> Subscription {
        let mut map = [0u8; 15];
        map[2] = 5;
        Subscription {
            id: SubscriptionId::new(1),
            session: Key::default(),
            track: Key::default(),
            rewrite: RewriteState::new(0xABCD_0001),
            ext_map: ExtMap { map, mid: sub_mid },
            pub_mid: 1,
            clock_rate: 48_000,
            pt_map: PtMap::new(&[(111, 100)]).unwrap(),
            mid: MidValue::new(b"s0").unwrap(),
            sent_packets: 0,
            sent_octets: 0,
        }
    }

    fn run(src: &[u8], sub: &mut Subscription, room: usize) -> Result<Vec<u8>, RewriteError> {
        run_at(src, sub, room, Instant::now())
    }

    fn run_at(
        src: &[u8],
        sub: &mut Subscription,
        room: usize,
        now: Instant,
    ) -> Result<Vec<u8>, RewriteError> {
        let hdr = RtpHeader::parse(src).unwrap();
        let mut dst = vec![0u8; room];
        let mut rng = Rng::new(1);
        let (n, advance) = rewrite(src, &hdr, sub, &mut rng, now, &mut dst)?;
        commit(&mut sub.rewrite, advance, now);
        Ok(dst[..n].to_vec())
    }

    /// The output with seq/ts zeroed (they are random).
    fn masked(mut out: Vec<u8>) -> Vec<u8> {
        out[2..8].fill(0);
        out
    }

    const SSRC: [u8; 4] = [0xAB, 0xCD, 0x00, 0x01];

    fn expected(first: u8, second: u8, rest: &[u8]) -> Vec<u8> {
        let mut e = vec![first, second, 0, 0, 0, 0, 0, 0];
        e.extend_from_slice(&SSRC);
        e.extend_from_slice(rest);
        e
    }

    #[test]
    fn table_of_headers_gives_exact_bytes() {
        let one_byte: &[u8] = &[0x10, b'a', 0x20, 0x85, 0x31, 7, 8, 0]; // mid, level, orientation
        let two_byte: &[u8] = &[1, 1, b'a', 2, 1, 0x85, 20, 2, 7, 8, 0, 0]; // mid, level, id 20
        let long_two: &[u8] = &[
            2, 17, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 0,
        ];
        let with_mid = |rest: &[u8]| -> Vec<u8> {
            let mut v = vec![0xBE, 0xDE, 0, 1, 0x11, b's', b'0', 0];
            v.extend_from_slice(rest);
            v
        };
        let level_and_mid = |rest: &[u8]| -> Vec<u8> {
            let mut v = vec![0xBE, 0xDE, 0, 2, 0x50, 0x85, 0x11, b's', b'0', 0, 0, 0];
            v.extend_from_slice(rest);
            v
        };
        let cases: Vec<(&str, Vec<u8>, u8, Vec<u8>)> = vec![
            (
                "none, no sub mid",
                packet(1, 1, 111, &[], None, b"P"),
                0,
                expected(0x80, 100, b"P"),
            ),
            (
                "none, sub mid",
                packet(1, 1, 111, &[], None, b"P"),
                1,
                expected(0x90, 100, &with_mid(b"P")),
            ),
            (
                "one-byte",
                packet(1, 1, 111, &[], Some((0xBEDE, one_byte)), b"P"),
                1,
                expected(0x90, 100, &level_and_mid(b"P")),
            ),
            (
                "two-byte",
                packet(1, 1, 111, &[], Some((0x1000, two_byte)), b"P"),
                1,
                expected(0x90, 100, &level_and_mid(b"P")),
            ),
            (
                "declined and too long only",
                packet(1, 1, 111, &[], Some((0x1000, long_two)), b"P"),
                0,
                expected(0x80, 100, b"P"),
            ),
            (
                "csrcs",
                packet(1, 1, 111, &[9], Some((0xBEDE, one_byte)), b"P"),
                0,
                expected(
                    0x91,
                    100,
                    &[
                        &[0, 0, 0, 9][..],
                        &[0xBE, 0xDE, 0, 1, 0x50, 0x85, 0, 0],
                        b"P",
                    ]
                    .concat(),
                ),
            ),
        ];
        for (name, src, sub_mid, want) in cases {
            let mut sub = subscription(sub_mid);
            let out = run(&src, &mut sub, 256).unwrap();
            assert_eq!(masked(out), want, "{name}");
        }
    }

    #[test]
    fn padding_bit_and_bytes_are_kept() {
        let mut src = packet(
            1,
            1,
            111,
            &[],
            Some((0xBEDE, &[0x10, b'a', 0, 0])),
            b"ab\0\0\x04",
        );
        src[0] |= 0x20;
        let out = run(&src, &mut subscription(1), 256).unwrap();
        assert_eq!(out[0], 0x80 | 0x20 | 0x10);
        assert_eq!(&out[out.len() - 5..], b"ab\0\0\x04");
    }

    #[test]
    fn at_most_sixteen_elements_are_mapped() {
        let block: Vec<u8> = (0..20).flat_map(|i| [0x20u8, i]).collect();
        let src = packet(1, 1, 111, &[], Some((0xBEDE, &block)), b"P");
        let out = run(&src, &mut subscription(0), 256).unwrap();
        let words = u16::from_be_bytes([out[14], out[15]]) as usize;
        assert_eq!(words, 8, "16 two-byte elements");
        assert_eq!(
            out[16..48]
                .iter()
                .step_by(2)
                .filter(|b| **b == 0x50)
                .count(),
            16
        );
    }

    #[test]
    fn offsets_are_constant_and_reordering_keeps_last_out() {
        let mut sub = subscription(0);
        let first = run(&packet(5, 1000, 111, &[], None, b"x"), &mut sub, 64).unwrap();
        let later = run(&packet(7, 1300, 111, &[], None, b"x"), &mut sub, 64).unwrap();
        let seq = |p: &[u8]| u16::from_be_bytes([p[2], p[3]]);
        let ts = |p: &[u8]| u32::from_be_bytes(p[4..8].try_into().unwrap());
        assert_eq!(seq(&later), seq(&first).wrapping_add(2));
        assert_eq!(ts(&later), ts(&first).wrapping_add(300));
        let high = sub.rewrite.last_out_seq;
        run(&packet(6, 1150, 111, &[], None, b"x"), &mut sub, 64).unwrap();
        assert_eq!(sub.rewrite.last_out_seq, high);
    }

    #[test]
    fn unmapped_pt_and_overflow_are_refused() {
        let mut sub = subscription(1);
        let src = packet(1, 1, 96, &[], None, b"x");
        assert_eq!(run(&src, &mut sub, 256), Err(RewriteError::UnmappedPt));
        assert!(
            !sub.rewrite.started,
            "a refused packet does not start the stream"
        );
        let big = packet(1, 1, 111, &[], None, &[0u8; 240]);
        assert_eq!(run(&big, &mut sub, 256), Err(RewriteError::TooLarge));
        // 12-byte header + 8-byte extension block (mid) + 1 payload byte.
        let small = packet(1, 1, 111, &[], None, b"x");
        for room in 0..21 {
            assert_eq!(
                run(&small, &mut subscription(1), room),
                Err(RewriteError::TooLarge)
            );
        }
        assert!(run(&small, &mut subscription(1), 21).is_ok());
    }

    #[test]
    fn nothing_changes_until_commit() {
        let mut sub = subscription(0);
        let src = packet(5, 1000, 111, &[], None, b"x");
        let hdr = RtpHeader::parse(&src).unwrap();
        let mut dst = [0u8; 64];
        let result = rewrite(&src, &hdr, &sub, &mut Rng::new(1), Instant::now(), &mut dst);
        assert!(result.is_ok());
        assert!(!sub.rewrite.started, "protect failed: stream not started");
        run(&src, &mut sub, 64).unwrap();
        assert!(sub.rewrite.started);
    }

    #[test]
    fn gap_beyond_rebase_limit_continues_after_last_sent() {
        let seq = |p: &[u8]| u16::from_be_bytes([p[2], p[3]]);
        let ts = |p: &[u8]| u32::from_be_bytes(p[4..8].try_into().unwrap());
        let behind = |n: u16| 0u16.wrapping_sub(n);
        for jump in [
            REBASE_GAP + 1,
            1 << 15,
            40_000,
            behind(REORDER_LIMIT + 1),
            behind(1_000),
        ] {
            let mut sub = subscription(0);
            let first = run(&packet(100, 5000, 111, &[], None, b"x"), &mut sub, 64).unwrap();
            let after = packet(100u16.wrapping_add(jump), 9000, 111, &[], None, b"y");
            let resumed = run(&after, &mut sub, 64).unwrap();
            assert_eq!(seq(&resumed), seq(&first).wrapping_add(1), "jump {jump}");
            assert!(
                ts(&resumed).wrapping_sub(ts(&first)) >= 1,
                "timestamp moves forward"
            );
            // And the stream continues from there without another rebase.
            let next = packet(101u16.wrapping_add(jump), 9960, 111, &[], None, b"z");
            let next = run(&next, &mut sub, 64).unwrap();
            assert_eq!(seq(&next), seq(&first).wrapping_add(2));
            assert_eq!(ts(&next), ts(&resumed).wrapping_add(960));
        }
        // A gap within the limit keeps the offsets (the subscriber sees the loss).
        let mut sub = subscription(0);
        let first = run(&packet(100, 0, 111, &[], None, b"x"), &mut sub, 64).unwrap();
        let later = run(
            &packet(100 + REBASE_GAP, 0, 111, &[], None, b"x"),
            &mut sub,
            64,
        )
        .unwrap();
        assert_eq!(seq(&later), seq(&first).wrapping_add(REBASE_GAP));
    }

    #[test]
    fn reordering_within_the_limit_keeps_offsets() {
        let seq = |p: &[u8]| u16::from_be_bytes([p[2], p[3]]);
        let mut sub = subscription(0);
        let first = run(&packet(1_000, 0, 111, &[], None, b"x"), &mut sub, 64).unwrap();
        let late = run(
            &packet(1_000 - REORDER_LIMIT, 0, 111, &[], None, b"x"),
            &mut sub,
            64,
        )
        .unwrap();
        assert_eq!(seq(&late), seq(&first).wrapping_sub(REORDER_LIMIT));
    }

    #[test]
    fn long_pause_rebases_even_when_the_input_wrapped_to_a_small_step() {
        let seq = |p: &[u8]| u16::from_be_bytes([p[2], p[3]]);
        let ts = |p: &[u8]| u32::from_be_bytes(p[4..8].try_into().unwrap());
        let t0 = Instant::now();
        let mut sub = subscription(0);
        let first = run_at(&packet(100, 0, 111, &[], None, b"x"), &mut sub, 64, t0).unwrap();
        // 65,536 + 50 packets later (a 10 s pause at ≈ 6,500 packets/s): the
        // input seq is 150, a step of +50 that looks normal.
        let t1 = t0 + Duration::from_secs(10);
        let wrapped = run_at(&packet(150, 0, 111, &[], None, b"y"), &mut sub, 64, t1).unwrap();
        assert_eq!(
            seq(&wrapped),
            seq(&first).wrapping_add(1),
            "continues after the last sent"
        );
        assert_eq!(
            ts(&wrapped),
            ts(&first).wrapping_add(480_000),
            "10 s at 48 kHz"
        );
        // The same step without the pause keeps the offsets.
        let mut sub = subscription(0);
        let first = run_at(&packet(100, 0, 111, &[], None, b"x"), &mut sub, 64, t0).unwrap();
        let t1 = t0 + REBASE_IDLE - Duration::from_millis(1);
        let near = run_at(&packet(150, 0, 111, &[], None, b"y"), &mut sub, 64, t1).unwrap();
        assert_eq!(seq(&near), seq(&first).wrapping_add(50));
    }
}
