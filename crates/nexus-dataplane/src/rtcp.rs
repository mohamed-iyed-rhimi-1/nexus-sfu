//! RTCP the shard reads and writes (note §12), without allocation.
//!
//! `nexus-media`'s `PliPacket::build` and `SenderReportGenerator::generate`
//! return `Vec`s and `FirPacket::parse` allocates, so the builders and the FIR
//! reader are here. Parsing of SR and PLI uses `nexus-media`.

use crate::ids::CnameValue;

/// RTCP packet types.
pub const PT_SR: u8 = 200;
/// SDES.
pub const PT_SDES: u8 = 202;
/// Payload-specific feedback.
pub const PT_PSFB: u8 = 206;
/// PSFB format: picture loss indication.
pub const FMT_PLI: u8 = 1;
/// PSFB format: full intra request.
pub const FMT_FIR: u8 = 4;

/// Length of an SR without report blocks.
pub const SR_LEN: usize = 28;
/// Length of a PLI.
pub const PLI_LEN: usize = 12;
/// Most FIR entries read from one FIR packet.
pub const MAX_FIR_ENTRIES: usize = 16;

/// A publisher's last SR on a layer (note §12.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SrInfo {
    /// NTP timestamp.
    pub ntp: u64,
    /// RTP timestamp at that NTP time.
    pub rtp: u32,
}

fn header(dst: &mut [u8], count: u8, pt: u8, len: usize) {
    debug_assert!(len % 4 == 0 && len >= 4);
    dst[0] = 0x80 | count;
    dst[1] = pt;
    dst[2..4].copy_from_slice(&((len / 4 - 1) as u16).to_be_bytes());
}

/// Writes an SR without report blocks (RFC 3550 §6.4.1).
pub fn write_sr(dst: &mut [u8], ssrc: u32, sr: SrInfo, packets: u32, octets: u32) -> Option<usize> {
    let out = dst.get_mut(..SR_LEN)?;
    header(out, 0, PT_SR, SR_LEN);
    out[4..8].copy_from_slice(&ssrc.to_be_bytes());
    out[8..16].copy_from_slice(&sr.ntp.to_be_bytes());
    out[16..20].copy_from_slice(&sr.rtp.to_be_bytes());
    out[20..24].copy_from_slice(&packets.to_be_bytes());
    out[24..28].copy_from_slice(&octets.to_be_bytes());
    Some(SR_LEN)
}

/// Writes an SDES packet with one chunk: `ssrc`, CNAME item, end of items,
/// padded to 32 bits (RFC 3550 §6.5).
pub fn write_sdes_cname(dst: &mut [u8], ssrc: u32, cname: &CnameValue) -> Option<usize> {
    let name = cname.as_bytes();
    // header 4 + SSRC 4 + type 1 + length 1 + name + at least one 0 byte.
    let len = (4 + 4 + 2 + name.len() + 1).div_ceil(4) * 4;
    let out = dst.get_mut(..len)?;
    header(out, 1, PT_SDES, len);
    out[4..8].copy_from_slice(&ssrc.to_be_bytes());
    out[8] = 1; // CNAME
    out[9] = name.len() as u8;
    out[10..10 + name.len()].copy_from_slice(name);
    out[10 + name.len()..].fill(0);
    Some(len)
}

/// Writes a PLI (RFC 4585 §6.3.1).
pub fn write_pli(dst: &mut [u8], sender_ssrc: u32, media_ssrc: u32) -> Option<usize> {
    let out = dst.get_mut(..PLI_LEN)?;
    header(out, FMT_PLI, PT_PSFB, PLI_LEN);
    out[4..8].copy_from_slice(&sender_ssrc.to_be_bytes());
    out[8..12].copy_from_slice(&media_ssrc.to_be_bytes());
    Some(PLI_LEN)
}

/// The media SSRCs a FIR asks keyframes for (RFC 5104 §4.3.1): FCI entries
/// of 8 bytes after the 12-byte header, at most `MAX_FIR_ENTRIES`. `packet`
/// is one block of a compound.
pub fn fir_targets(packet: &[u8]) -> impl Iterator<Item = u32> + '_ {
    let fci = packet.get(12..).unwrap_or(&[]);
    fci.chunks_exact(8)
        .take(MAX_FIR_ENTRIES)
        .map(|entry| u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_media::rtcp::{demux_compound, PliPacket, SenderReport};

    #[test]
    fn sr_and_sdes_form_a_parsable_compound() {
        let mut buf = [0u8; 128];
        let sr = SrInfo {
            ntp: 0x0102_0304_0506_0708,
            rtp: 90_000,
        };
        let n = write_sr(&mut buf, 7, sr, 10, 1_000).unwrap();
        let cname = CnameValue::new(b"abcde").unwrap();
        let m = write_sdes_cname(&mut buf[n..], 7, &cname).unwrap();
        assert_eq!(m % 4, 0);
        let compound = demux_compound(&buf[..n + m]).expect("valid compound");
        assert_eq!(compound.len(), 2);
        let parsed = SenderReport::parse(&buf[..n]).unwrap();
        assert_eq!(
            (parsed.ssrc, parsed.ntp_timestamp, parsed.rtp_timestamp),
            (7, sr.ntp, 90_000)
        );
        assert_eq!((parsed.packet_count, parsed.octet_count), (10, 1_000));
        let sdes = &buf[n..n + m];
        assert_eq!(&sdes[8..10], &[1, 5]);
        assert_eq!(&sdes[10..15], b"abcde");
        assert_eq!(sdes[15], 0, "end of items");
    }

    #[test]
    fn sdes_with_longest_cname_fits_and_pads() {
        let mut buf = [0u8; 300];
        let cname = CnameValue::new(&[b'c'; 255]).unwrap();
        let n = write_sdes_cname(&mut buf, 1, &cname).unwrap();
        assert_eq!(n, 268);
        assert!(write_sdes_cname(&mut buf[..100], 1, &cname).is_none());
    }

    #[test]
    fn pli_parses() {
        let mut buf = [0u8; 12];
        write_pli(&mut buf, 1, 2).unwrap();
        let pli = PliPacket::parse(&buf).unwrap();
        assert_eq!((pli.sender_ssrc, pli.media_ssrc), (1, 2));
        assert!(write_pli(&mut buf[..11], 1, 2).is_none());
    }

    #[test]
    fn fir_targets_are_bounded() {
        let mut fir = vec![0x84, PT_PSFB, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        for ssrc in 0..20u32 {
            fir.extend_from_slice(&ssrc.to_be_bytes());
            fir.extend_from_slice(&[1, 0, 0, 0]);
        }
        let targets: Vec<u32> = fir_targets(&fir).collect();
        assert_eq!(targets, (0..16).collect::<Vec<_>>());
        assert_eq!(fir_targets(&fir[..5]).count(), 0);
    }
}
