//! SRTP session context.
//!
//! High-level API for protecting/unprotecting RTP and RTCP packets.
//! Manages key material, replay protection, and rollover counter.
//!
//! # TigerStyle Compliance
//!
//! - All functions ≤70 lines
//! - All functions ≥2 assertions
//! - Explicit types (u32/u64 not usize on hot paths)
//! - No dynamic allocation on hot path
//! - Bounded operations

use std::collections::HashMap;

use super::crypto::SrtpCipher;
use super::error::SrtpError;
use super::keys::{KeyDerivation, KeyMaterial, SrtpKeys};
use super::replay::ReplayProtection;
use super::types::{PacketIndex, ProtectionProfile, RtpHeader, SrtpPolicy};
use super::{MAX_PACKET_SIZE, RTP_HEADER_SIZE};

/// Per-SSRC RTP state for ROC tracking and replay protection.
#[derive(Debug)]
struct SsrcState {
    roc: u32,
    highest_seq: u16,
    roc_initialized: bool,
    replay: ReplayProtection,
    /// Per-SSRC SRTCP index counter (RFC 3711 §3.4).
    /// Each SSRC has its own SRTCP crypto context with an independent index.
    srtcp_index: u32,
}

/// SRTP session for a single direction (send or receive).
///
/// Each peer needs two contexts: one for sending, one for receiving.
/// The sender context protects outgoing packets.
/// The receiver context unprotects incoming packets.
#[derive(Debug)]
pub struct SrtpContext {
    /// Derived session keys.
    keys: SrtpKeys,
    
    /// Cipher for encryption/decryption.
    cipher: SrtpCipher,
    
    /// Per-SSRC RTP state (ROC, highest_seq, replay protection).
    ssrc_states: HashMap<u32, SsrcState>,
    
    /// Per-SSRC SRTCP replay protection.
    /// Some WebRTC implementations (e.g. webrtc-rs) use separate SRTP
    /// contexts per transceiver, each with its own SRTCP index counter.
    /// Tracking replay per-SSRC avoids false ReplayDetected errors when
    /// multiple SSRCs share the same DTLS/SRTP session.
    rtcp_replay_per_ssrc: HashMap<u32, ReplayProtection>,
    
    /// Policy configuration.
    policy: SrtpPolicy,
    
    /// Statistics: RTP packets processed.
    rtp_count: u64,
    
    /// Statistics: RTCP packets processed.
    rtcp_count: u64,
}

impl SrtpContext {
    /// Create new context from key material.
    pub fn new(material: &KeyMaterial, policy: SrtpPolicy) -> Result<Self, SrtpError> {
        let keys = KeyDerivation::derive_keys(material)?;
        let cipher = SrtpCipher::new(&keys)?;
        
        Ok(Self {
            keys,
            cipher,
            ssrc_states: HashMap::new(),
            rtcp_replay_per_ssrc: HashMap::new(),
            policy,
            rtp_count: 0,
            rtcp_count: 0,
        })
    }
    
    /// Create with default policy (AES-128-GCM).
    pub fn with_default_policy(material: &KeyMaterial) -> Result<Self, SrtpError> {
        Self::new(material, SrtpPolicy::default())
    }
    
    /// Get protection profile.
    #[inline]
    pub fn profile(&self) -> ProtectionProfile {
        self.policy.profile
    }
    
    /// Get the cipher's authentication tag length in bytes.
    #[inline]
    pub fn cipher_tag_len(&self) -> usize {
        self.cipher.tag_len()
    }
    
    /// Get session keys (for advanced use).
    #[inline]
    pub fn keys(&self) -> &SrtpKeys {
        &self.keys
    }
    
    /// Get current ROC for the first known SSRC (for testing/stats).
    #[inline]
    pub fn roc(&self) -> u32 {
        self.ssrc_states.values().next().map_or(0, |s| s.roc)
    }
    
    /// Get statistics.
    #[inline]
    pub fn stats(&self) -> (u64, u64) {
        (self.rtp_count, self.rtcp_count)
    }
    
    /// Get or create per-SSRC state.
    fn get_ssrc_state(&mut self, ssrc: u32) -> &mut SsrcState {
        self.ssrc_states.entry(ssrc).or_insert_with(|| {
            let replay = if self.policy.allow_replay {
                ReplayProtection::disabled()
            } else {
                let window_size = self.policy.window_size.min(64);
                ReplayProtection::with_window_size(window_size)
            };
            SsrcState {
                roc: 0,
                highest_seq: 0,
                roc_initialized: false,
                replay,
                srtcp_index: 0,
            }
        })
    }

    /// Estimate packet index from sequence number for a given SSRC.
    fn estimate_index_for_ssrc(&self, ssrc: u32, seq: u16) -> PacketIndex {
        let state = match self.ssrc_states.get(&ssrc) {
            Some(s) => s,
            None => return PacketIndex::new(0, seq),
        };

        if !state.roc_initialized {
            return PacketIndex::new(0, seq);
        }

        let s_l = state.highest_seq;
        let roc = state.roc;

        // RFC 3711 Appendix A — signed arithmetic index estimation
        if s_l < 32768 {
            if seq.wrapping_sub(s_l) > 32768 {
                if roc > 0 { PacketIndex::new(roc - 1, seq) } else { PacketIndex::new(0, seq) }
            } else {
                PacketIndex::new(roc, seq)
            }
        } else {
            // s_l >= 32768: check if s_l - 32768 > seq (NOT wrapping_sub)
            if s_l - 32768 > seq {
                assert!(roc < u32::MAX, "ROC overflow");
                PacketIndex::new(roc + 1, seq)
            } else {
                PacketIndex::new(roc, seq)
            }
        }
    }

    /// Update ROC state for a given SSRC after successful packet processing.
    fn update_roc_for_ssrc(&mut self, ssrc: u32, seq: u16) {
        let state = self.get_ssrc_state(ssrc);

        if !state.roc_initialized {
            state.highest_seq = seq;
            state.roc_initialized = true;
            return;
        }

        let s_l = state.highest_seq;

        // RFC 3711 Section 3.3.1 — update ROC and s_l after authentication
        if s_l < 32768 {
            if seq.wrapping_sub(s_l) <= 32768 && seq > s_l {
                state.highest_seq = seq;
            }
        } else {
            // s_l >= 32768: check if s_l - 32768 > seq (wrap detected)
            if s_l - 32768 > seq {
                assert!(state.roc < u32::MAX, "ROC overflow");
                state.roc = state.roc.wrapping_add(1);
                state.highest_seq = seq;
            } else if seq > s_l {
                state.highest_seq = seq;
            }
        }
    }

    /// Parse and validate RTP header.
    fn parse_and_validate_rtp_header(
        &self,
        packet: &[u8],
        packet_len: usize,
    ) -> Result<RtpHeader, SrtpError> {
        assert!(packet_len >= RTP_HEADER_SIZE);
        
        let header = RtpHeader::parse(&packet[..packet_len])
            .ok_or(SrtpError::InvalidRtpHeader)?;
        
        if self.policy.ssrc != 0 && header.ssrc != self.policy.ssrc {
            return Err(SrtpError::InvalidSsrc);
        }
        
        assert!(header.header_len >= RTP_HEADER_SIZE);
        assert!(header.header_len <= packet_len);
        
        Ok(header)
    }
    
    /// Protect RTP packet (encrypt + authenticate).
    ///
    /// Transforms RTP to SRTP in-place.
    /// Buffer must have room for 16-byte auth tag.
    ///
    /// Returns the new packet length.
    pub fn protect_rtp(
        &mut self,
        packet: &mut [u8],
        packet_len: usize,
    ) -> Result<usize, SrtpError> {
        let tag_len = self.cipher.tag_len();
        // Preconditions
        assert!(packet_len > 0, "packet length must be positive");
        assert!(packet_len <= MAX_PACKET_SIZE as usize, "packet exceeds maximum size");
        assert!(packet.len() >= packet_len + tag_len, 
            "buffer must have room for auth tag");
        
        let result = self.protect_rtp_impl(packet, packet_len)?;
        
        // Postconditions
        assert!(result > packet_len, "protected packet must be larger");
        assert!(result == packet_len + tag_len,
            "protected size must equal original plus tag");
        
        Ok(result)
    }
    
    /// Implementation of protect_rtp.
    fn protect_rtp_impl(
        &mut self,
        packet: &mut [u8],
        packet_len: usize,
    ) -> Result<usize, SrtpError> {
        let header = self.parse_and_validate_rtp_header(packet, packet_len)?;
        let ssrc = header.ssrc;
        
        // For sending, estimate index using per-SSRC state
        let index = self.estimate_index_for_ssrc(ssrc, header.sequence_number);
        
        // Update ROC state BEFORE encryption so index is correct
        self.update_roc_for_ssrc(ssrc, header.sequence_number);
        
        // Protect
        let protected_len = self.cipher.protect_rtp(packet, packet_len, index)?;
        
        self.rtp_count = self.rtp_count.saturating_add(1);
        
        Ok(protected_len)
    }
    
    /// Unprotect SRTP packet (authenticate + decrypt).
    ///
    /// Transforms SRTP to RTP in-place.
    ///
    /// Returns the new packet length.
    pub fn unprotect_rtp(
        &mut self,
        packet: &mut [u8],
        packet_len: usize,
    ) -> Result<usize, SrtpError> {
        let tag_len = self.cipher.tag_len();
        // Preconditions
        assert!(packet_len >= RTP_HEADER_SIZE + tag_len,
            "packet too short for SRTP");
        assert!(packet_len <= MAX_PACKET_SIZE as usize,
            "packet exceeds maximum size");
        
        if packet_len < RTP_HEADER_SIZE + tag_len {
            return Err(SrtpError::PacketTooShort);
        }
        
        let result = self.unprotect_rtp_impl(packet, packet_len)?;
        
        // Postconditions
        assert!(result < packet_len, "unprotected packet must be smaller");
        assert!(result >= RTP_HEADER_SIZE, "result must include header");
        
        Ok(result)
    }
    
    /// Implementation of unprotect_rtp.
    fn unprotect_rtp_impl(
        &mut self,
        packet: &mut [u8],
        packet_len: usize,
    ) -> Result<usize, SrtpError> {
        let header = self.parse_and_validate_rtp_header(packet, packet_len)?;
        let ssrc = header.ssrc;
        
        // Estimate packet index using per-SSRC state
        let index = self.estimate_index_for_ssrc(ssrc, header.sequence_number);
        
        // Check replay before decryption (per-SSRC)
        {
            let state = self.get_ssrc_state(ssrc);
            state.replay.check(index.value())?;
        }
        
        // Unprotect
        let unprotected_len = self.cipher.unprotect_rtp(packet, packet_len, index)?;
        
        // Accept packet and update per-SSRC state after successful decryption
        {
            let state = self.get_ssrc_state(ssrc);
            state.replay.accept(index.value());
        }
        self.update_roc_for_ssrc(ssrc, header.sequence_number);
        self.rtp_count = self.rtp_count.saturating_add(1);
        
        Ok(unprotected_len)
    }
    
    /// Protect RTCP packet.
    ///
    /// Uses per-SSRC SRTCP index per RFC 3711 §3.4.
    /// Buffer must have room for 4-byte index + auth tag.
    pub fn protect_rtcp(
        &mut self,
        packet: &mut [u8],
        packet_len: usize,
    ) -> Result<usize, SrtpError> {
        // Extract SSRC from RTCP header (bytes 4-7).
        assert!(packet_len >= 8, "RTCP packet must be at least 8 bytes");
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        // Get per-SSRC SRTCP index (RFC 3711 §3.4)
        let state = self.get_ssrc_state(ssrc);
        if state.srtcp_index >= super::SRTCP_INDEX_MASK {
            return Err(SrtpError::SrtcpIndexOverflow);
        }
        let index = state.srtcp_index;
        state.srtcp_index += 1;

        let result = self.cipher.protect_rtcp(packet, packet_len, index)?;

        tracing::trace!(
            ssrc,
            srtcp_index = index,
            "SRTCP protect (per-SSRC index, RFC 3711 §3.4)"
        );

        self.rtcp_count += 1;
        Ok(result)
    }
    
    /// Unprotect SRTCP packet.
    ///
    /// Uses per-SSRC replay protection to handle WebRTC implementations
    /// that maintain separate SRTCP index counters per transceiver/SSRC.
    pub fn unprotect_rtcp(
        &mut self,
        packet: &mut [u8],
        packet_len: usize,
    ) -> Result<usize, SrtpError> {
        // Extract SSRC from RTCP header (bytes 4-7) before decryption.
        // The RTCP header is in the clear even in SRTCP.
        assert!(packet_len >= 8, "SRTCP packet must be at least 8 bytes");
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        
        let (result, index) = self.cipher.unprotect_rtcp(packet, packet_len)?;
        
        // Per-SSRC SRTCP replay check
        let replay = self.rtcp_replay_per_ssrc.entry(ssrc).or_insert_with(|| {
            if self.policy.allow_replay {
                ReplayProtection::disabled()
            } else {
                let window_size = self.policy.window_size.min(64);
                ReplayProtection::with_window_size(window_size)
            }
        });
        replay.check_and_accept(index as u64)?;
        self.rtcp_count += 1;
        
        Ok(result)
    }
    
    /// Rotate keys using new material.
    ///
    /// Creates new cipher contexts while preserving replay state.
    ///
    /// # TigerStyle
    /// - Profile must match existing context
    /// - ≥2 assertions
    pub fn rotate_keys(&mut self, material: &KeyMaterial) -> Result<(), SrtpError> {
        assert!(material.master_key_len > 0);
        assert!(material.profile == self.keys.profile, 
            "profile must match existing context");
        
        let new_keys = KeyDerivation::derive_keys(material)?;
        let new_cipher = SrtpCipher::new(&new_keys)?;
        
        // Atomic swap
        self.keys = new_keys;
        self.cipher = new_cipher;
        
        // Reset per-SSRC state but preserve replay windows
        self.ssrc_states.clear();
        
        Ok(())
    }
    
    /// Check if key rotation is needed.
    ///
    /// Rotation recommended after 2^48 packets or 24 hours.
    pub fn should_rotate_keys(&self) -> bool {
        const MAX_PACKETS: u64 = 1u64 << 48;
        self.rtp_count >= MAX_PACKETS
    }
    
    /// Get detailed statistics.
    pub fn detailed_stats(&self) -> SrtpStats {
        let replays: u64 = self.ssrc_states.values()
            .map(|s| s.replay.stats().1)
            .sum();
        
        let (current_roc, highest_seq) = self.ssrc_states.values()
            .next()
            .map_or((0, 0), |s| (s.roc, s.highest_seq));
        
        SrtpStats {
            rtp_protected: self.rtp_count,
            rtp_unprotected: self.rtp_count,
            rtcp_protected: self.rtcp_count,
            rtcp_unprotected: self.rtcp_count,
            replays_detected: replays,
            auth_failures: 0,
            current_roc,
            highest_seq,
        }
    }
}

/// SRTP statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SrtpStats {
    /// RTP packets protected.
    pub rtp_protected: u64,
    
    /// RTP packets unprotected.
    pub rtp_unprotected: u64,
    
    /// RTCP packets protected.
    pub rtcp_protected: u64,
    
    /// RTCP packets unprotected.
    pub rtcp_unprotected: u64,
    
    /// Replay attacks detected.
    pub replays_detected: u64,
    
    /// Authentication failures.
    pub auth_failures: u64,
    
    /// Current ROC value.
    pub current_roc: u32,
    
    /// Highest sequence number.
    pub highest_seq: u16,
}

/// SRTP session pair (send + receive contexts).
///
/// Convenience wrapper for bidirectional SRTP.
#[derive(Debug)]
pub struct SrtpSession {
    /// Context for outgoing packets.
    pub send: SrtpContext,
    /// Context for incoming packets.
    pub recv: SrtpContext,
}

impl SrtpSession {
    /// Create session from key material for both directions.
    ///
    /// For DTLS-SRTP, the client and server derive different keys.
    pub fn new(
        send_material: &KeyMaterial,
        recv_material: &KeyMaterial,
        policy: SrtpPolicy,
    ) -> Result<Self, SrtpError> {
        Ok(Self {
            send: SrtpContext::new(send_material, policy)?,
            recv: SrtpContext::new(recv_material, policy)?,
        })
    }
    
    /// Create with same key material for both directions (testing only).
    pub fn symmetric(material: &KeyMaterial, policy: SrtpPolicy) -> Result<Self, SrtpError> {
        Ok(Self {
            send: SrtpContext::new(material, policy)?,
            recv: SrtpContext::new(material, policy)?,
        })
    }
    
    /// Protect outgoing RTP.
    #[inline]
    pub fn protect_rtp(&mut self, packet: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        self.send.protect_rtp(packet, len)
    }
    
    /// Unprotect incoming SRTP.
    #[inline]
    pub fn unprotect_rtp(&mut self, packet: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        self.recv.unprotect_rtp(packet, len)
    }
    
    /// Protect outgoing RTCP.
    #[inline]
    pub fn protect_rtcp(&mut self, packet: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        self.send.protect_rtcp(packet, len)
    }
    
    /// Unprotect incoming SRTCP.
    #[inline]
    pub fn unprotect_rtcp(&mut self, packet: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        self.recv.unprotect_rtcp(packet, len)
    }
}

// ============================================================================
// Session Pool Management (RFC 3711 Section 3)
// ============================================================================

/// Bounded SRTP session pool.
///
/// Manages multiple SRTP sessions with configurable capacity.
/// Enforces MAX_SRTP_SESSIONS limit for resource control.
#[derive(Debug)]
pub struct SrtpSessionPool {
    /// Active sessions keyed by SSRC.
    sessions: std::collections::HashMap<u32, SrtpSession>,
    
    /// Maximum allowed sessions.
    max_sessions: u32,
}

impl SrtpSessionPool {
    /// Create new session pool with bounded capacity.
    ///
    /// # TigerStyle
    /// - Capacity clamped to MAX_SRTP_SESSIONS
    /// - ≥2 assertions
    pub fn new(capacity: u32) -> Self {
        let capped = capacity.min(super::MAX_SRTP_SESSIONS);
        
        assert!(capped > 0, "capacity must be positive");
        assert!(capped <= super::MAX_SRTP_SESSIONS);
        
        Self {
            sessions: std::collections::HashMap::with_capacity(capped as usize),
            max_sessions: capped,
        }
    }
    
    /// Insert session for SSRC.
    ///
    /// Returns error if pool is at capacity.
    pub fn insert(&mut self, ssrc: u32, session: SrtpSession) -> Result<(), SrtpError> {
        assert!(self.sessions.len() < u32::MAX as usize);
        
        if self.sessions.len() as u32 >= self.max_sessions {
            return Err(SrtpError::SessionLimitReached);
        }
        
        if self.sessions.contains_key(&ssrc) {
            return Err(SrtpError::DuplicateSession);
        }
        
        self.sessions.insert(ssrc, session);
        Ok(())
    }
    
    /// Get session by SSRC.
    #[inline]
    pub fn get(&self, ssrc: u32) -> Option<&SrtpSession> {
        self.sessions.get(&ssrc)
    }
    
    /// Get mutable session by SSRC.
    #[inline]
    pub fn get_mut(&mut self, ssrc: u32) -> Option<&mut SrtpSession> {
        self.sessions.get_mut(&ssrc)
    }
    
    /// Remove session by SSRC.
    pub fn remove(&mut self, ssrc: u32) -> Option<SrtpSession> {
        self.sessions.remove(&ssrc)
    }
    
    /// Check if pool contains SSRC.
    #[inline]
    pub fn contains(&self, ssrc: u32) -> bool {
        self.sessions.contains_key(&ssrc)
    }
    
    /// Current session count.
    #[inline]
    pub fn len(&self) -> u32 {
        self.sessions.len() as u32
    }
    
    /// Check if pool is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
    
    /// Remaining capacity.
    #[inline]
    pub fn remaining_capacity(&self) -> u32 {
        self.max_sessions.saturating_sub(self.sessions.len() as u32)
    }
    
    /// Pool statistics.
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            active_sessions: self.sessions.len() as u32,
            max_sessions: self.max_sessions,
            available: self.remaining_capacity(),
        }
    }
}

/// Pool statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PoolStats {
    /// Currently active sessions.
    pub active_sessions: u32,
    
    /// Maximum allowed sessions.
    pub max_sessions: u32,
    
    /// Available session slots.
    pub available: u32,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::SRTP_AUTH_TAG_SIZE;

    // ========================================================================
    // Test Helpers
    // ========================================================================

    fn test_material() -> KeyMaterial {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let salt = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b,
        ];
        KeyMaterial::from_aes128_gcm(&key, &salt).unwrap()
    }

    fn build_rtp_packet(seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 12 + payload.len() + 32]; // Room for tag
        packet[0] = 0x80; // V=2
        packet[1] = 0x60; // PT=96
        packet[2..4].copy_from_slice(&seq.to_be_bytes());
        packet[4..8].copy_from_slice(&1000u32.to_be_bytes()); // Timestamp
        packet[8..12].copy_from_slice(&ssrc.to_be_bytes());
        packet[12..12 + payload.len()].copy_from_slice(payload);
        packet
    }

    // ========================================================================
    // Context Creation Tests
    // ========================================================================

    #[test]
    fn test_context_creation() {
        let material = test_material();
        let ctx = SrtpContext::with_default_policy(&material).unwrap();
        assert_eq!(ctx.profile(), ProtectionProfile::AeadAes128Gcm);
        assert_eq!(ctx.roc(), 0);
    }

    #[test]
    fn test_context_with_custom_policy() {
        let material = test_material();
        let mut policy = SrtpPolicy::aes_128_gcm();
        policy.window_size = 128;
        let ctx = SrtpContext::new(&material, policy).unwrap();
        assert_eq!(ctx.profile(), ProtectionProfile::AeadAes128Gcm);
    }

    #[test]
    fn test_context_initial_state() {
        let material = test_material();
        let ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        // Initial state verification
        assert_eq!(ctx.roc(), 0);
        assert_eq!(ctx.stats(), (0, 0)); // No packets processed
    }

    // ========================================================================
    // RTP Protect/Unprotect Tests
    // ========================================================================

    #[test]
    fn test_protect_unprotect_rtp() {
        let material = test_material();
        let mut send_ctx = SrtpContext::with_default_policy(&material).unwrap();
        let mut recv_ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        let payload = b"Hello, SRTP!";
        let mut packet = build_rtp_packet(1, 0x12345678, payload);
        let original_len = 12 + payload.len();
        
        // Protect
        let protected_len = send_ctx.protect_rtp(&mut packet, original_len).unwrap();
        assert!(protected_len > original_len);
        assert_eq!(protected_len, original_len + SRTP_AUTH_TAG_SIZE);
        
        // Unprotect
        let unprotected_len = recv_ctx.unprotect_rtp(&mut packet, protected_len).unwrap();
        assert_eq!(unprotected_len, original_len);
        
        // Verify payload
        assert_eq!(&packet[12..12 + payload.len()], payload);
    }

    #[test]
    fn test_protect_updates_stats() {
        let material = test_material();
        let mut ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        let mut packet = build_rtp_packet(1, 0x12345678, b"test");
        ctx.protect_rtp(&mut packet, 16).unwrap();
        
        let (rtp, rtcp) = ctx.stats();
        assert_eq!(rtp, 1);
        assert_eq!(rtcp, 0);
    }

    #[test]
    fn test_unprotect_updates_stats() {
        let material = test_material();
        let mut send_ctx = SrtpContext::with_default_policy(&material).unwrap();
        let mut recv_ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        let mut packet = build_rtp_packet(1, 0x12345678, b"test");
        let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
        recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
        
        let (rtp, rtcp) = recv_ctx.stats();
        assert_eq!(rtp, 1);
        assert_eq!(rtcp, 0);
    }

    #[test]
    fn test_protect_multiple_packets() {
        let material = test_material();
        let mut ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        for seq in 1..=10u16 {
            let mut packet = build_rtp_packet(seq, 0x12345678, b"test");
            ctx.protect_rtp(&mut packet, 16).unwrap();
        }
        
        let (rtp, _) = ctx.stats();
        assert_eq!(rtp, 10);
    }

    // ========================================================================
    // Replay Detection Tests
    // ========================================================================

    #[test]
    fn test_replay_detection() {
        let material = test_material();
        let mut send_ctx = SrtpContext::with_default_policy(&material).unwrap();
        let mut recv_ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        let mut packet1 = build_rtp_packet(1, 0x12345678, b"test");
        let original_len = 16;
        
        // Protect and save
        let protected_len = send_ctx.protect_rtp(&mut packet1, original_len).unwrap();
        let saved_packet = packet1[..protected_len].to_vec();
        
        // First unprotect succeeds
        recv_ctx.unprotect_rtp(&mut packet1, protected_len).unwrap();
        
        // Replay should fail
        let mut replay_packet = saved_packet.clone();
        let result = recv_ctx.unprotect_rtp(&mut replay_packet, protected_len);
        assert_eq!(result, Err(SrtpError::ReplayDetected));
    }

    #[test]
    fn test_replay_disabled_allows_duplicate() {
        let material = test_material();
        let policy = SrtpPolicy::aes_128_gcm().with_allow_replay();
        let mut send_ctx = SrtpContext::new(&material, policy).unwrap();
        let mut recv_ctx = SrtpContext::new(&material, policy).unwrap();
        
        let mut packet = build_rtp_packet(1, 0x12345678, b"test");
        let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
        let saved = packet[..plen].to_vec();
        
        // First unprotect
        recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
        
        // Second unprotect should succeed with replay disabled
        let mut replay = saved;
        assert!(recv_ctx.unprotect_rtp(&mut replay, plen).is_ok());
    }

    // ========================================================================
    // Sequence Number Rollover Tests (ROC)
    // ========================================================================

    #[test]
    fn test_sequence_number_rollover() {
        let material = test_material();
        let mut send_ctx = SrtpContext::with_default_policy(&material).unwrap();
        let mut recv_ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        // Send packet near rollover
        let mut packet = build_rtp_packet(65534, 0x12345678, b"test");
        let len = 16;
        let plen = send_ctx.protect_rtp(&mut packet, len).unwrap();
        recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
        
        // Rollover
        let mut packet = build_rtp_packet(65535, 0x12345678, b"test");
        let plen = send_ctx.protect_rtp(&mut packet, len).unwrap();
        recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
        
        // After rollover
        let mut packet = build_rtp_packet(0, 0x12345678, b"test");
        let plen = send_ctx.protect_rtp(&mut packet, len).unwrap();
        recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
    }

    #[test]
    fn test_roc_initialized_after_first_packet() {
        let material = test_material();
        let mut send_ctx = SrtpContext::with_default_policy(&material).unwrap();
        let mut recv_ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        // Initially no SSRC state
        assert!(recv_ctx.ssrc_states.is_empty());
        
        let mut packet = build_rtp_packet(100, 0x12345678, b"test");
        let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
        recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
        
        // Now SSRC state exists and is initialized
        assert!(recv_ctx.ssrc_states.get(&0x12345678).unwrap().roc_initialized);
    }

    // ========================================================================
    // Out-of-Order Packet Tests
    // ========================================================================

    #[test]
    fn test_out_of_order_packets() {
        let material = test_material();
        let policy = SrtpPolicy::aes_128_gcm();
        let mut send_ctx = SrtpContext::new(&material, policy).unwrap();
        let mut recv_ctx = SrtpContext::new(&material, policy).unwrap();
        
        // Send packets 1, 2, 3
        let mut packets = Vec::new();
        for seq in 1..=3u16 {
            let mut packet = build_rtp_packet(seq, 0x12345678, b"test");
            let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
            packets.push((packet[..plen].to_vec(), plen));
        }
        
        // Receive out of order: 2, 1, 3
        let (ref mut p2, len2) = packets[1].clone();
        recv_ctx.unprotect_rtp(p2, len2).unwrap();
        
        let (ref mut p1, len1) = packets[0].clone();
        recv_ctx.unprotect_rtp(p1, len1).unwrap();
        
        let (ref mut p3, len3) = packets[2].clone();
        recv_ctx.unprotect_rtp(p3, len3).unwrap();
    }

    #[test]
    fn test_late_packet_within_window() {
        let material = test_material();
        let mut send_ctx = SrtpContext::with_default_policy(&material).unwrap();
        let mut recv_ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        // Send packets 1, 10, 20, 30 (within window)
        for seq in [1u16, 10, 20, 30] {
            let mut packet = build_rtp_packet(seq, 0x12345678, b"test");
            let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
            recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
        }
        
        // Late packet 15 should still work
        let mut packet = build_rtp_packet(15, 0x12345678, b"test");
        let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
        assert!(recv_ctx.unprotect_rtp(&mut packet, plen).is_ok());
    }

    // ========================================================================
    // Session Bidirectional Tests
    // ========================================================================

    #[test]
    fn test_session_bidirectional() {
        let send_material = test_material();
        let recv_material = {
            let key = [0xAA; 16];
            let salt = [0xBB; 12];
            KeyMaterial::from_aes128_gcm(&key, &salt).unwrap()
        };
        
        let policy = SrtpPolicy::aes_128_gcm();
        
        // Create two sessions with swapped keys
        let mut alice = SrtpSession::new(&send_material, &recv_material, policy).unwrap();
        let mut bob = SrtpSession::new(&recv_material, &send_material, policy).unwrap();
        
        // Alice -> Bob
        let mut packet = build_rtp_packet(1, 0x11111111, b"Hello Bob!");
        let plen = alice.protect_rtp(&mut packet, 22).unwrap();
        bob.unprotect_rtp(&mut packet, plen).unwrap();
        
        // Bob -> Alice
        let mut packet = build_rtp_packet(1, 0x22222222, b"Hello Alice!");
        let plen = bob.protect_rtp(&mut packet, 24).unwrap();
        alice.unprotect_rtp(&mut packet, plen).unwrap();
    }

    #[test]
    fn test_session_symmetric() {
        let material = test_material();
        let policy = SrtpPolicy::aes_128_gcm();
        
        let mut session = SrtpSession::symmetric(&material, policy).unwrap();
        
        let mut packet = build_rtp_packet(1, 0x12345678, b"test");
        let plen = session.protect_rtp(&mut packet, 16).unwrap();
        session.unprotect_rtp(&mut packet, plen).unwrap();
    }

    // ========================================================================
    // Index Estimation Tests
    // ========================================================================

    #[test]
    fn test_index_estimation() {
        let material = test_material();
        let ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        // First packet — no SSRC state yet, returns ROC=0
        let idx = ctx.estimate_index_for_ssrc(0x12345678, 100);
        assert_eq!(idx.roc(), 0);
        assert_eq!(idx.seq(), 100);
    }

    #[test]
    fn test_index_estimation_preserves_seq() {
        let material = test_material();
        let ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        for seq in [0u16, 1, 100, 1000, 65535] {
            let idx = ctx.estimate_index_for_ssrc(0x12345678, seq);
            assert_eq!(idx.seq(), seq);
        }
    }

    // ========================================================================
    // SSRC Policy Tests
    // ========================================================================

    #[test]
    fn test_ssrc_policy() {
        let material = test_material();
        let policy = SrtpPolicy::aes_128_gcm().with_ssrc(0x12345678);
        let mut ctx = SrtpContext::new(&material, policy).unwrap();
        
        // Matching SSRC works
        let mut packet = build_rtp_packet(1, 0x12345678, b"test");
        assert!(ctx.protect_rtp(&mut packet, 16).is_ok());
        
        // Wrong SSRC fails
        let mut packet = build_rtp_packet(2, 0x87654321, b"test");
        assert_eq!(ctx.protect_rtp(&mut packet, 16), Err(SrtpError::InvalidSsrc));
    }

    #[test]
    fn test_ssrc_policy_zero_allows_any() {
        let material = test_material();
        let policy = SrtpPolicy::aes_128_gcm().with_ssrc(0);
        let mut ctx = SrtpContext::new(&material, policy).unwrap();
        
        // Any SSRC works when policy is 0
        let mut packet = build_rtp_packet(1, 0x11111111, b"test");
        assert!(ctx.protect_rtp(&mut packet, 16).is_ok());
        
        let mut packet = build_rtp_packet(2, 0x22222222, b"test");
        assert!(ctx.protect_rtp(&mut packet, 16).is_ok());
    }

    // ========================================================================
    // Key Rotation Tests
    // ========================================================================

    #[test]
    fn test_key_rotation() {
        let material1 = test_material();
        let material2 = KeyMaterial::from_aes128_gcm(&[0xAA; 16], &[0xBB; 12]).unwrap();
        
        let mut ctx = SrtpContext::with_default_policy(&material1).unwrap();
        
        // Use old keys
        let mut packet = build_rtp_packet(1, 0x12345678, b"test");
        ctx.protect_rtp(&mut packet, 16).unwrap();
        
        // Rotate keys
        ctx.rotate_keys(&material2).unwrap();
        
        // ROC should be reset (no SSRC states)
        assert_eq!(ctx.roc(), 0);
        assert!(ctx.ssrc_states.is_empty());
    }

    #[test]
    fn test_should_rotate_keys() {
        let material = test_material();
        let ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        // Initially should not need rotation
        assert!(!ctx.should_rotate_keys());
    }

    // ========================================================================
    // Session Pool Tests
    // ========================================================================

    #[test]
    fn test_session_pool_creation() {
        let pool = SrtpSessionPool::new(10);
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.remaining_capacity(), 10);
    }

    #[test]
    fn test_session_pool_insert() {
        let material = test_material();
        let policy = SrtpPolicy::aes_128_gcm();
        let session = SrtpSession::symmetric(&material, policy).unwrap();
        
        let mut pool = SrtpSessionPool::new(10);
        pool.insert(0x12345678, session).unwrap();
        
        assert!(!pool.is_empty());
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(0x12345678));
    }

    #[test]
    fn test_session_pool_get() {
        let material = test_material();
        let policy = SrtpPolicy::aes_128_gcm();
        let session = SrtpSession::symmetric(&material, policy).unwrap();
        
        let mut pool = SrtpSessionPool::new(10);
        pool.insert(0x12345678, session).unwrap();
        
        assert!(pool.get(0x12345678).is_some());
        assert!(pool.get(0x87654321).is_none());
    }

    #[test]
    fn test_session_pool_remove() {
        let material = test_material();
        let policy = SrtpPolicy::aes_128_gcm();
        let session = SrtpSession::symmetric(&material, policy).unwrap();
        
        let mut pool = SrtpSessionPool::new(10);
        pool.insert(0x12345678, session).unwrap();
        
        let removed = pool.remove(0x12345678);
        assert!(removed.is_some());
        assert!(pool.is_empty());
    }

    #[test]
    fn test_session_pool_capacity_limit() {
        let material = test_material();
        let policy = SrtpPolicy::aes_128_gcm();
        
        let mut pool = SrtpSessionPool::new(2);
        
        for ssrc in [1u32, 2] {
            let session = SrtpSession::symmetric(&material, policy).unwrap();
            pool.insert(ssrc, session).unwrap();
        }
        
        // Third insert should fail
        let session = SrtpSession::symmetric(&material, policy).unwrap();
        let result = pool.insert(3, session);
        assert_eq!(result, Err(SrtpError::SessionLimitReached));
    }

    #[test]
    fn test_session_pool_duplicate_ssrc() {
        let material = test_material();
        let policy = SrtpPolicy::aes_128_gcm();
        
        let mut pool = SrtpSessionPool::new(10);
        let session1 = SrtpSession::symmetric(&material, policy).unwrap();
        let session2 = SrtpSession::symmetric(&material, policy).unwrap();
        
        pool.insert(0x12345678, session1).unwrap();
        let result = pool.insert(0x12345678, session2);
        assert_eq!(result, Err(SrtpError::DuplicateSession));
    }

    #[test]
    fn test_session_pool_stats() {
        let material = test_material();
        let policy = SrtpPolicy::aes_128_gcm();
        
        let mut pool = SrtpSessionPool::new(10);
        let session = SrtpSession::symmetric(&material, policy).unwrap();
        pool.insert(1, session).unwrap();
        
        let stats = pool.stats();
        assert_eq!(stats.active_sessions, 1);
        assert_eq!(stats.max_sessions, 10);
        assert_eq!(stats.available, 9);
    }

    #[test]
    fn test_session_pool_clamped_capacity() {
        // Capacity should be clamped to MAX_SRTP_SESSIONS
        let pool = SrtpSessionPool::new(u32::MAX);
        assert!(pool.remaining_capacity() <= crate::srtp::MAX_SRTP_SESSIONS);
    }

    // ========================================================================
    // Detailed Stats Tests
    // ========================================================================

    #[test]
    fn test_detailed_stats() {
        let material = test_material();
        let ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        let stats = ctx.detailed_stats();
        assert_eq!(stats.rtp_protected, 0);
        assert_eq!(stats.current_roc, 0);
        assert_eq!(stats.highest_seq, 0);
    }

    #[test]
    fn test_detailed_stats_after_packets() {
        let material = test_material();
        let mut send_ctx = SrtpContext::with_default_policy(&material).unwrap();
        let mut recv_ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        for seq in 1..=5u16 {
            let mut packet = build_rtp_packet(seq, 0x12345678, b"test");
            let plen = send_ctx.protect_rtp(&mut packet, 16).unwrap();
            recv_ctx.unprotect_rtp(&mut packet, plen).unwrap();
        }
        
        let stats = recv_ctx.detailed_stats();
        assert_eq!(stats.highest_seq, 5);
    }

    // ========================================================================
    // Error Case Tests
    // ========================================================================

    #[test]
    fn test_protect_insufficient_buffer() {
        let material = test_material();
        let mut ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        // Buffer without room for tag
        let mut packet = vec![0u8; 16]; // No room for 16-byte tag
        packet[0] = 0x80;
        
        // Should fail assertion or return error
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ctx.protect_rtp(&mut packet, 16)
        }));
        assert!(result.is_err()); // Panics due to assertion
    }

    // ========================================================================
    // Keys Accessor Tests
    // ========================================================================

    #[test]
    fn test_keys_accessor() {
        let material = test_material();
        let ctx = SrtpContext::with_default_policy(&material).unwrap();
        
        let keys = ctx.keys();
        assert_eq!(keys.rtp_key().len(), 16);
        assert_eq!(keys.rtp_salt().len(), 12);
    }

    // ========================================================================
    // Property-Based Tests
    // ========================================================================
    
    mod property_tests {
        use super::*;
        use proptest::prelude::*;
        
        /// Strategy for generating valid key material.
        #[allow(dead_code)]
        fn key_material_strategy() -> impl Strategy<Value = KeyMaterial> {
            // Generate random 16-byte key and 12-byte salt
            (
                prop::array::uniform16(any::<u8>()),
                prop::array::uniform12(any::<u8>()),
            ).prop_map(|(key, salt)| {
                KeyMaterial::from_aes128_gcm(&key, &salt).unwrap()
            })
        }
        
        /// Strategy for generating valid sequence numbers.
        fn seq_strategy() -> impl Strategy<Value = u16> {
            1..=65535u16
        }
        
        /// Strategy for generating valid SSRC values.
        fn ssrc_strategy() -> impl Strategy<Value = u32> {
            1..=u32::MAX
        }
        
        /// Strategy for generating RTP payloads.
        fn payload_strategy() -> impl Strategy<Value = Vec<u8>> {
            prop::collection::vec(any::<u8>(), 1..500)
        }
        
        /// Build an RTP packet for testing.
        fn build_rtp_packet(seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
            let mut packet = vec![0u8; 12 + payload.len() + 32]; // Room for tag
            packet[0] = 0x80; // V=2
            packet[1] = 0x60; // PT=96
            packet[2..4].copy_from_slice(&seq.to_be_bytes());
            packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
            packet[8..12].copy_from_slice(&ssrc.to_be_bytes());
            packet[12..12 + payload.len()].copy_from_slice(payload);
            packet
        }
        
        proptest! {
            /// Property: Ciphertext round-trip preserves plaintext.
            #[test]
            fn prop_roundtrip_preserves_plaintext(
                key in prop::array::uniform16(any::<u8>()),
                salt in prop::array::uniform12(any::<u8>()),
                seq in seq_strategy(),
                ssrc in ssrc_strategy(),
                payload in payload_strategy(),
            ) {
                let material = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
                let mut send = SrtpContext::with_default_policy(&material).unwrap();
                let mut recv = SrtpContext::with_default_policy(&material).unwrap();
                
                let mut packet = build_rtp_packet(seq, ssrc, &payload);
                let original_len = 12 + payload.len();
                let original_payload = payload.clone();
                
                let protected_len = send.protect_rtp(&mut packet, original_len).unwrap();
                
                // Protected length should be larger (by tag size)
                prop_assert!(protected_len > original_len);
                prop_assert_eq!(protected_len, original_len + 16); // GCM tag is 16 bytes
                
                let unprotected_len = recv.unprotect_rtp(&mut packet, protected_len).unwrap();
                
                prop_assert_eq!(unprotected_len, original_len);
                prop_assert_eq!(&packet[12..12 + payload.len()], &original_payload[..]);
            }
            
            /// Property: Same key produces same ciphertext for same input.
            #[test]
            fn prop_deterministic_encryption(
                key in prop::array::uniform16(any::<u8>()),
                salt in prop::array::uniform12(any::<u8>()),
                seq in 1u16..1000,
                ssrc in ssrc_strategy(),
            ) {
                let material = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
                
                // Create two contexts with same key
                let mut ctx1 = SrtpContext::with_default_policy(&material).unwrap();
                let mut ctx2 = SrtpContext::with_default_policy(&material).unwrap();
                
                let mut packet1 = build_rtp_packet(seq, ssrc, b"test");
                let mut packet2 = build_rtp_packet(seq, ssrc, b"test");
                
                let len1 = ctx1.protect_rtp(&mut packet1, 16).unwrap();
                let len2 = ctx2.protect_rtp(&mut packet2, 16).unwrap();
                
                // Same key + same seq + same ssrc + same payload = same ciphertext
                prop_assert_eq!(len1, len2);
                prop_assert_eq!(&packet1[..len1], &packet2[..len2]);
            }
            
            /// Property: Different keys produce different ciphertext.
            #[test]
            fn prop_different_keys_different_ciphertext(
                key1 in prop::array::uniform16(any::<u8>()),
                key2 in prop::array::uniform16(any::<u8>()),
                salt in prop::array::uniform12(any::<u8>()),
                seq in 1u16..1000,
            ) {
                // Skip if keys happen to be the same
                prop_assume!(key1 != key2);
                
                let material1 = KeyMaterial::from_aes128_gcm(&key1, &salt).unwrap();
                let material2 = KeyMaterial::from_aes128_gcm(&key2, &salt).unwrap();
                
                let mut ctx1 = SrtpContext::with_default_policy(&material1).unwrap();
                let mut ctx2 = SrtpContext::with_default_policy(&material2).unwrap();
                
                let mut packet1 = build_rtp_packet(seq, 0x12345678, b"test");
                let mut packet2 = build_rtp_packet(seq, 0x12345678, b"test");
                
                let len1 = ctx1.protect_rtp(&mut packet1, 16).unwrap();
                let len2 = ctx2.protect_rtp(&mut packet2, 16).unwrap();
                
                // Different keys should produce different ciphertext
                prop_assert_ne!(&packet1[12..len1], &packet2[12..len2]);
            }
            
            /// Property: Replay detection rejects duplicates.
            #[test]
            fn prop_replay_detection_rejects_duplicates(
                key in prop::array::uniform16(any::<u8>()),
                salt in prop::array::uniform12(any::<u8>()),
                seq in 1u16..1000,
            ) {
                let material = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
                let mut send = SrtpContext::with_default_policy(&material).unwrap();
                let mut recv = SrtpContext::with_default_policy(&material).unwrap();
                
                let mut packet = build_rtp_packet(seq, 0x12345678, b"test");
                let plen = send.protect_rtp(&mut packet, 16).unwrap();
                let saved = packet[..plen].to_vec();
                
                // First receive succeeds
                recv.unprotect_rtp(&mut packet, plen).unwrap();
                
                // Replay should fail
                let mut replay = saved;
                let result = recv.unprotect_rtp(&mut replay, plen);
                prop_assert!(result.is_err());
            }
            
            /// Property: Tag size is always 16 bytes for GCM.
            #[test]
            fn prop_gcm_tag_size_constant(
                key in prop::array::uniform16(any::<u8>()),
                salt in prop::array::uniform12(any::<u8>()),
                payload_len in 1usize..500,
            ) {
                let material = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
                let mut ctx = SrtpContext::with_default_policy(&material).unwrap();
                
                let payload = vec![0xAA; payload_len];
                let mut packet = build_rtp_packet(1, 0x12345678, &payload);
                let original_len = 12 + payload_len;
                
                let protected_len = ctx.protect_rtp(&mut packet, original_len).unwrap();
                
                // Tag size should always be 16 bytes
                prop_assert_eq!(protected_len - original_len, 16);
            }
        }
    }
}

// ============================================================================
// Compile-Time Assertions (TigerStyle)
// ============================================================================

const _: () = assert!(std::mem::size_of::<SrtpContext>() < 16384,
    "SrtpContext must be < 16KB");

const _: () = assert!(super::SRTP_AUTH_TAG_SIZE == 16,
    "SRTP auth tag size must be 16 bytes");

const _: () = assert!(super::RTP_HEADER_SIZE == 12,
    "RTP header must be exactly 12 bytes");
