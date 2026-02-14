//! SRTP cryptographic operations.
//!
//! RFC 3711 - AES-CM + HMAC-SHA1 for SRTP
//! RFC 7714 - AES-GCM for SRTP
//!
//! Provides encryption/decryption for SRTP packets.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit, generic_array::GenericArray as AesGenericArray};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use super::error::SrtpError;
use super::keys::SrtpKeys;
use super::types::{PacketIndex, ProtectionProfile, RtpHeader};
use super::{SRTP_AUTH_TAG_SIZE, RTP_HEADER_SIZE, RTCP_HEADER_SIZE};

type HmacSha1 = Hmac<Sha1>;

/// Cipher suite for SRTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// AES-128-GCM (RFC 7714).
    AeadAes128Gcm,
    /// AES-256-GCM (RFC 7714).
    AeadAes256Gcm,
    /// AES-128-CM + HMAC-SHA1-80 (RFC 3711).
    Aes128CmHmacSha1_80,
    /// AES-128-CM + HMAC-SHA1-32 (RFC 3711).
    Aes128CmHmacSha1_32,
}

impl From<ProtectionProfile> for CipherSuite {
    fn from(p: ProtectionProfile) -> Self {
        match p {
            ProtectionProfile::AeadAes128Gcm => Self::AeadAes128Gcm,
            ProtectionProfile::AeadAes256Gcm => Self::AeadAes256Gcm,
            ProtectionProfile::Aes128CmHmacSha1_80 => Self::Aes128CmHmacSha1_80,
            ProtectionProfile::Aes128CmHmacSha1_32 => Self::Aes128CmHmacSha1_32,
        }
    }
}

/// Inner cipher enum supporting both AES-128 and AES-256.
enum AesGcmCipherInner {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

impl AesGcmCipherInner {
    /// Encrypt in place with detached tag.
    fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, aes_gcm::aead::consts::U12>,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<aes_gcm::Tag, SrtpError> {
        match self {
            Self::Aes128(c) => c
                .encrypt_in_place_detached(nonce, aad, buffer)
                .map_err(|_| SrtpError::EncryptionFailed),
            Self::Aes256(c) => c
                .encrypt_in_place_detached(nonce, aad, buffer)
                .map_err(|_| SrtpError::EncryptionFailed),
        }
    }
    
    /// Decrypt in place with detached tag.
    fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, aes_gcm::aead::consts::U12>,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &aes_gcm::Tag,
    ) -> Result<(), SrtpError> {
        match self {
            Self::Aes128(c) => c
                .decrypt_in_place_detached(nonce, aad, buffer, tag)
                .map_err(|_| SrtpError::AuthenticationFailed),
            Self::Aes256(c) => c
                .decrypt_in_place_detached(nonce, aad, buffer, tag)
                .map_err(|_| SrtpError::AuthenticationFailed),
        }
    }
}

/// AES-GCM cipher context.
///
/// Handles encryption/decryption of SRTP/SRTCP packets.
/// Supports both AES-128-GCM and AES-256-GCM.
pub struct AesGcmCipher {
    /// RTP cipher (128 or 256 bit).
    rtp_cipher: AesGcmCipherInner,
    /// RTP salt.
    rtp_salt: [u8; 12],
    /// RTCP cipher (128 or 256 bit).
    rtcp_cipher: AesGcmCipherInner,
    /// RTCP salt.
    rtcp_salt: [u8; 12],
}

impl AesGcmCipher {
    /// Create cipher from derived keys.
    ///
    /// Supports AES-128-GCM and AES-256-GCM based on profile.
    pub fn new(keys: &SrtpKeys) -> Result<Self, SrtpError> {
        if !keys.profile.is_aead() {
            return Err(SrtpError::UnsupportedCipherSuite);
        }
        
        let (rtp_cipher, rtcp_cipher) = match keys.profile {
            ProtectionProfile::AeadAes128Gcm => {
                assert!(keys.rtp_key_len == 16);
                let rtp = Aes128Gcm::new(GenericArray::from_slice(keys.rtp_key()));
                let rtcp = Aes128Gcm::new(GenericArray::from_slice(keys.rtcp_key()));
                (AesGcmCipherInner::Aes128(rtp), AesGcmCipherInner::Aes128(rtcp))
            }
            ProtectionProfile::AeadAes256Gcm => {
                assert!(keys.rtp_key_len == 32);
                let rtp = Aes256Gcm::new(GenericArray::from_slice(keys.rtp_key()));
                let rtcp = Aes256Gcm::new(GenericArray::from_slice(keys.rtcp_key()));
                (AesGcmCipherInner::Aes256(rtp), AesGcmCipherInner::Aes256(rtcp))
            }
            _ => return Err(SrtpError::UnsupportedCipherSuite),
        };
        
        let mut rtp_salt = [0u8; 12];
        let mut rtcp_salt = [0u8; 12];
        rtp_salt.copy_from_slice(keys.rtp_salt());
        rtcp_salt.copy_from_slice(keys.rtcp_salt());
        
        Ok(Self {
            rtp_cipher,
            rtp_salt,
            rtcp_cipher,
            rtcp_salt,
        })
    }
    
    /// Build nonce for RTP packet (RFC 7714 Section 8.1).
    ///
    /// Nonce = salt XOR (SSRC || ROC || SEQ)
    #[inline]
    fn build_rtp_nonce(&self, ssrc: u32, index: PacketIndex) -> [u8; 12] {
        let mut nonce = self.rtp_salt;
        
        // XOR SSRC at bytes 2-5 (big-endian)
        let ssrc_bytes = ssrc.to_be_bytes();
        nonce[2] ^= ssrc_bytes[0];
        nonce[3] ^= ssrc_bytes[1];
        nonce[4] ^= ssrc_bytes[2];
        nonce[5] ^= ssrc_bytes[3];
        
        // XOR packet index (48-bit) at bytes 6-11
        let idx = index.value();
        nonce[6] ^= (idx >> 40) as u8;
        nonce[7] ^= (idx >> 32) as u8;
        nonce[8] ^= (idx >> 24) as u8;
        nonce[9] ^= (idx >> 16) as u8;
        nonce[10] ^= (idx >> 8) as u8;
        nonce[11] ^= idx as u8;
        
        nonce
    }
    
    /// Build nonce for RTCP packet (RFC 7714 Section 9.1).
    ///
    /// Nonce = salt XOR (SSRC || 0x0000 || SRTCP_index)
    #[inline]
    fn build_rtcp_nonce(&self, ssrc: u32, srtcp_index: u32) -> [u8; 12] {
        // Precondition: E flag must NOT be set — caller must pass the 31-bit index only
        debug_assert!(
            srtcp_index & super::SRTCP_E_FLAG == 0,
            "build_rtcp_nonce received srtcp_index with E flag set: {:#010x}",
            srtcp_index
        );
        let mut nonce = self.rtcp_salt;
        
        // XOR SSRC at bytes 2-5
        let ssrc_bytes = ssrc.to_be_bytes();
        nonce[2] ^= ssrc_bytes[0];
        nonce[3] ^= ssrc_bytes[1];
        nonce[4] ^= ssrc_bytes[2];
        nonce[5] ^= ssrc_bytes[3];
        
        // XOR SRTCP index at bytes 8-11 (with 0x0000 at 6-7)
        let idx_bytes = srtcp_index.to_be_bytes();
        nonce[8] ^= idx_bytes[0];
        nonce[9] ^= idx_bytes[1];
        nonce[10] ^= idx_bytes[2];
        nonce[11] ^= idx_bytes[3];
        
        nonce
    }
    
    /// Encrypt RTP payload in-place.
    ///
    /// Input: RTP packet with plaintext payload
    /// Output: SRTP packet with encrypted payload + auth tag
    ///
    /// Buffer must have room for 16-byte auth tag.
    ///
    /// # TigerStyle
    /// - Buffer bounds validated
    /// - ≥2 assertions
    pub fn protect_rtp(
        &self,
        packet: &mut [u8],
        packet_len: usize,
        index: PacketIndex,
    ) -> Result<usize, SrtpError> {
        assert!(packet_len >= RTP_HEADER_SIZE);
        assert!(packet.len() >= packet_len);
        
        // Validate input bounds
        if packet_len > super::MAX_PACKET_SIZE as usize {
            return Err(SrtpError::PacketTooLarge);
        }
        
        // Parse and validate header
        let header = self.parse_rtp_header_for_protect(packet, packet_len)?;
        
        // Check buffer has room for tag
        let output_len = packet_len + SRTP_AUTH_TAG_SIZE;
        if packet.len() < output_len {
            return Err(SrtpError::BufferTooSmall);
        }
        
        // Build nonce and encrypt
        self.encrypt_rtp_payload(packet, packet_len, &header, index)
    }
    
    /// Parse RTP header for protection.
    #[inline]
    fn parse_rtp_header_for_protect(
        &self,
        packet: &[u8],
        packet_len: usize,
    ) -> Result<RtpHeader, SrtpError> {
        assert!(packet.len() >= packet_len);
        
        RtpHeader::parse(&packet[..packet_len])
            .ok_or(SrtpError::InvalidRtpHeader)
    }
    
    /// Encrypt RTP payload after validation (in-place, zero-copy).
    fn encrypt_rtp_payload(
        &self,
        packet: &mut [u8],
        packet_len: usize,
        header: &RtpHeader,
        index: PacketIndex,
    ) -> Result<usize, SrtpError> {
        assert!(header.header_len <= packet_len);
        assert!(packet.len() >= packet_len + SRTP_AUTH_TAG_SIZE);
        
        let nonce = self.build_rtp_nonce(header.ssrc, index);
        let nonce_arr = GenericArray::from_slice(&nonce);
        
        // AAD is the RTP header (immutable copy for AEAD)
        let mut aad = [0u8; 128];
        aad[..header.header_len].copy_from_slice(&packet[..header.header_len]);
        
        // Encrypt payload in-place
        let _payload_len = packet_len - header.header_len;
        let payload = &mut packet[header.header_len..packet_len];
        
        let tag = self.rtp_cipher.encrypt_in_place_detached(
            nonce_arr,
            &aad[..header.header_len],
            payload,
        )?;
        
        // Append auth tag
        packet[packet_len..packet_len + SRTP_AUTH_TAG_SIZE].copy_from_slice(&tag);
        
        Ok(packet_len + SRTP_AUTH_TAG_SIZE)
    }
    
    /// Decrypt SRTP payload in-place.
    ///
    /// Input: SRTP packet with encrypted payload + auth tag
    /// Output: RTP packet with plaintext payload
    ///
    /// # TigerStyle
    /// - Buffer bounds validated
    /// - ≥2 assertions
    pub fn unprotect_rtp(
        &self,
        packet: &mut [u8],
        packet_len: usize,
        index: PacketIndex,
    ) -> Result<usize, SrtpError> {
        assert!(packet.len() >= packet_len);
        assert!(packet_len >= RTP_HEADER_SIZE + SRTP_AUTH_TAG_SIZE);
        
        if packet_len < RTP_HEADER_SIZE + SRTP_AUTH_TAG_SIZE {
            return Err(SrtpError::PacketTooShort);
        }
        
        if packet_len > super::MAX_PACKET_SIZE as usize {
            return Err(SrtpError::PacketTooLarge);
        }
        
        // Parse and validate header
        let header = self.parse_rtp_header_for_unprotect(packet, packet_len)?;
        
        // Decrypt payload
        self.decrypt_rtp_payload(packet, packet_len, &header, index)
    }
    
    /// Parse RTP header for unprotection.
    #[inline]
    fn parse_rtp_header_for_unprotect(
        &self,
        packet: &[u8],
        packet_len: usize,
    ) -> Result<RtpHeader, SrtpError> {
        assert!(packet.len() >= packet_len);
        
        let header = RtpHeader::parse(&packet[..packet_len])
            .ok_or(SrtpError::InvalidRtpHeader)?;
        
        if packet_len < header.header_len + SRTP_AUTH_TAG_SIZE {
            return Err(SrtpError::PacketTooShort);
        }
        
        Ok(header)
    }
    
    /// Decrypt RTP payload after validation (in-place, zero-copy).
    fn decrypt_rtp_payload(
        &self,
        packet: &mut [u8],
        packet_len: usize,
        header: &RtpHeader,
        index: PacketIndex,
    ) -> Result<usize, SrtpError> {
        assert!(header.header_len <= packet_len);
        assert!(packet_len >= header.header_len + SRTP_AUTH_TAG_SIZE);
        
        let nonce = self.build_rtp_nonce(header.ssrc, index);
        let nonce_arr = GenericArray::from_slice(&nonce);
        
        // AAD is the RTP header (immutable copy for AEAD)
        let mut aad = [0u8; 128];
        aad[..header.header_len].copy_from_slice(&packet[..header.header_len]);
        
        // Extract tag from end of packet
        let ciphertext_end = packet_len - SRTP_AUTH_TAG_SIZE;
        let mut tag_bytes = [0u8; SRTP_AUTH_TAG_SIZE];
        tag_bytes.copy_from_slice(&packet[ciphertext_end..packet_len]);
        let tag = GenericArray::from_slice(&tag_bytes);
        
        // Decrypt payload in-place
        let payload = &mut packet[header.header_len..ciphertext_end];
        
        self.rtp_cipher.decrypt_in_place_detached(
            nonce_arr,
            &aad[..header.header_len],
            payload,
            tag,
        )?;
        
        Ok(header.header_len + payload.len())
    }
    
    /// Encrypt RTCP packet in-place.
    ///
    /// Adds E-flag, SRTCP index, and auth tag.
    ///
    /// # TigerStyle
    /// - Buffer bounds validated
    /// - ≥2 assertions
    pub fn protect_rtcp(
        &self,
        packet: &mut [u8],
        packet_len: usize,
        srtcp_index: u32,
    ) -> Result<usize, SrtpError> {
        assert!(packet.len() >= packet_len);
        assert!(srtcp_index <= super::SRTCP_INDEX_MASK);
        
        if packet_len < RTCP_HEADER_SIZE {
            return Err(SrtpError::PacketTooShort);
        }
        
        if packet_len > super::MAX_PACKET_SIZE as usize {
            return Err(SrtpError::PacketTooLarge);
        }
        
        // SRTCP output: header(8) + encrypted_payload + SRTCP_index(4) + tag(16)
        let output_len = packet_len + 4 + SRTP_AUTH_TAG_SIZE;
        if packet.len() < output_len {
            return Err(SrtpError::BufferTooSmall);
        }
        
        // Encrypt RTCP payload
        self.encrypt_rtcp_payload(packet, packet_len, srtcp_index)
    }
    
    /// Encrypt RTCP payload after validation (in-place, zero-copy).
    fn encrypt_rtcp_payload(
        &self,
        packet: &mut [u8],
        packet_len: usize,
        srtcp_index: u32,
    ) -> Result<usize, SrtpError> {
        assert!(packet_len >= RTCP_HEADER_SIZE);
        assert!(packet.len() >= packet_len + 4 + SRTP_AUTH_TAG_SIZE);
        
        // Get SSRC from header
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        
        // Build nonce — per RFC 3711 §3.4, use the 31-bit SRTCP index WITHOUT E flag
        let nonce = self.build_rtcp_nonce(ssrc, srtcp_index);
        let nonce_arr = GenericArray::from_slice(&nonce);
        
        // AAD is the entire RTCP header (first 8 bytes) - copy for AEAD
        let mut aad = [0u8; RTCP_HEADER_SIZE];
        aad.copy_from_slice(&packet[..RTCP_HEADER_SIZE]);
        
        // Encrypt payload in-place
        let payload = &mut packet[RTCP_HEADER_SIZE..packet_len];
        
        let tag = self.rtcp_cipher.encrypt_in_place_detached(
            nonce_arr,
            &aad,
            payload,
        )?;
        
        // Append auth tag after ciphertext
        packet[packet_len..packet_len + SRTP_AUTH_TAG_SIZE].copy_from_slice(&tag);
        
        // Append SRTCP index with E-flag after tag
        let index_offset = packet_len + SRTP_AUTH_TAG_SIZE;
        let index_with_e = srtcp_index | super::SRTCP_E_FLAG;
        packet[index_offset..index_offset + 4].copy_from_slice(&index_with_e.to_be_bytes());
        
        Ok(index_offset + 4)
    }
    
    /// Decrypt SRTCP packet in-place.
    ///
    /// # TigerStyle
    /// - Buffer bounds validated
    /// - ≥2 assertions
    pub fn unprotect_rtcp(
        &self,
        packet: &mut [u8],
        packet_len: usize,
    ) -> Result<(usize, u32), SrtpError> {
        assert!(packet.len() >= packet_len);
        assert!(packet_len > 4);
        
        // Minimum: header(8) + tag(16) + index(4)
        if packet_len < RTCP_HEADER_SIZE + SRTP_AUTH_TAG_SIZE + 4 {
            return Err(SrtpError::PacketTooShort);
        }
        
        if packet_len > super::MAX_PACKET_SIZE as usize {
            return Err(SrtpError::PacketTooLarge);
        }
        
        // Extract and validate SRTCP index
        let (srtcp_index, encrypted) = self.extract_srtcp_index(packet, packet_len)?;
        
        if !encrypted {
            // Unencrypted RTCP - just strip the index
            return Ok((packet_len - 4, srtcp_index));
        }
        
        // Decrypt RTCP payload
        self.decrypt_rtcp_payload(packet, packet_len, srtcp_index)
    }
    
    /// Extract SRTCP index from packet.
    #[inline]
    fn extract_srtcp_index(
        &self,
        packet: &[u8],
        packet_len: usize,
    ) -> Result<(u32, bool), SrtpError> {
        assert!(packet_len >= 4);
        
        let index_offset = packet_len - 4;
        let index_bytes = [
            packet[index_offset],
            packet[index_offset + 1],
            packet[index_offset + 2],
            packet[index_offset + 3],
        ];
        let index_with_e = u32::from_be_bytes(index_bytes);
        let srtcp_index = index_with_e & super::SRTCP_INDEX_MASK;
        let encrypted = (index_with_e & super::SRTCP_E_FLAG) != 0;
        
        Ok((srtcp_index, encrypted))
    }
    
    /// Decrypt RTCP payload after validation (in-place, zero-copy).
    fn decrypt_rtcp_payload(
        &self,
        packet: &mut [u8],
        packet_len: usize,
        srtcp_index: u32,
    ) -> Result<(usize, u32), SrtpError> {
        assert!(packet_len >= RTCP_HEADER_SIZE + SRTP_AUTH_TAG_SIZE + 4);
        
        // SRTCP structure: header(8) | ciphertext | tag(16) | index(4)
        let index_offset = packet_len - 4;
        let tag_offset = index_offset - SRTP_AUTH_TAG_SIZE;
        
        // Get SSRC
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        
        // Build nonce — per RFC 3711 §3.4, use the 31-bit SRTCP index WITHOUT E flag
        let nonce = self.build_rtcp_nonce(ssrc, srtcp_index);
        let nonce_arr = GenericArray::from_slice(&nonce);
        
        // AAD is header - copy for AEAD
        let mut aad = [0u8; RTCP_HEADER_SIZE];
        aad.copy_from_slice(&packet[..RTCP_HEADER_SIZE]);
        
        // Extract tag
        let mut tag_bytes = [0u8; SRTP_AUTH_TAG_SIZE];
        tag_bytes.copy_from_slice(&packet[tag_offset..index_offset]);
        let tag = GenericArray::from_slice(&tag_bytes);
        
        // Decrypt payload in-place
        let payload = &mut packet[RTCP_HEADER_SIZE..tag_offset];
        
        self.rtcp_cipher.decrypt_in_place_detached(
            nonce_arr,
            &aad,
            payload,
            tag,
        )?;
        
        Ok((RTCP_HEADER_SIZE + payload.len(), srtcp_index))
    }
}

impl core::fmt::Debug for AesGcmCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesGcmCipher")
            .field("rtp_salt", &"[redacted]")
            .field("rtcp_salt", &"[redacted]")
            .finish()
    }
}

// ============================================================================
// AES-128-CM + HMAC-SHA1 cipher (RFC 3711)
// ============================================================================

/// AES-128-CM + HMAC-SHA1 cipher context.
///
/// Handles encryption/decryption of SRTP/SRTCP packets using
/// AES-128 counter mode for encryption and HMAC-SHA1 for authentication.
pub struct AesCmHmacCipher {
    /// RTP encryption key (AES-128).
    rtp_key: [u8; 16],
    /// RTP salt (14 bytes for CM mode).
    rtp_salt: [u8; 14],
    /// RTP HMAC-SHA1 auth key (20 bytes).
    rtp_auth_key: [u8; 20],
    /// RTCP encryption key (AES-128).
    rtcp_key: [u8; 16],
    /// RTCP salt (14 bytes for CM mode).
    rtcp_salt: [u8; 14],
    /// RTCP HMAC-SHA1 auth key (20 bytes).
    rtcp_auth_key: [u8; 20],
    /// Authentication tag length (10 for SHA1-80, 4 for SHA1-32).
    tag_len: usize,
}

impl AesCmHmacCipher {
    /// Create cipher from derived keys.
    pub fn new(keys: &SrtpKeys) -> Result<Self, SrtpError> {
        assert!(!keys.profile.is_aead());
        assert!(keys.rtp_key_len == 16);
        
        let tag_len = keys.profile.tag_len();
        assert!(tag_len == 10 || tag_len == 4);
        
        let mut rtp_key = [0u8; 16];
        let mut rtp_salt = [0u8; 14];
        let mut rtp_auth_key = [0u8; 20];
        let mut rtcp_key = [0u8; 16];
        let mut rtcp_salt = [0u8; 14];
        let mut rtcp_auth_key = [0u8; 20];
        
        rtp_key.copy_from_slice(keys.rtp_key());
        rtp_salt.copy_from_slice(keys.rtp_salt());
        rtp_auth_key.copy_from_slice(&keys.rtp_auth[..keys.rtp_auth_len]);
        rtcp_key.copy_from_slice(keys.rtcp_key());
        rtcp_salt.copy_from_slice(keys.rtcp_salt());
        rtcp_auth_key.copy_from_slice(&keys.rtcp_auth[..keys.rtcp_auth_len]);
        
        Ok(Self {
            rtp_key,
            rtp_salt,
            rtp_auth_key,
            rtcp_key,
            rtcp_salt,
            rtcp_auth_key,
            tag_len,
        })
    }
    
    /// AES-128-CM keystream generation (RFC 3711 Section 4.1).
    ///
    /// IV = (salt XOR (SSRC || packet_index)) << 16
    fn aes_cm_encrypt(
        key: &[u8; 16],
        iv: &[u8; 16],
        data: &mut [u8],
    ) {
        assert!(key.len() == 16);
        
        let cipher = Aes128::new(AesGenericArray::from_slice(key));
        let mut counter_block = *iv;
        let mut offset = 0;
        let mut counter = 0u16;
        
        while offset < data.len() {
            counter_block[14] = (counter >> 8) as u8;
            counter_block[15] = counter as u8;
            
            let mut block = AesGenericArray::clone_from_slice(&counter_block);
            cipher.encrypt_block(&mut block);
            
            let remaining = data.len() - offset;
            let xor_len = remaining.min(16);
            for i in 0..xor_len {
                data[offset + i] ^= block[i];
            }
            
            offset += 16;
            counter += 1;
        }
    }
    
    /// Build IV for RTP AES-CM (RFC 3711 Section 4.1).
    #[inline]
    fn build_rtp_iv(salt: &[u8; 14], ssrc: u32, index: PacketIndex) -> [u8; 16] {
        let mut iv = [0u8; 16];
        // Per RFC 3711 §4.1.1: IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
        // k_s (14 bytes) at bytes 0-13, SSRC at bytes 4-7, index (48-bit) at bytes 8-13
        // Bytes 14-15 are the block counter (start at 0, incremented by AES-CM)
        iv[0..14].copy_from_slice(salt);
        
        // XOR SSRC at bytes 4-7
        let ssrc_bytes = ssrc.to_be_bytes();
        iv[4] ^= ssrc_bytes[0];
        iv[5] ^= ssrc_bytes[1];
        iv[6] ^= ssrc_bytes[2];
        iv[7] ^= ssrc_bytes[3];
        
        // XOR packet index (48-bit) at bytes 8-13
        let idx = index.value();
        iv[8] ^= (idx >> 40) as u8;
        iv[9] ^= (idx >> 32) as u8;
        iv[10] ^= (idx >> 24) as u8;
        iv[11] ^= (idx >> 16) as u8;
        iv[12] ^= (idx >> 8) as u8;
        iv[13] ^= idx as u8;
        
        iv
    }
    
    /// Build IV for RTCP AES-CM.
    #[inline]
    fn build_rtcp_iv(salt: &[u8; 14], ssrc: u32, srtcp_index: u32) -> [u8; 16] {
        // Precondition: E flag must NOT be set — caller must pass the 31-bit index only
        debug_assert!(
            srtcp_index & super::SRTCP_E_FLAG == 0,
            "build_rtcp_iv received srtcp_index with E flag set: {:#010x}",
            srtcp_index
        );
        let mut iv = [0u8; 16];
        // Per RFC 3711 §3.4: same IV construction as RTP but with SRTCP index.
        // The srtcp_index here must be the 31-bit index WITHOUT the E flag.
        // k_s (14 bytes) at bytes 0-13
        iv[0..14].copy_from_slice(salt);
        
        let ssrc_bytes = ssrc.to_be_bytes();
        iv[4] ^= ssrc_bytes[0];
        iv[5] ^= ssrc_bytes[1];
        iv[6] ^= ssrc_bytes[2];
        iv[7] ^= ssrc_bytes[3];
        
        let idx_bytes = srtcp_index.to_be_bytes();
        iv[10] ^= idx_bytes[0];
        iv[11] ^= idx_bytes[1];
        iv[12] ^= idx_bytes[2];
        iv[13] ^= idx_bytes[3];
        
        iv
    }
    
    /// Compute HMAC-SHA1 over data, return truncated tag.
    fn compute_auth_tag(auth_key: &[u8; 20], data: &[u8], roc: u32, tag_len: usize) -> [u8; 20] {
        assert!(tag_len <= 20);
        
        let mut mac = <HmacSha1 as Mac>::new_from_slice(auth_key)
            .expect("HMAC key length is always valid");
        mac.update(data);
        // Append ROC (4 bytes, big-endian) per RFC 3711 Section 4.2
        mac.update(&roc.to_be_bytes());
        
        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; 20];
        tag.copy_from_slice(&result);
        tag
    }
    
    /// Protect RTP packet: encrypt payload + append HMAC tag.
    pub fn protect_rtp(
        &self,
        packet: &mut [u8],
        packet_len: usize,
        index: PacketIndex,
    ) -> Result<usize, SrtpError> {
        assert!(packet_len >= RTP_HEADER_SIZE);
        assert!(packet.len() >= packet_len);
        
        if packet_len > super::MAX_PACKET_SIZE as usize {
            return Err(SrtpError::PacketTooLarge);
        }
        
        let header = RtpHeader::parse(&packet[..packet_len])
            .ok_or(SrtpError::InvalidRtpHeader)?;
        
        let output_len = packet_len + self.tag_len;
        if packet.len() < output_len {
            return Err(SrtpError::BufferTooSmall);
        }
        
        // Encrypt payload in-place using AES-CM
        let iv = Self::build_rtp_iv(&self.rtp_salt, header.ssrc, index);
        Self::aes_cm_encrypt(
            &self.rtp_key,
            &iv,
            &mut packet[header.header_len..packet_len],
        );
        
        // Compute HMAC-SHA1 over header + encrypted payload, with ROC appended
        let tag = Self::compute_auth_tag(
            &self.rtp_auth_key,
            &packet[..packet_len],
            index.roc(),
            self.tag_len,
        );
        
        // Append truncated auth tag
        packet[packet_len..packet_len + self.tag_len]
            .copy_from_slice(&tag[..self.tag_len]);
        
        Ok(output_len)
    }
    
    /// Unprotect SRTP packet: verify HMAC tag + decrypt payload.
    pub fn unprotect_rtp(
        &self,
        packet: &mut [u8],
        packet_len: usize,
        index: PacketIndex,
    ) -> Result<usize, SrtpError> {
        assert!(packet.len() >= packet_len);
        assert!(packet_len >= RTP_HEADER_SIZE + self.tag_len);
        
        if packet_len < RTP_HEADER_SIZE + self.tag_len {
            return Err(SrtpError::PacketTooShort);
        }
        
        if packet_len > super::MAX_PACKET_SIZE as usize {
            return Err(SrtpError::PacketTooLarge);
        }
        
        let header = RtpHeader::parse(&packet[..packet_len])
            .ok_or(SrtpError::InvalidRtpHeader)?;
        
        if packet_len < header.header_len + self.tag_len {
            return Err(SrtpError::PacketTooShort);
        }
        
        let ciphertext_end = packet_len - self.tag_len;
        
        // Verify HMAC-SHA1 tag
        let expected_tag = Self::compute_auth_tag(
            &self.rtp_auth_key,
            &packet[..ciphertext_end],
            index.roc(),
            self.tag_len,
        );
        
        // Constant-time comparison of truncated tag
        let received_tag = &packet[ciphertext_end..packet_len];
        if !constant_time_eq(&expected_tag[..self.tag_len], received_tag) {
            // Debug: dump diagnostic info for first few failures
            tracing::warn!(
                ssrc = header.ssrc,
                seq = header.sequence_number,
                roc = index.roc(),
                index_value = index.value(),
                packet_len,
                tag_len = self.tag_len,
                header_len = header.header_len,
                ciphertext_end,
                expected_tag = ?&expected_tag[..self.tag_len],
                received_tag = ?received_tag,
                auth_key_prefix = ?&self.rtp_auth_key[..4],
                rtp_key_prefix = ?&self.rtp_key[..4],
                rtp_salt_prefix = ?&self.rtp_salt[..4],
                "SRTP auth tag mismatch"
            );
            return Err(SrtpError::AuthenticationFailed);
        }
        
        // Decrypt payload in-place using AES-CM
        let iv = Self::build_rtp_iv(&self.rtp_salt, header.ssrc, index);
        Self::aes_cm_encrypt(
            &self.rtp_key,
            &iv,
            &mut packet[header.header_len..ciphertext_end],
        );
        
        Ok(ciphertext_end)
    }
    
    /// Protect RTCP packet.
    ///
    /// SRTCP format: header(8) | encrypted_payload | E+SRTCP_index(4) | auth_tag
    pub fn protect_rtcp(
        &self,
        packet: &mut [u8],
        packet_len: usize,
        srtcp_index: u32,
    ) -> Result<usize, SrtpError> {
        assert!(packet.len() >= packet_len);
        assert!(srtcp_index <= super::SRTCP_INDEX_MASK);
        
        if packet_len < RTCP_HEADER_SIZE {
            return Err(SrtpError::PacketTooShort);
        }
        
        if packet_len > super::MAX_PACKET_SIZE as usize {
            return Err(SrtpError::PacketTooLarge);
        }
        
        let output_len = packet_len + 4 + self.tag_len;
        if packet.len() < output_len {
            return Err(SrtpError::BufferTooSmall);
        }
        
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        
        // Encrypt payload
        // Per RFC 3711 §3.4: IV uses the 31-bit SRTCP index WITHOUT the E flag.
        // The E flag is only an encryption indicator, not part of the index.
        let iv = Self::build_rtcp_iv(&self.rtcp_salt, ssrc, srtcp_index);
        Self::aes_cm_encrypt(
            &self.rtcp_key,
            &iv,
            &mut packet[RTCP_HEADER_SIZE..packet_len],
        );
        
        // Append E + SRTCP index after encrypted payload
        let index_with_e = srtcp_index | super::SRTCP_E_FLAG;
        packet[packet_len..packet_len + 4]
            .copy_from_slice(&index_with_e.to_be_bytes());
        
        // Compute HMAC over header + encrypted_payload + E+index
        let auth_end = packet_len + 4;
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&self.rtcp_auth_key)
            .expect("HMAC key length is always valid");
        mac.update(&packet[..auth_end]);
        let result = mac.finalize().into_bytes();
        
        // Append truncated auth tag
        packet[auth_end..auth_end + self.tag_len]
            .copy_from_slice(&result[..self.tag_len]);
        
        Ok(auth_end + self.tag_len)
    }
    
    /// Unprotect SRTCP packet.
    pub fn unprotect_rtcp(
        &self,
        packet: &mut [u8],
        packet_len: usize,
    ) -> Result<(usize, u32), SrtpError> {
        assert!(packet.len() >= packet_len);
        assert!(packet_len > 4);
        
        // Minimum: header(8) + E+index(4) + tag
        if packet_len < RTCP_HEADER_SIZE + 4 + self.tag_len {
            return Err(SrtpError::PacketTooShort);
        }
        
        if packet_len > super::MAX_PACKET_SIZE as usize {
            return Err(SrtpError::PacketTooLarge);
        }
        
        // Extract auth tag from end
        let tag_offset = packet_len - self.tag_len;
        let index_offset = tag_offset - 4;
        
        // Verify HMAC over header + encrypted_payload + E+index
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&self.rtcp_auth_key)
            .expect("HMAC key length is always valid");
        mac.update(&packet[..tag_offset]);
        let expected = mac.finalize().into_bytes();
        
        if !constant_time_eq(&expected[..self.tag_len], &packet[tag_offset..packet_len]) {
            return Err(SrtpError::AuthenticationFailed);
        }
        
        // Extract E + SRTCP index
        let index_with_e = u32::from_be_bytes([
            packet[index_offset],
            packet[index_offset + 1],
            packet[index_offset + 2],
            packet[index_offset + 3],
        ]);
        let srtcp_index = index_with_e & super::SRTCP_INDEX_MASK;
        let encrypted = (index_with_e & super::SRTCP_E_FLAG) != 0;
        
        if !encrypted {
            return Ok((index_offset, srtcp_index));
        }
        
        // Decrypt payload
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        // Per RFC 3711 §3.4: IV uses the 31-bit SRTCP index WITHOUT the E flag.
        let iv = Self::build_rtcp_iv(&self.rtcp_salt, ssrc, srtcp_index);
        Self::aes_cm_encrypt(
            &self.rtcp_key,
            &iv,
            &mut packet[RTCP_HEADER_SIZE..index_offset],
        );
        
        Ok((index_offset, srtcp_index))
    }
}

impl core::fmt::Debug for AesCmHmacCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesCmHmacCipher")
            .field("tag_len", &self.tag_len)
            .finish()
    }
}

/// Constant-time byte comparison.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    assert!(a.len() == b.len());
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ============================================================================
// Unified SRTP cipher
// ============================================================================

/// Unified SRTP cipher supporting both AEAD and non-AEAD profiles.
pub enum SrtpCipher {
    /// AES-GCM (AEAD) cipher.
    AesGcm(AesGcmCipher),
    /// AES-CM + HMAC-SHA1 cipher.
    AesCmHmac(AesCmHmacCipher),
}

impl SrtpCipher {
    /// Create the appropriate cipher from derived keys.
    pub fn new(keys: &SrtpKeys) -> Result<Self, SrtpError> {
        if keys.profile.is_aead() {
            Ok(Self::AesGcm(AesGcmCipher::new(keys)?))
        } else {
            Ok(Self::AesCmHmac(AesCmHmacCipher::new(keys)?))
        }
    }
    
    /// Get the auth tag length for this cipher.
    #[inline]
    pub fn tag_len(&self) -> usize {
        match self {
            Self::AesGcm(_) => SRTP_AUTH_TAG_SIZE,
            Self::AesCmHmac(c) => c.tag_len,
        }
    }
    
    /// Protect RTP packet.
    pub fn protect_rtp(
        &self,
        packet: &mut [u8],
        packet_len: usize,
        index: PacketIndex,
    ) -> Result<usize, SrtpError> {
        match self {
            Self::AesGcm(c) => c.protect_rtp(packet, packet_len, index),
            Self::AesCmHmac(c) => c.protect_rtp(packet, packet_len, index),
        }
    }
    
    /// Unprotect SRTP packet.
    pub fn unprotect_rtp(
        &self,
        packet: &mut [u8],
        packet_len: usize,
        index: PacketIndex,
    ) -> Result<usize, SrtpError> {
        match self {
            Self::AesGcm(c) => c.unprotect_rtp(packet, packet_len, index),
            Self::AesCmHmac(c) => c.unprotect_rtp(packet, packet_len, index),
        }
    }
    
    /// Protect RTCP packet.
    pub fn protect_rtcp(
        &self,
        packet: &mut [u8],
        packet_len: usize,
        srtcp_index: u32,
    ) -> Result<usize, SrtpError> {
        match self {
            Self::AesGcm(c) => c.protect_rtcp(packet, packet_len, srtcp_index),
            Self::AesCmHmac(c) => c.protect_rtcp(packet, packet_len, srtcp_index),
        }
    }
    
    /// Unprotect SRTCP packet.
    pub fn unprotect_rtcp(
        &self,
        packet: &mut [u8],
        packet_len: usize,
    ) -> Result<(usize, u32), SrtpError> {
        match self {
            Self::AesGcm(c) => c.unprotect_rtcp(packet, packet_len),
            Self::AesCmHmac(c) => c.unprotect_rtcp(packet, packet_len),
        }
    }
}

impl core::fmt::Debug for SrtpCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AesGcm(c) => c.fmt(f),
            Self::AesCmHmac(c) => c.fmt(f),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srtp::keys::{KeyDerivation, KeyMaterial};

    fn test_keys() -> SrtpKeys {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let salt = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b,
        ];
        let km = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
        KeyDerivation::derive_keys(&km).unwrap()
    }

    #[test]
    fn test_cipher_creation() {
        let keys = test_keys();
        let cipher = AesGcmCipher::new(&keys).unwrap();
        assert!(format!("{:?}", cipher).contains("AesGcmCipher"));
    }

    #[test]
    fn test_rtp_protect_unprotect() {
        let keys = test_keys();
        let cipher = AesGcmCipher::new(&keys).unwrap();
        
        // Build RTP packet
        let mut packet = [0u8; 100];
        // RTP header
        packet[0] = 0x80; // V=2
        packet[1] = 0x60; // PT=96
        packet[2] = 0x00; packet[3] = 0x01; // Seq=1
        packet[4..8].copy_from_slice(&100u32.to_be_bytes()); // Timestamp
        packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes()); // SSRC
        // Payload
        packet[12..20].copy_from_slice(b"testdata");
        let original_payload = packet[12..20].to_vec();
        
        let packet_len = 20;
        let index = PacketIndex::new(0, 1);
        
        // Protect
        let protected_len = cipher.protect_rtp(&mut packet, packet_len, index).unwrap();
        assert_eq!(protected_len, packet_len + SRTP_AUTH_TAG_SIZE);
        
        // Payload should be encrypted (different from original)
        assert_ne!(&packet[12..20], original_payload.as_slice());
        
        // Unprotect
        let unprotected_len = cipher.unprotect_rtp(&mut packet, protected_len, index).unwrap();
        assert_eq!(unprotected_len, packet_len);
        
        // Payload should be restored
        assert_eq!(&packet[12..20], original_payload.as_slice());
    }

    #[test]
    fn test_rtp_auth_failure() {
        let keys = test_keys();
        let cipher = AesGcmCipher::new(&keys).unwrap();
        
        let mut packet = [0u8; 100];
        packet[0] = 0x80;
        packet[1] = 0x60;
        packet[2..4].copy_from_slice(&1u16.to_be_bytes());
        packet[4..8].copy_from_slice(&100u32.to_be_bytes());
        packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
        packet[12..20].copy_from_slice(b"testdata");
        
        let index = PacketIndex::new(0, 1);
        let protected_len = cipher.protect_rtp(&mut packet, 20, index).unwrap();
        
        // Tamper with encrypted payload
        packet[15] ^= 0xFF;
        
        // Should fail authentication
        let result = cipher.unprotect_rtp(&mut packet, protected_len, index);
        assert_eq!(result, Err(SrtpError::AuthenticationFailed));
    }

    #[test]
    fn test_rtcp_protect_unprotect() {
        let keys = test_keys();
        let cipher = AesGcmCipher::new(&keys).unwrap();
        
        // Build RTCP SR packet
        let mut packet = [0u8; 100];
        packet[0] = 0x80; // V=2, PT=200 (SR)
        packet[1] = 0xC8;
        packet[2..4].copy_from_slice(&6u16.to_be_bytes()); // Length
        packet[4..8].copy_from_slice(&0x12345678u32.to_be_bytes()); // SSRC
        // Sender info (20 bytes) + payload
        for i in 8..28 {
            packet[i] = i as u8;
        }
        
        let packet_len = 28;
        let srtcp_index = 1u32;
        
        // Protect
        let protected_len = cipher.protect_rtcp(&mut packet, packet_len, srtcp_index).unwrap();
        // Output should be: header(8) + encrypted(20+16) + index(4) = 48
        assert!(protected_len > packet_len);
        
        // Unprotect
        let (unprotected_len, idx) = cipher.unprotect_rtcp(&mut packet, protected_len).unwrap();
        assert_eq!(unprotected_len, packet_len);
        assert_eq!(idx, srtcp_index);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let keys = test_keys();
        let cipher = AesGcmCipher::new(&keys).unwrap();
        
        // Different sequence numbers should produce different nonces
        let n1 = cipher.build_rtp_nonce(0x12345678, PacketIndex::new(0, 1));
        let n2 = cipher.build_rtp_nonce(0x12345678, PacketIndex::new(0, 2));
        assert_ne!(n1, n2);
        
        // Different SSRCs should produce different nonces
        let n3 = cipher.build_rtp_nonce(0x87654321, PacketIndex::new(0, 1));
        assert_ne!(n1, n3);
        
        // Different ROCs should produce different nonces
        let n4 = cipher.build_rtp_nonce(0x12345678, PacketIndex::new(1, 1));
        assert_ne!(n1, n4);
    }
    
    #[test]
    fn test_aes256_gcm_protect_unprotect() {
        // Create AES-256-GCM keys
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let salt = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b,
        ];
        let km = KeyMaterial::from_aes256_gcm(&key, &salt).unwrap();
        let keys = KeyDerivation::derive_keys(&km).unwrap();
        let cipher = AesGcmCipher::new(&keys).unwrap();
        
        // Build RTP packet
        let mut packet = [0u8; 100];
        packet[0] = 0x80;
        packet[1] = 0x60;
        packet[2..4].copy_from_slice(&1u16.to_be_bytes());
        packet[4..8].copy_from_slice(&100u32.to_be_bytes());
        packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
        packet[12..20].copy_from_slice(b"testdata");
        let original_payload = packet[12..20].to_vec();
        
        let packet_len = 20;
        let index = PacketIndex::new(0, 1);
        
        // Protect
        let protected_len = cipher.protect_rtp(&mut packet, packet_len, index).unwrap();
        assert_eq!(protected_len, packet_len + SRTP_AUTH_TAG_SIZE);
        
        // Payload should be encrypted
        assert_ne!(&packet[12..20], original_payload.as_slice());
        
        // Unprotect
        let unprotected_len = cipher.unprotect_rtp(&mut packet, protected_len, index).unwrap();
        assert_eq!(unprotected_len, packet_len);
        
        // Payload should be restored
        assert_eq!(&packet[12..20], original_payload.as_slice());
    }

    // ========================================================================
    // AES-CM-HMAC-SHA1-80 Tests
    // ========================================================================

    fn test_hmac_keys() -> SrtpKeys {
        let key = [0x01u8; 16];
        let salt = [0x02u8; 14];
        let km = KeyMaterial::from_dtls_export(
            &[key.as_slice(), salt.as_slice()].concat(),
            ProtectionProfile::Aes128CmHmacSha1_80,
        ).unwrap();
        KeyDerivation::derive_keys(&km).unwrap()
    }

    #[test]
    fn test_aes_cm_hmac_sha1_rtp_roundtrip() {
        let keys = test_hmac_keys();
        let cipher = AesCmHmacCipher::new(&keys).unwrap();
        assert_eq!(cipher.tag_len, 10);

        // Build RTP packet with room for 10-byte auth tag
        let mut packet = [0u8; 100];
        packet[0] = 0x80;
        packet[1] = 0x60;
        packet[2..4].copy_from_slice(&42u16.to_be_bytes());
        packet[4..8].copy_from_slice(&1000u32.to_be_bytes());
        packet[8..12].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        packet[12..24].copy_from_slice(b"hello world!");
        let original_payload = packet[12..24].to_vec();
        let packet_len = 24;
        let index = PacketIndex::new(0, 42);

        // Protect
        let protected_len = cipher.protect_rtp(&mut packet, packet_len, index).unwrap();
        assert_eq!(protected_len, packet_len + 10);

        // Payload should be encrypted
        assert_ne!(&packet[12..24], original_payload.as_slice());

        // Unprotect
        let unprotected_len = cipher.unprotect_rtp(&mut packet, protected_len, index).unwrap();
        assert_eq!(unprotected_len, packet_len);

        // Payload should be restored
        assert_eq!(&packet[12..24], original_payload.as_slice());
    }

    #[test]
    fn test_aes_cm_hmac_sha1_rtcp_roundtrip() {
        let keys = test_hmac_keys();
        let cipher = AesCmHmacCipher::new(&keys).unwrap();

        // Build RTCP SR packet
        let mut packet = [0u8; 100];
        packet[0] = 0x80;
        packet[1] = 0xC8; // SR
        packet[2..4].copy_from_slice(&6u16.to_be_bytes());
        packet[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        let packet_len = 28;
        let srtcp_index = 0u32;

        // Protect
        let protected_len = cipher.protect_rtcp(&mut packet, packet_len, srtcp_index).unwrap();
        assert_eq!(protected_len, packet_len + 4 + 10); // +4 index +10 tag

        // Unprotect
        let (unprotected_len, idx) = cipher.unprotect_rtcp(&mut packet, protected_len).unwrap();
        assert_eq!(unprotected_len, packet_len);
        assert_eq!(idx, srtcp_index);
    }

    #[test]
    fn test_aes_cm_hmac_sha1_auth_tag_mismatch() {
        let keys = test_hmac_keys();
        let cipher = AesCmHmacCipher::new(&keys).unwrap();

        let mut packet = [0u8; 100];
        packet[0] = 0x80;
        packet[1] = 0x60;
        packet[2..4].copy_from_slice(&1u16.to_be_bytes());
        packet[4..8].copy_from_slice(&100u32.to_be_bytes());
        packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
        packet[12..16].copy_from_slice(b"test");
        let packet_len = 16;
        let index = PacketIndex::new(0, 1);

        let protected_len = cipher.protect_rtp(&mut packet, packet_len, index).unwrap();

        // Corrupt the auth tag
        packet[protected_len - 1] ^= 0xFF;

        let result = cipher.unprotect_rtp(&mut packet, protected_len, index);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_cm_hmac_sha1_different_keys_fail() {
        let keys1 = test_hmac_keys();
        let cipher1 = AesCmHmacCipher::new(&keys1).unwrap();

        // Different key material
        let key2 = [0xAA; 16];
        let salt2 = [0xBB; 14];
        let km2 = KeyMaterial::from_dtls_export(
            &[key2.as_slice(), salt2.as_slice()].concat(),
            ProtectionProfile::Aes128CmHmacSha1_80,
        ).unwrap();
        let keys2 = KeyDerivation::derive_keys(&km2).unwrap();
        let cipher2 = AesCmHmacCipher::new(&keys2).unwrap();

        let mut packet = [0u8; 100];
        packet[0] = 0x80;
        packet[1] = 0x60;
        packet[2..4].copy_from_slice(&1u16.to_be_bytes());
        packet[4..8].copy_from_slice(&100u32.to_be_bytes());
        packet[8..12].copy_from_slice(&0x12345678u32.to_be_bytes());
        packet[12..16].copy_from_slice(b"test");
        let packet_len = 16;
        let index = PacketIndex::new(0, 1);

        let protected_len = cipher1.protect_rtp(&mut packet, packet_len, index).unwrap();

        // Unprotect with different keys should fail
        let result = cipher2.unprotect_rtp(&mut packet, protected_len, index);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_cm_hmac_sha1_iv_construction() {
        // Verify IV matches RFC 3711 §4.1.1:
        // IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
        let salt: [u8; 14] = [
            0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB,
            0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
        ];
        let ssrc: u32 = 0x12345678;
        let index = PacketIndex::new(0, 1); // ROC=0, seq=1 → index=1

        let iv = AesCmHmacCipher::build_rtp_iv(&salt, ssrc, index);

        // Expected: salt at bytes 0-13, XOR SSRC at 4-7, XOR index at 8-13
        // Bytes 14-15 = 0 (counter)
        let mut expected = [0u8; 16];
        expected[0..14].copy_from_slice(&salt);
        // XOR SSRC at bytes 4-7
        expected[4] ^= 0x12;
        expected[5] ^= 0x34;
        expected[6] ^= 0x56;
        expected[7] ^= 0x78;
        // XOR index (48-bit value = 1) at bytes 8-13
        expected[13] ^= 0x01;
        // Bytes 14-15 remain 0

        assert_eq!(iv, expected, "RTP IV must match RFC 3711 §4.1.1");
    }
}
