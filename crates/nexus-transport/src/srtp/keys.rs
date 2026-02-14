//! SRTP key derivation.
//!
//! RFC 3711 Section 4.3 - Key derivation using AES-CM PRF.
//! RFC 7714 Section 9 - AEAD key derivation.
//!
//! Derives session keys from master key/salt for SRTP/SRTCP.

use aes::{Aes128, Aes256};
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

use super::error::SrtpError;
use super::types::ProtectionProfile;
use super::{
    LABEL_RTP_ENCRYPTION, LABEL_RTP_AUTH, LABEL_RTP_SALT,
    LABEL_RTCP_ENCRYPTION, LABEL_RTCP_AUTH, LABEL_RTCP_SALT,
};

/// Master key material from DTLS-SRTP.
#[derive(Clone)]
pub struct KeyMaterial {
    /// Master key (16 or 32 bytes).
    pub master_key: [u8; 32],
    /// Master key length.
    pub master_key_len: usize,
    /// Master salt (12 or 14 bytes).
    pub master_salt: [u8; 14],
    /// Master salt length.
    pub master_salt_len: usize,
    /// Protection profile.
    pub profile: ProtectionProfile,
}

impl KeyMaterial {
    /// Create from raw bytes (AES-128-GCM).
    pub fn from_aes128_gcm(key: &[u8], salt: &[u8]) -> Result<Self, SrtpError> {
        if key.len() != 16 {
            return Err(SrtpError::InvalidKeyMaterial);
        }
        if salt.len() != 12 {
            return Err(SrtpError::InvalidKeyMaterial);
        }
        
        let mut master_key = [0u8; 32];
        let mut master_salt = [0u8; 14];
        master_key[..16].copy_from_slice(key);
        master_salt[..12].copy_from_slice(salt);
        
        Ok(Self {
            master_key,
            master_key_len: 16,
            master_salt,
            master_salt_len: 12,
            profile: ProtectionProfile::AeadAes128Gcm,
        })
    }
    
    /// Create from raw bytes (AES-256-GCM).
    pub fn from_aes256_gcm(key: &[u8], salt: &[u8]) -> Result<Self, SrtpError> {
        if key.len() != 32 {
            return Err(SrtpError::InvalidKeyMaterial);
        }
        if salt.len() != 12 {
            return Err(SrtpError::InvalidKeyMaterial);
        }
        
        let mut master_key = [0u8; 32];
        let mut master_salt = [0u8; 14];
        master_key.copy_from_slice(key);
        master_salt[..12].copy_from_slice(salt);
        
        Ok(Self {
            master_key,
            master_key_len: 32,
            master_salt,
            master_salt_len: 12,
            profile: ProtectionProfile::AeadAes256Gcm,
        })
    }
    
    /// Create from DTLS key export.
    pub fn from_dtls_export(material: &[u8], profile: ProtectionProfile) -> Result<Self, SrtpError> {
        let key_len = profile.key_len();
        let salt_len = profile.salt_len();
        let expected_len = key_len + salt_len;
        
        if material.len() < expected_len {
            return Err(SrtpError::InvalidKeyMaterial);
        }
        
        let mut master_key = [0u8; 32];
        let mut master_salt = [0u8; 14];
        master_key[..key_len].copy_from_slice(&material[..key_len]);
        master_salt[..salt_len].copy_from_slice(&material[key_len..key_len + salt_len]);
        
        Ok(Self {
            master_key,
            master_key_len: key_len,
            master_salt,
            master_salt_len: salt_len,
            profile,
        })
    }
    
    /// Get master key slice.
    #[inline]
    pub fn key(&self) -> &[u8] {
        &self.master_key[..self.master_key_len]
    }
    
    /// Get master salt slice.
    #[inline]
    pub fn salt(&self) -> &[u8] {
        &self.master_salt[..self.master_salt_len]
    }
}

impl core::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("master_key_len", &self.master_key_len)
            .field("master_salt_len", &self.master_salt_len)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

/// Derived session keys for SRTP.
#[derive(Clone)]
pub struct SrtpKeys {
    /// RTP encryption key.
    pub rtp_key: [u8; 32],
    /// RTP encryption key length.
    pub rtp_key_len: usize,
    /// RTP salt.
    pub rtp_salt: [u8; 14],
    /// RTP salt length.
    pub rtp_salt_len: usize,
    /// RTP authentication key (for non-AEAD).
    pub rtp_auth: [u8; 20],
    /// RTP auth key length.
    pub rtp_auth_len: usize,
    
    /// RTCP encryption key.
    pub rtcp_key: [u8; 32],
    /// RTCP encryption key length.
    pub rtcp_key_len: usize,
    /// RTCP salt.
    pub rtcp_salt: [u8; 14],
    /// RTCP salt length.
    pub rtcp_salt_len: usize,
    /// RTCP authentication key (for non-AEAD).
    pub rtcp_auth: [u8; 20],
    /// RTCP auth key length.
    pub rtcp_auth_len: usize,
    
    /// Protection profile.
    pub profile: ProtectionProfile,
}

impl SrtpKeys {
    /// Get RTP key slice.
    #[inline]
    pub fn rtp_key(&self) -> &[u8] {
        &self.rtp_key[..self.rtp_key_len]
    }
    
    /// Get RTP salt slice.
    #[inline]
    pub fn rtp_salt(&self) -> &[u8] {
        &self.rtp_salt[..self.rtp_salt_len]
    }
    
    /// Get RTCP key slice.
    #[inline]
    pub fn rtcp_key(&self) -> &[u8] {
        &self.rtcp_key[..self.rtcp_key_len]
    }
    
    /// Get RTCP salt slice.
    #[inline]
    pub fn rtcp_salt(&self) -> &[u8] {
        &self.rtcp_salt[..self.rtcp_salt_len]
    }
}

impl core::fmt::Debug for SrtpKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SrtpKeys")
            .field("rtp_key_len", &self.rtp_key_len)
            .field("rtp_salt_len", &self.rtp_salt_len)
            .field("rtcp_key_len", &self.rtcp_key_len)
            .field("rtcp_salt_len", &self.rtcp_salt_len)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

/// Key derivation functions.
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive session keys from master key material.
    ///
    /// # TigerStyle
    /// - Material validated
    /// - ≥2 assertions
    pub fn derive_keys(material: &KeyMaterial) -> Result<SrtpKeys, SrtpError> {
        assert!(material.master_key_len > 0);
        assert!(material.master_salt_len > 0);
        
        let profile = material.profile;
        
        let mut keys = SrtpKeys {
            rtp_key: [0u8; 32],
            rtp_key_len: profile.key_len(),
            rtp_salt: [0u8; 14],
            rtp_salt_len: profile.salt_len(),
            rtp_auth: [0u8; 20],
            rtp_auth_len: 0,
            rtcp_key: [0u8; 32],
            rtcp_key_len: profile.key_len(),
            rtcp_salt: [0u8; 14],
            rtcp_salt_len: profile.salt_len(),
            rtcp_auth: [0u8; 20],
            rtcp_auth_len: 0,
            profile,
        };
        
        if profile.is_aead() {
            Self::derive_aead_keys(material, &mut keys)?;
        } else {
            Self::derive_prf_keys(material, &mut keys)?;
        }
        
        Ok(keys)
    }
    
    /// Derive keys for AEAD mode.
    fn derive_aead_keys(material: &KeyMaterial, keys: &mut SrtpKeys) -> Result<(), SrtpError> {
        assert!(material.profile.is_aead());
        
        Self::derive_key_aead(
            material.key(),
            material.salt(),
            LABEL_RTP_ENCRYPTION,
            &mut keys.rtp_key[..keys.rtp_key_len],
        )?;
        Self::derive_key_aead(
            material.key(),
            material.salt(),
            LABEL_RTP_SALT,
            &mut keys.rtp_salt[..keys.rtp_salt_len],
        )?;
        Self::derive_key_aead(
            material.key(),
            material.salt(),
            LABEL_RTCP_ENCRYPTION,
            &mut keys.rtcp_key[..keys.rtcp_key_len],
        )?;
        Self::derive_key_aead(
            material.key(),
            material.salt(),
            LABEL_RTCP_SALT,
            &mut keys.rtcp_salt[..keys.rtcp_salt_len],
        )?;
        
        Ok(())
    }
    
    /// Derive keys for non-AEAD mode.
    fn derive_prf_keys(material: &KeyMaterial, keys: &mut SrtpKeys) -> Result<(), SrtpError> {
        assert!(!material.profile.is_aead());
        
        Self::derive_key_prf(
            material.key(),
            material.salt(),
            LABEL_RTP_ENCRYPTION,
            0,
            &mut keys.rtp_key[..keys.rtp_key_len],
        )?;
        Self::derive_key_prf(
            material.key(),
            material.salt(),
            LABEL_RTP_SALT,
            0,
            &mut keys.rtp_salt[..keys.rtp_salt_len],
        )?;
        keys.rtp_auth_len = 20;
        Self::derive_key_prf(
            material.key(),
            material.salt(),
            LABEL_RTP_AUTH,
            0,
            &mut keys.rtp_auth,
        )?;
        
        Self::derive_key_prf(
            material.key(),
            material.salt(),
            LABEL_RTCP_ENCRYPTION,
            0,
            &mut keys.rtcp_key[..keys.rtcp_key_len],
        )?;
        Self::derive_key_prf(
            material.key(),
            material.salt(),
            LABEL_RTCP_SALT,
            0,
            &mut keys.rtcp_salt[..keys.rtcp_salt_len],
        )?;
        keys.rtcp_auth_len = 20;
        Self::derive_key_prf(
            material.key(),
            material.salt(),
            LABEL_RTCP_AUTH,
            0,
            &mut keys.rtcp_auth,
        )?;
        
        Ok(())
    }
    
    /// AEAD key derivation (RFC 7714 Section 9).
    ///
    /// For AEAD modes, KDF is simply:
    /// - key = AES-CM(master_key, (salt XOR (label << 48)))
    ///
    /// # TigerStyle
    /// - ≥2 assertions
    fn derive_key_aead(
        master_key: &[u8],
        master_salt: &[u8],
        label: u8,
        output: &mut [u8],
    ) -> Result<(), SrtpError> {
        assert!(master_key.len() >= 16);
        assert!(output.len() <= 32);
        
        // Build IV: salt XOR (label << 48)
        // For 12-byte salt, label goes at byte index 6 (bit 48)
        let mut iv = [0u8; 16];
        iv[..master_salt.len()].copy_from_slice(master_salt);
        if master_salt.len() > 6 {
            iv[6] ^= label;
        }
        
        // Use AES-CM (counter mode) to generate key stream
        Self::aes_cm_generate(master_key, &iv, output)
    }
    
    /// PRF key derivation (RFC 3711 Section 4.3).
    ///
    /// key_derivation_rate is typically 0 (no re-keying).
    ///
    /// # TigerStyle
    /// - ≥2 assertions
    fn derive_key_prf(
        master_key: &[u8],
        master_salt: &[u8],
        label: u8,
        index: u64,
        output: &mut [u8],
    ) -> Result<(), SrtpError> {
        assert!(master_key.len() >= 16);
        assert!(output.len() <= 32);
        
        // x = (index DIV key_derivation_rate)
        // For rate 0, x = 0
        let x = if index == 0 { 0u64 } else { index };
        
        // Build IV for PRF
        let mut iv = [0u8; 16];
        
        // Copy salt (up to 14 bytes)
        let salt_len = master_salt.len().min(14);
        iv[..salt_len].copy_from_slice(&master_salt[..salt_len]);
        
        // XOR with (label << 48) || x
        // Per RFC 3711 §4.3.1: key_id = label || r, where label is 8 bits
        // at byte position 7 and r is 48 bits at bytes 8-13 of the 14-byte field.
        iv[7] ^= label;
        
        // For non-zero x (re-keying), XOR packet index
        if x != 0 {
            let x_bytes = x.to_be_bytes();
            for i in 0..6 {
                iv[8 + i] ^= x_bytes[2 + i];
            }
        }
        
        Self::aes_cm_generate(master_key, &iv, output)
    }
    
    /// Generate key material using AES-CM.
    ///
    /// Uses AES-128-CM for 16-byte keys, AES-256-CM for 32-byte keys.
    fn aes_cm_generate(
        master_key: &[u8],
        iv: &[u8; 16],
        output: &mut [u8],
    ) -> Result<(), SrtpError> {
        assert!(master_key.len() >= 16);
        
        let mut counter = 0u16;
        let mut offset = 0;
        let mut block_iv = *iv;
        
        // Use AES-256-CM for 32-byte keys, AES-128-CM otherwise
        if master_key.len() >= 32 {
            let cipher = Aes256::new(GenericArray::from_slice(&master_key[..32]));
            
            while offset < output.len() {
                block_iv[14] = (counter >> 8) as u8;
                block_iv[15] = counter as u8;
                
                let mut block = GenericArray::clone_from_slice(&block_iv);
                cipher.encrypt_block(&mut block);
                
                let copy_len = (output.len() - offset).min(16);
                output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
                
                offset += 16;
                counter += 1;
            }
        } else {
            let cipher = Aes128::new(GenericArray::from_slice(&master_key[..16]));
            
            while offset < output.len() {
                block_iv[14] = (counter >> 8) as u8;
                block_iv[15] = counter as u8;
                
                let mut block = GenericArray::clone_from_slice(&block_iv);
                cipher.encrypt_block(&mut block);
                
                let copy_len = (output.len() - offset).min(16);
                output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);
                
                offset += 16;
                counter += 1;
            }
        }
        
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srtp::{SRTP_KEY_SIZE, SRTP_SALT_SIZE};

    // ========================================================================
    // KeyMaterial Creation Tests
    // ========================================================================

    #[test]
    fn test_key_material_aes128_gcm() {
        let key = [1u8; 16];
        let salt = [2u8; 12];
        
        let km = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
        assert_eq!(km.key(), &key);
        assert_eq!(km.salt(), &salt);
        assert_eq!(km.profile, ProtectionProfile::AeadAes128Gcm);
    }

    #[test]
    fn test_key_material_invalid_key_len() {
        let key = [1u8; 10]; // Wrong length
        let salt = [2u8; 12];
        
        assert!(KeyMaterial::from_aes128_gcm(&key, &salt).is_err());
    }

    #[test]
    fn test_key_material_invalid_salt_len() {
        let key = [1u8; 16];
        let salt = [2u8; 10]; // Wrong length
        
        assert!(KeyMaterial::from_aes128_gcm(&key, &salt).is_err());
    }

    #[test]
    fn test_key_derivation_aead() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let salt = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b,
        ];
        
        let km = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
        let keys = KeyDerivation::derive_keys(&km).unwrap();
        
        // Keys should be derived (not zero)
        assert_ne!(&keys.rtp_key[..16], &[0u8; 16]);
        assert_ne!(&keys.rtp_salt[..12], &[0u8; 12]);
        assert_ne!(&keys.rtcp_key[..16], &[0u8; 16]);
        assert_ne!(&keys.rtcp_salt[..12], &[0u8; 12]);
        
        // RTP and RTCP keys should be different
        assert_ne!(&keys.rtp_key[..16], &keys.rtcp_key[..16]);
        assert_ne!(&keys.rtp_salt[..12], &keys.rtcp_salt[..12]);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let key = [0xAB; 16];
        let salt = [0xCD; 12];
        
        let km = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
        let keys1 = KeyDerivation::derive_keys(&km).unwrap();
        let keys2 = KeyDerivation::derive_keys(&km).unwrap();
        
        // Same input should produce same output
        assert_eq!(&keys1.rtp_key[..16], &keys2.rtp_key[..16]);
        assert_eq!(&keys1.rtp_salt[..12], &keys2.rtp_salt[..12]);
    }

    #[test]
    fn test_key_material_from_dtls() {
        let material = [0x42u8; 28]; // 16 key + 12 salt
        
        let km = KeyMaterial::from_dtls_export(&material, ProtectionProfile::AeadAes128Gcm).unwrap();
        assert_eq!(km.master_key_len, 16);
        assert_eq!(km.master_salt_len, 12);
    }

    #[test]
    fn test_srtp_keys_accessors() {
        let key = [0x11; 16];
        let salt = [0x22; 12];
        
        let km = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
        let keys = KeyDerivation::derive_keys(&km).unwrap();
        
        assert_eq!(keys.rtp_key().len(), 16);
        assert_eq!(keys.rtp_salt().len(), 12);
        assert_eq!(keys.rtcp_key().len(), 16);
        assert_eq!(keys.rtcp_salt().len(), 12);
    }

    // ========================================================================
    // Key Derivation from Master Key Tests (RFC 3711 Section 4.3)
    // ========================================================================

    #[test]
    fn test_key_derivation_label_based() {
        let key = [0x42u8; 16];
        let salt = [0x24u8; 12];
        
        let km = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
        let keys = KeyDerivation::derive_keys(&km).unwrap();
        
        // Verify label constants
        assert_eq!(LABEL_RTP_ENCRYPTION, 0x00);
        assert_eq!(LABEL_RTP_AUTH, 0x01);
        assert_eq!(LABEL_RTP_SALT, 0x02);
        assert_eq!(LABEL_RTCP_ENCRYPTION, 0x03);
        assert_eq!(LABEL_RTCP_AUTH, 0x04);
        assert_eq!(LABEL_RTCP_SALT, 0x05);
        
        // Keys should be non-zero
        assert!(keys.rtp_key().iter().any(|&b| b != 0));
        assert!(keys.rtcp_key().iter().any(|&b| b != 0));
    }

    // ========================================================================
    // Key Length Tests
    // ========================================================================

    #[test]
    fn test_aes_128_key_length() {
        let key = [0x00u8; 16];
        let salt = [0x00u8; 12];
        
        let km = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
        assert_eq!(km.master_key_len, 16);
    }

    #[test]
    fn test_aes_256_key_length() {
        let key = [0x00u8; 32];
        let salt = [0x00u8; 12];
        
        let km = KeyMaterial::from_aes256_gcm(&key, &salt).unwrap();
        assert_eq!(km.master_key_len, 32);
    }

    // ========================================================================
    // Salt Length Tests
    // ========================================================================

    #[test]
    fn test_aead_salt_length() {
        let key = [0x00u8; 16];
        let salt = [0x00u8; 12];
        
        let km = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
        assert_eq!(km.master_salt_len, 12);
    }

    // ========================================================================
    // Invalid Key Material Tests
    // ========================================================================

    #[test]
    fn test_invalid_key_length_short() {
        let key = [0u8; 8]; // Too short
        let salt = [0u8; 12];
        
        let result = KeyMaterial::from_aes128_gcm(&key, &salt);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_length_long() {
        let key = [0u8; 20]; // Wrong size for AES-128
        let salt = [0u8; 12];
        
        let result = KeyMaterial::from_aes128_gcm(&key, &salt);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_salt_length_short() {
        let key = [0u8; 16];
        let salt = [0u8; 8]; // Too short
        
        let result = KeyMaterial::from_aes128_gcm(&key, &salt);
        assert!(result.is_err());
    }

    // ========================================================================
    // Key Derivation Determinism Tests
    // ========================================================================

    #[test]
    fn test_same_input_same_output() {
        let key = [0x55u8; 16];
        let salt = [0xAAu8; 12];
        
        let km = KeyMaterial::from_aes128_gcm(&key, &salt).unwrap();
        
        let keys1 = KeyDerivation::derive_keys(&km).unwrap();
        let keys2 = KeyDerivation::derive_keys(&km).unwrap();
        
        assert_eq!(keys1.rtp_key(), keys2.rtp_key());
        assert_eq!(keys1.rtp_salt(), keys2.rtp_salt());
        assert_eq!(keys1.rtcp_key(), keys2.rtcp_key());
        assert_eq!(keys1.rtcp_salt(), keys2.rtcp_salt());
    }

    #[test]
    fn test_different_input_different_output() {
        let km1 = KeyMaterial::from_aes128_gcm(&[0x11u8; 16], &[0x22u8; 12]).unwrap();
        let km2 = KeyMaterial::from_aes128_gcm(&[0x33u8; 16], &[0x44u8; 12]).unwrap();
        
        let keys1 = KeyDerivation::derive_keys(&km1).unwrap();
        let keys2 = KeyDerivation::derive_keys(&km2).unwrap();
        
        assert_ne!(keys1.rtp_key(), keys2.rtp_key());
        assert_ne!(keys1.rtp_salt(), keys2.rtp_salt());
    }

    // ========================================================================
    // DTLS Export Tests
    // ========================================================================

    #[test]
    fn test_dtls_export_aes128_gcm() {
        // AES-128-GCM: 16 byte key + 12 byte salt = 28 bytes
        let material = [0x42u8; 28];
        
        let km = KeyMaterial::from_dtls_export(&material, ProtectionProfile::AeadAes128Gcm).unwrap();
        
        assert_eq!(km.master_key_len, 16);
        assert_eq!(km.master_salt_len, 12);
        assert_eq!(km.profile, ProtectionProfile::AeadAes128Gcm);
    }

    #[test]
    fn test_dtls_export_too_short() {
        let material = [0x42u8; 20]; // Too short for AES-128-GCM (needs 28)
        
        let result = KeyMaterial::from_dtls_export(&material, ProtectionProfile::AeadAes128Gcm);
        assert!(result.is_err());
    }

    // ========================================================================
    // Key Material Debug Implementation Test
    // ========================================================================

    #[test]
    fn test_key_material_debug_no_secrets() {
        let km = KeyMaterial::from_aes128_gcm(&[0x42u8; 16], &[0x24u8; 12]).unwrap();
        
        let debug_str = format!("{:?}", km);
        
        // Debug output should NOT contain actual key bytes
        assert!(!debug_str.contains("42"), "Debug should not expose key material");
        
        // But should contain metadata
        assert!(debug_str.contains("KeyMaterial"));
        assert!(debug_str.contains("16")); // key length
    }

    // ========================================================================
    // SrtpKeys Structure Tests
    // ========================================================================

    #[test]
    fn test_srtp_keys_rtp_rtcp_different() {
        let km = KeyMaterial::from_aes128_gcm(&[0x42u8; 16], &[0x24u8; 12]).unwrap();
        let keys = KeyDerivation::derive_keys(&km).unwrap();
        
        // RTP and RTCP keys must be different (different labels)
        assert_ne!(keys.rtp_key(), keys.rtcp_key());
        assert_ne!(keys.rtp_salt(), keys.rtcp_salt());
    }

    // ========================================================================
    // Protection Profile Tests
    // ========================================================================

    #[test]
    fn test_protection_profile_key_lengths() {
        assert_eq!(ProtectionProfile::AeadAes128Gcm.key_len(), 16);
        assert_eq!(ProtectionProfile::AeadAes256Gcm.key_len(), 32);
    }

    #[test]
    fn test_protection_profile_salt_lengths() {
        assert_eq!(ProtectionProfile::AeadAes128Gcm.salt_len(), 12);
        assert_eq!(ProtectionProfile::AeadAes256Gcm.salt_len(), 12);
    }

    // ========================================================================
    // Constants Validation Tests
    // ========================================================================

    #[test]
    fn test_srtp_key_size_constant() {
        assert_eq!(SRTP_KEY_SIZE, 16);
    }

    #[test]
    fn test_srtp_salt_size_constant() {
        assert_eq!(SRTP_SALT_SIZE, 12);
    }

    // ========================================================================
    // RFC 3711 Appendix B.3 Test Vectors
    // ========================================================================

    #[test]
    fn test_rfc3711_kdf_cipher_key() {
        // RFC 3711 Appendix B.3 test vectors
        let master_key = hex_to_bytes("E1F97A0D3E018BE0D64FA32C06DE4139");
        let master_salt = hex_to_bytes("0EC675AD498AFEEBB6960B3AABE6");

        let km = KeyMaterial::from_dtls_export(
            &[master_key.as_slice(), master_salt.as_slice()].concat(),
            ProtectionProfile::Aes128CmHmacSha1_80,
        ).unwrap();

        let keys = KeyDerivation::derive_keys(&km).unwrap();

        // Expected cipher key from RFC 3711 B.3
        let expected_cipher_key = hex_to_bytes("C61E7A93744F39EE10734AFE3FF7A087");
        assert_eq!(keys.rtp_key(), &expected_cipher_key[..], "cipher key mismatch");

        // Expected cipher salt from RFC 3711 B.3
        let expected_cipher_salt = hex_to_bytes("30CBBC08863D8C85D49DB34A9AE1");
        assert_eq!(keys.rtp_salt(), &expected_cipher_salt[..], "cipher salt mismatch");

        // Expected auth key from RFC 3711 B.3 (20 bytes)
        let expected_auth_key = hex_to_bytes("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4");
        assert_eq!(&keys.rtp_auth[..keys.rtp_auth_len], &expected_auth_key[..], "auth key mismatch");
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
