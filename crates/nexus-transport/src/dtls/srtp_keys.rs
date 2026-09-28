//! SRTP keying material exported by the DTLS handshake (RFC 5764): the negotiated
//! protection profile and the client/server master keys and salts. Filled by the
//! OpenSSL engine (`openssl_backend.rs`); the pure-Rust DTLS that also used these
//! types was removed in Phase 1 (C5).

/// SRTP protection profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SrtpProfile {
    /// SRTP_AES128_CM_HMAC_SHA1_80
    Aes128CmHmacSha1_80 = 0x0001,

    /// SRTP_AES128_CM_HMAC_SHA1_32
    Aes128CmHmacSha1_32 = 0x0002,

    /// SRTP_AEAD_AES_128_GCM
    AeadAes128Gcm = 0x0007,

    /// SRTP_AEAD_AES_256_GCM
    AeadAes256Gcm = 0x0008,
}

impl SrtpProfile {
    /// Parse from u16.
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::Aes128CmHmacSha1_80),
            0x0002 => Some(Self::Aes128CmHmacSha1_32),
            0x0007 => Some(Self::AeadAes128Gcm),
            0x0008 => Some(Self::AeadAes256Gcm),
            _ => None,
        }
    }

    /// Key length for this profile.
    #[inline]
    pub const fn key_length(self) -> usize {
        match self {
            Self::Aes128CmHmacSha1_80 | Self::Aes128CmHmacSha1_32 | Self::AeadAes128Gcm => 16,
            Self::AeadAes256Gcm => 32,
        }
    }

    /// Salt length for this profile.
    #[inline]
    pub const fn salt_length(self) -> usize {
        match self {
            Self::Aes128CmHmacSha1_80 | Self::Aes128CmHmacSha1_32 => 14,
            Self::AeadAes128Gcm | Self::AeadAes256Gcm => 12,
        }
    }

    /// Total keying material length.
    #[inline]
    pub const fn keying_material_length(self) -> usize {
        // client_key + server_key + client_salt + server_salt
        2 * self.key_length() + 2 * self.salt_length()
    }

    /// Returns true if this is an AEAD profile.
    #[inline]
    pub const fn is_aead(self) -> bool {
        matches!(self, Self::AeadAes128Gcm | Self::AeadAes256Gcm)
    }

    /// The SRTP layer's profile with the same id (both follow RFC 5764 / RFC 7714
    /// numbering; key and salt lengths agree, checked in the tests).
    #[inline]
    pub const fn protection_profile(self) -> crate::srtp::ProtectionProfile {
        use crate::srtp::ProtectionProfile as P;
        match self {
            Self::Aes128CmHmacSha1_80 => P::Aes128CmHmacSha1_80,
            Self::Aes128CmHmacSha1_32 => P::Aes128CmHmacSha1_32,
            Self::AeadAes128Gcm => P::AeadAes128Gcm,
            Self::AeadAes256Gcm => P::AeadAes256Gcm,
        }
    }
}

// Compile-time assertions for SrtpProfile
const _: () = {
    assert!(SrtpProfile::AeadAes128Gcm as u16 == 0x0007);
    assert!(SrtpProfile::AeadAes256Gcm as u16 == 0x0008);
    assert!(SrtpProfile::Aes128CmHmacSha1_80 as u16 == 0x0001);
};

/// SRTP keying material.
#[derive(Debug, Clone)]
pub struct SrtpKeyMaterial {
    /// Client master key.
    pub client_master_key: [u8; 32],
    pub client_master_key_len: u8,

    /// Server master key.
    pub server_master_key: [u8; 32],
    pub server_master_key_len: u8,

    /// Client master salt.
    pub client_master_salt: [u8; 14],
    pub client_master_salt_len: u8,

    /// Server master salt.
    pub server_master_salt: [u8; 14],
    pub server_master_salt_len: u8,

    /// Selected profile.
    pub profile: SrtpProfile,
}

impl SrtpKeyMaterial {
    /// Create empty keying material.
    pub const fn empty() -> Self {
        Self {
            client_master_key: [0u8; 32],
            client_master_key_len: 0,
            server_master_key: [0u8; 32],
            server_master_key_len: 0,
            client_master_salt: [0u8; 14],
            client_master_salt_len: 0,
            server_master_salt: [0u8; 14],
            server_master_salt_len: 0,
            profile: SrtpProfile::AeadAes128Gcm,
        }
    }

    /// Get client master key.
    #[inline]
    pub fn client_key(&self) -> &[u8] {
        &self.client_master_key[..self.client_master_key_len as usize]
    }

    /// Get server master key.
    #[inline]
    pub fn server_key(&self) -> &[u8] {
        &self.server_master_key[..self.server_master_key_len as usize]
    }

    /// Get client master salt.
    #[inline]
    pub fn client_salt(&self) -> &[u8] {
        &self.client_master_salt[..self.client_master_salt_len as usize]
    }

    /// Get server master salt.
    #[inline]
    pub fn server_salt(&self) -> &[u8] {
        &self.server_master_salt[..self.server_master_salt_len as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_profile_matches_id_and_lengths() {
        for id in [0x0001u16, 0x0002, 0x0007, 0x0008] {
            let dtls = SrtpProfile::from_u16(id).unwrap();
            let srtp = dtls.protection_profile();
            assert_eq!(srtp as u16, id);
            assert_eq!(srtp.key_len(), dtls.key_length());
            assert_eq!(srtp.salt_len(), dtls.salt_length());
        }
    }

    #[test]
    fn test_srtp_profile_sizes() {
        assert_eq!(SrtpProfile::AeadAes128Gcm.key_length(), 16);
        assert_eq!(SrtpProfile::AeadAes128Gcm.salt_length(), 12);

        assert_eq!(SrtpProfile::Aes128CmHmacSha1_80.key_length(), 16);
        assert_eq!(SrtpProfile::Aes128CmHmacSha1_80.salt_length(), 14);
    }

    #[test]
    fn test_srtp_profile_from_u16() {
        assert_eq!(
            SrtpProfile::from_u16(0x0001),
            Some(SrtpProfile::Aes128CmHmacSha1_80)
        );
        assert_eq!(
            SrtpProfile::from_u16(0x0002),
            Some(SrtpProfile::Aes128CmHmacSha1_32)
        );
        assert_eq!(
            SrtpProfile::from_u16(0x0007),
            Some(SrtpProfile::AeadAes128Gcm)
        );
        assert_eq!(
            SrtpProfile::from_u16(0x0008),
            Some(SrtpProfile::AeadAes256Gcm)
        );

        // Invalid profiles
        assert_eq!(SrtpProfile::from_u16(0x0000), None);
        assert_eq!(SrtpProfile::from_u16(0xFFFF), None);
    }

    #[test]
    fn test_srtp_profile_key_lengths() {
        // AES-128 profiles
        assert_eq!(SrtpProfile::Aes128CmHmacSha1_80.key_length(), 16);
        assert_eq!(SrtpProfile::Aes128CmHmacSha1_32.key_length(), 16);
        assert_eq!(SrtpProfile::AeadAes128Gcm.key_length(), 16);

        // AES-256 profiles
        assert_eq!(SrtpProfile::AeadAes256Gcm.key_length(), 32);
    }

    #[test]
    fn test_srtp_profile_salt_lengths() {
        // Non-AEAD profiles use 14-byte salts
        assert_eq!(SrtpProfile::Aes128CmHmacSha1_80.salt_length(), 14);
        assert_eq!(SrtpProfile::Aes128CmHmacSha1_32.salt_length(), 14);

        // AEAD profiles use 12-byte salts
        assert_eq!(SrtpProfile::AeadAes128Gcm.salt_length(), 12);
        assert_eq!(SrtpProfile::AeadAes256Gcm.salt_length(), 12);
    }

    #[test]
    fn test_srtp_profile_keying_material_length() {
        // client_key + server_key + client_salt + server_salt

        // AES-128-GCM: 2*16 + 2*12 = 56
        assert_eq!(SrtpProfile::AeadAes128Gcm.keying_material_length(), 56);

        // AES-256-GCM: 2*32 + 2*12 = 88
        assert_eq!(SrtpProfile::AeadAes256Gcm.keying_material_length(), 88);

        // AES-128-CM-HMAC-SHA1-80: 2*16 + 2*14 = 60
        assert_eq!(
            SrtpProfile::Aes128CmHmacSha1_80.keying_material_length(),
            60
        );
    }

    #[test]
    fn test_srtp_profile_is_aead() {
        assert!(!SrtpProfile::Aes128CmHmacSha1_80.is_aead());
        assert!(!SrtpProfile::Aes128CmHmacSha1_32.is_aead());
        assert!(SrtpProfile::AeadAes128Gcm.is_aead());
        assert!(SrtpProfile::AeadAes256Gcm.is_aead());
    }
}
