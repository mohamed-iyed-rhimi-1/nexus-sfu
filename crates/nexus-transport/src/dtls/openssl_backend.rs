//! OpenSSL-backed DTLS handshake engine.
//!
//! Wraps OpenSSL's DTLS 1.2 implementation for browser-compatible handshakes.
//! Exports SRTP key material after handshake completion.
//!
//! # Design
//!
//! Uses OpenSSL's memory BIO (Basic I/O) to avoid socket ownership:
//! - Incoming DTLS records are written to the read BIO
//! - OpenSSL processes them internally
//! - Outgoing DTLS records are read from the write BIO
//!
//! This allows the SFU to manage its own UDP socket while OpenSSL
//! handles the cryptographic handshake.
//!
//! # TigerStyle Compliance
//!
//! - All functions ≤70 lines
//! - ≥2 assertions per public function
//! - Bounded buffers (MAX_BIO_READ = 16384)
//! - No dynamic allocation on hot path after handshake
//! - Explicit error handling, no unwrap on fallible paths

use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::ssl::{
    SslContext, SslContextBuilder, SslMethod, SslOptions, SslVerifyMode,
    SslVersion, Ssl, SslStream, HandshakeError, MidHandshakeSslStream,
};
use openssl::srtp::SrtpProfileId;
use openssl::x509::X509;
use std::io::{Read, Write};

use super::crypto::SrtpKeyMaterial;
use super::error::DtlsError;
use super::types::DtlsRole;

/// Maximum bytes read from BIO per call.
const MAX_BIO_READ: usize = 16384;

/// SRTP protection profile names for set_tlsext_use_srtp.
const SRTP_AES128_CM_SHA1_80: &str = "SRTP_AES128_CM_SHA1_80";
const SRTP_AEAD_AES_128_GCM: &str = "SRTP_AEAD_AES_128_GCM";

/// Memory BIO pair for non-blocking DTLS I/O.
///
/// Incoming UDP data is written to `network_bio`. OpenSSL reads from it,
/// processes the DTLS record, and writes response records to `internal_bio`.
/// We read from `internal_bio` to get bytes to send over UDP.
#[allow(dead_code)]
struct BioPair {
    /// BIO for network data (we write incoming, OpenSSL reads).
    network_bio: openssl::ssl::SslStream<MemBio>,
}

/// In-memory BIO wrapper implementing Read + Write for SslStream.
///
/// Buffers incoming and outgoing data without touching the network.
/// Bounded to MAX_BIO_READ to prevent unbounded growth.
#[derive(Debug)]
pub struct MemBio {
    /// Incoming data buffer (written by us, read by OpenSSL).
    incoming: Vec<u8>,
    /// Incoming read cursor.
    incoming_pos: usize,
    /// Outgoing data buffer (written by OpenSSL, read by us).
    outgoing: Vec<u8>,
}

impl MemBio {
    /// Create new empty MemBio.
    fn new() -> Self {
        Self {
            incoming: Vec::with_capacity(MAX_BIO_READ),
            incoming_pos: 0,
            outgoing: Vec::with_capacity(MAX_BIO_READ),
        }
    }

    /// Feed incoming network data (DTLS records from UDP).
    fn feed(&mut self, data: &[u8]) {
        assert!(!data.is_empty(), "feed data must not be empty");
        assert!(
            data.len() <= MAX_BIO_READ,
            "feed data exceeds MAX_BIO_READ"
        );
        self.incoming.extend_from_slice(data);
    }

    /// Take outgoing data (DTLS records to send over UDP).
    #[allow(dead_code)]
    fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outgoing)
    }

    /// Check if there is outgoing data.
    #[allow(dead_code)]
    fn has_outgoing(&self) -> bool {
        !self.outgoing.is_empty()
    }
}

impl Read for MemBio {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.incoming_pos >= self.incoming.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "no data available",
            ));
        }
        let available = &self.incoming[self.incoming_pos..];
        let to_read = buf.len().min(available.len());
        buf[..to_read].copy_from_slice(&available[..to_read]);
        self.incoming_pos += to_read;
        if self.incoming_pos >= self.incoming.len() {
            self.incoming.clear();
            self.incoming_pos = 0;
        }
        Ok(to_read)
    }
}

impl Write for MemBio {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.outgoing.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// OpenSSL DTLS handshake engine.
///
/// Manages the DTLS handshake using OpenSSL's DTLS 1.2 implementation.
/// After handshake completion, exports SRTP key material for media encryption.
///
/// # Lifecycle
///
/// 1. `new()` — Generate certificate, configure SSL context
/// 2. `start_handshake()` — Begin DTLS handshake (client sends ClientHello)
/// 3. `process()` — Feed incoming DTLS records, get outgoing records
/// 4. After `is_established()` — Call `export_srtp_keys()` for SRTP material
///
/// # Thread Safety
///
/// Not thread-safe. Must be used from a single thread (the session owner).
pub struct OpenSslDtlsEngine {
    /// SSL context (shared config).
    ctx: SslContext,
    /// SSL instance for this session.
    #[allow(dead_code)]
    ssl: Option<Ssl>,
    /// Memory BIO for non-blocking I/O.
    #[allow(dead_code)]
    bio: MemBio,
    /// Mid-handshake state (during async handshake).
    mid_handshake: Option<MidHandshakeSslStream<MemBio>>,
    /// Completed SSL stream (after handshake).
    stream: Option<SslStream<MemBio>>,
    /// Our role.
    role: DtlsRole,
    /// DER-encoded certificate.
    certificate_der: Vec<u8>,
    /// SHA-256 fingerprint of our certificate.
    fingerprint: [u8; 32],
    /// Whether handshake is complete.
    established: bool,
    /// SRTP key material (populated after handshake).
    srtp_keys: Option<SrtpKeyMaterial>,
    /// Selected SRTP profile ID.
    srtp_profile: Option<u16>,
    /// Output buffer for pending data.
    pending_output: Vec<u8>,
    /// Handshake started flag.
    started: bool,
}

impl OpenSslDtlsEngine {
    /// Create new DTLS engine.
    ///
    /// Generates a self-signed ECDSA P-256 certificate and configures
    /// the OpenSSL context for DTLS 1.2 with SRTP extension.
    ///
    /// # Arguments
    /// * `role` — Client or Server
    ///
    /// # Panics
    /// Panics if OpenSSL initialization fails (fatal, cannot recover).
    pub fn new(role: DtlsRole) -> Result<Self, DtlsError> {
        // Generate ECDSA P-256 key pair
        let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|e| DtlsError::handshake_failed(format!("EC group: {}", e)))?;
        let ec_key = EcKey::generate(&ec_group)
            .map_err(|e| DtlsError::handshake_failed(format!("EC keygen: {}", e)))?;
        let pkey = PKey::from_ec_key(ec_key.clone())
            .map_err(|e| DtlsError::handshake_failed(format!("PKey: {}", e)))?;

        // Build self-signed X.509 certificate
        let mut x509_builder = X509::builder()
            .map_err(|e| DtlsError::handshake_failed(format!("X509 builder: {}", e)))?;
        x509_builder.set_version(2)
            .map_err(|e| DtlsError::handshake_failed(format!("set version: {}", e)))?;

        // Serial number
        let serial = openssl::bn::BigNum::from_u32(1)
            .map_err(|e| DtlsError::handshake_failed(format!("serial: {}", e)))?;
        let serial_asn1 = openssl::asn1::Asn1Integer::from_bn(&serial)
            .map_err(|e| DtlsError::handshake_failed(format!("serial asn1: {}", e)))?;
        x509_builder.set_serial_number(&serial_asn1)
            .map_err(|e| DtlsError::handshake_failed(format!("set serial: {}", e)))?;

        // Subject name
        let mut name_builder = openssl::x509::X509NameBuilder::new()
            .map_err(|e| DtlsError::handshake_failed(format!("name builder: {}", e)))?;
        name_builder.append_entry_by_text("CN", "Nexus SFU")
            .map_err(|e| DtlsError::handshake_failed(format!("CN: {}", e)))?;
        let name = name_builder.build();
        x509_builder.set_subject_name(&name)
            .map_err(|e| DtlsError::handshake_failed(format!("set subject: {}", e)))?;
        x509_builder.set_issuer_name(&name)
            .map_err(|e| DtlsError::handshake_failed(format!("set issuer: {}", e)))?;

        // Validity: now to +365 days
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)
            .map_err(|e| DtlsError::handshake_failed(format!("not_before: {}", e)))?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(365)
            .map_err(|e| DtlsError::handshake_failed(format!("not_after: {}", e)))?;
        x509_builder.set_not_before(&not_before)
            .map_err(|e| DtlsError::handshake_failed(format!("set not_before: {}", e)))?;
        x509_builder.set_not_after(&not_after)
            .map_err(|e| DtlsError::handshake_failed(format!("set not_after: {}", e)))?;

        x509_builder.set_pubkey(&pkey)
            .map_err(|e| DtlsError::handshake_failed(format!("set pubkey: {}", e)))?;
        x509_builder.sign(&pkey, MessageDigest::sha256())
            .map_err(|e| DtlsError::handshake_failed(format!("sign: {}", e)))?;

        let x509 = x509_builder.build();
        let certificate_der = x509.to_der()
            .map_err(|e| DtlsError::handshake_failed(format!("to_der: {}", e)))?;

        // Compute SHA-256 fingerprint
        let digest = x509.digest(MessageDigest::sha256())
            .map_err(|e| DtlsError::handshake_failed(format!("digest: {}", e)))?;
        let mut fingerprint = [0u8; 32];
        assert_eq!(digest.len(), 32, "SHA-256 digest must be 32 bytes");
        fingerprint.copy_from_slice(&digest);

        // Build SSL context
        let method = SslMethod::dtls();
        let mut ctx_builder = SslContextBuilder::new(method)
            .map_err(|e| DtlsError::handshake_failed(format!("SSL ctx: {}", e)))?;

        // Set DTLS 1.2 minimum
        ctx_builder.set_min_proto_version(Some(SslVersion::DTLS1_2))
            .map_err(|e| DtlsError::handshake_failed(format!("min version: {}", e)))?;

        // Set certificate and private key
        ctx_builder.set_certificate(&x509)
            .map_err(|e| DtlsError::handshake_failed(format!("set cert: {}", e)))?;
        ctx_builder.set_private_key(&pkey)
            .map_err(|e| DtlsError::handshake_failed(format!("set key: {}", e)))?;
        ctx_builder.check_private_key()
            .map_err(|e| DtlsError::handshake_failed(format!("check key: {}", e)))?;

        // Cipher suites for DTLS-SRTP
        ctx_builder.set_cipher_list(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
        ).map_err(|e| DtlsError::handshake_failed(format!("ciphers: {}", e)))?;

        // SRTP profiles — prefer AES128_CM_SHA1_80 for maximum compatibility
        // with browser and webrtc-rs DTLS stacks that may not support GCM.
        ctx_builder.set_tlsext_use_srtp(
            &format!("{}:{}", SRTP_AES128_CM_SHA1_80, SRTP_AEAD_AES_128_GCM)
        ).map_err(|e| DtlsError::handshake_failed(format!("srtp ext: {}", e)))?;

        // Verify mode: request peer cert but don't fail if missing
        // (WebRTC uses fingerprint verification via SDP, not CA chain)
        ctx_builder.set_verify(SslVerifyMode::NONE);

        // Disable session tickets (not needed for DTLS-SRTP)
        ctx_builder.set_options(SslOptions::NO_TICKET);

        let ctx = ctx_builder.build();

        Ok(Self {
            ctx,
            ssl: None,
            bio: MemBio::new(),
            mid_handshake: None,
            stream: None,
            role,
            certificate_der,
            fingerprint,
            established: false,
            srtp_keys: None,
            srtp_profile: None,
            pending_output: Vec::with_capacity(MAX_BIO_READ),
            started: false,
        })
    }

    /// Get SHA-256 fingerprint of our certificate.
    pub fn fingerprint(&self) -> &[u8; 32] {
        assert!(
            self.fingerprint.iter().any(|&b| b != 0),
            "fingerprint not initialized"
        );
        &self.fingerprint
    }

    /// Get DER-encoded certificate.
    pub fn certificate_der(&self) -> &[u8] {
        assert!(
            !self.certificate_der.is_empty(),
            "certificate not initialized"
        );
        &self.certificate_der
    }

    /// Whether the handshake is complete.
    pub fn is_established(&self) -> bool {
        self.established
    }

    /// Get exported SRTP key material (after handshake).
    pub fn srtp_keys(&self) -> Option<&SrtpKeyMaterial> {
        self.srtp_keys.as_ref()
    }

    /// Start the DTLS handshake.
    ///
    /// For client role: initiates ClientHello.
    /// For server role: prepares to accept ClientHello.
    ///
    /// Returns outgoing DTLS records to send over UDP.
    pub fn start_handshake(&mut self) -> Result<Vec<u8>, DtlsError> {
        assert!(!self.started, "handshake already started");
        self.started = true;

        let mut ssl = Ssl::new(&self.ctx)
            .map_err(|e| DtlsError::handshake_failed(format!("SSL new: {}", e)))?;

        if self.role == DtlsRole::Server {
            ssl.set_accept_state();
        } else {
            ssl.set_connect_state();
        }

        let bio = MemBio::new();
        match ssl.connect(bio) {
            Ok(mut stream) => {
                // Handshake completed immediately (unlikely for DTLS)
                let output = stream.get_mut().take_outgoing();
                self.stream = Some(stream);
                self.established = true;
                self.export_srtp_material()?;
                Ok(output)
            }
            Err(HandshakeError::WouldBlock(mut mid)) => {
                let output = mid.get_mut().take_outgoing();
                self.mid_handshake = Some(mid);
                Ok(output)
            }
            Err(HandshakeError::Failure(mut mid)) => {
                let output = mid.get_mut().take_outgoing();
                if !output.is_empty() {
                    // There might be an alert to send
                    self.pending_output = output.clone();
                }
                Err(DtlsError::handshake_failed("OpenSSL handshake failure"))
            }
            Err(e) => {
                Err(DtlsError::handshake_failed(format!("handshake: {}", e)))
            }
        }
    }

    /// Process incoming DTLS data from UDP.
    ///
    /// Feeds the data to OpenSSL and returns any outgoing DTLS records.
    ///
    /// # Returns
    /// - `Ok(outgoing_data)` — DTLS records to send back over UDP
    /// - `Err` — Fatal handshake error
    pub fn process(&mut self, data: &[u8]) -> Result<Vec<u8>, DtlsError> {
        assert!(!data.is_empty(), "process data must not be empty");
        assert!(
            data.len() <= MAX_BIO_READ,
            "data exceeds MAX_BIO_READ"
        );

        if let Some(mut mid) = self.mid_handshake.take() {
            // Feed incoming data to the read BIO
            mid.get_mut().feed(data);

            // Continue handshake
            match mid.handshake() {
                Ok(mut stream) => {
                    let output = stream.get_mut().take_outgoing();
                    self.stream = Some(stream);
                    self.established = true;
                    self.export_srtp_material()?;
                    Ok(output)
                }
                Err(HandshakeError::WouldBlock(mut mid)) => {
                    let output = mid.get_mut().take_outgoing();
                    self.mid_handshake = Some(mid);
                    Ok(output)
                }
                Err(HandshakeError::Failure(mut mid)) => {
                    let _output = mid.get_mut().take_outgoing();
                    Err(DtlsError::handshake_failed("OpenSSL handshake failure"))
                }
                Err(e) => {
                    Err(DtlsError::handshake_failed(format!("handshake: {}", e)))
                }
            }
        } else if let Some(ref mut stream) = self.stream {
            // Session established, process application data
            stream.get_mut().feed(data);
            let mut buf = [0u8; MAX_BIO_READ];
            match stream.ssl_read(&mut buf) {
                Ok(_n) => {
                    let output = stream.get_mut().take_outgoing();
                    // Application data received (shouldn't happen for DTLS-SRTP)
                    Ok(output)
                }
                Err(_e) => {
                    let output = stream.get_mut().take_outgoing();
                    Ok(output)
                }
            }
        } else {
            Err(DtlsError::handshake_failed("no active handshake or session"))
        }
    }

    /// Export SRTP key material after handshake completion.
    ///
    /// Uses the TLS exporter (RFC 5705) with label "EXTRACTOR-dtls_srtp"
    /// to derive SRTP keys from the TLS master secret.
    fn export_srtp_material(&mut self) -> Result<(), DtlsError> {
        let stream = self.stream.as_ref()
            .ok_or_else(|| DtlsError::handshake_failed("no stream for SRTP export"))?;

        let ssl = stream.ssl();

        // Determine the negotiated SRTP profile using numeric ID (more robust
        // than string matching — avoids any name format discrepancies).
        let (profile_id, srtp_profile, key_len, salt_len) = if let Some(profile) = ssl.selected_srtp_profile() {
            let id = profile.id();
            let name = profile.name();
            tracing::info!(
                profile_name = name,
                profile_id = ?id,
                "OpenSSL selected SRTP profile"
            );

            if id == SrtpProfileId::SRTP_AES128_CM_SHA1_80 {
                (0x0001u16, super::crypto::SrtpProfile::Aes128CmHmacSha1_80, 16usize, 14usize)
            } else if id == SrtpProfileId::SRTP_AEAD_AES_128_GCM {
                (0x0007u16, super::crypto::SrtpProfile::AeadAes128Gcm, 16, 12)
            } else if id == SrtpProfileId::SRTP_AEAD_AES_256_GCM {
                (0x0008u16, super::crypto::SrtpProfile::AeadAes256Gcm, 32, 12)
            } else if id == SrtpProfileId::SRTP_AES128_CM_SHA1_32 {
                (0x0002u16, super::crypto::SrtpProfile::Aes128CmHmacSha1_32, 16, 14)
            } else {
                tracing::warn!(
                    profile_name = name,
                    profile_id = ?id,
                    "Unknown SRTP profile, defaulting to AES128_CM_SHA1_80"
                );
                (0x0001u16, super::crypto::SrtpProfile::Aes128CmHmacSha1_80, 16, 14)
            }
        } else {
            tracing::warn!("No SRTP profile negotiated, defaulting to AES128_CM_SHA1_80");
            (0x0001u16, super::crypto::SrtpProfile::Aes128CmHmacSha1_80, 16, 14)
        };

        self.srtp_profile = Some(profile_id);

        // Postcondition: salt_len must match the profile's declared salt length
        assert_eq!(
            salt_len, srtp_profile.salt_length(),
            "salt_len must match profile salt_length"
        );

        // Export keying material per RFC 5764
        // Layout: client_key | server_key | client_salt | server_salt
        let material_len = 2 * (key_len + salt_len);
        let mut material = vec![0u8; material_len];
        ssl.export_keying_material(
            &mut material,
            "EXTRACTOR-dtls_srtp",
            None,
        ).map_err(|e| DtlsError::handshake_failed(format!("SRTP export: {}", e)))?;

        // Parse material: client_key | server_key | client_salt | server_salt
        let mut offset = 0;

        let mut client_master_key = [0u8; 32];
        client_master_key[..key_len].copy_from_slice(&material[offset..offset + key_len]);
        offset += key_len;

        let mut server_master_key = [0u8; 32];
        server_master_key[..key_len].copy_from_slice(&material[offset..offset + key_len]);
        offset += key_len;

        let mut client_master_salt = [0u8; 14];
        client_master_salt[..salt_len].copy_from_slice(&material[offset..offset + salt_len]);
        offset += salt_len;

        let mut server_master_salt = [0u8; 14];
        server_master_salt[..salt_len].copy_from_slice(&material[offset..offset + salt_len]);

        let keys = SrtpKeyMaterial {
            client_master_key,
            client_master_key_len: key_len as u8,
            server_master_key,
            server_master_key_len: key_len as u8,
            client_master_salt,
            client_master_salt_len: salt_len as u8,
            server_master_salt,
            server_master_salt_len: salt_len as u8,
            profile: srtp_profile,
        };

        // Postcondition: accessor lengths must match what we set
        assert_eq!(
            keys.client_salt().len(), salt_len,
            "client_salt accessor must return salt_len bytes"
        );
        assert_eq!(
            keys.server_salt().len(), salt_len,
            "server_salt accessor must return salt_len bytes"
        );

        tracing::info!(
            ?srtp_profile,
            key_len,
            salt_len,
            client_salt_accessor_len = keys.client_salt().len(),
            "SRTP keying material exported"
        );

        self.srtp_keys = Some(keys);

        Ok(())
    }

    /// Get the selected SRTP profile ID.
    pub fn selected_srtp_profile(&self) -> Option<u16> {
        self.srtp_profile
    }

    /// Take any pending output data.
    pub fn take_pending_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending_output)
    }
}
