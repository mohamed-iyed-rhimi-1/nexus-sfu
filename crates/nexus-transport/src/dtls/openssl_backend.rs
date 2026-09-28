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

use foreign_types::ForeignTypeRef;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::srtp::SrtpProfileId;
use openssl::ssl::{
    HandshakeError, MidHandshakeSslStream, Ssl, SslContext, SslContextBuilder, SslMethod,
    SslOptions, SslSessionCacheMode, SslStream, SslVerifyMode, SslVersion,
};
use openssl::x509::X509;
use std::io::{Read, Write};
use std::sync::Arc;

use super::crypto::SrtpKeyMaterial;
use super::error::DtlsError;
use super::types::DtlsRole;

/// Maximum bytes read from BIO per call, and the largest datagram `process` accepts.
pub const MAX_BIO_READ: usize = 16384;

/// Path MTU given to OpenSSL: handshake messages are fragmented into records that fit
/// datagrams of this size (the memory BIO cannot report one; without it OpenSSL falls
/// back to its minimum). Callers split the output at record boundaries.
pub const DTLS_MTU: u32 = 1200;

/// `SSL_ctrl` command behind `DTLSv1_handle_timeout` (a macro in `ssl.h`, so
/// not exported by openssl-sys).
const DTLS_CTRL_HANDLE_TIMEOUT: libc::c_int = 74;

/// SRTP protection profile names for set_tlsext_use_srtp.
const SRTP_AES128_CM_SHA1_80: &str = "SRTP_AES128_CM_SHA1_80";
const SRTP_AEAD_AES_128_GCM: &str = "SRTP_AEAD_AES_128_GCM";

/// Memory BIO pair for non-blocking DTLS I/O.
///
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
        // `process` checks the length before calling (network input never panics).
        debug_assert!(!data.is_empty(), "feed data must not be empty");
        debug_assert!(data.len() <= MAX_BIO_READ, "feed data exceeds MAX_BIO_READ");
        self.incoming.extend_from_slice(data);
    }

    /// Take outgoing data (DTLS records to send over UDP).
    #[allow(dead_code)]
    /// Take outgoing data (DTLS records to send over UDP).
    fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outgoing)
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

/// The process's DTLS identity: an ECDSA P-256 key, a self-signed X.509 certificate,
/// its SHA-256 fingerprint and the `SslContext` that serves them (design note §6.3).
///
/// Created once; every session's engine builds only its own `Ssl` from the shared
/// context (`OpenSslDtlsEngine::with_certificate`), so the fingerprint in every offer is
/// the same. Cloning is cheap: the context is reference-counted and the DER shared.
#[derive(Clone)]
pub struct DtlsCertificate {
    /// SSL context holding the key and certificate.
    ctx: SslContext,
    /// SHA-256 fingerprint of the certificate.
    fingerprint: [u8; 32],
    /// DER-encoded certificate.
    der: Arc<[u8]>,
}

impl std::fmt::Debug for DtlsCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsCertificate")
            .field("fingerprint", &self.fingerprint)
            .field("der_len", &self.der.len())
            .finish()
    }
}

impl DtlsCertificate {
    /// Generate a key and self-signed certificate and configure the DTLS 1.2 context
    /// (DTLS-SRTP profiles, peer certificate required, no tickets).
    pub fn generate() -> Result<Self, DtlsError> {
        let pkey = generate_key()?;
        let x509 = build_certificate(&pkey)?;
        let der = x509
            .to_der()
            .map_err(|e| DtlsError::handshake_failed(format!("to_der: {}", e)))?;
        let fingerprint = fingerprint_of(&x509)?;
        let ctx = build_context(&pkey, &x509)?;

        // Postconditions: a usable identity.
        assert!(!der.is_empty(), "certificate DER must not be empty");
        assert!(
            fingerprint.iter().any(|&b| b != 0),
            "fingerprint must be set"
        );
        Ok(Self {
            ctx,
            fingerprint,
            der: der.into(),
        })
    }

    /// SHA-256 fingerprint of the certificate (the SDP `a=fingerprint`).
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// DER-encoded certificate.
    pub fn der(&self) -> &[u8] {
        &self.der
    }
}

/// An ECDSA P-256 key pair.
fn generate_key() -> Result<PKey<Private>, DtlsError> {
    let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| DtlsError::handshake_failed(format!("EC group: {}", e)))?;
    let ec_key = EcKey::generate(&ec_group)
        .map_err(|e| DtlsError::handshake_failed(format!("EC keygen: {}", e)))?;
    PKey::from_ec_key(ec_key).map_err(|e| DtlsError::handshake_failed(format!("PKey: {}", e)))
}

/// A self-signed X.509 v3 certificate for `pkey`, CN "Nexus SFU", with a random 64-bit
/// serial, valid from one day ago (tolerates peers whose clock is behind) for 365 days.
fn build_certificate(pkey: &PKey<Private>) -> Result<X509, DtlsError> {
    let err = |what: &str, e: openssl::error::ErrorStack| {
        DtlsError::handshake_failed(format!("{}: {}", what, e))
    };
    let mut builder = X509::builder().map_err(|e| err("X509 builder", e))?;
    builder.set_version(2).map_err(|e| err("set version", e))?;

    let mut serial = openssl::bn::BigNum::new().map_err(|e| err("serial", e))?;
    serial
        .rand(64, openssl::bn::MsbOption::ONE, false)
        .map_err(|e| err("serial", e))?;
    let serial = openssl::asn1::Asn1Integer::from_bn(&serial).map_err(|e| err("serial asn1", e))?;
    builder
        .set_serial_number(&serial)
        .map_err(|e| err("set serial", e))?;

    let mut name = openssl::x509::X509NameBuilder::new().map_err(|e| err("name builder", e))?;
    name.append_entry_by_text("CN", "Nexus SFU")
        .map_err(|e| err("CN", e))?;
    let name = name.build();
    builder
        .set_subject_name(&name)
        .map_err(|e| err("set subject", e))?;
    builder
        .set_issuer_name(&name)
        .map_err(|e| err("set issuer", e))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| DtlsError::handshake_failed("clock before 1970".to_string()))?
        .as_secs() as i64;
    let not_before =
        openssl::asn1::Asn1Time::from_unix(now - 86_400).map_err(|e| err("not_before", e))?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(365).map_err(|e| err("not_after", e))?;
    builder
        .set_not_before(&not_before)
        .map_err(|e| err("set not_before", e))?;
    builder
        .set_not_after(&not_after)
        .map_err(|e| err("set not_after", e))?;

    builder.set_pubkey(pkey).map_err(|e| err("set pubkey", e))?;
    builder
        .sign(pkey, MessageDigest::sha256())
        .map_err(|e| err("sign", e))?;
    Ok(builder.build())
}

/// SHA-256 of a certificate.
fn fingerprint_of(x509: &X509) -> Result<[u8; 32], DtlsError> {
    let digest = x509
        .digest(MessageDigest::sha256())
        .map_err(|e| DtlsError::handshake_failed(format!("digest: {}", e)))?;
    assert_eq!(digest.len(), 32, "SHA-256 digest must be 32 bytes");
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&digest);
    Ok(fingerprint)
}

/// The DTLS 1.2 context serving `pkey` and `x509`.
fn build_context(pkey: &PKey<Private>, x509: &X509) -> Result<SslContext, DtlsError> {
    let err = |what: &str, e: openssl::error::ErrorStack| {
        DtlsError::handshake_failed(format!("{}: {}", what, e))
    };
    let mut ctx = SslContextBuilder::new(SslMethod::dtls()).map_err(|e| err("SSL ctx", e))?;
    ctx.set_min_proto_version(Some(SslVersion::DTLS1_2))
        .map_err(|e| err("min version", e))?;
    ctx.set_certificate(x509).map_err(|e| err("set cert", e))?;
    ctx.set_private_key(pkey).map_err(|e| err("set key", e))?;
    ctx.check_private_key().map_err(|e| err("check key", e))?;

    // Cipher suites for DTLS-SRTP
    ctx.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")
        .map_err(|e| err("ciphers", e))?;

    // SRTP profiles: AEAD_AES_128_GCM first (RFC 8827 §6.5; design note §9:
    // GCM on ring is the fast path), AES128_CM_SHA1_80 for peers without GCM.
    // As DTLS server, OpenSSL picks the first profile of this list the client
    // offers; as client, the peer's server chooses.
    ctx.set_tlsext_use_srtp(&format!(
        "{}:{}",
        SRTP_AEAD_AES_128_GCM, SRTP_AES128_CM_SHA1_80
    ))
    .map_err(|e| err("srtp ext", e))?;

    // Require the peer's certificate (RFC 8827 §6.5: both sides present
    // one). It is self-signed, so skip CA-chain validation here; the
    // session checks its SHA-256 against the SDP a=fingerprint instead
    // (see `peer_fingerprint`). Without PEER a server never requests the
    // client certificate and there is nothing to verify.
    ctx.set_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        |_preverify_ok, _store| true,
    );

    // Disable session tickets and the session cache (not needed for DTLS-SRTP): the
    // context is shared by every session of the process, so a server-side cache would
    // keep one entry per handshake, process-wide.
    // NO_QUERY_MTU: the MTU comes from `DTLS_MTU` (set per `Ssl`), not from the BIO.
    ctx.set_options(SslOptions::NO_TICKET | SslOptions::NO_QUERY_MTU);
    ctx.set_session_cache_mode(SslSessionCacheMode::OFF);
    Ok(ctx.build())
}

/// OpenSSL DTLS handshake engine.
///
/// Manages the DTLS handshake using OpenSSL's DTLS 1.2 implementation.
/// After handshake completion, exports SRTP key material for media encryption.
///
/// # Lifecycle
///
/// 1. `with_certificate()` — take the shared certificate and context
///    (`new()` generates a certificate of its own, as the old path does)
/// 2. `start_handshake()` — Begin DTLS handshake (client sends ClientHello)
/// 3. `process()` — Feed incoming DTLS records, get outgoing records
/// 4. After `is_established()` — Call `export_srtp_keys()` for SRTP material
///
/// # Thread Safety
///
/// Not thread-safe. Must be used from a single thread (the session owner).
pub struct OpenSslDtlsEngine {
    /// Certificate, fingerprint and SSL context (shared between engines).
    certificate: DtlsCertificate,
    /// Mid-handshake state (during async handshake).
    mid_handshake: Option<MidHandshakeSslStream<MemBio>>,
    /// Completed SSL stream (after handshake).
    stream: Option<SslStream<MemBio>>,
    /// Our role.
    role: DtlsRole,
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
    /// SHA-256 of the peer's certificate (populated after handshake).
    peer_fingerprint: Option<[u8; 32]>,
}

impl OpenSslDtlsEngine {
    /// Create a DTLS engine on a shared certificate: only the per-session `Ssl` is
    /// built (at `start_handshake`), from the certificate's context.
    pub fn with_certificate(role: DtlsRole, certificate: &DtlsCertificate) -> Self {
        let engine = Self {
            certificate: certificate.clone(),
            mid_handshake: None,
            stream: None,
            role,
            established: false,
            srtp_keys: None,
            srtp_profile: None,
            pending_output: Vec::with_capacity(MAX_BIO_READ),
            started: false,
            peer_fingerprint: None,
        };
        debug_assert_eq!(engine.fingerprint(), certificate.fingerprint());
        engine
    }

    /// Get SHA-256 fingerprint of our certificate.
    pub fn fingerprint(&self) -> &[u8; 32] {
        assert!(
            self.certificate.fingerprint.iter().any(|&b| b != 0),
            "fingerprint not initialized"
        );
        &self.certificate.fingerprint
    }

    /// Get DER-encoded certificate.
    pub fn certificate_der(&self) -> &[u8] {
        assert!(
            !self.certificate.der.is_empty(),
            "certificate not initialized"
        );
        &self.certificate.der
    }

    /// Whether the handshake has been started (the role is fixed from then on).
    pub fn is_started(&self) -> bool {
        self.started
    }

    /// Whether the handshake is complete.
    pub fn is_established(&self) -> bool {
        self.established
    }

    /// SHA-256 of the peer's certificate, available once the handshake is
    /// complete. Callers must compare it with the fingerprint signalled in
    /// SDP before trusting the connection.
    pub fn peer_fingerprint(&self) -> Option<&[u8; 32]> {
        self.peer_fingerprint.as_ref()
    }

    /// Hash the peer certificate from the completed handshake.
    fn record_peer_fingerprint(&mut self) -> Result<(), DtlsError> {
        let stream = self
            .stream
            .as_ref()
            .expect("stream must exist after handshake");
        let cert = stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| DtlsError::handshake_failed("peer sent no certificate".to_string()))?;
        let digest = cert
            .digest(MessageDigest::sha256())
            .map_err(|e| DtlsError::handshake_failed(format!("peer digest: {}", e)))?;
        assert_eq!(digest.len(), 32, "SHA-256 digest must be 32 bytes");
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&digest);
        self.peer_fingerprint = Some(fingerprint);
        Ok(())
    }

    /// Get exported SRTP key material (after handshake).
    pub fn srtp_keys(&self) -> Option<&SrtpKeyMaterial> {
        self.srtp_keys.as_ref()
    }

    /// Our DTLS role.
    pub fn role(&self) -> DtlsRole {
        self.role
    }

    /// Change the DTLS role before the handshake starts (the role is only
    /// known once the SDP answer's `a=setup` arrives; the certificate, and so
    /// the fingerprint already sent in the offer, stays the same).
    ///
    /// # Errors
    /// `InvalidState` once the handshake has started (the role is fixed then).
    pub fn set_role(&mut self, role: DtlsRole) -> Result<(), DtlsError> {
        if self.started {
            return Err(DtlsError::invalid_state(
                "DTLS role is fixed once the handshake starts",
            ));
        }
        self.role = role;
        assert_eq!(self.role, role);
        Ok(())
    }

    /// Start the DTLS handshake.
    ///
    /// For client role: initiates ClientHello.
    /// For server role: prepares to accept ClientHello.
    ///
    /// Returns outgoing DTLS records to send over UDP.
    ///
    /// # Errors
    /// `InvalidState` if the handshake was already started; `HandshakeFailed` on an
    /// OpenSSL error.
    pub fn start_handshake(&mut self) -> Result<Vec<u8>, DtlsError> {
        if self.started {
            return Err(DtlsError::invalid_state("handshake already started"));
        }
        self.started = true;

        let mut ssl = Ssl::new(&self.certificate.ctx)
            .map_err(|e| DtlsError::handshake_failed(format!("SSL new: {}", e)))?;
        ssl.set_mtu(DTLS_MTU)
            .map_err(|e| DtlsError::handshake_failed(format!("SSL mtu: {}", e)))?;

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
                self.record_peer_fingerprint()?;
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
            Err(e) => Err(DtlsError::handshake_failed(format!("handshake: {}", e))),
        }
    }

    /// Process incoming DTLS data from UDP.
    ///
    /// Feeds the data to OpenSSL and returns any outgoing DTLS records.
    ///
    /// # Returns
    /// - `Ok(outgoing_data)` — DTLS records to send back over UDP
    /// - `Err` — Fatal handshake error, or a datagram that is empty or longer than
    ///   `MAX_BIO_READ` (network input: refused, never a panic)
    pub fn process(&mut self, data: &[u8]) -> Result<Vec<u8>, DtlsError> {
        if data.is_empty() || data.len() > MAX_BIO_READ {
            return Err(DtlsError::invalid_state(format!(
                "DTLS datagram of {} bytes (1..={} accepted)",
                data.len(),
                MAX_BIO_READ
            )));
        }

        if let Some(mut mid) = self.mid_handshake.take() {
            // Feed incoming data to the read BIO
            mid.get_mut().feed(data);

            // Continue handshake
            match mid.handshake() {
                Ok(mut stream) => {
                    let output = stream.get_mut().take_outgoing();
                    self.stream = Some(stream);
                    self.established = true;
                    self.record_peer_fingerprint()?;
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

                    // Log OpenSSL error details
                    let ssl_error = mid.error();
                    tracing::error!(
                        ssl_error = ?ssl_error,
                        "OpenSSL handshake failure - detailed error"
                    );

                    Err(DtlsError::handshake_failed("OpenSSL handshake failure"))
                }
                Err(e) => Err(DtlsError::handshake_failed(format!("handshake: {}", e))),
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
            Err(DtlsError::handshake_failed(
                "no active handshake or session",
            ))
        }
    }

    /// Export SRTP key material after handshake completion.
    ///
    /// Uses the TLS exporter (RFC 5705) with label "EXTRACTOR-dtls_srtp"
    /// to derive SRTP keys from the TLS master secret.
    fn export_srtp_material(&mut self) -> Result<(), DtlsError> {
        let stream = self
            .stream
            .as_ref()
            .ok_or_else(|| DtlsError::handshake_failed("no stream for SRTP export"))?;

        let ssl = stream.ssl();

        // Determine the negotiated SRTP profile using numeric ID (more robust
        // than string matching — avoids any name format discrepancies).
        let (profile_id, srtp_profile, key_len, salt_len) =
            if let Some(profile) = ssl.selected_srtp_profile() {
                let id = profile.id();
                let name = profile.name();
                tracing::info!(
                    profile_name = name,
                    profile_id = ?id,
                    "OpenSSL selected SRTP profile"
                );

                if id == SrtpProfileId::SRTP_AES128_CM_SHA1_80 {
                    (
                        0x0001u16,
                        super::crypto::SrtpProfile::Aes128CmHmacSha1_80,
                        16usize,
                        14usize,
                    )
                } else if id == SrtpProfileId::SRTP_AEAD_AES_128_GCM {
                    (0x0007u16, super::crypto::SrtpProfile::AeadAes128Gcm, 16, 12)
                } else if id == SrtpProfileId::SRTP_AEAD_AES_256_GCM {
                    (0x0008u16, super::crypto::SrtpProfile::AeadAes256Gcm, 32, 12)
                } else if id == SrtpProfileId::SRTP_AES128_CM_SHA1_32 {
                    (
                        0x0002u16,
                        super::crypto::SrtpProfile::Aes128CmHmacSha1_32,
                        16,
                        14,
                    )
                } else {
                    return Err(DtlsError::UnsupportedSrtpProfile(id.as_raw() as u16));
                }
            } else {
                // RFC 5764 §4.1: use_srtp extension MUST be present in the handshake.
                // Without it, SRTP keys cannot be derived and media cannot flow.
                return Err(DtlsError::SrtpNotNegotiated);
            };

        self.srtp_profile = Some(profile_id);

        // Postcondition: salt_len must match the profile's declared salt length
        assert_eq!(
            salt_len,
            srtp_profile.salt_length(),
            "salt_len must match profile salt_length"
        );

        // Export keying material per RFC 5764 §4.2.
        // Layout: client_key | server_key | client_salt | server_salt
        //
        // Note: RFC 5764 §4.2 specifies the empty context, but RFC 5705 §4
        // distinguishes "no context" from "empty context" in the PRF seed.
        // webrtc-rs (and most WebRTC stacks) use "no context" (None) for
        // DTLS-SRTP key export. We match this for interoperability.
        let material_len = 2 * (key_len + salt_len);
        let mut material = vec![0u8; material_len];
        ssl.export_keying_material(&mut material, "EXTRACTOR-dtls_srtp", None)
            .map_err(|e| DtlsError::handshake_failed(format!("SRTP export: {}", e)))?;

        tracing::debug!(
            material_len,
            "DTLS-SRTP keying material exported (RFC 5764 §4.2)"
        );

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
            keys.client_salt().len(),
            salt_len,
            "client_salt accessor must return salt_len bytes"
        );
        assert_eq!(
            keys.server_salt().len(),
            salt_len,
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

    /// Drive OpenSSL's DTLS retransmission timer.
    ///
    /// While the handshake is in progress and OpenSSL's timer has expired
    /// (1 s initially, doubling up to 60 s), OpenSSL rebuilds its last flight;
    /// the records are returned for sending. Before the deadline, or outside a
    /// handshake, returns an empty buffer. Safe to call as often as wanted.
    pub fn handle_timeout(&mut self) -> Result<Vec<u8>, DtlsError> {
        let Some(mid) = self.mid_handshake.as_mut() else {
            return Ok(Vec::new());
        };
        assert!(self.started, "mid-handshake implies started");
        assert!(!self.established, "mid-handshake implies not established");

        let ssl = mid.ssl().as_ptr();
        assert!(!ssl.is_null());
        // SAFETY: `ssl` is the live `SSL*` owned by `mid`, which stays borrowed
        // (and so alive and unmoved) for this call. DTLSv1_handle_timeout only
        // touches that SSL object and writes to its BIO, which is our MemBio;
        // larg and parg are unused by this command.
        let ret = unsafe {
            openssl_sys::SSL_ctrl(ssl, DTLS_CTRL_HANDLE_TIMEOUT, 0, std::ptr::null_mut())
        };
        // 1: retransmitted, 0: timer not expired or not running, <0: error
        // (for example, too many retransmissions).
        if ret < 0 {
            return Err(DtlsError::handshake_failed(
                "DTLS retransmission failed (peer unreachable)",
            ));
        }
        Ok(mid.get_mut().take_outgoing())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An engine on a certificate of its own (a peer with its own identity).
    fn own_engine(role: DtlsRole) -> OpenSslDtlsEngine {
        OpenSslDtlsEngine::with_certificate(role, &DtlsCertificate::generate().unwrap())
    }

    /// Run a handshake between `client` and `server` in memory. Bounded: a DTLS 1.2
    /// handshake takes two round trips; 16 exchanges is ample.
    fn handshake(client: &mut OpenSslDtlsEngine, server: &mut OpenSslDtlsEngine) {
        assert!(server.start_handshake().unwrap().is_empty(), "server waits");
        let mut to_server = client.start_handshake().unwrap();
        let mut to_client = Vec::new();
        for _ in 0..16 {
            if client.is_established() && server.is_established() {
                return;
            }
            if !to_server.is_empty() {
                to_client = server.process(&std::mem::take(&mut to_server)).unwrap();
            }
            if !to_client.is_empty() {
                to_server = client.process(&std::mem::take(&mut to_client)).unwrap();
            }
        }
        assert!(client.is_established() && server.is_established());
    }

    #[test]
    fn engines_on_one_certificate_handshake_with_each_other() {
        let certificate = DtlsCertificate::generate().unwrap();
        let mut client = OpenSslDtlsEngine::with_certificate(DtlsRole::Client, &certificate);
        let mut server = OpenSslDtlsEngine::with_certificate(DtlsRole::Server, &certificate);
        assert_eq!(client.fingerprint(), certificate.fingerprint());
        assert_eq!(server.fingerprint(), certificate.fingerprint());
        assert_eq!(client.certificate_der(), certificate.der());

        handshake(&mut client, &mut server);

        // Each side saw the shared certificate as the peer's.
        assert_eq!(client.peer_fingerprint(), Some(certificate.fingerprint()));
        assert_eq!(server.peer_fingerprint(), Some(certificate.fingerprint()));
        // Both exported the same keying material (client write = server read).
        let (c, s) = (client.srtp_keys().unwrap(), server.srtp_keys().unwrap());
        assert_eq!(c.client_master_key, s.client_master_key);
        assert_eq!(c.server_master_key, s.server_master_key);
        assert_eq!(c.client_master_salt, s.client_master_salt);
        assert_eq!(c.server_master_salt, s.server_master_salt);
        assert_ne!(c.client_master_key, c.server_master_key);
    }

    #[test]
    fn many_sessions_share_one_context() {
        let certificate = DtlsCertificate::generate().unwrap();
        let other = DtlsCertificate::generate().unwrap();
        assert_ne!(certificate.fingerprint(), other.fingerprint());
        // Two independent handshakes on the same certificate, one after the other.
        for _ in 0..2 {
            let mut client = OpenSslDtlsEngine::with_certificate(DtlsRole::Client, &other);
            let mut server = OpenSslDtlsEngine::with_certificate(DtlsRole::Server, &certificate);
            handshake(&mut client, &mut server);
            assert_eq!(client.peer_fingerprint(), Some(certificate.fingerprint()));
            assert_eq!(server.peer_fingerprint(), Some(other.fingerprint()));
        }
    }

    /// A read-only `SSL_CTX_ctrl` query (the `SSL_CTX_sess_*` macros of OpenSSL's ssl.h).
    fn ctx_query(ctx: &SslContext, cmd: std::os::raw::c_int) -> i64 {
        use foreign_types::ForeignType;
        // SAFETY: `ctx` is a live context for the duration of the call, and `cmd` is one
        // of the getters below, which only read the context.
        unsafe { openssl_sys::SSL_CTX_ctrl(ctx.as_ptr(), cmd, 0, std::ptr::null_mut()) as i64 }
    }

    /// `SSL_CTRL_SESS_NUMBER`: sessions held in the cache.
    const SSL_CTRL_SESS_NUMBER: std::os::raw::c_int = 20;
    /// `SSL_CTRL_GET_SESS_CACHE_MODE`: the cache mode (0 = `SSL_SESS_CACHE_OFF`).
    const SSL_CTRL_GET_SESS_CACHE_MODE: std::os::raw::c_int = 45;

    /// The shared context has its session cache off. (With `SSL_VERIFY_PEER` and no
    /// session id context OpenSSL already stores nothing on the server, so the count
    /// stays 0 either way; the mode is what guards against a later change.)
    #[test]
    fn shared_context_keeps_no_session_cache() {
        let certificate = DtlsCertificate::generate().unwrap();
        assert_eq!(ctx_query(&certificate.ctx, SSL_CTRL_GET_SESS_CACHE_MODE), 0);
        for _ in 0..3 {
            let mut client = OpenSslDtlsEngine::with_certificate(DtlsRole::Client, &certificate);
            let mut server = OpenSslDtlsEngine::with_certificate(DtlsRole::Server, &certificate);
            handshake(&mut client, &mut server);
        }
        assert_eq!(ctx_query(&certificate.ctx, SSL_CTRL_SESS_NUMBER), 0);
    }

    #[test]
    fn certificate_serial_is_random_and_validity_backdated() {
        let a = X509::from_der(DtlsCertificate::generate().unwrap().der()).unwrap();
        let b = X509::from_der(DtlsCertificate::generate().unwrap().der()).unwrap();
        let serial = |x: &X509| x.serial_number().to_bn().unwrap();
        assert_ne!(serial(&a), serial(&b));
        assert!(serial(&a).num_bits() > 32, "64-bit serial");
        let yesterday = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
        let diff = a.not_before().diff(&yesterday).unwrap();
        assert_eq!(diff.days, 1, "not_before one day in the past: {:?}", diff);
    }

    /// Record sizes (header included) of a buffer of whole DTLS records.
    fn record_sizes(mut buf: &[u8]) -> Vec<usize> {
        let mut sizes = Vec::new();
        while !buf.is_empty() {
            assert!(buf.len() >= 13, "truncated record header");
            let len = 13 + u16::from_be_bytes([buf[11], buf[12]]) as usize;
            assert!(buf.len() >= len, "truncated record");
            sizes.push(len);
            buf = &buf[len..];
        }
        sizes
    }

    /// Every record of both sides' flights fits `DTLS_MTU`, the certificate flight
    /// included, and OpenSSL fragments at `DTLS_MTU` rather than at its minimum.
    #[test]
    fn flights_are_cut_into_records_that_fit_the_mtu() {
        let certificate = DtlsCertificate::generate().unwrap();
        let mut client = own_engine(DtlsRole::Client);
        let mut server = OpenSslDtlsEngine::with_certificate(DtlsRole::Server, &certificate);
        assert!(server.start_handshake().unwrap().is_empty());
        let hello = client.start_handshake().unwrap();
        let server_flight = server.process(&hello).unwrap();
        let client_flight = client.process(&server_flight).unwrap();
        for flight in [&hello, &server_flight, &client_flight] {
            let sizes = record_sizes(flight);
            assert!(!sizes.is_empty());
            assert!(sizes.iter().all(|&n| n <= DTLS_MTU as usize), "{:?}", sizes);
        }
        // The server flight carries the certificate: more than one small record.
        // The certificate message fits one record: OpenSSL used `DTLS_MTU`, not its
        // 256-byte minimum (measured: 320-byte record here, ≤ 180 without the MTU).
        let largest = record_sizes(&server_flight).into_iter().max().unwrap();
        assert!(largest > certificate.der().len(), "{} bytes", largest);
        let finished = server.process(&client_flight).unwrap();
        client.process(&finished).unwrap();
        assert!(client.is_established() && server.is_established());
    }

    /// Network input: empty and oversized datagrams are errors in every state, never a
    /// panic (they were `assert!`s).
    #[test]
    fn process_refuses_empty_and_oversized_datagrams_in_every_state() {
        let oversized = vec![22u8; MAX_BIO_READ + 1];
        let check = |engine: &mut OpenSslDtlsEngine| {
            assert!(engine.process(&[]).is_err());
            assert!(engine.process(&oversized).is_err());
        };
        let mut idle = own_engine(DtlsRole::Server);
        check(&mut idle);
        let mut client = own_engine(DtlsRole::Client);
        let mut server = own_engine(DtlsRole::Server);
        server.start_handshake().unwrap();
        check(&mut server);
        handshake_started(&mut client, &mut server);
        check(&mut client);
        check(&mut server);
        // A maximal datagram of garbage is refused by OpenSSL or ignored, not a panic.
        let _ = server.process(&vec![0xAB; MAX_BIO_READ]);
    }

    /// `handshake` for a server that was already started.
    fn handshake_started(client: &mut OpenSslDtlsEngine, server: &mut OpenSslDtlsEngine) {
        let mut to_server = client.start_handshake().unwrap();
        for _ in 0..16 {
            if client.is_established() && server.is_established() {
                return;
            }
            let to_client = server.process(&to_server).unwrap();
            if to_client.is_empty() {
                break;
            }
            to_server = client.process(&to_client).unwrap();
            if to_server.is_empty() {
                break;
            }
        }
        assert!(client.is_established() && server.is_established());
    }

    #[test]
    fn role_and_start_are_errors_once_started() {
        let mut engine = own_engine(DtlsRole::Server);
        engine.set_role(DtlsRole::Client).unwrap();
        engine.set_role(DtlsRole::Server).unwrap();
        engine.start_handshake().unwrap();
        assert!(engine.set_role(DtlsRole::Client).is_err());
        assert_eq!(engine.role(), DtlsRole::Server);
        assert!(engine.start_handshake().is_err());
    }
}
