//! One session's DTLS handshake on the control plane (design note §6.3).
//!
//! The shard only moves datagrams (`DtlsDatagram` events in, `SendDatagram` commands
//! out); the handshake runs here on the process-wide certificate. The logic follows
//! `check_dtls_completion` / `initialize_srtp` of the old `WebRtcSession`, with three
//! additions the old path did not need:
//!
//! - **The role is fixed lazily.** The SFU offers `actpass`. Browsers answer `active`
//!   (the SFU is the DTLS server), webrtc-rs can answer `passive` (the SFU is the
//!   client). The engine's role cannot change once it has started, and a ClientHello
//!   can arrive before the answer is processed. So the engine starts on whichever comes
//!   first: a ClientHello (server) or the answer (server at once; client on the first
//!   selected address, since there is nowhere to send a ClientHello before). An answer
//!   that contradicts a role already fixed fails the handshake.
//! - **Output is split into datagrams.** OpenSSL returns a flight as one buffer of
//!   records; each output datagram holds whole records and at most `DTLS_MTU` bytes.
//! - **Input is checked** before OpenSSL sees it: a datagram is network input.

use nexus_dataplane::SrtpInstall;
use nexus_transport::dtls::{
    DtlsCertificate, DtlsError, DtlsRole, OpenSslDtlsEngine, SrtpKeyMaterial, SrtpProfile,
    DTLS_MTU, MAX_BIO_READ,
};
use nexus_transport::srtp::KeyMaterial;

/// DTLS record header: type (1), version (2), epoch (2), sequence (6), length (2).
const RECORD_HEADER_LEN: usize = 13;
/// Record content type of handshake messages.
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
/// Handshake message type of a ClientHello.
const HANDSHAKE_CLIENT_HELLO: u8 = 1;

/// What a handshake step produced.
#[derive(Debug, Default)]
pub struct Progress {
    /// Datagrams to send to the peer, in order (one `SendDatagram` each).
    pub datagrams: Vec<Vec<u8>>,
    /// The handshake completed with a matching fingerprint during this step: install
    /// SRTP now. True at most once per handshake.
    pub completed: bool,
}

/// Why the handshake failed or a step was refused.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// The datagram is empty or longer than `MAX_BIO_READ`; ignored, state unchanged.
    #[error("DTLS datagram of {0} bytes refused")]
    InvalidDatagram(usize),
    /// The answer's role contradicts the one already fixed (by a ClientHello or an
    /// earlier answer).
    #[error("DTLS role conflict: fixed {fixed:?}, answer says {answer:?}")]
    RoleConflict {
        /// Role in use.
        fixed: DtlsRole,
        /// Role the answer asked for.
        answer: DtlsRole,
    },
    /// The signaled fingerprint is all zeros.
    #[error("remote fingerprint is all zeros")]
    ZeroFingerprint,
    /// The peer's certificate does not match the signaled fingerprint, or a later
    /// answer signaled a different one.
    #[error("DTLS fingerprint mismatch")]
    FingerprintMismatch,
    /// OpenSSL failed the handshake (alert, retransmission limit, bad output).
    #[error("DTLS handshake failed: {0}")]
    Engine(#[from] DtlsError),
    /// Keys asked for before the handshake completed, or unusable key material.
    #[error("SRTP keys unavailable: {0}")]
    Keys(&'static str),
    /// The handshake already failed; the session is being closed.
    #[error("DTLS handshake already failed")]
    Failed,
}

/// Where the handshake is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Not complete, or complete but the fingerprint is not known yet.
    Running,
    /// Complete with a matching fingerprint.
    Complete,
    /// Failed for good.
    Failed,
    /// Complete, and the OpenSSL state was freed (`free_ssl`).
    Freed,
}

/// One session's DTLS handshake.
pub struct DtlsHandshake {
    certificate: DtlsCertificate,
    engine: Option<OpenSslDtlsEngine>,
    role: Option<DtlsRole>,
    remote_fingerprint: Option<[u8; 32]>,
    address_selected: bool,
    state: State,
}

impl std::fmt::Debug for DtlsHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsHandshake")
            .field("role", &self.role)
            .field("engine", &self.engine.is_some())
            .field("fingerprint_pinned", &self.remote_fingerprint.is_some())
            .field("address_selected", &self.address_selected)
            .field("state", &self.state)
            .finish()
    }
}

impl DtlsHandshake {
    /// A handshake on the process certificate: role unknown, no OpenSSL state yet.
    pub fn new(certificate: &DtlsCertificate) -> Self {
        Self {
            certificate: certificate.clone(),
            engine: None,
            role: None,
            remote_fingerprint: None,
            address_selected: false,
            state: State::Running,
        }
    }

    /// Our role, once fixed.
    pub fn role(&self) -> Option<DtlsRole> {
        self.role
    }

    /// Whether the handshake completed with a matching fingerprint.
    pub fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete | State::Freed)
    }

    /// Whether the handshake failed.
    pub fn is_failed(&self) -> bool {
        self.state == State::Failed
    }

    /// Whether OpenSSL state is held (for memory accounting and tests).
    pub fn holds_ssl(&self) -> bool {
        self.engine.is_some()
    }

    /// The answer was processed: pin the fingerprint and fix the role (`Server` for
    /// `active`, `Client` for `passive`). Called for every answer; later answers must
    /// repeat both. Resolves a handshake that completed before the answer.
    pub fn on_answer(
        &mut self,
        role: DtlsRole,
        remote_fingerprint: [u8; 32],
    ) -> Result<Progress, HandshakeError> {
        self.check_usable()?;
        let result = self.apply_answer(role, remote_fingerprint);
        self.fail_on_error(result)
    }

    fn apply_answer(
        &mut self,
        role: DtlsRole,
        fingerprint: [u8; 32],
    ) -> Result<Progress, HandshakeError> {
        if fingerprint.iter().all(|&b| b == 0) {
            return Err(HandshakeError::ZeroFingerprint);
        }
        match self.remote_fingerprint {
            Some(pinned) if pinned != fingerprint => {
                return Err(HandshakeError::FingerprintMismatch)
            }
            _ => self.remote_fingerprint = Some(fingerprint),
        }
        match self.role {
            Some(fixed) if fixed != role => {
                return Err(HandshakeError::RoleConflict {
                    fixed,
                    answer: role,
                })
            }
            _ => self.role = Some(role),
        }
        let mut progress = Progress::default();
        if self.state == State::Running && self.engine.is_none() {
            if role == DtlsRole::Server {
                self.start_engine(DtlsRole::Server)?;
            } else if self.address_selected {
                progress.datagrams = self.start_engine(DtlsRole::Client)?;
            }
        }
        progress.completed = self.check_completion()?;
        Ok(progress)
    }

    /// The shard selected the peer's address (first `AddressSelected`). As DTLS
    /// client, this sends the ClientHello; later calls do nothing.
    pub fn on_address_selected(&mut self) -> Result<Progress, HandshakeError> {
        self.check_usable()?;
        self.address_selected = true;
        let mut progress = Progress::default();
        if self.state == State::Running
            && self.engine.is_none()
            && self.role == Some(DtlsRole::Client)
        {
            let result = self.start_engine(DtlsRole::Client);
            progress.datagrams = self.fail_on_error(result)?;
        }
        Ok(progress)
    }

    /// A DTLS datagram from the peer. `InvalidDatagram` leaves the handshake as it was;
    /// any other error fails it.
    pub fn process(&mut self, datagram: &[u8]) -> Result<Progress, HandshakeError> {
        if datagram.is_empty() || datagram.len() > MAX_BIO_READ {
            return Err(HandshakeError::InvalidDatagram(datagram.len()));
        }
        self.check_usable()?;
        if self.state == State::Freed {
            // The peer proved it finished (authenticated SRTP); nothing to answer.
            return Ok(Progress::default());
        }
        let result = self.feed(datagram);
        self.fail_on_error(result)
    }

    fn feed(&mut self, datagram: &[u8]) -> Result<Progress, HandshakeError> {
        if self.engine.is_none() {
            // Before our engine exists, only a ClientHello can start it (as server).
            if self.role == Some(DtlsRole::Client) || !is_client_hello(datagram) {
                return Ok(Progress::default());
            }
            self.role = Some(DtlsRole::Server);
            self.start_engine(DtlsRole::Server)?;
        }
        let engine = self.engine.as_mut().expect("engine exists");
        let output = engine.process(datagram)?;
        Ok(Progress {
            datagrams: split_records(&output)?,
            completed: self.check_completion()?,
        })
    }

    /// Drives OpenSSL's retransmission timer (call every 200 ms while handshaking).
    pub fn handle_timeout(&mut self) -> Result<Vec<Vec<u8>>, HandshakeError> {
        self.check_usable()?;
        let Some(engine) = self.engine.as_mut() else {
            return Ok(Vec::new());
        };
        if self.state != State::Running {
            return Ok(Vec::new());
        }
        let result = engine
            .handle_timeout()
            .map_err(HandshakeError::from)
            .and_then(|output| split_records(&output));
        self.fail_on_error(result)
    }

    /// SRTP keys for `InstallSrtp`, split by role (note §9.2): `local` is our write key.
    pub fn srtp_install(&self) -> Result<SrtpInstall, HandshakeError> {
        if self.state != State::Complete {
            return Err(HandshakeError::Keys("handshake not complete"));
        }
        let engine = self
            .engine
            .as_ref()
            .ok_or(HandshakeError::Keys("no engine"))?;
        let keys = engine
            .srtp_keys()
            .ok_or(HandshakeError::Keys("no key material"))?;
        let role = self.role.ok_or(HandshakeError::Keys("no role"))?;
        let client = direction_key(keys, keys.client_key(), keys.client_salt())?;
        let server = direction_key(keys, keys.server_key(), keys.server_salt())?;
        let install = match role {
            DtlsRole::Server => SrtpInstall {
                local: server,
                remote: client,
            },
            DtlsRole::Client => SrtpInstall {
                local: client,
                remote: server,
            },
        };
        assert!(
            install.local != install.remote,
            "directions use distinct keys"
        );
        Ok(install)
    }

    /// Drops the OpenSSL state once the peer proved it finished (`PeerSrtpVerified`).
    /// Later datagrams are ignored. Only a complete handshake is freed: otherwise
    /// (a stray or early event) nothing changes and `false` is returned, so a later
    /// ClientHello can never start a second engine or report `completed` twice.
    pub fn free_ssl(&mut self) -> bool {
        if self.state != State::Complete {
            return false;
        }
        self.engine = None;
        self.state = State::Freed;
        assert!(self.engine.is_none() && self.is_complete());
        true
    }

    fn start_engine(&mut self, role: DtlsRole) -> Result<Vec<Vec<u8>>, HandshakeError> {
        assert!(self.engine.is_none(), "engine starts once");
        let mut engine = OpenSslDtlsEngine::with_certificate(role, &self.certificate);
        let output = engine.start_handshake()?;
        self.engine = Some(engine);
        split_records(&output)
    }

    /// `Complete` once the engine finished and the peer's certificate matches the
    /// pinned fingerprint; true only on the step that got there.
    fn check_completion(&mut self) -> Result<bool, HandshakeError> {
        let Some(engine) = self.engine.as_ref() else {
            return Ok(false);
        };
        if self.state != State::Running || !engine.is_established() {
            return Ok(false);
        }
        let Some(pinned) = self.remote_fingerprint else {
            return Ok(false); // Pending: the answer has not arrived yet.
        };
        if engine.peer_fingerprint() != Some(&pinned) {
            return Err(HandshakeError::FingerprintMismatch);
        }
        self.state = State::Complete;
        Ok(true)
    }

    fn check_usable(&self) -> Result<(), HandshakeError> {
        if self.state == State::Failed {
            return Err(HandshakeError::Failed);
        }
        Ok(())
    }

    fn fail_on_error<T>(&mut self, result: Result<T, HandshakeError>) -> Result<T, HandshakeError> {
        if result.is_err() {
            self.state = State::Failed;
            self.engine = None;
        }
        result
    }
}

/// Whether a datagram starts with a ClientHello record (epoch 0 handshake record whose
/// first message is a ClientHello).
fn is_client_hello(datagram: &[u8]) -> bool {
    datagram.len() > RECORD_HEADER_LEN
        && datagram[0] == CONTENT_TYPE_HANDSHAKE
        && datagram[3] == 0
        && datagram[4] == 0
        && datagram[RECORD_HEADER_LEN] == HANDSHAKE_CLIENT_HELLO
}

/// Packs whole DTLS records into datagrams of at most `DTLS_MTU` bytes (a record
/// larger than that goes alone). The input is OpenSSL's output; a truncated record is
/// an error.
pub fn split_records(mut records: &[u8]) -> Result<Vec<Vec<u8>>, HandshakeError> {
    let mtu = DTLS_MTU as usize;
    let mut datagrams: Vec<Vec<u8>> = Vec::new();
    // Each pass consumes at least one header, so the input length bounds the loop.
    while !records.is_empty() {
        if records.len() < RECORD_HEADER_LEN {
            return Err(HandshakeError::Engine(DtlsError::invalid_state(
                "truncated DTLS record header in engine output",
            )));
        }
        let len = RECORD_HEADER_LEN + u16::from_be_bytes([records[11], records[12]]) as usize;
        if records.len() < len {
            return Err(HandshakeError::Engine(DtlsError::invalid_state(
                "truncated DTLS record in engine output",
            )));
        }
        match datagrams.last_mut() {
            Some(last) if last.len() + len <= mtu => last.extend_from_slice(&records[..len]),
            _ => datagrams.push(records[..len].to_vec()),
        }
        records = &records[len..];
    }
    Ok(datagrams)
}

/// One direction's `KeyMaterial` (key ‖ salt) in the negotiated profile.
fn direction_key(
    keys: &SrtpKeyMaterial,
    key: &[u8],
    salt: &[u8],
) -> Result<KeyMaterial, HandshakeError> {
    let profile: SrtpProfile = keys.profile;
    if key.len() != profile.key_length() || salt.len() != profile.salt_length() {
        return Err(HandshakeError::Keys(
            "key length does not match the profile",
        ));
    }
    if key.iter().all(|&b| b == 0) || salt.iter().all(|&b| b == 0) {
        return Err(HandshakeError::Keys("all-zero key material"));
    }
    let mut material = [0u8; 46];
    material[..key.len()].copy_from_slice(key);
    material[key.len()..key.len() + salt.len()].copy_from_slice(salt);
    KeyMaterial::from_dtls_export(
        &material[..key.len() + salt.len()],
        profile.protection_profile(),
    )
    .map_err(|_| HandshakeError::Keys("invalid key material"))
}

#[cfg(test)]
#[path = "dtls_tests.rs"]
mod tests;
