//! Why the orchestrator closes a participant's session (design note §6.4).

/// Why a session was closed by the SFU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// RFC 7675: no authenticated traffic for the consent timeout (`ConsentLost`).
    ConsentExpired,
    /// No address selected within `ICE_CONNECT_TIMEOUT`.
    IceFailed,
    /// The DTLS handshake failed or did not finish within `DTLS_HANDSHAKE_TIMEOUT`.
    DtlsFailed,
    /// A shard's command queue was full (note §5.3).
    Overloaded,
    /// The shard refused a command the orchestrator should never have sent.
    Internal,
}

impl DisconnectReason {
    /// Error code sent to the client when its session is closed.
    pub fn code(self) -> &'static str {
        match self {
            DisconnectReason::ConsentExpired => "CONSENT_EXPIRED",
            DisconnectReason::IceFailed => "ICE_FAILED",
            DisconnectReason::DtlsFailed => "DTLS_FAILED",
            DisconnectReason::Overloaded => "OVERLOADED",
            DisconnectReason::Internal => "INTERNAL_ERROR",
        }
    }
}
