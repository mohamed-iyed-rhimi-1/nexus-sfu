use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignalError {
    #[error("QUIC endpoint creation failed: {0}")]
    EndpointCreationFailed(String),

    #[error("TLS configuration failed: {0}")]
    TlsConfigFailed(String),

    #[error("Certificate load failed: {0}")]
    CertificateLoadFailed(io::Error),

    #[error("Connection limit reached: {current}/{max}")]
    ConnectionLimitReached { current: u32, max: u32 },

    #[error("Stream creation failed: {0}")]
    StreamCreationFailed(String),

    #[error("0-RTT validation failed: {0}")]
    ZeroRttValidationFailed(String),

    #[error("Connection migration failed: {0}")]
    MigrationFailed(String),

    #[error("Session ticket storage full")]
    SessionTicketStorageFull,

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}
