# QUIC Local Testing Guide

This guide explains how to set up and test QUIC signaling locally using self-signed certificates with the `nexus-signal` crate.

## Overview

QUIC requires TLS 1.3, which means you need valid certificates even for local development. This guide covers two approaches:

1. **OpenSSL** - Generate certificates using command-line tools
2. **rcgen** - Generate certificates programmatically in Rust

## Certificate Generation

### Option 1: OpenSSL (Command Line)

Generate a self-signed certificate and private key:

```bash
# Create a directory for certificates
mkdir -p /tmp/nexus-certs
cd /tmp/nexus-certs

# Generate private key (ECDSA P-256 for better performance)
openssl ecparam -name prime256v1 -genkey -noout -out key.pem

# Generate self-signed certificate (valid for 365 days)
openssl req -new -x509 -key key.pem -out cert.pem -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
```

For RSA keys (if ECDSA is not preferred):

```bash
# Generate RSA private key
openssl genrsa -out key.pem 2048

# Generate self-signed certificate
openssl req -new -x509 -key key.pem -out cert.pem -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
```

Verify the certificate:

```bash
openssl x509 -in cert.pem -text -noout
```

### Option 2: rcgen (Rust)

Generate certificates programmatically using the `rcgen` crate. Add to your `Cargo.toml`:

```toml
[dev-dependencies]
rcgen = "0.12"
```

Example code to generate certificates:

```rust
use rcgen::{Certificate, CertificateParams, DnType, SanType};
use std::fs;

fn generate_self_signed_cert() -> Result<(), Box<dyn std::error::Error>> {
    // Configure certificate parameters
    let mut params = CertificateParams::default();
    
    // Set subject name
    params.distinguished_name.push(DnType::CommonName, "localhost");
    
    // Add Subject Alternative Names for local testing
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".to_string()),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];
    
    // Generate the certificate
    let cert = Certificate::from_params(params)?;
    
    // Write certificate and key to files
    fs::write("/tmp/nexus-certs/cert.pem", cert.serialize_pem()?)?;
    fs::write("/tmp/nexus-certs/key.pem", cert.serialize_private_key_pem())?;
    
    println!("Certificate generated at /tmp/nexus-certs/");
    Ok(())
}
```


## Server Configuration

### Basic Server Setup

Configure the QUIC server to use self-signed certificates:

```rust
use nexus_signal::{QuicConfig, QuicSignaling};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging for debugging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Configure QUIC server with self-signed certificates
    let config = QuicConfig {
        bind_addr: "127.0.0.1:4433".to_string(),
        max_connections: 100,
        max_session_tickets: 100,
        session_ticket_ttl_secs: 3600,
        max_bi_streams: 10,
        max_uni_streams: 10,
        stream_recv_window_bytes: 256 * 1024,
        connection_recv_window_bytes: 1024 * 1024,
        keep_alive_interval_ms: 10_000,
        idle_timeout_ms: 30_000,
        enable_0rtt: false, // Disable 0-RTT for simpler local testing
        cert_path: "/tmp/nexus-certs/cert.pem".to_string(),
        key_path: "/tmp/nexus-certs/key.pem".to_string(),
    };

    // Validate configuration
    config.validate()?;

    // Create and run server
    let bind_addr = config.bind_addr.parse()?;
    let server = Arc::new(QuicSignaling::new(bind_addr, config).await?);

    println!("QUIC server listening on 127.0.0.1:4433");
    server.run().await?;

    Ok(())
}
```

### Configuration Options for Local Testing

| Option | Recommended Value | Description |
|--------|-------------------|-------------|
| `enable_0rtt` | `false` | Disable for simpler debugging |
| `idle_timeout_ms` | `30_000` | 30 seconds for local testing |
| `keep_alive_interval_ms` | `10_000` | 10 seconds |
| `max_connections` | `100` | Lower limit for local testing |

## Client Configuration

### Accepting Self-Signed Certificates

QUIC clients must be configured to accept self-signed certificates. This is done by providing a custom certificate verifier.

```rust
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName};
use std::sync::Arc;

/// Create a client configuration that accepts self-signed certificates.
/// 
/// WARNING: Only use this for local development/testing!
fn create_insecure_client_config() -> ClientConfig {
    // Create a crypto provider
    let provider = rustls::crypto::ring::default_provider();
    
    // Create client config with dangerous certificate verifier
    let crypto = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 should be supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("Failed to create QUIC client config"),
    ))
}

/// Certificate verifier that skips all verification.
/// 
/// WARNING: This is insecure and should only be used for local testing!
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Accept any certificate for local testing
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}
```

### Alternative: Trust the Self-Signed Certificate

Instead of skipping verification, you can add the self-signed certificate to the client's trust store:

```rust
use rustls::pki_types::CertificateDer;
use std::fs;

fn create_client_config_with_cert(cert_path: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    // Load the server's certificate
    let cert_pem = fs::read(cert_path)?;
    let cert = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .next()
        .ok_or("No certificate found")??;

    // Create root certificate store with our self-signed cert
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert)?;

    // Create client config
    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    )))
}
```


## Complete Working Example

Here's a complete example demonstrating local QUIC signaling with the `nexus-signal` crate.

### Dependencies

Add these to your `Cargo.toml`:

```toml
[dependencies]
nexus-signal = { path = "../crates/nexus-signal" }
quinn = "0.11"
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }
rustls-pemfile = "2"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = "0.3"

[dev-dependencies]
rcgen = "0.12"
```

### Server Example

```rust
// examples/local_quic_server.rs
use nexus_signal::{QuicConfig, QuicSignaling};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Ensure certificates exist
    let cert_path = "/tmp/nexus-certs/cert.pem";
    let key_path = "/tmp/nexus-certs/key.pem";
    
    if !std::path::Path::new(cert_path).exists() {
        eprintln!("Certificate not found. Generate with:");
        eprintln!("  mkdir -p /tmp/nexus-certs");
        eprintln!("  openssl ecparam -name prime256v1 -genkey -noout -out /tmp/nexus-certs/key.pem");
        eprintln!("  openssl req -new -x509 -key /tmp/nexus-certs/key.pem -out /tmp/nexus-certs/cert.pem -days 365 -subj '/CN=localhost'");
        return Ok(());
    }

    let config = QuicConfig {
        bind_addr: "127.0.0.1:4433".to_string(),
        max_connections: 100,
        max_session_tickets: 100,
        session_ticket_ttl_secs: 3600,
        max_bi_streams: 10,
        max_uni_streams: 10,
        stream_recv_window_bytes: 256 * 1024,
        connection_recv_window_bytes: 1024 * 1024,
        keep_alive_interval_ms: 10_000,
        idle_timeout_ms: 30_000,
        enable_0rtt: false,
        cert_path: cert_path.to_string(),
        key_path: key_path.to_string(),
    };

    let bind_addr = config.bind_addr.parse()?;
    let server = Arc::new(QuicSignaling::new(bind_addr, config).await?);

    println!("QUIC signaling server running on 127.0.0.1:4433");
    println!("Press Ctrl+C to stop");

    server.run().await?;
    Ok(())
}
```

### Client Example

```rust
// examples/local_quic_client.rs
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName};
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Create client with insecure config for local testing
    let client_config = create_insecure_client_config();
    
    // Bind to any available port
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    // Connect to local server
    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let connection = endpoint
        .connect(server_addr, "localhost")?
        .await?;

    println!("Connected to server at {}", server_addr);
    println!("Connection ID: {}", connection.stable_id());

    // Open a bidirectional stream for SDP exchange
    let (mut send, mut recv) = connection.open_bi().await?;

    // Send a test message (in real usage, this would be SDP)
    let test_message = b"Hello from QUIC client!";
    send.write_all(test_message).await?;
    send.finish()?;

    println!("Sent test message");

    // Read response
    let response = recv.read_to_end(4096).await?;
    println!("Received: {} bytes", response.len());

    // Close connection gracefully
    connection.close(0u32.into(), b"done");

    Ok(())
}

fn create_insecure_client_config() -> ClientConfig {
    let provider = rustls::crypto::ring::default_provider();
    
    let crypto = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 should be supported")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("Failed to create QUIC client config"),
    ))
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}
```


## Quick Start

1. **Generate certificates:**
   ```bash
   mkdir -p /tmp/nexus-certs
   openssl ecparam -name prime256v1 -genkey -noout -out /tmp/nexus-certs/key.pem
   openssl req -new -x509 -key /tmp/nexus-certs/key.pem -out /tmp/nexus-certs/cert.pem \
       -days 365 -subj "/CN=localhost" \
       -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
   ```

2. **Start the server:**
   ```bash
   cargo run --example local_quic_server
   ```

3. **Connect with client:**
   ```bash
   cargo run --example local_quic_client
   ```

## Troubleshooting

### Certificate Errors

**Error:** `CertificateLoadFailed` or `TlsConfigFailed`

- Verify certificate files exist and are readable
- Check file permissions: `chmod 644 cert.pem key.pem`
- Ensure PEM format (files should start with `-----BEGIN`)

### Connection Refused

**Error:** `ConnectionRefused` or timeout

- Verify server is running on the expected port
- Check firewall settings: `sudo lsof -i :4433`
- Ensure bind address matches (use `127.0.0.1` for local testing)

### Handshake Failures

**Error:** `HandshakeFailed` or `CertificateRequired`

- Client must use `dangerous()` verifier or trust the self-signed cert
- Verify TLS 1.3 is enabled on both sides
- Check that server name matches certificate CN or SAN

### Debug Logging

Enable detailed logging to diagnose issues:

```rust
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::TRACE)
    .with_target(true)
    .init();
```

Or via environment variable:

```bash
RUST_LOG=debug cargo run --example local_quic_server
```

## Security Considerations

The insecure certificate verifier (`SkipServerVerification`) should **never** be used in production. It disables all certificate validation, making the connection vulnerable to man-in-the-middle attacks.

For production deployments:
- Use certificates from a trusted CA (e.g., Let's Encrypt)
- Configure proper certificate validation
- Enable certificate revocation checking
- Use certificate pinning for additional security

## Additional Resources

- [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)
- [quinn documentation](https://docs.rs/quinn)
- [rustls documentation](https://docs.rs/rustls)
- [rcgen documentation](https://docs.rs/rcgen)
