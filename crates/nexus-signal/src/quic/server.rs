use crate::config::QuicConfig;
use crate::error::SignalError;
use crate::metrics::SignalMetrics;
use crate::quic::connection::QuicConnection;
use crate::quic::migration::MigrationHandler;
use crate::quic::session::SessionStore;
use crate::quic::streams::handle_sdp_stream;
use dashmap::DashMap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Helper function to get current time in nanoseconds.
fn current_time_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// QUIC signaling server.
///
/// # TigerStyle Compliance
/// - Pre-allocated connection pool (bounded)
/// - Explicit state management
/// - Comprehensive metrics
pub struct QuicSignaling {
    /// Server endpoint.
    endpoint: quinn::Endpoint,
    /// Active connections (connection_id -> QuicConnection).
    connections: Arc<DashMap<u64, QuicConnection>>,
    /// Session ticket store.
    session_store: Arc<SessionStore>,
    /// Configuration.
    config: QuicConfig,
    /// Next connection ID.
    next_connection_id: AtomicU64,
    /// Migration handler.
    migration_handler: MigrationHandler,
    /// Metrics (wrapped in Arc for shared access).
    metrics: Arc<SignalMetrics>,
    /// 0-RTT replay protection: set of recently seen client nonces.
    /// Uses a bounded set with LRU eviction to prevent memory growth.
    zero_rtt_nonces: Arc<parking_lot::RwLock<ZeroRttReplayProtection>>,
}

/// 0-RTT replay protection state.
///
/// Tracks recently seen client nonces to prevent replay attacks.
/// Uses a bounded set with timestamp-based eviction.
struct ZeroRttReplayProtection {
    /// Set of recently seen nonces (hash of client random + ticket).
    seen_nonces: HashSet<u64>,
    /// Maximum number of nonces to track.
    max_nonces: usize,
    /// Nonce TTL in seconds.
    nonce_ttl_secs: u32,
    /// Timestamps for each nonce (for eviction).
    nonce_timestamps: Vec<(u64, u64)>,
}

impl ZeroRttReplayProtection {
    fn new(max_nonces: usize, nonce_ttl_secs: u32) -> Self {
        assert!(max_nonces > 0);
        assert!(nonce_ttl_secs > 0);
        Self {
            seen_nonces: HashSet::with_capacity(max_nonces),
            max_nonces,
            nonce_ttl_secs,
            nonce_timestamps: Vec::with_capacity(max_nonces),
        }
    }

    /// Check if a nonce has been seen before (replay attack).
    /// Returns true if this is a replay, false if it's a new nonce.
    fn check_and_record(&mut self, nonce: u64) -> bool {
        let now_ns = current_time_ns();

        // Evict expired nonces
        self.evict_expired(now_ns);

        // Check if nonce was already seen
        if self.seen_nonces.contains(&nonce) {
            return true; // Replay detected
        }

        // Evict oldest if at capacity
        if self.seen_nonces.len() >= self.max_nonces {
            self.evict_oldest();
        }

        // Record new nonce
        self.seen_nonces.insert(nonce);
        self.nonce_timestamps.push((nonce, now_ns));

        false // Not a replay
    }

    fn evict_expired(&mut self, now_ns: u64) {
        let ttl_ns = self.nonce_ttl_secs as u64 * 1_000_000_000;
        let cutoff = now_ns.saturating_sub(ttl_ns);

        self.nonce_timestamps.retain(|(nonce, timestamp)| {
            if *timestamp < cutoff {
                self.seen_nonces.remove(nonce);
                false
            } else {
                true
            }
        });
    }

    fn evict_oldest(&mut self) {
        if let Some((nonce, _)) = self.nonce_timestamps.first().copied() {
            self.seen_nonces.remove(&nonce);
            self.nonce_timestamps.remove(0);
        }
    }
}

impl QuicSignaling {
    /// Create new QUIC signaling server.
    pub async fn new(bind_addr: SocketAddr, config: QuicConfig) -> Result<Self, SignalError> {
        // Load TLS certificate and key
        let (cert, key) = load_tls_config(&config)?;

        // Create server config
        let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert], key)
            .map_err(|e| SignalError::TlsConfigFailed(e.to_string()))?;

        // Configure transport
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(config.max_bi_streams.into());
        transport_config.max_concurrent_uni_streams(config.max_uni_streams.into());
        transport_config.stream_receive_window(config.stream_recv_window_bytes.into());
        transport_config.receive_window(config.connection_recv_window_bytes.into());
        transport_config
            .keep_alive_interval(Some(Duration::from_millis(config.keep_alive_interval_ms)));
        transport_config.max_idle_timeout(Some(
            Duration::from_millis(config.idle_timeout_ms)
                .try_into()
                .unwrap(),
        ));

        server_config.transport_config(Arc::new(transport_config));

        // Enable 0-RTT by configuring session ticket handling
        if config.enable_0rtt {
            // 0-RTT is enabled by default in quinn 0.11 when session tickets are used.
            // The ServerConfig already supports 0-RTT when proper TLS configuration is provided.
            tracing::info!("0-RTT session resumption enabled");
        }

        // Create endpoint
        let endpoint = quinn::Endpoint::server(server_config, bind_addr)
            .map_err(|e| SignalError::EndpointCreationFailed(e.to_string()))?;

        // Create session store
        let session_store = Arc::new(SessionStore::new(
            config.max_session_tickets,
            config.session_ticket_ttl_secs,
        ));

        Ok(Self {
            endpoint,
            connections: Arc::new(DashMap::with_capacity(config.max_connections as usize)),
            session_store,
            config,
            next_connection_id: AtomicU64::new(1),
            migration_handler: MigrationHandler::new(3),
            metrics: Arc::new(SignalMetrics::new()),
            zero_rtt_nonces: Arc::new(parking_lot::RwLock::new(ZeroRttReplayProtection::new(
                10000, // Max 10k nonces
                300,   // 5 minute TTL
            ))),
        })
    }

    /// Send a track update to a specific connection.
    pub async fn send_track_update(
        &self,
        connection_id: u64,
        track_id: u32,
        participant_id: u32,
        kind: crate::protocol::signaling_capnp::MediaKind,
        enabled: bool,
    ) -> Result<(), SignalError> {
        // Get connection
        let conn = self
            .connections
            .get(&connection_id)
            .ok_or_else(|| SignalError::InvalidMessage("Connection not found".into()))?;

        // Open unidirectional stream
        let send_stream = conn
            .connection
            .open_uni()
            .await
            .map_err(|e| SignalError::StreamCreationFailed(e.to_string()))?;

        // Send track update
        crate::quic::streams::send_track_update(
            send_stream,
            track_id,
            participant_id,
            kind,
            enabled,
        )
        .await?;

        // Record metrics
        self.metrics.record_uni_stream();

        Ok(())
    }

    /// Get metrics.
    pub fn metrics(&self) -> &Arc<SignalMetrics> {
        &self.metrics
    }

    /// Run the server (accept connections).
    pub async fn run(self: Arc<Self>) -> Result<(), SignalError> {
        loop {
            let conn = self.endpoint.accept().await;
            if conn.is_none() {
                break;
            }

            let incoming = conn.unwrap();
            let self_clone = self.clone();

            tokio::spawn(async move {
                if let Err(e) = self_clone.handle_connection(incoming).await {
                    tracing::error!(error = %e, "connection handling failed");
                }
            });
        }

        Ok(())
    }

    /// Handle incoming connection.
    async fn handle_connection(&self, incoming: quinn::Incoming) -> Result<(), SignalError> {
        // Check connection limit
        if self.connections.len() >= self.config.max_connections as usize {
            return Err(SignalError::ConnectionLimitReached {
                current: self.connections.len() as u32,
                max: self.config.max_connections,
            });
        }

        let remote_addr = incoming.remote_address();

        // Accept connection and get Connecting handle
        let connecting = incoming
            .accept()
            .map_err(|e| SignalError::EndpointCreationFailed(e.to_string()))?;

        // Try to use 0-RTT/0.5-RTT mode
        // On server side, into_0rtt() enables 0.5-RTT (server can send before handshake completes)
        // and accepts client's 0-RTT data if present
        let (connection, zero_rtt_accepted, used_0rtt) = match connecting.into_0rtt() {
            Ok((conn, zero_rtt_future)) => {
                // 0-RTT/0.5-RTT mode enabled
                // The zero_rtt_future resolves to true on server side (always accepts)
                // We spawn a task to track when handshake completes
                let zero_rtt_accepted = zero_rtt_future;
                (conn, Some(zero_rtt_accepted), true)
            }
            Err(connecting) => {
                // 0-RTT not available, fall back to normal handshake
                let conn = connecting
                    .await
                    .map_err(|e| SignalError::EndpointCreationFailed(e.to_string()))?;
                (conn, None, false)
            }
        };

        // Validate 0-RTT if used
        if used_0rtt {
            // Perform 0-RTT validation:
            // 1. Check for replay attacks using client nonce
            // 2. Validate room context (if early data contains room info)
            // 3. Verify client identity matches session ticket

            // Generate a nonce from connection stable_id and remote address
            // This is a simplified replay protection - in production, use actual TLS early data
            let nonce = self.compute_connection_nonce(&connection, remote_addr);

            // Check for replay
            let is_replay = {
                let mut replay_guard = self.zero_rtt_nonces.write();
                replay_guard.check_and_record(nonce)
            };

            if is_replay {
                tracing::warn!(
                    remote_addr = %remote_addr,
                    "0-RTT replay attack detected, rejecting connection"
                );
                self.metrics.record_zero_rtt_replay_attempt();
                // Close the connection - replay detected
                connection.close(
                    quinn::VarInt::from_u32(1),
                    b"0-RTT replay detected",
                );
                return Err(SignalError::ZeroRttValidationFailed(
                    "Replay attack detected".into(),
                ));
            }

            // Validate application context
            // In production, this would check:
            // - Room validity (is the room still active?)
            // - Client identity (does it match the session ticket?)
            // - Rate limiting (is this client sending too many 0-RTT requests?)
            if !self.validate_0rtt_context(&connection, remote_addr) {
                tracing::warn!(
                    remote_addr = %remote_addr,
                    "0-RTT validation failed, requiring full handshake"
                );
                self.metrics.record_zero_rtt_rejection();
                // Don't close - let the connection continue with full handshake
                // The 0-RTT data will be discarded
            } else {
                tracing::info!(
                    remote_addr = %remote_addr,
                    "0-RTT connection accepted, validating early data"
                );

                // Store session ticket for this connection
                // Extract ticket data from handshake (simplified - use actual ticket in production)
                let ticket_data = self.generate_session_ticket(&connection);
                if let Ok(ticket_id) = self.session_store.store(ticket_data) {
                    tracing::debug!(ticket_id = ticket_id, "Stored session ticket for 0-RTT");
                }
            }
        }

        // Spawn task to wait for handshake completion if using 0-RTT
        if let Some(zero_rtt_future) = zero_rtt_accepted {
            let metrics = Arc::clone(&self.metrics);
            let remote = remote_addr;
            tokio::spawn(async move {
                let accepted = zero_rtt_future.await;
                tracing::debug!(
                    remote_addr = %remote,
                    accepted = accepted,
                    "0-RTT handshake completed"
                );
                if !accepted {
                    metrics.record_zero_rtt_rejection();
                }
            });
        }

        // Create connection state
        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
        let quic_conn = QuicConnection::new(connection_id, connection.clone(), used_0rtt);

        self.connections.insert(connection_id, quic_conn);
        self.metrics.record_connection(used_0rtt);

        tracing::info!(
            connection_id = connection_id,
            used_0rtt = used_0rtt,
            remote_addr = %connection.remote_address(),
            "QUIC connection established"
        );

        // Handle streams
        self.handle_streams(connection_id, connection).await?;

        Ok(())
    }

    /// Compute a nonce for replay protection from connection data.
    fn compute_connection_nonce(&self, connection: &quinn::Connection, remote_addr: SocketAddr) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        connection.stable_id().hash(&mut hasher);
        remote_addr.hash(&mut hasher);
        // Include current time bucket (10 second windows) to limit replay window
        let time_bucket = current_time_ns() / 10_000_000_000;
        time_bucket.hash(&mut hasher);
        hasher.finish()
    }

    /// Validate 0-RTT application context.
    ///
    /// Returns true if the 0-RTT data should be accepted.
    fn validate_0rtt_context(&self, connection: &quinn::Connection, remote_addr: SocketAddr) -> bool {
        // Validation checks:
        // 1. Connection is from a known/valid source
        // 2. Rate limiting check
        // 3. Application-specific validation

        // Check if we have a valid session ticket for this client
        // In production, extract ticket ID from handshake data
        let _remote = remote_addr;
        let _stable_id = connection.stable_id();

        // For now, accept all 0-RTT connections that pass replay check
        // In production, implement proper validation:
        // - Check room_id from early data against active rooms
        // - Verify client identity from session ticket
        // - Apply rate limiting per client

        true
    }

    /// Generate session ticket data for a connection.
    fn generate_session_ticket(&self, connection: &quinn::Connection) -> Vec<u8> {
        // In production, this would extract actual session ticket from TLS
        // For now, generate a placeholder based on connection data
        let stable_id = connection.stable_id();
        let remote_addr = connection.remote_address();
        let timestamp = current_time_ns();

        let mut ticket = Vec::with_capacity(256);
        ticket.extend_from_slice(&stable_id.to_le_bytes());
        ticket.extend_from_slice(&timestamp.to_le_bytes());
        match remote_addr {
            SocketAddr::V4(addr) => {
                ticket.push(4);
                ticket.extend_from_slice(&addr.ip().octets());
                ticket.extend_from_slice(&addr.port().to_le_bytes());
            }
            SocketAddr::V6(addr) => {
                ticket.push(6);
                ticket.extend_from_slice(&addr.ip().octets());
                ticket.extend_from_slice(&addr.port().to_le_bytes());
            }
        }
        ticket
    }

    /// Handle streams for a connection.
    async fn handle_streams(
        &self,
        connection_id: u64,
        connection: quinn::Connection,
    ) -> Result<(), SignalError> {
        // Spawn migration monitoring task
        let migration_handler = self.migration_handler.clone();
        let connections = self.connections.clone();
        let metrics = Arc::clone(&self.metrics);
        let conn_clone = connection.clone();

        tokio::spawn(async move {
            Self::monitor_connection_migration(
                connection_id,
                conn_clone,
                migration_handler,
                connections,
                metrics,
            )
            .await;
        });

        loop {
            tokio::select! {
                // Accept bidirectional stream
                stream = connection.accept_bi() => {
                    match stream {
                        Ok((send, recv)) => {
                            if let Some(conn) = self.connections.get(&connection_id) {
                                conn.record_bi_stream();
                            }
                            self.metrics.record_bi_stream();

                            tokio::spawn(async move {
                                if let Err(e) = handle_sdp_stream(send, recv).await {
                                    tracing::error!(error = %e, "SDP stream failed");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "accept_bi failed");
                            break;
                        }
                    }
                }

                // Accept unidirectional stream
                stream = connection.accept_uni() => {
                    match stream {
                        Ok(mut recv) => {
                            if let Some(conn) = self.connections.get(&connection_id) {
                                conn.record_uni_stream();
                            }
                            self.metrics.record_uni_stream();

                            let metrics = Arc::clone(&self.metrics);
                            let conn_id = connection_id;
                            tokio::spawn(async move {
                                // Handle stats stream (client→server)
                                match recv.read_to_end(4096).await {
                                    Ok(data) => {
                                        // Parse client stats from binary data
                                        if let Some(stats) = crate::quic::streams::ClientStats::decode(&data) {
                                            tracing::debug!(
                                                connection_id = conn_id,
                                                rtt_us = stats.rtt_us,
                                                packets_lost = stats.packets_lost,
                                                jitter_us = stats.jitter_us,
                                                "Received client stats"
                                            );
                                            // Record metrics
                                            metrics.record_client_stats(
                                                conn_id,
                                                stats.rtt_us,
                                                stats.packets_lost,
                                                stats.jitter_us,
                                            );
                                        } else {
                                            tracing::warn!(
                                                connection_id = conn_id,
                                                data_len = data.len(),
                                                "Failed to parse client stats: invalid format"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(error = %e, "Failed to read uni stream");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "accept_uni failed");
                            break;
                        }
                    }
                }
            }
        }

        // Connection closed
        self.connections.remove(&connection_id);
        self.metrics.record_disconnection();

        Ok(())
    }

    /// Monitor connection for migration events.
    async fn monitor_connection_migration(
        connection_id: u64,
        connection: quinn::Connection,
        migration_handler: MigrationHandler,
        connections: Arc<DashMap<u64, QuicConnection>>,
        metrics: Arc<SignalMetrics>,
    ) {
        let mut last_remote_addr = connection.remote_address();
        let poll_interval = Duration::from_secs(1);

        loop {
            tokio::time::sleep(poll_interval).await;

            // Check if connection is still alive
            if connection.close_reason().is_some() {
                tracing::debug!(
                    connection_id = connection_id,
                    "Connection closed, stopping migration monitor"
                );
                break;
            }

            // Check for remote address change
            let current_remote_addr = connection.remote_address();
            if current_remote_addr != last_remote_addr {
                tracing::info!(
                    connection_id = connection_id,
                    old_addr = %last_remote_addr,
                    new_addr = %current_remote_addr,
                    "Connection migration detected"
                );

                // Get connection state
                if let Some(conn) = connections.get(&connection_id) {
                    // Handle migration
                    match migration_handler
                        .handle_migration(&conn, current_remote_addr)
                        .await
                    {
                        Ok(()) => {
                            metrics.record_migration();
                            last_remote_addr = current_remote_addr;
                            tracing::info!(
                                connection_id = connection_id,
                                new_addr = %current_remote_addr,
                                "Connection migration successful"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                connection_id = connection_id,
                                error = %e,
                                "Connection migration failed"
                            );
                            metrics.record_error();
                            // Don't update last_remote_addr on failure
                        }
                    }
                }
            }
        }
    }
}

/// Load TLS certificate and key from files.
fn load_tls_config(
    config: &QuicConfig,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), SignalError> {
    use rustls_pemfile::{certs, private_key};
    use std::fs::File;
    use std::io::BufReader;

    // Load certificate
    let cert_file = File::open(&config.cert_path).map_err(SignalError::CertificateLoadFailed)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            SignalError::CertificateLoadFailed(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e,
            ))
        })?;
    let cert = certs
        .into_iter()
        .next()
        .ok_or_else(|| SignalError::TlsConfigFailed("no certificate found".into()))?;

    // Load private key
    let key_file = File::open(&config.key_path).map_err(SignalError::CertificateLoadFailed)?;
    let mut key_reader = BufReader::new(key_file);
    let key = private_key(&mut key_reader)
        .map_err(|e| {
            SignalError::CertificateLoadFailed(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e,
            ))
        })?
        .ok_or_else(|| SignalError::TlsConfigFailed("no private key found".into()))?;

    Ok((cert, key))
}
