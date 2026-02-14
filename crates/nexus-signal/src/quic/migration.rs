use crate::error::SignalError;
use crate::quic::connection::QuicConnection;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

/// Connection migration handler.
///
/// # TigerStyle Compliance
/// - Bounded migration attempts (max 3 per connection)
/// - Explicit path validation
/// - State machine with assertions
#[derive(Clone)]
pub struct MigrationHandler {
    /// Maximum migrations per connection.
    max_migrations_per_connection: u32,
}

impl MigrationHandler {
    pub fn new(max_migrations: u32) -> Self {
        assert!(max_migrations > 0);
        assert!(max_migrations <= 10);

        Self {
            max_migrations_per_connection: max_migrations,
        }
    }

    /// Handle connection migration event.
    pub async fn handle_migration(
        &self,
        conn: &QuicConnection,
        new_addr: SocketAddr,
    ) -> Result<(), SignalError> {
        // Check migration limit
        let migration_count = conn.migration_count.load(Ordering::Relaxed);
        if migration_count >= self.max_migrations_per_connection {
            return Err(SignalError::MigrationFailed(format!(
                "migration limit reached: {}",
                migration_count
            )));
        }

        // Validate new path
        self.validate_path(&conn.connection, new_addr).await?;

        // Record migration
        conn.record_migration();

        tracing::info!(
            connection_id = conn.connection_id,
            new_addr = %new_addr,
            migration_count = migration_count + 1,
            "connection migrated"
        );

        Ok(())
    }

    /// Validate new path using QUIC path validation.
    async fn validate_path(
        &self,
        connection: &quinn::Connection,
        _new_addr: SocketAddr,
    ) -> Result<(), SignalError> {
        // Quinn handles path validation automatically
        // We just need to check if the connection is still alive
        if connection.close_reason().is_some() {
            return Err(SignalError::MigrationFailed("connection closed".into()));
        }

        Ok(())
    }
}
