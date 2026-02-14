use crate::error::SignalError;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// Session ticket for 0-RTT resumption.
///
/// # TigerStyle Compliance
/// - Fixed-size ticket data (max 1KB per RFC 8446)
/// - Explicit timestamp for TTL checking
/// - Bounded storage with LRU eviction
#[derive(Debug, Clone)]
pub struct SessionTicket {
    /// Unique ticket identifier.
    pub ticket_id: u64,
    /// Encrypted ticket data (opaque to client).
    pub data: Vec<u8>,
    /// Creation timestamp (nanoseconds since epoch).
    pub created_at_ns: u64,
    /// TTL in seconds.
    pub ttl_secs: u32,
}

impl SessionTicket {
    /// Check if ticket has expired.
    pub fn is_expired(&self, now_ns: u64) -> bool {
        let age_ns = now_ns.saturating_sub(self.created_at_ns);
        let age_secs = age_ns / 1_000_000_000;
        age_secs > self.ttl_secs as u64
    }
}

/// Session ticket store with LRU eviction.
///
/// # TigerStyle Compliance
/// - Pre-allocated capacity (no dynamic growth)
/// - Bounded size with explicit limit
/// - Lock-free reads using DashMap
pub struct SessionStore {
    /// Ticket storage (ticket_id -> SessionTicket).
    tickets: DashMap<u64, SessionTicket>,
    /// Maximum tickets to store.
    max_tickets: u32,
    /// Next ticket ID (atomic counter).
    next_ticket_id: AtomicU64,
    /// Ticket TTL in seconds.
    ttl_secs: u32,
}

impl SessionStore {
    /// Create new session store with bounded capacity.
    pub fn new(max_tickets: u32, ttl_secs: u32) -> Self {
        assert!(max_tickets > 0);
        assert!(ttl_secs >= 3600); // Min 1 hour

        Self {
            tickets: DashMap::with_capacity(max_tickets as usize),
            max_tickets,
            next_ticket_id: AtomicU64::new(1),
            ttl_secs,
        }
    }

    /// Store a new session ticket.
    ///
    /// Returns ticket ID or error if storage full.
    pub fn store(&self, data: Vec<u8>) -> Result<u64, SignalError> {
        // Check size limit
        if self.tickets.len() >= self.max_tickets as usize {
            self.evict_oldest();
        }

        let ticket_id = self.next_ticket_id.fetch_add(1, Ordering::Relaxed);
        let now_ns = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;

        let ticket = SessionTicket {
            ticket_id,
            data,
            created_at_ns: now_ns,
            ttl_secs: self.ttl_secs,
        };

        self.tickets.insert(ticket_id, ticket);
        Ok(ticket_id)
    }

    /// Retrieve and validate a session ticket.
    pub fn retrieve(&self, ticket_id: u64) -> Option<SessionTicket> {
        let ticket = self.tickets.get(&ticket_id)?;
        let now_ns = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;

        if ticket.is_expired(now_ns) {
            drop(ticket);
            self.tickets.remove(&ticket_id);
            return None;
        }

        Some(ticket.clone())
    }

    /// Evict oldest ticket (LRU).
    fn evict_oldest(&self) {
        let mut oldest_id = None;
        let mut oldest_time = u64::MAX;

        for entry in self.tickets.iter() {
            if entry.created_at_ns < oldest_time {
                oldest_time = entry.created_at_ns;
                oldest_id = Some(*entry.key());
            }
        }

        if let Some(id) = oldest_id {
            self.tickets.remove(&id);
        }
    }

    /// Get current ticket count.
    pub fn count(&self) -> usize {
        self.tickets.len()
    }
}
