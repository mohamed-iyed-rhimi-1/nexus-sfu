use capnp::{message, serialize};
use std::io::Cursor;

pub mod signaling_capnp {
    include!(concat!(env!("OUT_DIR"), "/signaling_capnp.rs"));
}

pub mod metrics_capnp {
    include!(concat!(env!("OUT_DIR"), "/metrics_capnp.rs"));
}

/// Zero-copy message builder with pre-allocated arena.
pub struct MessageBuilder {
    arena_size_words: u32,
}

impl MessageBuilder {
    /// Create new builder with fixed arena size.
    ///
    /// # Arguments
    /// * `arena_size_bytes` - Pre-allocated arena size (default 4096 bytes)
    pub fn new(arena_size_bytes: u32) -> Self {
        assert!(arena_size_bytes > 0);
        assert!(arena_size_bytes <= 1024 * 1024); // Max 1MB per message
        Self {
            arena_size_words: arena_size_bytes / 8,
        }
    }

    /// Create a new HeapAllocator for each message.
    fn new_allocator(&self) -> message::HeapAllocator {
        message::HeapAllocator::new().first_segment_words(self.arena_size_words)
    }

    /// Serialize SignalMessage to bytes.
    ///
    /// Returns byte slice valid until next build() call.
    pub fn build_signal_message<F>(&self, builder_fn: F) -> Vec<u8>
    where
        F: FnOnce(signaling_capnp::signal_message::Builder),
    {
        let mut message = message::Builder::new(self.new_allocator());
        let root = message.init_root::<signaling_capnp::signal_message::Builder>();
        builder_fn(root);

        let mut buffer = Vec::new();
        serialize::write_message(&mut buffer, &message).expect("Serialization must succeed");
        assert!(!buffer.is_empty());
        buffer
    }

    /// Serialize WsMessage to bytes.
    pub fn build_ws_message<F>(&self, builder_fn: F) -> Vec<u8>
    where
        F: FnOnce(metrics_capnp::ws_message::Builder),
    {
        let mut message = message::Builder::new(self.new_allocator());
        let root = message.init_root::<metrics_capnp::ws_message::Builder>();
        builder_fn(root);

        let mut buffer = Vec::new();
        serialize::write_message(&mut buffer, &message).expect("Serialization must succeed");
        assert!(!buffer.is_empty());
        buffer
    }
}

/// Zero-copy message reader.
pub struct MessageReader {
    // No state needed - stateless reader
}

impl MessageReader {
    pub fn new() -> Self {
        Self {}
    }

    /// Deserialize SignalMessage from bytes.
    pub fn read_signal_message(
        &self,
        bytes: &[u8],
    ) -> capnp::Result<capnp::message::Reader<capnp::serialize::OwnedSegments>> {
        assert!(!bytes.is_empty());
        let reader =
            serialize::read_message(&mut Cursor::new(bytes), message::ReaderOptions::new())?;
        Ok(reader)
    }

    /// Deserialize WsMessage from bytes.
    pub fn read_ws_message(
        &self,
        bytes: &[u8],
    ) -> capnp::Result<capnp::message::Reader<capnp::serialize::OwnedSegments>> {
        assert!(!bytes.is_empty());
        let reader =
            serialize::read_message(&mut Cursor::new(bytes), message::ReaderOptions::new())?;
        Ok(reader)
    }
}

impl Default for MessageReader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_message_roundtrip() {
        let builder = MessageBuilder::new(4096);

        // Build Join message
        let bytes = builder.build_signal_message(|msg| {
            let mut join = msg.init_join();
            join.set_room_id("test-room");
            join.set_participant_name("alice");
            join.set_schema_version(1);
        });

        // Read back
        let reader = MessageReader::new();
        let msg_reader = reader.read_signal_message(&bytes).unwrap();
        let msg = msg_reader
            .get_root::<signaling_capnp::signal_message::Reader>()
            .unwrap();

        assert!(msg.has_join());
        match msg.which().unwrap() {
            signaling_capnp::signal_message::Which::Join(join_result) => {
                let join = join_result.unwrap();
                assert_eq!(join.get_room_id().unwrap(), "test-room");
                assert_eq!(join.get_participant_name().unwrap(), "alice");
                assert_eq!(join.get_schema_version(), 1);
            }
            _ => panic!("Expected Join variant"),
        }
    }

    #[test]
    fn test_ws_message_roundtrip() {
        let builder = MessageBuilder::new(4096);

        // Build error message
        let bytes = builder.build_ws_message(|msg| {
            let mut error = msg.init_error();
            error.set_code("TEST_ERROR");
            error.set_message("Test error message");
        });

        // Read back
        let reader = MessageReader::new();
        let msg_reader = reader.read_ws_message(&bytes).unwrap();
        let msg = msg_reader
            .get_root::<metrics_capnp::ws_message::Reader>()
            .unwrap();

        assert!(msg.has_error());
        match msg.which().unwrap() {
            metrics_capnp::ws_message::Which::Error(error_result) => {
                let error = error_result.unwrap();
                assert_eq!(error.get_code().unwrap(), "TEST_ERROR");
                assert_eq!(error.get_message().unwrap(), "Test error message");
            }
            _ => panic!("Expected Error variant"),
        }
    }
}
