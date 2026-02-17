pub mod capnp_codec;
pub mod messages;
#[cfg(test)]
mod tests;

pub use capnp_codec::{MessageBuilder, MessageReader, signaling_capnp, metrics_capnp};

// Re-export message types
pub use messages::{SignalMessage, ParticipantInfo, TrackInfo, TrackKind};
