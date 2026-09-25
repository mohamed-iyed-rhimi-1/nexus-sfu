pub mod capnp_codec;
pub mod messages;
#[cfg(test)]
mod tests;

pub use capnp_codec::{metrics_capnp, signaling_capnp, MessageBuilder, MessageReader};

// Re-export message types
pub use messages::{OfferTrack, ParticipantInfo, SignalMessage, TrackInfo, TrackKind};
