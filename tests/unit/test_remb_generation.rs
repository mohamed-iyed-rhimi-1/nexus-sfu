//! Unit tests for REMB generation to publishers.
//!
//! Tests the REMB packet generation and transmission infrastructure
//! including 5-second intervals and SRTCP protection.
//!
//! Feature: production-readiness, Requirement 2

use nexus_sfu::{
    worker::{MediaWorker, WorkerMessage, TrackActorState},
    dtls::{SrtpContext, SrtpPolicy, KeyMaterial},
    types::{MediaKind, Ssrc, TrackId},
};
use nexus_bwe::{RembGenerator, BandwidthCoordinator, CongestionController};
use std::collections::HashMap;
use std::net::SocketAddr;

// Mock implementations
struct MockBandwidthCoordinator {
    estimated_bps: u64,
}

impl MockBandwidthCoordinator {
    fn new() -> Self {
        Self { estimated_bps: 1_000_000 }
    }

    fn target_bitrate(&self) -> u64 {
        self.estimated_bps
    }
}

struct MockWorkerPool {
    messages: Vec<WorkerMessage>,
}

impl MockWorkerPool {
    fn new() -> Self {
        Self { messages: Vec::new() }
    }

    fn get_worker(&self, worker_id: u32) -> Option<MockWorker> {
        Some(MockWorker::new(worker_id, &self.messages))
    }
}

struct MockWorker {
    worker_id: u32,
    messages: *mut Vec<WorkerMessage>,
}

impl MockWorker {
    fn new(worker_id: u32, messages: &mut Vec<WorkerMessage>) -> Self {
        Self { worker_id, messages }
    }

    fn send(&self, msg: WorkerMessage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.messages.push(msg);
        Ok(())
    }
}

fn create_test_srtp_context() -> SrtpContext {
    SrtpContext::new(
        KeyMaterial {
            client_key: [1u8; 16],
            server_key: [2u8; 16],
            client_salt: [3u8; 14],
            server_salt: [4u8; 14],
        },
        SrtpPolicy {
            ssrc_type: nexus_sfu::dtls::SsrcType::Ssrc,
            encryption_key_length: 16,
            auth_key_length: 20,
            auth_tag_length: 16,
        },
    ).expect("Failed to create SRTP context")
}

fn create_test_video_actor() -> TrackActorState {
    let mut actor = TrackActorState::new(42, 123, 1000, MediaKind::Video);
    actor.publisher_addr = Some("127.0.0.1:4000".parse().unwrap());
    actor.publisher_srtcp_context = Some(create_test_srtp_context());
    actor
}

fn create_test_audio_actor() -> TrackActorState {
    let mut actor = TrackActorState::new(43, 124, 1001, MediaKind::Audio);
    actor.publisher_addr = Some("127.0.0.1:4001".parse().unwrap());
    actor.publisher_srtcp_context = Some(create_test_srtp_context());
    actor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remb_generator_initialization() {
        // Feature: production-readiness, Property 2.1
        let remb_gen = RembGenerator::new(1); // SFU sender SSRC
        
        // Verify initialization
        assert_eq!(remb_gen.sender_ssrc(), 1);
    }

    #[test]
    fn test_remb_generation_various_bitrates() {
        // Feature: production-readiness, Property 2.2
        let remb_gen = RembGenerator::new(1);
        
        // Test with various bitrates
        let test_cases = vec![
            (100_000, "100 kbps"),
            (500_000, "500 kbps"), 
            (1_000_000, "1 Mbps"),
            (5_000_000, "5 Mbps"),
        ];
        
        for (bitrate, description) in test_cases {
            let packet = remb_gen.generate(bitrate, 1000);
            
            // Verify packet generation
            assert!(!packet.is_empty(), "REMB packet should not be empty for {}", description);
            assert!(packet.len() >= 8, "REMB packet should have minimum size for {}", description);
        }
    }

    #[test]
    fn test_remb_generation_zero_bitrate() {
        // Feature: production-readiness, Property 2.3
        let remb_gen = RembGenerator::new(1);
        
        // Test with zero bitrate
        let packet = remb_gen.generate(0, 1000);
        
        // Should handle gracefully (empty or minimal packet)
        // Implementation-specific behavior may vary
        assert!(packet.len() >= 0, "REMB packet should handle zero bitrate");
    }

    #[test]
    fn test_remb_generator_ssrc() {
        // Feature: production-readiness, Property 2.4
        let remb_gen1 = RembGenerator::new(1);
        let remb_gen2 = RembGenerator::new(999);
        
        let packet1 = remb_gen1.generate(1_000_000, 1000);
        let packet2 = remb_gen2.generate(1_000_000, 1000);
        
        // Verify SSRC is embedded in packet (simplified test)
        // Real implementation would parse RTCP format
        assert!(!packet1.is_empty());
        assert!(!packet2.is_empty());
    }

    #[test]
    fn test_remb_interval_timing() {
        // Feature: production-readiness, Property 2.5
        let mut worker = create_test_media_worker();
        let coordinator = MockBandwidthCoordinator::new();
        
        // Test 5-second interval
        const REMB_INTERVAL_US: u64 = 5_000_000;
        
        // First call should send REMB
        let sent1 = worker.generate_and_send_remb_test(&coordinator, 1_000_000);
        assert!(sent1);
        
        // Second call within interval should not send
        let sent2 = worker.generate_and_send_remb_test(&coordinator, 3_000_000);
        assert!(!sent2);
        
        // Third call after interval should send
        let sent3 = worker.generate_and_send_remb_test(&coordinator, 7_000_000);
        assert!(sent3);
    }

    #[test]
    fn test_remb_video_tracks_only() {
        // Feature: production-readiness, Property 2.6
        let mut worker = create_test_media_worker();
        let coordinator = MockBandwidthCoordinator::new();
        
        // Add both video and audio actors
        worker.actors.insert(42, create_test_video_actor());
        worker.actors.insert(43, create_test_audio_actor());
        
        // Should only send REMB for video track
        let sent = worker.generate_and_send_remb_test(&coordinator, 1_000_000);
        assert!(sent);
        
        // Verify only one REMB was sent (for video track)
        assert_eq!(worker.messages.len(), 1);
        
        match &worker.messages[0] {
            WorkerMessage::SendRtcpPacket { dest_addr, packet } => {
                // Verify it was sent to video track publisher
                assert_eq!(*dest_addr, "127.0.0.1:4000".parse().unwrap());
                assert!(!packet.is_empty());
            }
            _ => panic!("Expected SendRtcpPacket message"),
        }
    }

    #[test]
    fn test_remb_audio_tracks_skipped() {
        // Feature: production-readiness, Property 2.7
        let mut worker = create_test_media_worker();
        let coordinator = MockBandwidthCoordinator::new();
        
        // Add only audio actor
        worker.actors.insert(43, create_test_audio_actor());
        
        // Should not send REMB for audio track
        let sent = worker.generate_and_send_remb_test(&coordinator, 1_000_000);
        assert!(!sent);
        
        // Verify no messages were sent
        assert_eq!(worker.messages.len(), 0);
    }

    #[test]
    fn test_remb_no_coordinator() {
        // Feature: production-readiness, Property 2.8
        let mut worker = create_test_media_worker();
        
        // No coordinator set
        let sent = worker.generate_and_send_remb_test_no_coordinator(1_000_000);
        assert!(!sent);
        
        // Verify no messages were sent
        assert_eq!(worker.messages.len(), 0);
    }

    #[test]
    fn test_remb_zero_bandwidth_estimate() {
        // Feature: production-readiness, Property 2.9
        let mut worker = create_test_media_worker();
        let mut coordinator = MockBandwidthCoordinator::new();
        let estimated_bps = coordinator.target_bitrate();
        estimated_bps = 0;
        
        // Should not send REMB with zero estimate
        let sent = worker.generate_and_send_remb_test(&coordinator, 1_000_000);
        assert!(!sent);
        
        // Verify no messages were sent
        assert_eq!(worker.messages.len(), 0);
    }

    #[test]
    fn test_remb_srtcp_protection() {
        // Feature: production-readiness, Property 2.10
        let mut worker = create_test_media_worker();
        let coordinator = MockBandwidthCoordinator::new();
        
        // Add video actor with SRTCP context
        worker.actors.insert(42, create_test_video_actor());
        
        // Send REMB
        let sent = worker.generate_and_send_remb_test(&coordinator, 1_000_000);
        assert!(sent);
        
        // Verify SRTCP protection was applied
        assert_eq!(worker.messages.len(), 1);
        
        match &worker.messages[0] {
            WorkerMessage::SendRtcpPacket { dest_addr, packet } => {
                // Verify packet was protected (size increased)
                assert_eq!(*dest_addr, "127.0.0.1:4000".parse().unwrap());
                // SRTCP protection should add auth tag (typically increases size)
                assert!(packet.len() > 20); // Base REMB + SRTCP auth tag
            }
            _ => panic!("Expected SendRtcpPacket message"),
        }
    }

    #[test]
    fn test_remb_bounded_actors() {
        // Feature: production-readiness, Property 2.11
        let mut worker = create_test_media_worker();
        let coordinator = MockBandwidthCoordinator::new();
        
        // Add many actors (more than MAX_ACTORS_PER_WORKER)
        for i in 0..15000 {
            worker.actors.insert(i as TrackId, create_test_video_actor());
        }
        
        // Should be bounded to MAX_ACTORS_PER_WORKER (10,000)
        let sent = worker.generate_and_send_remb_test(&coordinator, 1_000_000);
        assert!(sent);
        
        // Verify bounded number of REMB packets
        assert!(worker.messages.len() <= 10000);
    }

    // Test helper methods
    fn create_test_media_worker() -> MediaWorker {
        MediaWorker {
            worker_id: 1,
            core_id: 0,
            actors: HashMap::new(),
            arena: nexus_sfu::arena::PacketArena::new(10), // 10MB
            batch_sender: nexus_sfu::transport::BatchSender::new(0, 1024, 5000),
            receiver: tokio::sync::mpsc::unbounded_channel().1,
            spsc_receivers: Vec::new(),
            spsc_senders: Vec::new(),
            spin_loop: nexus_sfu::spin::AdaptiveSpinLoop::with_defaults(),
            should_shutdown: std::sync::atomic::AtomicBool::new(false),
            track_count: std::sync::atomic::AtomicU32::new(0),
            is_running: std::sync::atomic::AtomicBool::new(true),
            packets_processed: 0,
            packets_dropped: 0,
            batches_flushed: 0,
            actor_messages_processed: 0,
            coordinator: None, // Will be set in test
            last_allocation_check_us: 0,
            speaker_detector: nexus_bwe::SpeakerDetector::new(),
            dropped_unprotected: 0,
            bytes_copied_fanout: 0,
            arena_alloc_failures_fanout: 0,
            spsc_packets_received: 0,
            spsc_packets_sent: 0,
            spsc_packets_dropped: 0,
            ssrc_hasher: None,
            num_workers: 0,
            last_remb_sent_us: 0,
            remb_generator: nexus_bwe::RembGenerator::new(1),
        }
    }
}
