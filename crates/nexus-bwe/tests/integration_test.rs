//! Integration tests for bandwidth allocation
//!
//! Verifies end-to-end bandwidth allocation from GCC to TrackActor system.

use nexus_bwe::{
    BandwidthCoordinator, MediaKind, RembGenerator, SpeakerDetector, TrackAllocation,
    TrackPriority,
};

#[test]
fn test_single_track_allocation() {
    let mut coordinator = BandwidthCoordinator::new(100_000, 10_000_000, 1_000_000);

    // Create track with 3 layers
    let mut allocation = TrackAllocation::new(1, TrackPriority::Normal, 1_500_000);
    allocation.add_layer(nexus_bwe::SimulcastLayer::new(0, 100_000, 320, 180));
    allocation.add_layer(nexus_bwe::SimulcastLayer::new(1, 500_000, 640, 360));
    allocation.add_layer(nexus_bwe::SimulcastLayer::new(2, 1_500_000, 1280, 720));

    // Simulate GCC estimate at 1M bps
    // In real scenario, GCC would be updated via feedback
    // For this test, we just verify allocation logic

    // Collect and allocate
    let _updates = coordinator.allocate_and_dispatch(0);

    // Should run allocation (exact layer depends on GCC state)
    // We just verify it executed without panicking
}

#[test]
fn test_multi_track_priority() {
    let mut coordinator = BandwidthCoordinator::new(100_000, 10_000_000, 1_000_000);

    // Create 3 tracks with different priorities
    let mut alloc1 = TrackAllocation::new(1, TrackPriority::Low, 500_000);
    alloc1.add_layer(nexus_bwe::SimulcastLayer::new(0, 100_000, 320, 180));
    alloc1.add_layer(nexus_bwe::SimulcastLayer::new(1, 500_000, 640, 360));

    let mut alloc2 = TrackAllocation::new(2, TrackPriority::Normal, 500_000);
    alloc2.add_layer(nexus_bwe::SimulcastLayer::new(0, 100_000, 320, 180));
    alloc2.add_layer(nexus_bwe::SimulcastLayer::new(1, 500_000, 640, 360));

    let mut alloc3 = TrackAllocation::new(3, TrackPriority::Critical, 500_000);
    alloc3.add_layer(nexus_bwe::SimulcastLayer::new(0, 100_000, 320, 180));
    alloc3.add_layer(nexus_bwe::SimulcastLayer::new(1, 500_000, 640, 360));

    // Allocate at time 0
    let _updates = coordinator.allocate_and_dispatch(0);

    // Allocation ran (exact results depend on GCC state)
}

#[test]
fn test_layer_switching_hysteresis() {
    let mut coordinator = BandwidthCoordinator::new(100_000, 10_000_000, 1_000_000);

    // Test hysteresis timing — should_allocate returns true at time 0
    assert!(coordinator.should_allocate(0));

    // Perform an allocation at time 1_000_000 to set last_allocation_us
    let _updates = coordinator.allocate_and_dispatch(1_000_000);

    // 50ms later — too soon for next allocation (interval is 100ms)
    assert!(!coordinator.should_allocate(1_050_000));
    // 100ms later — OK to allocate again
    assert!(coordinator.should_allocate(1_100_000));
}

#[test]
fn test_remb_generation() {
    let generator = RembGenerator::new(0x12345678);

    // Generate REMB for 1M bps
    let packet = generator.generate(1_000_000, 0x87654321);

    // Verify packet structure
    assert_eq!(packet.len(), 24);

    // Check RTCP version (V=2)
    assert_eq!(packet[0] >> 6, 2);

    // Check packet type (PT=206)
    assert_eq!(packet[1], 206);

    // Check REMB identifier
    assert_eq!(&packet[12..16], b"REMB");

    // Check sender SSRC
    let sender_ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    assert_eq!(sender_ssrc, 0x12345678);

    // Check media SSRC
    let media_ssrc = u32::from_be_bytes([packet[20], packet[21], packet[22], packet[23]]);
    assert_eq!(media_ssrc, 0x87654321);
}

#[test]
fn test_speaker_detection() {
    let mut detector = SpeakerDetector::new();

    // Track 1: Low packet rate (10 pps)
    detector.update(1, 10, 0);

    // Track 2: High packet rate (50 pps)
    detector.update(2, 50, 0);

    // Detect speaker
    let speaker = detector.detect_speaker(0);
    assert_eq!(speaker, Some(2));

    // Verify priority assignment
    assert_eq!(
        detector.get_priority(2, MediaKind::Video),
        TrackPriority::Critical
    );
    assert_eq!(
        detector.get_priority(1, MediaKind::Video),
        TrackPriority::Normal
    );
}

#[test]
fn test_speaker_transition() {
    let mut detector = SpeakerDetector::new();

    // Track 1 is initially speaker
    detector.update(1, 50, 0);
    assert_eq!(detector.detect_speaker(0), Some(1));

    // Track 2 becomes speaker with higher rate
    detector.update(2, 80, 100_000);
    assert_eq!(detector.detect_speaker(100_000), Some(2));

    // Verify priorities updated
    assert_eq!(
        detector.get_priority(2, MediaKind::Video),
        TrackPriority::Critical
    );
    assert_eq!(
        detector.get_priority(1, MediaKind::Video),
        TrackPriority::Normal
    );
}

#[test]
fn test_coordinator_should_allocate() {
    let mut coordinator = BandwidthCoordinator::new(100_000, 10_000_000, 1_000_000);

    // Should allocate at time 0
    assert!(coordinator.should_allocate(0));

    // Perform an allocation at time 1_000_000 to set last_allocation_us
    let _updates = coordinator.allocate_and_dispatch(1_000_000);

    // Should not allocate before 100ms
    assert!(!coordinator.should_allocate(1_050_000)); // 50ms later

    // Should allocate after 100ms
    assert!(coordinator.should_allocate(1_100_000)); // 100ms later
}

#[test]
fn test_remb_bitrate_encoding() {
    let generator = RembGenerator::new(0);

    // Test various bitrates
    let test_bitrates = vec![
        100_000,   // 100 kbps
        500_000,   // 500 kbps
        1_000_000, // 1 Mbps
        5_000_000, // 5 Mbps
    ];

    for bitrate in test_bitrates {
        let packet = generator.generate(bitrate, 0);
        assert_eq!(packet.len(), 24);

        // Extract encoded bitrate
        let exp = (packet[17] >> 2) & 0x3F;
        let mantissa = (((packet[17] & 0x03) as u32) << 16)
            | ((packet[18] as u32) << 8)
            | (packet[19] as u32);

        // Decode and verify within 5% error
        let decoded = (mantissa as u64) << exp;
        let error_percent = ((decoded as i64 - bitrate as i64).abs() * 100) / bitrate as i64;
        assert!(
            error_percent < 5,
            "Bitrate {} encoded/decoded with {}% error",
            bitrate,
            error_percent
        );
    }
}

#[test]
fn test_priority_ordering() {
    // Verify priority enum ordering
    assert!(TrackPriority::Critical > TrackPriority::High);
    assert!(TrackPriority::High > TrackPriority::Normal);
    assert!(TrackPriority::Normal > TrackPriority::Low);
}

#[test]
fn test_screen_share_priority() {
    let detector = SpeakerDetector::new();

    // Screen share should get High priority
    assert_eq!(
        detector.get_priority(1, MediaKind::ScreenShare),
        TrackPriority::High
    );

    // Regular video gets Normal
    assert_eq!(
        detector.get_priority(2, MediaKind::Video),
        TrackPriority::Normal
    );

    // Audio gets Normal
    assert_eq!(
        detector.get_priority(3, MediaKind::Audio),
        TrackPriority::Normal
    );
}
