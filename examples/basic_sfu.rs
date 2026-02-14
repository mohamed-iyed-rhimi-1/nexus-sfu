//! Basic SFU Example - Demonstrates Nexus SFU MVP configuration and types
//!
//! Run with: cargo run --example basic_sfu

use nexus_sfu::{NexusConfig, MediaKind, tier};

fn main() {
    println!("=== Nexus SFU MVP Demo ===\n");
    println!("Performance Tier: {}", tier::CURRENT);
    println!("Target throughput: {} pps/core", tier::metrics::PACKETS_PER_SEC_PER_CORE);
    println!("Target latency: {}ms (P50), {}ms (P99)", 
             tier::metrics::LATENCY_P50_MS,
             tier::metrics::LATENCY_P99_MS);
    println!("Max participants: {}", tier::metrics::MAX_PARTICIPANTS_PER_ROOM);
    println!();

    // Create default configuration
    let config = NexusConfig::default();
    
    println!("=== Default Configuration ===");
    println!("Media bind address: {}", config.transport.media_bind_addr);
    println!("Signaling bind address: {}", config.transport.signaling_bind_addr);
    println!("Arena size: {} MB", config.memory.arena_size_mb);
    println!("Ring buffer size: {} packets", config.memory.ring_buffer_size);
    println!("Workers: {} (0 = auto-detect)", config.worker.num_workers);
    println!("Batch size: {} packets", config.transport.batch_size);
    println!("Batch flush interval: {} μs", config.transport.batch_flush_interval_us);
    println!("Max participants per room: {}", config.room.max_participants_per_room);
    println!();

    // Validate configuration
    match config.validate() {
        Ok(()) => println!("✓ Configuration is valid"),
        Err(e) => println!("✗ Configuration error: {}", e),
    }
    println!();

    // Show media kinds
    println!("=== Media Types ===");
    println!("Audio: {}", MediaKind::Audio);
    println!("Video: {}", MediaKind::Video);
    println!();

    // Simulate RTP packet creation
    println!("=== Simulated RTP Packet ===");
    let ssrc: u32 = 0xDEADBEEF;
    let seq: u16 = 1234;
    let timestamp: u32 = 160000;
    let packet = create_rtp_packet(ssrc, seq, timestamp);
    
    println!("SSRC: {:#X}", ssrc);
    println!("Sequence: {}", seq);
    println!("Timestamp: {}", timestamp);
    println!("Packet size: {} bytes", packet.len());
    println!("Header (first 12 bytes): {:02X?}", &packet[..12]);
    println!();

    println!("=== Demo Complete ===");
    println!("\nNote: Full packet processing requires implementing the remaining tasks:");
    println!("  - Task 2: Packet Arena");
    println!("  - Task 3: Ring Buffer");
    println!("  - Task 5: RTP/RTCP Parser");
    println!("  - Task 6: UDP Transport");
    println!("  - etc.");
}

/// Create a simple RTP packet for demonstration
fn create_rtp_packet(ssrc: u32, seq: u16, timestamp: u32) -> Vec<u8> {
    let mut packet = vec![0u8; 172]; // 12 byte header + 160 byte payload
    
    // RTP header (RFC 3550)
    packet[0] = 0x80; // V=2, P=0, X=0, CC=0
    packet[1] = 0x60; // M=0, PT=96 (dynamic)
    packet[2] = (seq >> 8) as u8;
    packet[3] = seq as u8;
    packet[4] = (timestamp >> 24) as u8;
    packet[5] = (timestamp >> 16) as u8;
    packet[6] = (timestamp >> 8) as u8;
    packet[7] = timestamp as u8;
    packet[8] = (ssrc >> 24) as u8;
    packet[9] = (ssrc >> 16) as u8;
    packet[10] = (ssrc >> 8) as u8;
    packet[11] = ssrc as u8;
    
    // Fill payload with dummy audio data
    for i in 12..172 {
        packet[i] = (i % 256) as u8;
    }
    
    packet
}
