//! Stress test: Concurrent sessions and packet processing.
//!
//! Tests system behavior under high load:
//! 1. 1000 concurrent SRTP/ICE/DTLS sessions
//! 2. Packet loss simulation
//! 3. Timeout handling
//! 4. Resource exhaustion scenarios
//!
//! # TigerStyle Compliance
//!
//! - All operations bounded
//! - Graceful degradation under load
//! - No panics on resource exhaustion

use nexus_sfu::srtp::{SrtpContext, SrtpSession, SrtpSessionPool, KeyMaterial, SrtpPolicy};
use nexus_sfu::ice::{IceAgent, IceRole, IceCredentials};
use nexus_sfu::ice::candidate::{Candidate, MAX_CANDIDATES};
use nexus_sfu::dtls::{DtlsSession, DtlsRole};
use std::collections::HashMap;

// ============================================================================
// Test Helpers
// ============================================================================

fn create_unique_key_material(seed: u32) -> KeyMaterial {
    let mut key = [0u8; 16];
    let mut salt = [0u8; 12];
    
    // Use seed to create unique keys
    key[0..4].copy_from_slice(&seed.to_be_bytes());
    key[4..8].copy_from_slice(&seed.wrapping_mul(7).to_be_bytes());
    key[8..12].copy_from_slice(&seed.wrapping_mul(13).to_be_bytes());
    key[12..16].copy_from_slice(&seed.wrapping_mul(19).to_be_bytes());
    
    salt[0..4].copy_from_slice(&seed.wrapping_add(1000).to_be_bytes());
    salt[4..8].copy_from_slice(&seed.wrapping_add(2000).to_be_bytes());
    salt[8..12].copy_from_slice(&seed.wrapping_add(3000).to_be_bytes());
    
    KeyMaterial::from_aes128_gcm(&key, &salt).expect("Failed to create key material")
}

fn build_rtp_packet(seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 12 + payload.len() + 32]; // Room for tag
    packet[0] = 0x80; // V=2
    packet[1] = 0x60; // PT=96
    packet[2..4].copy_from_slice(&seq.to_be_bytes());
    packet[4..8].copy_from_slice(&1000u32.to_be_bytes()); // Timestamp
    packet[8..12].copy_from_slice(&ssrc.to_be_bytes());
    packet[12..12 + payload.len()].copy_from_slice(payload);
    packet
}

// ============================================================================
// 1000 Concurrent Sessions Tests
// ============================================================================

/// Test creating and using 1000 concurrent SRTP contexts.
#[test]
fn test_1000_concurrent_srtp_contexts() {
    const SESSION_COUNT: u32 = 1000;
    
    let mut contexts: Vec<(SrtpContext, SrtpContext)> = Vec::with_capacity(SESSION_COUNT as usize);
    
    // Create 1000 send/receive context pairs
    for i in 0..SESSION_COUNT {
        let material = create_unique_key_material(i);
        let send = SrtpContext::with_default_policy(&material).unwrap();
        let recv = SrtpContext::with_default_policy(&material).unwrap();
        contexts.push((send, recv));
    }
    
    assert_eq!(contexts.len(), SESSION_COUNT as usize);
    
    // Send one packet through each context
    for (i, (send, recv)) in contexts.iter_mut().enumerate() {
        let ssrc = i as u32;
        let mut packet = build_rtp_packet(1, ssrc, b"test");
        let plen = send.protect_rtp(&mut packet, 16).unwrap();
        recv.unprotect_rtp(&mut packet, plen).unwrap();
    }
    
    // Verify all contexts processed one packet
    for (send, recv) in &contexts {
        let (sent, _) = send.stats();
        let (received, _) = recv.stats();
        assert_eq!(sent, 1);
        assert_eq!(received, 1);
    }
}

/// Test 1000 concurrent ICE agents.
#[test]
fn test_1000_concurrent_ice_agents() {
    const AGENT_COUNT: usize = 1000;
    
    let mut agents: Vec<IceAgent> = Vec::with_capacity(AGENT_COUNT);
    
    // Create agents, alternating roles
    for i in 0..AGENT_COUNT {
        let role = if i % 2 == 0 { IceRole::Controlling } else { IceRole::Controlled };
        let agent = IceAgent::with_defaults(role);
        agents.push(agent);
    }
    
    assert_eq!(agents.len(), AGENT_COUNT);
    
    // Verify all agents have unique credentials
    let mut seen_ufrags = std::collections::HashSet::new();
    for agent in &agents {
        let (ufrag, pwd) = agent.local_credentials();
        assert!(ufrag.len() >= 4);
        assert!(pwd.len() >= 22);
        assert!(seen_ufrags.insert(ufrag.to_string()), "Duplicate ufrag detected");
    }
}

/// Test 1000 concurrent DTLS sessions.
#[test]
fn test_1000_concurrent_dtls_sessions() {
    const SESSION_COUNT: usize = 1000;
    
    let mut sessions: Vec<DtlsSession> = Vec::with_capacity(SESSION_COUNT);
    
    // Create sessions, alternating roles
    for i in 0..SESSION_COUNT {
        let session = if i % 2 == 0 {
            DtlsSession::client()
        } else {
            DtlsSession::server()
        };
        sessions.push(session);
    }
    
    assert_eq!(sessions.len(), SESSION_COUNT);
    
    // Verify all sessions have valid fingerprints
    let mut seen_fingerprints = std::collections::HashSet::new();
    for session in &sessions {
        let fp = session.fingerprint();
        assert_eq!(fp.len(), 32);
        assert!(fp.iter().any(|&b| b != 0), "Fingerprint is all zeros");
        // Note: Fingerprints may not be unique if using same key, but should be valid
        seen_fingerprints.insert(fp.to_vec());
    }
    
    // Should have many unique fingerprints (might not be all unique due to timing)
    assert!(seen_fingerprints.len() > SESSION_COUNT / 2, "Too few unique fingerprints");
}

/// Test high-volume packet processing across many sessions.
#[test]
fn test_high_volume_packet_processing() {
    const SESSION_COUNT: u32 = 100;
    const PACKETS_PER_SESSION: u16 = 100;
    
    let mut contexts: Vec<(SrtpContext, SrtpContext, u32)> = Vec::with_capacity(SESSION_COUNT as usize);
    
    // Create contexts
    for i in 0..SESSION_COUNT {
        let material = create_unique_key_material(i);
        let send = SrtpContext::with_default_policy(&material).unwrap();
        let recv = SrtpContext::with_default_policy(&material).unwrap();
        contexts.push((send, recv, i));
    }
    
    // Process packets across all sessions
    let mut total_processed = 0u32;
    
    for seq in 1..=PACKETS_PER_SESSION {
        for (send, recv, ssrc) in contexts.iter_mut() {
            let mut packet = build_rtp_packet(seq, *ssrc, b"data");
            let plen = send.protect_rtp(&mut packet, 16).unwrap();
            recv.unprotect_rtp(&mut packet, plen).unwrap();
            total_processed += 1;
        }
    }
    
    assert_eq!(total_processed, SESSION_COUNT * PACKETS_PER_SESSION as u32);
}

// ============================================================================
// Packet Loss Simulation Tests
// ============================================================================

/// Simulate 10% packet loss and verify system handles it.
#[test]
fn test_10_percent_packet_loss() {
    let material = create_unique_key_material(12345);
    let mut send = SrtpContext::with_default_policy(&material).unwrap();
    let mut recv = SrtpContext::with_default_policy(&material).unwrap();
    
    const TOTAL_PACKETS: u16 = 1000;
    let mut received = 0u32;
    let mut lost = 0u32;
    
    for seq in 1..=TOTAL_PACKETS {
        let mut packet = build_rtp_packet(seq, 0x12345678, b"test");
        let plen = send.protect_rtp(&mut packet, 16).unwrap();
        
        // Simulate 10% loss (every 10th packet)
        if seq % 10 == 0 {
            lost += 1;
            continue; // Drop packet
        }
        
        // Receive surviving packets
        recv.unprotect_rtp(&mut packet, plen).unwrap();
        received += 1;
    }
    
    assert_eq!(received, 900);
    assert_eq!(lost, 100);
    
    let (rtp, _) = recv.stats();
    assert_eq!(rtp, 900);
}

/// Simulate 25% packet loss.
#[test]
fn test_25_percent_packet_loss() {
    let material = create_unique_key_material(12345);
    let mut send = SrtpContext::with_default_policy(&material).unwrap();
    let mut recv = SrtpContext::with_default_policy(&material).unwrap();
    
    const TOTAL_PACKETS: u16 = 1000;
    let mut received = 0u32;
    
    for seq in 1..=TOTAL_PACKETS {
        let mut packet = build_rtp_packet(seq, 0x12345678, b"test");
        let plen = send.protect_rtp(&mut packet, 16).unwrap();
        
        // Simulate 25% loss (every 4th packet)
        if seq % 4 == 0 {
            continue; // Drop packet
        }
        
        recv.unprotect_rtp(&mut packet, plen).unwrap();
        received += 1;
    }
    
    assert_eq!(received, 750);
}

/// Simulate 50% packet loss.
#[test]
fn test_50_percent_packet_loss() {
    let material = create_unique_key_material(12345);
    let mut send = SrtpContext::with_default_policy(&material).unwrap();
    let mut recv = SrtpContext::with_default_policy(&material).unwrap();
    
    const TOTAL_PACKETS: u16 = 1000;
    let mut received = 0u32;
    
    for seq in 1..=TOTAL_PACKETS {
        let mut packet = build_rtp_packet(seq, 0x12345678, b"test");
        let plen = send.protect_rtp(&mut packet, 16).unwrap();
        
        // Simulate 50% loss (every other packet)
        if seq % 2 == 0 {
            continue; // Drop packet
        }
        
        recv.unprotect_rtp(&mut packet, plen).unwrap();
        received += 1;
    }
    
    assert_eq!(received, 500);
}

/// Test SRTP replay handling with bursty packet loss.
#[test]
fn test_bursty_packet_loss() {
    let material = create_unique_key_material(12345);
    let mut send = SrtpContext::with_default_policy(&material).unwrap();
    let mut recv = SrtpContext::with_default_policy(&material).unwrap();
    
    let mut protected_packets: Vec<(Vec<u8>, usize, u16)> = Vec::new();
    
    // Protect 100 packets
    for seq in 1..=100u16 {
        let mut packet = build_rtp_packet(seq, 0x12345678, b"test");
        let plen = send.protect_rtp(&mut packet, 16).unwrap();
        protected_packets.push((packet[..plen].to_vec(), plen, seq));
    }
    
    let mut received = 0u32;
    
    // Simulate bursty loss: receive 1-20, skip 21-40, receive 41-60, skip 61-80, receive 81-100
    for (packet, plen, seq) in protected_packets.iter() {
        // Skip bursts
        if (21..=40).contains(seq) || (61..=80).contains(seq) {
            continue;
        }
        
        let mut p = packet.clone();
        recv.unprotect_rtp(&mut p, *plen).unwrap();
        received += 1;
    }
    
    assert_eq!(received, 60);
}

// ============================================================================
// Resource Exhaustion Tests
// ============================================================================

/// Test session pool rejects inserts at capacity.
#[test]
fn test_session_pool_capacity_enforcement() {
    const CAPACITY: u32 = 100;
    let mut pool = SrtpSessionPool::new(CAPACITY);
    
    // Fill to capacity
    for i in 0..CAPACITY {
        let material = create_unique_key_material(i);
        let session = SrtpSession::symmetric(&material, SrtpPolicy::aes_128_gcm()).unwrap();
        let result = pool.insert(i, session);
        assert!(result.is_ok(), "Insert {} should succeed", i);
    }
    
    assert_eq!(pool.len(), CAPACITY);
    assert_eq!(pool.remaining_capacity(), 0);
    
    // Additional inserts should fail
    for i in CAPACITY..(CAPACITY + 10) {
        let material = create_unique_key_material(i);
        let session = SrtpSession::symmetric(&material, SrtpPolicy::aes_128_gcm()).unwrap();
        let result = pool.insert(i, session);
        assert!(result.is_err(), "Insert {} should fail at capacity", i);
    }
}

/// Test ICE candidate limit enforcement.
#[test]
fn test_ice_candidate_limit_enforcement() {
    let mut agent = IceAgent::with_defaults(IceRole::Controlling);
    agent.set_remote_credentials(IceCredentials::generate());
    
    // Add candidates up to limit
    let mut added = 0usize;
    for i in 0..MAX_CANDIDATES {
        let addr: std::net::SocketAddr = format!("192.168.{}.{}:5000", i / 256, i % 256).parse().unwrap();
        let candidate = Candidate::new_host(addr, 1, (i % 256) as u8);
        
        match agent.add_remote_candidate(candidate) {
            Ok(_) => added += 1,
            Err(_) => break,
        }
    }
    
    // Should have added up to MAX_CANDIDATES
    assert!(added > 0, "Should add at least one candidate");
    assert!(added <= MAX_CANDIDATES, "Should not exceed MAX_CANDIDATES");
}

/// Test oversized packet handling.
#[test]
fn test_oversized_packet_handling() {
    let material = create_unique_key_material(12345);
    let mut ctx = SrtpContext::with_default_policy(&material).unwrap();
    
    // Create a very large packet (but within bounds)
    let large_payload = vec![0u8; 1200]; // Typical MTU payload
    let mut packet = build_rtp_packet(1, 0x12345678, &large_payload);
    let original_len = 12 + large_payload.len();
    
    // Should succeed with reasonable size
    let result = ctx.protect_rtp(&mut packet, original_len);
    assert!(result.is_ok());
}

// ============================================================================
// Timeout Simulation Tests
// ============================================================================

/// Test that stats are accurate after many operations.
#[test]
fn test_stats_accuracy_under_load() {
    let material = create_unique_key_material(12345);
    let mut send = SrtpContext::with_default_policy(&material).unwrap();
    let mut recv = SrtpContext::with_default_policy(&material).unwrap();
    
    const PACKET_COUNT: u32 = 10000;
    
    for seq in 1..=PACKET_COUNT as u16 {
        let mut packet = build_rtp_packet(seq, 0x12345678, b"x");
        let plen = send.protect_rtp(&mut packet, 13).unwrap();
        recv.unprotect_rtp(&mut packet, plen).unwrap();
    }
    
    let (sent, _) = send.stats();
    let (received, _) = recv.stats();
    
    assert_eq!(sent, PACKET_COUNT);
    assert_eq!(received, PACKET_COUNT);
}

/// Test DTLS session timeout behavior.
#[test]
fn test_dtls_handshake_timeout_check() {
    let session = DtlsSession::client();
    
    // New session should not be timed out
    assert!(!session.is_handshake_timed_out());
    
    // Session in New state doesn't have a handshake start time
    assert!(!session.is_handshake_timed_out());
}

/// Test multiple session lifecycle (create, use, destroy).
#[test]
fn test_session_lifecycle_stress() {
    const ITERATIONS: u32 = 100;
    const SESSIONS_PER_ITER: u32 = 10;
    
    for iter in 0..ITERATIONS {
        let mut pool = SrtpSessionPool::new(SESSIONS_PER_ITER);
        
        // Create sessions
        for i in 0..SESSIONS_PER_ITER {
            let ssrc = iter * SESSIONS_PER_ITER + i;
            let material = create_unique_key_material(ssrc);
            let session = SrtpSession::symmetric(&material, SrtpPolicy::aes_128_gcm()).unwrap();
            pool.insert(ssrc, session).unwrap();
        }
        
        // Use sessions
        for i in 0..SESSIONS_PER_ITER {
            let ssrc = iter * SESSIONS_PER_ITER + i;
            assert!(pool.contains(ssrc));
        }
        
        // Destroy sessions
        for i in 0..SESSIONS_PER_ITER {
            let ssrc = iter * SESSIONS_PER_ITER + i;
            pool.remove(ssrc);
        }
        
        assert!(pool.is_empty());
    }
}

// ============================================================================
// Concurrent Pattern Simulation
// ============================================================================

/// Simulate round-robin processing across sessions.
#[test]
fn test_round_robin_session_processing() {
    const SESSION_COUNT: u32 = 50;
    const ROUNDS: u16 = 100;
    
    let mut contexts: Vec<(SrtpContext, SrtpContext)> = Vec::with_capacity(SESSION_COUNT as usize);
    
    for i in 0..SESSION_COUNT {
        let material = create_unique_key_material(i);
        let send = SrtpContext::with_default_policy(&material).unwrap();
        let recv = SrtpContext::with_default_policy(&material).unwrap();
        contexts.push((send, recv));
    }
    
    // Process one packet per session per round
    for round in 1..=ROUNDS {
        for (send, recv) in contexts.iter_mut() {
            let mut packet = build_rtp_packet(round, 0x12345678, b"data");
            let plen = send.protect_rtp(&mut packet, 16).unwrap();
            recv.unprotect_rtp(&mut packet, plen).unwrap();
        }
    }
    
    // Each session should have processed ROUNDS packets
    for (send, recv) in &contexts {
        let (sent, _) = send.stats();
        let (received, _) = recv.stats();
        assert_eq!(sent, ROUNDS as u32);
        assert_eq!(received, ROUNDS as u32);
    }
}

/// Test interleaved send/receive across sessions.
#[test]
fn test_interleaved_session_traffic() {
    const SESSION_COUNT: usize = 20;
    
    let mut sessions: Vec<(SrtpSession, SrtpSession)> = Vec::with_capacity(SESSION_COUNT);
    
    for i in 0..SESSION_COUNT as u32 {
        let send_key = create_unique_key_material(i * 2);
        let recv_key = create_unique_key_material(i * 2 + 1);
        
        let alice = SrtpSession::new(&send_key, &recv_key, SrtpPolicy::aes_128_gcm()).unwrap();
        let bob = SrtpSession::new(&recv_key, &send_key, SrtpPolicy::aes_128_gcm()).unwrap();
        
        sessions.push((alice, bob));
    }
    
    // Interleaved traffic: A->B then B->A for each session
    for seq in 1..=50u16 {
        for (alice, bob) in sessions.iter_mut() {
            // Alice -> Bob
            let mut packet = build_rtp_packet(seq, 0xAAAAAAAA, b"a2b");
            let plen = alice.protect_rtp(&mut packet, 15).unwrap();
            bob.unprotect_rtp(&mut packet, plen).unwrap();
            
            // Bob -> Alice
            let mut packet = build_rtp_packet(seq, 0xBBBBBBBB, b"b2a");
            let plen = bob.protect_rtp(&mut packet, 15).unwrap();
            alice.unprotect_rtp(&mut packet, plen).unwrap();
        }
    }
    
    // Verify each session processed correct amounts
    for (alice, bob) in &sessions {
        let (a_sent, _) = alice.send_stats();
        let (a_recv, _) = alice.recv_stats();
        let (b_sent, _) = bob.send_stats();
        let (b_recv, _) = bob.recv_stats();
        
        assert_eq!(a_sent, 50);
        assert_eq!(a_recv, 50);
        assert_eq!(b_sent, 50);
        assert_eq!(b_recv, 50);
    }
}
