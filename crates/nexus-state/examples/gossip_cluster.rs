//! Example: 3-node gossip cluster demonstration.
//!
//! This example demonstrates:
//! - Creating a 3-node SWIM gossip cluster
//! - Peer discovery and failure detection
//! - State update propagation via piggyback
//! - Timing measurements for performance analysis
//!
//! # Running
//!
//! ```bash
//! cargo run --example gossip_cluster
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nexus_state::gossip::{GossipConfig, StateUpdate, SwimProtocol};
use nexus_state::types::Dot;

fn main() {
    println!("=== SWIM Gossip Protocol Demo ===\n");

    // Configuration for demo (faster than production for visibility)
    let config = GossipConfig::new()
        .with_probe_interval(200)
        .with_ping_timeout(100)
        .with_suspect_timeout(500)
        .with_fanout(2);

    println!("Configuration:");
    println!("  Probe interval: {}ms", config.probe_interval_ms);
    println!("  Ping timeout: {}ms", config.ping_timeout_ms);
    println!("  Suspect timeout: {}ms", config.suspect_timeout_ms);
    println!("  Fanout: {}", config.fanout);
    println!();

    // Create 3 nodes
    let node1 = SwimProtocol::new(1, "127.0.0.1:0".parse().unwrap(), config.clone()).unwrap();
    let node2 = SwimProtocol::new(2, "127.0.0.1:0".parse().unwrap(), config.clone()).unwrap();
    let node3 = SwimProtocol::new(3, "127.0.0.1:0".parse().unwrap(), config).unwrap();

    println!("Created nodes:");
    println!("  Node 1: {} (actor_id=1)", node1.local_addr());
    println!("  Node 2: {} (actor_id=2)", node2.local_addr());
    println!("  Node 3: {} (actor_id=3)", node3.local_addr());
    println!();

    // Get addresses before moving into threads
    let _node1_addr = node1.local_addr();
    let node2_addr = node2.local_addr();
    let node3_addr = node3.local_addr();

    // Shutdown signal
    let running = Arc::new(AtomicBool::new(true));

    // Wrap nodes in Arc<Mutex> for thread sharing
    let node1 = Arc::new(std::sync::Mutex::new(node1));
    let node2 = Arc::new(std::sync::Mutex::new(node2));
    let node3 = Arc::new(std::sync::Mutex::new(node3));

    // Clone references for threads
    let node1_clone = Arc::clone(&node1);
    let node2_clone = Arc::clone(&node2);
    let node3_clone = Arc::clone(&node3);
    let running1 = Arc::clone(&running);
    let running2 = Arc::clone(&running);
    let running3 = Arc::clone(&running);

    // Start node threads
    let handle1 = thread::spawn(move || {
        run_node_loop(node1_clone, running1);
    });

    let handle2 = thread::spawn(move || {
        run_node_loop(node2_clone, running2);
    });

    let handle3 = thread::spawn(move || {
        run_node_loop(node3_clone, running3);
    });

    // Bootstrap the cluster: Node 1 connects to Node 2 and Node 3
    println!("Bootstrapping cluster...");
    let start = Instant::now();

    {
        let mut n1 = node1.lock().unwrap();
        n1.add_seed_peer(2, node2_addr).unwrap();
        n1.add_seed_peer(3, node3_addr).unwrap();
    }

    // Wait for cluster to form
    thread::sleep(Duration::from_millis(500));

    println!("Cluster formation took {:?}", start.elapsed());
    println!();

    // Check cluster state
    print_cluster_state(&node1, &node2, &node3);

    // Demonstrate state propagation
    println!("\n--- State Propagation Demo ---\n");

    let dot = Dot::new(1, 1);
    let update = StateUpdate::ParticipantAdded {
        room_id: 1,
        participant_id: 42,
        dot,
    };

    println!("Node 1 broadcasting: ParticipantAdded(id=42)");
    {
        let mut n1 = node1.lock().unwrap();
        n1.broadcast_state_update(update);
    }

    // Wait for propagation
    thread::sleep(Duration::from_millis(500));

    // Check update received
    println!("\nState update propagation:");
    {
        let n1 = node1.lock().unwrap();
        let n2 = node2.lock().unwrap();
        let n3 = node3.lock().unwrap();

        let stats1 = n1.stats().snapshot();
        let stats2 = n2.stats().snapshot();
        let stats3 = n3.stats().snapshot();

        println!(
            "  Node 1: sent={}, received={}",
            stats1.state_updates_sent, stats1.state_updates_received
        );
        println!(
            "  Node 2: sent={}, received={}",
            stats2.state_updates_sent, stats2.state_updates_received
        );
        println!(
            "  Node 3: sent={}, received={}",
            stats3.state_updates_sent, stats3.state_updates_received
        );
    }

    // Run for a bit longer to show ongoing protocol
    println!("\n--- Running Protocol for 2 seconds ---\n");
    thread::sleep(Duration::from_secs(2));

    // Final stats
    println!("Final Statistics:");
    {
        let n1 = node1.lock().unwrap();
        let n2 = node2.lock().unwrap();
        let n3 = node3.lock().unwrap();

        print_node_stats("Node 1", &n1);
        print_node_stats("Node 2", &n2);
        print_node_stats("Node 3", &n3);
    }

    // Shutdown
    println!("\nShutting down...");
    running.store(false, Ordering::Relaxed);

    handle1.join().unwrap();
    handle2.join().unwrap();
    handle3.join().unwrap();

    println!("Done!");
}

fn run_node_loop(node: Arc<std::sync::Mutex<SwimProtocol>>, running: Arc<AtomicBool>) {
    while running.load(Ordering::Relaxed) {
        {
            let mut n = node.lock().unwrap();
            let _ = n.run_probe_cycle();
            for _ in 0..5 {
                let _ = n.recv_loop_iteration();
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn print_cluster_state(
    node1: &Arc<std::sync::Mutex<SwimProtocol>>,
    node2: &Arc<std::sync::Mutex<SwimProtocol>>,
    node3: &Arc<std::sync::Mutex<SwimProtocol>>,
) {
    println!("Cluster State:");

    let n1 = node1.lock().unwrap();
    let n2 = node2.lock().unwrap();
    let n3 = node3.lock().unwrap();

    println!(
        "  Node 1 knows {} peers: {:?}",
        n1.membership().peer_count(),
        n1.membership()
            .get_all_peers()
            .iter()
            .map(|p| p.actor_id())
            .collect::<Vec<_>>()
    );

    println!(
        "  Node 2 knows {} peers: {:?}",
        n2.membership().peer_count(),
        n2.membership()
            .get_all_peers()
            .iter()
            .map(|p| p.actor_id())
            .collect::<Vec<_>>()
    );

    println!(
        "  Node 3 knows {} peers: {:?}",
        n3.membership().peer_count(),
        n3.membership()
            .get_all_peers()
            .iter()
            .map(|p| p.actor_id())
            .collect::<Vec<_>>()
    );
}

fn print_node_stats(name: &str, node: &SwimProtocol) {
    let stats = node.stats().snapshot();
    let transport_stats = node.transport().stats().snapshot();

    println!("  {}:", name);
    println!("    Pings sent: {}", stats.pings_sent);
    println!("    Acks received: {}", stats.acks_received);
    println!("    Ping timeouts: {}", stats.ping_timeouts);
    println!("    Suspicions raised: {}", stats.suspicions_raised);
    println!(
        "    Network: {} msgs sent, {} msgs received",
        transport_stats.messages_sent, transport_stats.messages_received
    );
    println!(
        "    Bytes: {} sent, {} received",
        transport_stats.bytes_sent, transport_stats.bytes_received
    );
}
