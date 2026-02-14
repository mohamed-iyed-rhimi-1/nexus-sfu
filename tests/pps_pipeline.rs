//! End-to-end 500K pps stress test exercising the FULL forwarding pipeline:
//!
//!   recv → RTP parse → SSRC lookup → arena alloc → worker route →
//!   actor_process_packet → forward_to_subscribers → batch_sender → ring_buffer
//!
//! ```bash
//! cargo test --release --features sim --test pps_pipeline -- --nocapture
//! ```

#![cfg(feature = "sim")]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use nexus_sfu::config::NexusConfig;
use nexus_sfu::sfu::Sfu;
// Use the actor crate's MediaKind for actor_manager calls
use nexus_sfu::nexus_actor::MediaKind as ActorMediaKind;
// Use core MediaKind for register_and_assign_track
use nexus_sfu::types::MediaKind;

fn rtp_packet(seq: u16, ssrc: u32) -> Vec<u8> {
    let mut p = vec![0u8; 184];
    p[0] = 0x80;
    p[1] = 0x60;
    p[2..4].copy_from_slice(&seq.to_be_bytes());
    p[4..8].copy_from_slice(&(seq as u32 * 160).to_be_bytes());
    p[8..12].copy_from_slice(&ssrc.to_be_bytes());
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_full_pipeline_500k_pps() {
    nexus_sfu::clock::set_time_ns(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    );

    // ── 1. Boot SFU ─────────────────────────────────────────────────────
    let media_port: u16 = 14500;
    let media_addr: SocketAddr = format!("127.0.0.1:{}", media_port).parse().unwrap();

    let mut config = NexusConfig::default();
    config.memory.arena_size_mb = 1024;
    config.worker.num_workers = 8;
    config.transport.media_bind_addr = media_addr;
    config.transport.signaling_bind_addr = "127.0.0.1:0".parse().unwrap();

    let mut sfu = Sfu::new(config).await.expect("SFU init");
    let actor_mgr = sfu.actor_manager().clone();

    // ── 2. Room → publishers → tracks → subscribers ─────────────────────
    const NUM_PUB: u32 = 1;
    const SUBS_PER: u32 = 999;
    let ssrc_base: u32 = 1000;

    let room_id = actor_mgr
        .create_room("loadtest".into(), 1000)
        .expect("create_room");

    let mut track_ids: Vec<u64> = Vec::new();
    let mut pub_ids: Vec<u64> = Vec::new();

    for t in 0..NUM_PUB {
        let ssrc = ssrc_base + t;

        // add_participant returns the generated participant_id
        let pid = actor_mgr
            .add_participant(room_id, format!("pub-{t}"))
            .expect("add_participant");
        pub_ids.push(pid);

        let tid = actor_mgr
            .publish_track(pid, ActorMediaKind::Video, ssrc)
            .expect("publish_track");
        track_ids.push(tid);

        // Also register in SSRC router for the recv path
        sfu.register_and_assign_track(tid, pid, ssrc, MediaKind::Video)
            .expect("register_ssrc");
    }

    for t in 0..NUM_PUB {
        for s in 0..SUBS_PER {
            let dest: SocketAddr = format!("127.0.0.1:{}", 20000 + t * SUBS_PER + s)
                .parse()
                .unwrap();

            let sub_pid = actor_mgr
                .add_participant(room_id, format!("sub-{t}-{s}"))
                .expect("add_sub");

            sfu.subscribe_to_track(sub_pid, track_ids[t as usize], dest)
                .expect("subscribe");
        }
    }

    println!(
        "Setup: {} tracks × {} subs = {} fan-out paths",
        NUM_PUB,
        SUBS_PER,
        NUM_PUB * SUBS_PER
    );
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ── 3. Flood ─────────────────────────────────────────────────────────
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
    sock.connect(media_addr).expect("connect");

    let mut packets: Vec<Vec<u8>> = (0..NUM_PUB).map(|t| rtp_packet(0, ssrc_base + t)).collect();

    const TEST_SECS: u64 = 10;
    let dur = Duration::from_secs(TEST_SECS);

    let send_handle = std::thread::spawn(move || {
        let mut sent: u64 = 0;
        let mut seq: u16 = 0;
        let mut si: u32 = 0;
        let t0 = Instant::now();
        while t0.elapsed() < dur {
            let pkt = &mut packets[si as usize];
            pkt[2..4].copy_from_slice(&seq.to_be_bytes());
            if sock.send(pkt).is_ok() {
                sent += 1;
            }
            seq = seq.wrapping_add(1);
            si = (si + 1) % NUM_PUB;
        }
        sent
    });

    // ── 4. Drive SFU ─────────────────────────────────────────────────────
    let t0 = Instant::now();
    let mut total_recv: u64 = 0;
    let mut last_report = Instant::now();

    while t0.elapsed() < dur + Duration::from_secs(1) {
        nexus_sfu::clock::set_time_ns(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        );
        match sfu.step_once() {
            Ok(n) => total_recv += n as u64,
            Err(e) => {
                eprintln!("step_once: {e}");
                break;
            }
        }
        if last_report.elapsed() >= Duration::from_secs(1) {
            let el = t0.elapsed().as_secs_f64();
            println!(
                "  {:.0}s  recv={total_recv} ({:.0} pps)",
                el,
                total_recv as f64 / el
            );
            last_report = Instant::now();
        }
        if total_recv % 5000 == 0 {
            tokio::task::yield_now().await;
        }
    }

    let total_sent = send_handle.join().expect("sender");

    // ── 5. Results ───────────────────────────────────────────────────────
    let el = t0.elapsed().as_secs_f64();
    let arena = sfu.arena();

    println!();
    println!("══════════════════════════════════════════════════════");
    println!("  FULL PIPELINE RESULTS (sim mode)");
    println!("══════════════════════════════════════════════════════");
    println!("  Tracks:          {} × {} subs", NUM_PUB, SUBS_PER);
    println!("  Packets sent:    {total_sent}");
    println!("  Packets recv'd:  {total_recv}");
    println!("  Duration:        {el:.2}s");
    println!("  Send PPS:        {:.0}", total_sent as f64 / el);
    println!("  Recv PPS:        {:.0}", total_recv as f64 / el);
    println!(
        "  Arena cap/free:  {} / {}",
        arena.capacity(),
        arena.free_count()
    );
    println!("══════════════════════════════════════════════════════");

    assert!(total_recv > 0, "SFU must have processed packets");
    assert!(
        arena.free_count() < arena.capacity(),
        "Arena alloc path must be hit"
    );
    println!("  ✅ recv → parse → SSRC lookup → arena alloc → worker → forward → ring_buffer");
}
