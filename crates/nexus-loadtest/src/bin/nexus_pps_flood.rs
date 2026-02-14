//! Raw UDP packet flood targeting 500K+ pps on the Nexus SFU.
//!
//! Sends valid RTP packets directly to the SFU media port, bypassing
//! WebRTC signaling. Run the SFU with `cargo run --features sim` so
//! packets are processed without SRTP/DTLS.
//!
//! ```bash
//! # Terminal 1 – start SFU in sim mode
//! cargo run --features sim
//!
//! # Terminal 2 – flood
//! cargo run --release --bin nexus-pps-flood -p nexus-loadtest -- \
//!     --target 127.0.0.1:10000 --pps 500000 --duration 30
//! ```

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;

// ── Signal handling (no external crate) ──────────────────────────────────

static SIGNAL_RECEIVED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_: libc::c_int) {
    SIGNAL_RECEIVED.store(true, Ordering::Relaxed);
}

fn install_signal_handler(stop: &Arc<AtomicBool>) {
    let s = Arc::clone(stop);
    unsafe { libc::signal(libc::SIGINT, on_sigint as libc::sighandler_t); }
    std::thread::spawn(move || {
        while !SIGNAL_RECEIVED.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(50));
        }
        s.store(true, Ordering::Relaxed);
    });
}

// ── CLI ──────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "nexus-pps-flood")]
struct Args {
    /// SFU media address (UDP)
    #[arg(long, default_value = "127.0.0.1:10000")]
    target: SocketAddr,
    /// Target total packets/sec across all threads
    #[arg(long, default_value = "500000")]
    pps: u64,
    /// Test duration in seconds
    #[arg(long, default_value = "30")]
    duration: u64,
    /// Sender threads
    #[arg(long, default_value = "4")]
    threads: u32,
    /// RTP payload bytes (packet = payload + 12-byte header)
    #[arg(long, default_value = "172")]
    payload_size: usize,
    /// Distinct SSRCs (simulated tracks)
    #[arg(long, default_value = "50")]
    ssrc_count: u32,
    /// Socket send buffer size
    #[arg(long, default_value = "4194304")]
    sndbuf: i32,
    /// Disable rate limiting (send as fast as possible)
    #[arg(long)]
    unlimited: bool,
}

// ── Packet builder ───────────────────────────────────────────────────────

fn build_rtp(seq: u16, ts: u32, ssrc: u32, payload_size: usize) -> Vec<u8> {
    let mut p = vec![0u8; 12 + payload_size];
    p[0] = 0x80;       // V=2
    p[1] = 0x60;       // PT=96
    p[2..4].copy_from_slice(&seq.to_be_bytes());
    p[4..8].copy_from_slice(&ts.to_be_bytes());
    p[8..12].copy_from_slice(&ssrc.to_be_bytes());
    for i in 0..payload_size { p[12 + i] = (i & 0xFF) as u8; }
    p
}

// ── Per-thread stats ─────────────────────────────────────────────────────

struct Stats {
    sent: AtomicU64,
    bytes: AtomicU64,
    errors: AtomicU64,
}

// ── Sender thread ────────────────────────────────────────────────────────

fn sender(
    id: u32,
    target: SocketAddr,
    pps: u64,
    dur: Duration,
    payload_size: usize,
    ssrc_base: u32,
    ssrc_count: u32,
    sndbuf: i32,
    unlimited: bool,
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
) {
    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind");
    // connect() avoids per-send address lookup – big perf win
    sock.connect(target).expect("connect");
    sock.set_nonblocking(false).ok();

    // Enlarge send buffer
    {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::setsockopt(
                sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF,
                &sndbuf as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
        }
    }

    // Pre-build one packet per SSRC
    let mut pkts: Vec<Vec<u8>> = (0..ssrc_count)
        .map(|i| build_rtp(0, 0, ssrc_base + i, payload_size))
        .collect();

    let pkt_len = 12 + payload_size;
    let start = Instant::now();

    // Burst parameters for rate limiting
    // Larger bursts = less spin-wait overhead = more accurate at high rates
    let burst: u64 = if unlimited { 128 } else { (pps / 200).max(1) };
    let burst_ns: u64 = if unlimited || pps == 0 { 0 } else { 1_000_000_000 * burst / pps };

    let mut seq: u16 = (id as u16).wrapping_mul(10000);
    let mut ts: u32 = 0;
    let mut si: u32 = 0;
    let mut bc: u64 = 0;
    let mut bstart = Instant::now();

    // Check stop flag every N packets to reduce atomic load overhead
    const STOP_CHECK_INTERVAL: u64 = 1024;
    let mut since_check: u64 = 0;

    loop {
        since_check += 1;
        if since_check >= STOP_CHECK_INTERVAL {
            since_check = 0;
            if stop.load(Ordering::Relaxed) || start.elapsed() >= dur {
                break;
            }
        }

        // Update header in-place
        let pkt = &mut pkts[si as usize];
        pkt[2..4].copy_from_slice(&seq.to_be_bytes());
        pkt[4..8].copy_from_slice(&ts.to_be_bytes());

        // send() on connected socket – single syscall, no address copy
        match sock.send(pkt) {
            Ok(_) => {
                stats.sent.fetch_add(1, Ordering::Relaxed);
                stats.bytes.fetch_add(pkt_len as u64, Ordering::Relaxed);
            }
            Err(_) => {
                stats.errors.fetch_add(1, Ordering::Relaxed);
            }
        }

        seq = seq.wrapping_add(1);
        ts = ts.wrapping_add(160);
        si = (si + 1) % ssrc_count;
        bc += 1;

        // Rate limit
        if !unlimited && bc >= burst {
            let target_dur = Duration::from_nanos(burst_ns);
            let elapsed = bstart.elapsed();
            if elapsed < target_dur {
                // spin-wait for sub-ms precision
                while bstart.elapsed() < target_dur {
                    std::hint::spin_loop();
                }
            }
            bc = 0;
            bstart = Instant::now();
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────────────

fn main() {
    let args = Args::parse();

    println!("╔══════════════════════════════════════════════════╗");
    println!("║        Nexus SFU – Raw PPS Flood Test           ║");
    println!("╠══════════════════════════════════════════════════╣");
    println!("║  Target addr : {:<33} ║", args.target);
    println!("║  Target PPS  : {:<33} ║", args.pps);
    println!("║  Duration    : {:<33} ║", format!("{}s", args.duration));
    println!("║  Threads     : {:<33} ║", args.threads);
    println!("║  Packet size : {:<33} ║", format!("{} B ({}+12)", args.payload_size + 12, args.payload_size));
    println!("║  SSRCs       : {:<33} ║", args.ssrc_count);
    println!("║  Rate limit  : {:<33} ║", if args.unlimited { "OFF" } else { "ON" });
    println!("╚══════════════════════════════════════════════════╝");
    println!();

    let pps_per_thread = args.pps / args.threads as u64;
    let dur = Duration::from_secs(args.duration);
    let stop = Arc::new(AtomicBool::new(false));

    install_signal_handler(&stop);

    let mut all_stats: Vec<Arc<Stats>> = Vec::new();
    let mut handles = Vec::new();

    for t in 0..args.threads {
        let st = Arc::new(Stats {
            sent: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        });
        all_stats.push(Arc::clone(&st));

        let stop = Arc::clone(&stop);
        let (tgt, ps, sc, sb, ul) =
            (args.target, args.payload_size, args.ssrc_count, args.sndbuf, args.unlimited);

        handles.push(
            std::thread::Builder::new()
                .name(format!("tx-{t}"))
                .spawn(move || sender(t, tgt, pps_per_thread, dur, ps, t * sc, sc, sb, ul, stop, st))
                .expect("spawn"),
        );
    }

    // ── Live monitor ─────────────────────────────────────────────────────
    let t0 = Instant::now();
    let mut last_sent = 0u64;
    let mut last_t = Instant::now();
    let mut peak: f64 = 0.0;

    println!("{:>6}  {:>12}  {:>12}  {:>12}  {:>8}", "Time", "Total", "Curr PPS", "Avg PPS", "Errors");
    println!("{}", "─".repeat(58));

    while t0.elapsed() < dur && !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(1));

        let total: u64 = all_stats.iter().map(|s| s.sent.load(Ordering::Relaxed)).sum();
        let errs: u64 = all_stats.iter().map(|s| s.errors.load(Ordering::Relaxed)).sum();
        let now = Instant::now();
        let dt = now.duration_since(last_t).as_secs_f64();
        let cur = if dt > 0.0 { (total - last_sent) as f64 / dt } else { 0.0 };
        let avg = {
            let e = t0.elapsed().as_secs_f64();
            if e > 0.0 { total as f64 / e } else { 0.0 }
        };
        if cur > peak { peak = cur; }

        println!(
            "{:>5.0}s  {:>12}  {:>12.0}  {:>12.0}  {:>8}",
            t0.elapsed().as_secs_f64(), total, cur, avg, errs
        );
        last_sent = total;
        last_t = now;
    }

    stop.store(true, Ordering::Relaxed);
    for h in handles { h.join().ok(); }

    // ── Final report ─────────────────────────────────────────────────────
    let total: u64 = all_stats.iter().map(|s| s.sent.load(Ordering::Relaxed)).sum();
    let bytes: u64 = all_stats.iter().map(|s| s.bytes.load(Ordering::Relaxed)).sum();
    let errs: u64 = all_stats.iter().map(|s| s.errors.load(Ordering::Relaxed)).sum();
    let el = t0.elapsed().as_secs_f64();
    let avg = if el > 0.0 { total as f64 / el } else { 0.0 };
    let mbps = if el > 0.0 { bytes as f64 * 8.0 / el / 1_000_000.0 } else { 0.0 };
    let met = avg >= args.pps as f64;

    println!();
    println!("╔══════════════════════════════════════════════════╗");
    println!("║                   RESULTS                       ║");
    println!("╠══════════════════════════════════════════════════╣");
    println!("║  Packets sent : {:<32} ║", total);
    println!("║  Duration     : {:<32} ║", format!("{el:.2}s"));
    println!("║  Avg PPS      : {:<32} ║", format!("{avg:.0}"));
    println!("║  Peak PPS     : {:<32} ║", format!("{peak:.0}"));
    println!("║  Throughput   : {:<32} ║", format!("{mbps:.1} Mbps"));
    println!("║  Errors       : {:<32} ║", errs);
    println!("║  Target {}K : {:<32} ║", args.pps / 1000, if met { "✅ MET" } else { "❌ NOT MET" });
    println!("╚══════════════════════════════════════════════════╝");

    if !met { std::process::exit(1); }
}
