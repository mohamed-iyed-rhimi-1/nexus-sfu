use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nexus_bwe::{
    CongestionController, SimulcastLayer, TrackAllocation, TrackPriority, TransportFeedback,
};

fn bench_gcc_on_transport_feedback(c: &mut Criterion) {
    let gcc = CongestionController::new(100_000, 50_000_000, 1_000_000);
    let mut feedback = TransportFeedback::new(12345, 0);

    // Add typical feedback packet count
    for i in 0..20 {
        let _ = feedback.add_packet(nexus_bwe::PacketArrivalInfo {
            sequence: i,
            send_time_us: i as u64 * 20_000,
            recv_time_us: i as u64 * 20_000 + 5_000,
            size_bytes: 1200,
        });
    }

    c.bench_function("gcc_on_transport_feedback", |b| {
        b.iter(|| {
            gcc.on_transport_feedback(black_box(&feedback), black_box(1_000_000));
        })
    });
}

fn bench_gcc_on_receiver_report(c: &mut Criterion) {
    let gcc = CongestionController::new(100_000, 50_000_000, 1_000_000);

    c.bench_function("gcc_on_receiver_report", |b| {
        b.iter(|| {
            gcc.on_receiver_report(
                black_box(10),
                black_box(Some(50_000)),
                black_box(1_000_000),
            );
        })
    });
}

fn bench_gcc_update_estimate(c: &mut Criterion) {
    let gcc = CongestionController::new(100_000, 50_000_000, 1_000_000);

    c.bench_function("gcc_update_estimate", |b| {
        b.iter(|| {
            gcc.update_estimate(black_box(1_000_000));
        })
    });
}

fn bench_gcc_allocate_bandwidth_10_tracks(c: &mut Criterion) {
    let gcc = CongestionController::new(100_000, 50_000_000, 10_000_000);

    let mut tracks: Vec<TrackAllocation> = (0..10)
        .map(|i| {
            let mut track = TrackAllocation::new(i, TrackPriority::Normal, 1_000_000);
            track.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
            track.add_layer(SimulcastLayer::new(1, 500_000, 640, 480));
            track.add_layer(SimulcastLayer::new(2, 1_000_000, 1280, 720));
            track
        })
        .collect();

    c.bench_function("gcc_allocate_bandwidth_10_tracks", |b| {
        b.iter(|| {
            gcc.allocate_bandwidth(black_box(&mut tracks));
        })
    });
}

fn bench_gcc_allocate_bandwidth_100_tracks(c: &mut Criterion) {
    let gcc = CongestionController::new(100_000, 50_000_000, 50_000_000);

    let mut tracks: Vec<TrackAllocation> = (0..100)
        .map(|i| {
            let priority = match i % 4 {
                0 => TrackPriority::Critical,
                1 => TrackPriority::High,
                2 => TrackPriority::Normal,
                _ => TrackPriority::Low,
            };
            let mut track = TrackAllocation::new(i, priority, 1_000_000);
            track.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
            track.add_layer(SimulcastLayer::new(1, 500_000, 640, 480));
            track.add_layer(SimulcastLayer::new(2, 1_000_000, 1280, 720));
            track
        })
        .collect();

    c.bench_function("gcc_allocate_bandwidth_100_tracks", |b| {
        b.iter(|| {
            gcc.allocate_bandwidth(black_box(&mut tracks));
        })
    });
}

criterion_group!(
    benches,
    bench_gcc_on_transport_feedback,
    bench_gcc_on_receiver_report,
    bench_gcc_update_estimate,
    bench_gcc_allocate_bandwidth_10_tracks,
    bench_gcc_allocate_bandwidth_100_tracks
);
criterion_main!(benches);
