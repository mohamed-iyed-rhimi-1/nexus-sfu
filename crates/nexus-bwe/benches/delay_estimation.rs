use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use nexus_bwe::{KalmanFilter, DelayBasedBweDetector, TransportFeedback, PacketArrivalInfo};

fn bench_kalman_filter_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("kalman_filter");
    group.throughput(Throughput::Elements(1));

    group.bench_function("update", |b| {
        let mut filter = KalmanFilter::new();
        b.iter(|| {
            black_box(filter.update(10.0, 100.0));
        });
    });

    group.finish();
}

fn bench_delay_detector_feedback(c: &mut Criterion) {
    let mut group = c.benchmark_group("delay_detector");

    // Create feedback with 100 packets
    let mut feedback = TransportFeedback::new(12345, 100);
    for i in 0..100 {
        feedback
            .add_packet(PacketArrivalInfo {
                sequence: 100 + i,
                send_time_us: i as u64 * 20_000,
                recv_time_us: i as u64 * 20_000 + 1000,
                size_bytes: 1200,
            })
            .unwrap();
    }

    group.throughput(Throughput::Elements(100));
    group.bench_function("process_feedback_100_packets", |b| {
        let mut detector = DelayBasedBweDetector::with_defaults();
        b.iter(|| {
            black_box(detector.on_feedback(&feedback));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_kalman_filter_update, bench_delay_detector_feedback);
criterion_main!(benches);
