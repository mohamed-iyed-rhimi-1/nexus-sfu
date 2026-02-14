//! Benchmarks for CRDT operations
//!
//! Performance targets:
//! - GCounter increment: < 50ns
//! - GCounter merge: < 500ns
//! - LWWReg set: < 100ns
//! - LWWReg merge: < 200ns
//! - Orswot add: < 500ns
//! - Orswot remove: < 500ns
//! - Orswot merge (100 elements): < 50μs
//! - Orswot contains: < 200ns

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use nexus_state::crdt::{GCounter, LWWReg, Orswot};
use nexus_state::types::{Dot, MAX_ACTORS};

// ============================================================================
// GCounter Benchmarks
// ============================================================================

fn bench_gcounter_increment(c: &mut Criterion) {
    let mut group = c.benchmark_group("gcounter");
    group.throughput(Throughput::Elements(1));

    group.bench_function("increment", |b| {
        let counter = GCounter::new();
        let mut actor = 0u64;
        
        b.iter(|| {
            counter.increment(actor, 1);
            actor = (actor + 1) % (MAX_ACTORS as u64);
        });
    });

    group.finish();
}

fn bench_gcounter_value(c: &mut Criterion) {
    let mut group = c.benchmark_group("gcounter");
    group.throughput(Throughput::Elements(MAX_ACTORS as u64));

    let counter = GCounter::new();
    // Populate some counters
    for i in 0..MAX_ACTORS as u64 {
        counter.increment(i, i + 1);
    }

    group.bench_function("value", |b| {
        b.iter(|| {
            black_box(counter.value())
        });
    });

    group.finish();
}

fn bench_gcounter_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("gcounter");
    group.throughput(Throughput::Elements(MAX_ACTORS as u64));

    let counter1 = GCounter::new();
    let counter2 = GCounter::new();

    // Populate counters with different values
    for i in 0..MAX_ACTORS as u64 {
        counter1.increment(i, i + 1);
        counter2.increment(i, (MAX_ACTORS as u64) - i);
    }

    group.bench_function("merge", |b| {
        b.iter(|| {
            counter1.merge(black_box(&counter2));
        });
    });

    group.finish();
}

// ============================================================================
// LWWReg Benchmarks
// ============================================================================

fn bench_lwwreg_set(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwwreg");
    group.throughput(Throughput::Elements(1));

    group.bench_function("set", |b| {
        let mut reg = LWWReg::new(0u32, 0);
        let mut ts = 1u64;

        b.iter(|| {
            reg.set(black_box(42), ts, 0);
            ts += 1;
        });
    });

    group.finish();
}

fn bench_lwwreg_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwwreg");
    group.throughput(Throughput::Elements(1));

    let reg = LWWReg::with_timestamp(42u32, 100, 0);

    group.bench_function("get", |b| {
        b.iter(|| {
            black_box(reg.get())
        });
    });

    group.finish();
}

fn bench_lwwreg_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("lwwreg");
    group.throughput(Throughput::Elements(1));

    let reg2 = LWWReg::with_timestamp(99u32, 200, 1);

    group.bench_function("merge", |b| {
        b.iter_batched(
            || LWWReg::with_timestamp(42u32, 100, 0),
            |mut reg1| {
                reg1.merge(black_box(&reg2));
                reg1
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ============================================================================
// Orswot Benchmarks
// ============================================================================

fn bench_orswot_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("orswot");
    group.throughput(Throughput::Elements(1));

    group.bench_function("add", |b| {
        b.iter_batched(
            Orswot::<u32>::new,
            |mut set| {
                set.add(black_box(42), Dot::new(0, 1)).unwrap();
                set
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_orswot_add_to_populated(c: &mut Criterion) {
    let mut group = c.benchmark_group("orswot");
    group.throughput(Throughput::Elements(1));

    group.bench_function("add_to_100", |b| {
        b.iter_batched(
            || {
                let mut set = Orswot::<u32>::new();
                for i in 0..100 {
                    set.add(i, Dot::new((i % MAX_ACTORS as u32) as u64, 1)).unwrap();
                }
                set
            },
            |mut set| {
                set.add(black_box(1000), Dot::new(0, 2)).unwrap();
                set
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_orswot_remove(c: &mut Criterion) {
    let mut group = c.benchmark_group("orswot");
    group.throughput(Throughput::Elements(1));

    group.bench_function("remove", |b| {
        b.iter_batched(
            || {
                let mut set = Orswot::<u32>::new();
                set.add(42, Dot::new(0, 1)).unwrap();
                set
            },
            |mut set| {
                set.remove(black_box(&42), Dot::new(0, 2)).unwrap();
                set
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_orswot_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("orswot");
    group.throughput(Throughput::Elements(1));

    let mut set = Orswot::<u32>::new();
    for i in 0..100 {
        set.add(i, Dot::new((i % MAX_ACTORS as u32) as u64, 1)).unwrap();
    }

    group.bench_function("contains_100", |b| {
        b.iter(|| {
            black_box(set.contains(&50))
        });
    });

    group.finish();
}

fn bench_orswot_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("orswot");
    group.throughput(Throughput::Elements(100));

    let mut set2 = Orswot::<u32>::new();
    for i in 50..150 {
        set2.add(i, Dot::new(1, (i - 49) as u64)).unwrap();
    }

    group.bench_function("merge_100", |b| {
        b.iter_batched(
            || {
                let mut set1 = Orswot::<u32>::new();
                for i in 0..100 {
                    set1.add(i, Dot::new(0, (i + 1) as u64)).unwrap();
                }
                set1
            },
            |mut set1| {
                set1.merge(black_box(&set2)).unwrap();
                set1
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_orswot_iter(c: &mut Criterion) {
    let mut group = c.benchmark_group("orswot");
    group.throughput(Throughput::Elements(100));

    let mut set = Orswot::<u32>::new();
    for i in 0..100 {
        set.add(i, Dot::new((i % MAX_ACTORS as u32) as u64, 1)).unwrap();
    }

    group.bench_function("iter_100", |b| {
        b.iter(|| {
            let sum: u32 = set.iter().sum();
            black_box(sum)
        });
    });

    group.finish();
}

// ============================================================================
// Combined Benchmark Groups
// ============================================================================

criterion_group!(
    gcounter_benches,
    bench_gcounter_increment,
    bench_gcounter_value,
    bench_gcounter_merge,
);

criterion_group!(
    lwwreg_benches,
    bench_lwwreg_set,
    bench_lwwreg_get,
    bench_lwwreg_merge,
);

criterion_group!(
    orswot_benches,
    bench_orswot_add,
    bench_orswot_add_to_populated,
    bench_orswot_remove,
    bench_orswot_contains,
    bench_orswot_merge,
    bench_orswot_iter,
);

criterion_main!(gcounter_benches, lwwreg_benches, orswot_benches);
