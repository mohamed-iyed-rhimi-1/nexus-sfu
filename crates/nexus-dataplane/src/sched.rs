//! CPU pinning and real-time priority of shard threads (note §3.1). Both
//! are best effort: a failure is logged and the shard runs without it.

use crate::ids::ShardId;

/// Pins the calling thread to core `shard` of the machine's core list: N
/// shards take cores 0..N−1, in order; a shard beyond the list runs unpinned.
pub(crate) fn pin_current(shard: ShardId) {
    let index = usize::from(shard.index());
    let cores = core_affinity::get_core_ids().unwrap_or_default();
    let Some(&core) = cores.get(index) else {
        tracing::warn!(
            shard = index,
            cores = cores.len(),
            "no core to pin the shard to, running unpinned"
        );
        return;
    };
    if !core_affinity::set_for_current(core) {
        tracing::warn!(
            shard = index,
            core = core.id,
            "failed to pin the shard, running unpinned"
        );
    }
}

/// Sets SCHED_FIFO at `priority` for the calling thread (Linux).
#[cfg(target_os = "linux")]
pub(crate) fn set_realtime(shard: ShardId, priority: u8) {
    match crate::shard::io::linux::set_realtime_scheduling(priority) {
        Ok(()) => tracing::info!(shard = shard.index(), priority, "shard runs SCHED_FIFO"),
        Err(e) => tracing::warn!(shard = shard.index(), error = %e, "SCHED_FIFO not set"),
    }
}

/// Real-time scheduling is Linux only: one warning per process.
#[cfg(not(target_os = "linux"))]
pub(crate) fn set_realtime(_shard: ShardId, _priority: u8) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!("realtime_priority is ignored: SCHED_FIFO is Linux only");
    });
}

/// Whether the process has CAP_SYS_NICE (needed for SCHED_FIFO). Reads
/// `/proc/self/status`; any read or parse error means no. Copied from
/// `src/worker/pool.rs`.
#[cfg(target_os = "linux")]
pub(crate) fn has_cap_sys_nice() -> bool {
    const CAP_SYS_NICE_BIT: u32 = 23;
    const MAX_LINES: usize = 100;
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let effective = status
        .lines()
        .take(MAX_LINES)
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok());
    effective.is_some_and(|caps| caps & (1 << CAP_SYS_NICE_BIT) != 0)
}
