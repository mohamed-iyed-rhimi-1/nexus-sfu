//! The shard thread's loop (note §3.2-3.3): iterate, busy-poll for
//! `busy_poll_rounds` idle iterations, then park until the socket is
//! readable, a command or a peer shard's message arrives (the producer
//! wakes the shard), or the next timer is due.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::io::DatagramIo;
use super::park::Parker;
use super::Shard;
use crate::command::EventSink;
use crate::ids::ShardId;

/// Longest park when a receive neither got datagrams nor reported the
/// socket drained (pool dry, interrupted call): mio is edge-triggered, so
/// the socket may already be readable and the shard must not sleep long.
const UNCONFIRMED_IDLE_PARK: Duration = Duration::from_millis(1);

/// What a shard thread runs.
pub(crate) struct ShardThread<I: DatagramIo, S: EventSink> {
    pub shard: Shard<I, S>,
    pub parker: Parker,
    pub stop: Arc<AtomicBool>,
    pub running: Arc<AtomicBool>,
    pub busy_poll_rounds: u32,
    pub cpu_affinity: bool,
    pub realtime_priority: Option<u8>,
}

/// Clears `running` however the thread ends, a panic included, so the
/// handle reports a dead shard.
struct RunningGuard(Arc<AtomicBool>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl<I: DatagramIo, S: EventSink> ShardThread<I, S> {
    /// Runs until `stop` is set; publishes the final stats.
    pub fn run(mut self, id: ShardId) {
        assert!(self.running.load(Ordering::SeqCst));
        let _guard = RunningGuard(Arc::clone(&self.running));
        if self.cpu_affinity {
            crate::sched::pin_current(id);
        }
        if let Some(priority) = self.realtime_priority {
            crate::sched::set_realtime(id, priority);
        }
        let mut idle_rounds: u32 = 0;
        // Ends only on `stop`: the shard runs for the life of the process.
        loop {
            let now = Instant::now();
            let stats = self.shard.iterate(now);
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            // Any datagram taken from the socket is work, even one dropped
            // before handling: parking after an all-truncated batch would
            // pace an oversized flood to one batch per millisecond.
            if stats.taken > 0 || stats.commands > 0 || stats.cross_shard > 0 {
                idle_rounds = 0;
                continue;
            }
            idle_rounds = idle_rounds.saturating_add(1);
            if idle_rounds <= self.busy_poll_rounds {
                continue;
            }
            let timeout = if stats.would_block {
                self.shard.park_deadline(now).saturating_duration_since(now)
            } else {
                UNCONFIRMED_IDLE_PARK
            };
            let (shard, stop) = (&self.shard, &self.stop);
            let pending =
                || shard.commands_pending() || shard.xs_pending() || stop.load(Ordering::SeqCst);
            if self.parker.park(timeout, pending) {
                self.shard.count_park();
            }
        }
        self.shard.publish_stats();
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::sync::Mutex;

    use super::*;
    use crate::command::Event;
    use crate::config::ShardConfig;
    use crate::pool::BufferPool;
    use crate::shard::io::{RecvBatch, RecvResult, SendBatch, Sent, RECV_BATCH};

    /// A socket that holds `batches` full batches of oversized datagrams,
    /// then is drained; records when the shard first found it drained.
    struct FloodIo {
        batches: usize,
        drained_at: Arc<Mutex<Option<Instant>>>,
    }

    impl DatagramIo for FloodIo {
        fn recv_batch(&mut self, _: &mut RecvBatch, _: &mut BufferPool) -> io::Result<RecvResult> {
            if self.batches > 0 {
                self.batches -= 1;
                let truncated = RECV_BATCH;
                return Ok(RecvResult {
                    truncated,
                    ..RecvResult::default()
                });
            }
            let mut drained = self.drained_at.lock().unwrap();
            drained.get_or_insert_with(Instant::now);
            Ok(RecvResult {
                would_block: true,
                ..RecvResult::default()
            })
        }

        fn flush(&mut self, tx: &mut SendBatch, pool: &mut BufferPool) -> Sent {
            for d in tx.iter() {
                pool.put(d.buf);
            }
            tx.clear();
            Sent::default()
        }
    }

    #[test]
    fn an_oversized_flood_is_drained_without_parking() {
        const BATCHES: usize = 500;
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (parker, wake) = Parker::new(socket.as_raw_fd()).unwrap();
        let drained_at = Arc::new(Mutex::new(None));
        let io = FloodIo {
            batches: BATCHES,
            drained_at: Arc::clone(&drained_at),
        };
        let start = Instant::now();
        let events: Vec<Event> = Vec::new();
        let shard = Shard::new(ShardConfig::default(), io, events, start).unwrap();
        let stats = shard.stats();
        let stop = Arc::new(AtomicBool::new(false));
        let thread = ShardThread {
            shard,
            parker,
            stop: Arc::clone(&stop),
            running: Arc::new(AtomicBool::new(true)),
            busy_poll_rounds: 0,
            cpu_affinity: false,
            realtime_priority: None,
        };
        let join = std::thread::spawn(move || thread.run(ShardId::new(0)));
        let deadline = start + Duration::from_secs(10);
        while drained_at.lock().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        stop.store(true, Ordering::SeqCst);
        wake.wake_always().unwrap();
        join.join().unwrap();
        let took = drained_at.lock().unwrap().expect("drained") - start;
        let counters = stats.load().counters;
        assert_eq!(counters.rx_truncated, (BATCHES * RECV_BATCH) as u64);
        // Parking 1 ms per all-truncated batch would take ≥ 500 ms.
        assert!(took < Duration::from_millis(100), "drain took {took:?}");
    }
}
