//! The client's signaling task: once started, the only reader of the signaling
//! connection. It answers the SFU's offers, adds trickled candidates, records
//! announced tracks, and forwards what a caller waits for (confirmations,
//! errors, answered offers) through a bounded channel.
//!
//! Senders share the connection through its lock; the task holds it only for
//! one receive of at most [`RECV_WAIT`], so a send waits at most that long.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use nexus_core::ParticipantId;
use nexus_signal::{OfferTrack, SignalMessage};
use tokio::sync::{mpsc, Mutex};
use webrtc::peer_connection::RTCPeerConnection;

use crate::announced::{Announced, AnnouncedSsrcs};
use crate::signaling::SignalingConnection;

/// Events buffered for the caller; further ones are counted and dropped.
pub const EVENT_CAPACITY: usize = 256;

/// Longest single receive, and so the longest a sender waits for the lock.
pub const RECV_WAIT: Duration = Duration::from_millis(200);

/// Most remote tracks remembered per client.
pub const MAX_KNOWN_TRACKS: usize = 256;

/// What the task forwards to the client.
#[derive(Clone, Debug)]
pub enum SignalEvent {
    Subscribed(Vec<u64>),
    Unsubscribed(Vec<u64>),
    Error {
        code: String,
        message: String,
    },
    /// An SFU offer was applied and answered: its track list and the m-lines it
    /// announces for tracks sent to us.
    OfferAnswered {
        tracks: Vec<OfferTrack>,
        announced: Vec<Announced>,
    },
}

/// A track another participant publishes, from `Joined` or `TrackPublished`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteTrack {
    pub track_id: u64,
    pub publisher_id: ParticipantId,
    /// `audio` or `video`.
    pub kind: String,
}

/// Remote tracks a client has heard of, shared with its signaling task.
#[derive(Clone, Default)]
pub struct KnownTracks {
    inner: Arc<StdMutex<Vec<RemoteTrack>>>,
}

impl KnownTracks {
    /// Remember `track`; false if it was known or the table is full.
    pub fn note(&self, track: RemoteTrack) -> bool {
        let mut tracks = self.inner.lock().expect("known tracks lock");
        if tracks.len() >= MAX_KNOWN_TRACKS || tracks.iter().any(|t| t.track_id == track.track_id) {
            return false;
        }
        tracks.push(track);
        true
    }

    /// Forget an unpublished track.
    pub fn remove(&self, track_id: u64) {
        let mut tracks = self.inner.lock().expect("known tracks lock");
        tracks.retain(|t| t.track_id != track_id);
    }

    /// Every known track, sorted by id.
    pub fn snapshot(&self) -> Vec<RemoteTrack> {
        let tracks = self.inner.lock().expect("known tracks lock");
        let mut all = tracks.clone();
        all.sort_by_key(|t| t.track_id);
        all
    }
}

/// What the task needs from its client.
pub(crate) struct TaskContext {
    pub signaling: Arc<Mutex<SignalingConnection>>,
    pub peer_connection: Arc<RTCPeerConnection>,
    pub announced: AnnouncedSsrcs,
    pub known: KnownTracks,
    pub own_id: Option<ParticipantId>,
}

/// A running signaling task, owned by its client.
pub(crate) struct SignalTask {
    stop: Arc<AtomicBool>,
    events: mpsc::Receiver<SignalEvent>,
    dropped: Arc<AtomicU64>,
}

impl SignalTask {
    /// Start the task; it runs until [`SignalTask::stop`] or the connection closes.
    pub fn spawn(ctx: TaskContext) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicU64::new(0));
        let (tx, events) = mpsc::channel(EVENT_CAPACITY);
        let (task_stop, task_dropped) = (Arc::clone(&stop), Arc::clone(&dropped));
        tokio::spawn(async move {
            while !task_stop.load(Ordering::Relaxed) {
                let received = {
                    let mut sig = ctx.signaling.lock().await;
                    tokio::time::timeout(RECV_WAIT, sig.recv()).await
                };
                match received {
                    Ok(Ok(msg)) => handle(msg, &ctx, &tx, &task_dropped).await,
                    Ok(Err(e)) => {
                        tracing::debug!("signaling task: connection ended: {e}");
                        break;
                    }
                    Err(_) => continue, // quiet for RECV_WAIT
                }
            }
        });
        Self {
            stop,
            events,
            dropped,
        }
    }

    /// Ask the task to end after its current receive.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// The next event, or `None` at `deadline` (or if the task ended).
    pub async fn next(&mut self, deadline: tokio::time::Instant) -> Option<SignalEvent> {
        tokio::time::timeout_at(deadline, self.events.recv())
            .await
            .ok()
            .flatten()
    }

    /// Events dropped because the caller did not read them.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl Drop for SignalTask {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn handle(
    msg: SignalMessage,
    ctx: &TaskContext,
    tx: &mpsc::Sender<SignalEvent>,
    dropped: &AtomicU64,
) {
    let event = match msg {
        SignalMessage::Offer { sdp, tracks } => {
            let result = crate::client::answer_offer(
                &ctx.peer_connection,
                &ctx.signaling,
                sdp,
                &tracks,
                &ctx.announced,
            )
            .await;
            match result {
                Ok(announced) => SignalEvent::OfferAnswered { tracks, announced },
                Err(e) => {
                    tracing::warn!("signaling task: answering an offer failed: {e}");
                    SignalEvent::Error {
                        code: "CLIENT_ANSWER_FAILED".to_string(),
                        message: e.to_string(),
                    }
                }
            }
        }
        SignalMessage::IceCandidate {
            candidate,
            sdp_mid,
            sdp_mline_index,
        } => {
            crate::client::add_remote_candidate(
                &ctx.peer_connection,
                candidate,
                sdp_mid,
                sdp_mline_index,
            )
            .await;
            return;
        }
        SignalMessage::TrackPublished {
            track_id,
            publisher_id,
            kind,
            ..
        } => {
            if Some(publisher_id) != ctx.own_id {
                ctx.known.note(RemoteTrack {
                    track_id,
                    publisher_id,
                    kind,
                });
            }
            return;
        }
        SignalMessage::TrackUnpublished { track_id } => {
            ctx.known.remove(track_id);
            return;
        }
        SignalMessage::Subscribed { track_ids } => SignalEvent::Subscribed(track_ids),
        SignalMessage::Unsubscribed { track_ids } => SignalEvent::Unsubscribed(track_ids),
        SignalMessage::Error { code, message } => SignalEvent::Error { code, message },
        other => {
            tracing::debug!("signaling task: ignoring {other:?}");
            return;
        }
    };
    if tx.try_send(event).is_err() {
        dropped.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn track(track_id: u64) -> RemoteTrack {
        RemoteTrack {
            track_id,
            publisher_id: 7,
            kind: "video".to_string(),
        }
    }

    #[test]
    fn known_tracks_are_deduplicated_sorted_and_bounded() {
        let known = KnownTracks::default();
        assert!(known.note(track(3)));
        assert!(known.note(track(1)));
        assert!(!known.note(track(3)));
        let ids: Vec<u64> = known.snapshot().iter().map(|t| t.track_id).collect();
        assert_eq!(ids, vec![1, 3]);
        known.remove(1);
        assert_eq!(known.snapshot().len(), 1);
        for id in 100..(100 + MAX_KNOWN_TRACKS as u64) {
            known.note(track(id));
        }
        assert_eq!(known.snapshot().len(), MAX_KNOWN_TRACKS);
        assert!(!known.note(track(99)));
    }
}
