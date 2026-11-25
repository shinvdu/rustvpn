//! Traffic sampling and history persistence.
//!
//! Hooks are deliberately non-blocking: they only enqueue work on a bounded
//! channel.  A dedicated worker performs SQLite writes off the data-path
//! tasks.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::model::{
    now_unix, Counters, PeerId, Rate, SessionEnd, SessionInfo, SessionObserver, SessionStart,
};
use crate::store::Store;

#[derive(Clone, Debug)]
struct Tracked {
    peer_id: PeerId,
    counters: Counters,
}

struct Sample {
    session_id: u64,
    peer_id: PeerId,
    minute: i64,
    hour: i64,
    counters: Counters,
    total: Counters,
}

enum Cmd {
    Start(SessionStart),
    End(SessionEnd, bool),
    Tick(Vec<Sample>),
}

pub struct History {
    tx: mpsc::Sender<Cmd>,
    last: Mutex<HashMap<u64, Tracked>>,
    rates: Mutex<HashMap<u64, Rate>>,
    dropped: AtomicU64,
}

impl History {
    pub fn spawn(store: Arc<Store>) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(1024);
        let history = Arc::new(Self {
            tx,
            last: Mutex::new(HashMap::new()),
            rates: Mutex::new(HashMap::new()),
            dropped: AtomicU64::new(0),
        });
        tokio::spawn(worker(store, rx));
        history
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn rates(&self) -> HashMap<u64, Rate> {
        self.rates.lock().unwrap().clone()
    }

    /// Compute per-session deltas and rates from a snapshot of the live
    /// counters.  Called by the sampler every 10 seconds.
    pub fn record_tick(&self, sessions: &[SessionInfo], elapsed_secs: f64) {
        let now = now_unix();
        let minute = now - now.rem_euclid(60);
        let hour = now - now.rem_euclid(3600);
        let elapsed = elapsed_secs.max(0.001);
        let mut samples = Vec::with_capacity(sessions.len());
        let mut rates = HashMap::with_capacity(sessions.len());
        let mut current = HashMap::with_capacity(sessions.len());

        {
            let mut last = self.last.lock().unwrap();
            for session in sessions {
                let tracked = last.get(&session.session_id);
                let delta = match tracked {
                    Some(prev) => session.counters.delta_since(&prev.counters),
                    None => session.counters,
                };
                rates.insert(
                    session.session_id,
                    Rate {
                        rate_in_bps: (delta.bytes_in as f64 / elapsed) as u64,
                        rate_out_bps: (delta.bytes_out as f64 / elapsed) as u64,
                    },
                );
                current.insert(
                    session.session_id,
                    Tracked {
                        peer_id: parse_session_peer(&session.peer_id),
                        counters: session.counters,
                    },
                );
                samples.push(Sample {
                    session_id: session.session_id,
                    peer_id: parse_session_peer(&session.peer_id),
                    minute,
                    hour,
                    counters: delta,
                    total: session.counters,
                });
            }

            // Sessions that vanished without an end hook get a synthetic end
            // record; the real hook (if it arrives later) overwrites it.
            for (session_id, tracked) in last.iter() {
                if !current.contains_key(session_id) {
                    let _ = self.tx.try_send(Cmd::End(
                        SessionEnd {
                            session_id: *session_id,
                            peer_id: tracked.peer_id,
                            ended_at: now,
                            reason: "unknown".into(),
                            counters: tracked.counters,
                        },
                        true,
                    ));
                }
            }
            *last = current;
        }

        *self.rates.lock().unwrap() = rates;
        if self.tx.try_send(Cmd::Tick(samples)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl SessionObserver for History {
    fn session_started(&self, start: SessionStart) {
        if self.tx.try_send(Cmd::Start(start)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn session_ended(&self, end: SessionEnd) {
        if self.tx.try_send(Cmd::End(end, false)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn parse_session_peer(hex_id: &str) -> PeerId {
    crate::model::parse_id(hex_id).unwrap_or([0u8; 16])
}

async fn worker(store: Arc<Store>, mut rx: mpsc::Receiver<Cmd>) {
    // Skip the immediate first tick from `interval`.
    let mut cleanup = tokio::time::interval(Duration::from_secs(3600));
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    cleanup.tick().await;
    loop {
        tokio::select! {
            _ = cleanup.tick() => {
                let store = store.clone();
                let _ = tokio::task::spawn_blocking(move || store.cleanup()).await;
            }
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { break };
                let store = store.clone();
                let _ = tokio::task::spawn_blocking(move || match cmd {
                    Cmd::Start(start) => store.start_session(&start),
                    Cmd::End(end, only_if_open) => store.finish_session(&end, only_if_open),
                    Cmd::Tick(samples) => {
                        let mut rows = Vec::with_capacity(samples.len());
                        let mut totals = Vec::with_capacity(samples.len());
                        for sample in samples {
                            rows.push((
                                sample.peer_id,
                                sample.minute,
                                sample.hour,
                                sample.counters,
                            ));
                            totals.push((sample.session_id, sample.total));
                        }
                        store.add_samples(&rows)?;
                        store.update_session_counters(&totals)
                    }
                })
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(id: u64, bytes: u64) -> SessionInfo {
        SessionInfo {
            session_id: id,
            peer_id: "01010101010101010101010101010101".into(),
            name: "alice".into(),
            addr: "1.2.3.4:5".into(),
            proto: "udp".into(),
            mode: "plain".into(),
            mtu: 1515,
            established: String::new(),
            started_at_unix: 1_000,
            last_ping: String::new(),
            last_sent: String::new(),
            counters: Counters {
                bytes_in: bytes,
                bytes_out: bytes,
                ..Counters::default()
            },
            rate_in_bps: 0,
            rate_out_bps: 0,
        }
    }

    #[tokio::test]
    async fn records_deltas_and_rates() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let history = History::spawn(store.clone());
        history.record_tick(&[session(1, 100)], 10.0);
        let rates = history.rates();
        assert_eq!(rates.get(&1).unwrap().rate_in_bps, 10);
        history.record_tick(&[session(1, 300)], 10.0);
        let rates = history.rates();
        assert_eq!(rates.get(&1).unwrap().rate_in_bps, 20);
        // Let the worker drain the queue.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
