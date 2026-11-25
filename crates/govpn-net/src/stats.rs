//! GoVPN-compatible JSON stats endpoint.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Times {
    established: SystemTime,
    last_ping: SystemTime,
    last_sent: SystemTime,
}

pub struct LiveStats {
    pub addr: String,
    pub id: [u8; 16],
    pub noise: bool,
    pub cpr: u32,
    pub encless: bool,
    pub mtu: usize,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    payload_in: AtomicU64,
    payload_out: AtomicU64,
    frames_in: AtomicU64,
    frames_out: AtomicU64,
    unauth: AtomicU64,
    dup: AtomicU64,
    heartbeat_recv: AtomicU64,
    heartbeat_sent: AtomicU64,
    times: Mutex<Times>,
}

#[derive(Serialize)]
pub struct PeerStats {
    #[serde(rename = "BytesIn")]
    bytes_in: u64,
    #[serde(rename = "BytesOut")]
    bytes_out: u64,
    #[serde(rename = "BytesPayloadIn")]
    payload_in: u64,
    #[serde(rename = "BytesPayloadOut")]
    payload_out: u64,
    #[serde(rename = "FramesIn")]
    frames_in: u64,
    #[serde(rename = "FramesOut")]
    frames_out: u64,
    #[serde(rename = "FramesUnauth")]
    unauth: u64,
    #[serde(rename = "FramesDup")]
    dup: u64,
    #[serde(rename = "HeartbeatRecv")]
    heartbeat_recv: u64,
    #[serde(rename = "HeartbeatSent")]
    heartbeat_sent: u64,
    #[serde(rename = "Addr")]
    addr: String,
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "NoiseEnable")]
    noise: bool,
    #[serde(rename = "CPR")]
    cpr: u32,
    #[serde(rename = "Encless")]
    encless: bool,
    #[serde(rename = "MTU")]
    mtu: usize,
    #[serde(rename = "Established")]
    established: DateTime<Utc>,
    #[serde(rename = "LastPing")]
    last_ping: DateTime<Utc>,
    #[serde(rename = "LastSent")]
    last_sent: DateTime<Utc>,
}

impl LiveStats {
    pub fn new(
        addr: String,
        id: [u8; 16],
        noise: bool,
        cpr: u32,
        encless: bool,
        mtu: usize,
    ) -> Arc<Self> {
        let now = SystemTime::now();
        Arc::new(Self {
            addr,
            id,
            noise,
            cpr,
            encless,
            mtu,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            payload_in: AtomicU64::new(0),
            payload_out: AtomicU64::new(0),
            frames_in: AtomicU64::new(0),
            frames_out: AtomicU64::new(0),
            unauth: AtomicU64::new(0),
            dup: AtomicU64::new(0),
            heartbeat_recv: AtomicU64::new(0),
            heartbeat_sent: AtomicU64::new(0),
            times: Mutex::new(Times {
                established: now,
                last_ping: now,
                last_sent: SystemTime::UNIX_EPOCH,
            }),
        })
    }

    pub fn add_wire_out(&self, n: usize) {
        self.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
        self.frames_out.fetch_add(1, Ordering::Relaxed);
        self.touch_sent();
    }
    pub fn add_wire_in(&self, n: usize) {
        self.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
        self.frames_in.fetch_add(1, Ordering::Relaxed);
        self.touch_ping();
    }
    pub fn add_payload_in(&self, n: usize) {
        self.payload_in.fetch_add(n as u64, Ordering::Relaxed);
    }
    pub fn add_payload_out(&self, n: usize) {
        self.payload_out.fetch_add(n as u64, Ordering::Relaxed);
    }
    pub fn add_unauth(&self) {
        self.unauth.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add_dup(&self) {
        self.dup.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add_heartbeat_recv(&self) {
        self.heartbeat_recv.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add_heartbeat_sent(&self) {
        self.heartbeat_sent.fetch_add(1, Ordering::Relaxed);
    }
    pub fn touch_ping(&self) {
        if let Ok(mut t) = self.times.lock() {
            t.last_ping = SystemTime::now();
        }
    }
    pub fn touch_sent(&self) {
        if let Ok(mut t) = self.times.lock() {
            t.last_sent = SystemTime::now();
        }
    }
    pub fn bytes_in_total(&self) -> u64 {
        self.bytes_in.load(Ordering::Relaxed)
    }
    pub fn bytes_out_total(&self) -> u64 {
        self.bytes_out.load(Ordering::Relaxed)
    }
    pub fn last_ping(&self) -> SystemTime {
        self.times
            .lock()
            .map(|t| t.last_ping)
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }
    pub fn snapshot(&self) -> PeerStats {
        let times = self.times.lock().unwrap();
        PeerStats {
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            payload_in: self.payload_in.load(Ordering::Relaxed),
            payload_out: self.payload_out.load(Ordering::Relaxed),
            frames_in: self.frames_in.load(Ordering::Relaxed),
            frames_out: self.frames_out.load(Ordering::Relaxed),
            unauth: self.unauth.load(Ordering::Relaxed),
            dup: self.dup.load(Ordering::Relaxed),
            heartbeat_recv: self.heartbeat_recv.load(Ordering::Relaxed),
            heartbeat_sent: self.heartbeat_sent.load(Ordering::Relaxed),
            addr: self.addr.clone(),
            id: STANDARD_NO_PAD.encode(self.id),
            noise: self.noise,
            cpr: self.cpr,
            encless: self.encless,
            mtu: self.mtu,
            established: DateTime::<Utc>::from(times.established),
            last_ping: DateTime::<Utc>::from(times.last_ping),
            last_sent: DateTime::<Utc>::from(times.last_sent),
        }
    }
}

#[derive(Default)]
pub struct StatsState {
    entries: Mutex<HashMap<String, Arc<LiveStats>>>,
}

impl StatsState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn insert(&self, stats: Arc<LiveStats>) {
        self.entries
            .lock()
            .unwrap()
            .insert(stats.addr.clone(), stats);
    }
    pub fn remove(&self, addr: &str) {
        self.entries.lock().unwrap().remove(addr);
    }
    pub fn snapshot(&self) -> Vec<PeerStats> {
        self.entries
            .lock()
            .unwrap()
            .values()
            .map(|s| s.snapshot())
            .collect()
    }
}

pub async fn stats_listener(listener: TcpListener, state: Arc<StatsState>) {
    loop {
        match listener.accept().await {
            Ok((conn, _)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    let _ = handle_stats(conn, state).await;
                });
            }
            Err(e) => {
                eprintln!("stats accept failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_stats(mut conn: TcpStream, state: Arc<StatsState>) -> std::io::Result<()> {
    let mut buf = [0u8; 2048];
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), conn.read(&mut buf)).await;
    let mut body = Vec::new();
    body.extend_from_slice(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n");
    serde_json::to_writer(&mut body, &state.snapshot()).map_err(std::io::Error::other)?;
    conn.write_all(&body).await?;
    conn.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_field_names_match_go() {
        let state = StatsState::new();
        let stats = LiveStats::new("1.2.3.4:5".into(), [7u8; 16], true, 10, false, 1515);
        stats.add_wire_in(100);
        state.insert(stats);
        let value = serde_json::to_value(state.snapshot()).unwrap();
        let obj = value[0].as_object().unwrap();
        for key in [
            "BytesIn",
            "BytesOut",
            "BytesPayloadIn",
            "BytesPayloadOut",
            "FramesIn",
            "FramesOut",
            "FramesUnauth",
            "FramesDup",
            "HeartbeatRecv",
            "HeartbeatSent",
            "Addr",
            "Id",
            "NoiseEnable",
            "CPR",
            "Encless",
            "MTU",
            "Established",
            "LastPing",
            "LastSent",
        ] {
            assert!(obj.contains_key(key), "missing {key}");
        }
        assert_eq!(obj["BytesIn"], 100);
    }
}
