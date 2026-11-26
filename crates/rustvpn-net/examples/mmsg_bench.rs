//! Micro-benchmark for the batched UDP syscalls (`sendmmsg`/`recvmmsg`
//! on Linux) over loopback.
//!
//! It sends full `MAX_BATCH` batches and drains them with `recv_batch`,
//! reporting the combined per-datagram cost.  Use it to compare batching
//! against a plain `send_to`/`recv_from` loop on the same host.
//!
//! The real benchmark is Linux-only; other targets build a stub so
//! `cargo check --all-targets` works on Windows.

#![cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, unused_imports, unused_variables)
)]

use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use rustvpn_net::udp_batch::{recv_batch, send_batch, MAX_BATCH};
use tokio::net::UdpSocket;

const PAYLOAD: usize = 1024;
const BATCHES: usize = 2_000;

#[allow(clippy::too_many_arguments)]
async fn round(
    tx: &UdpSocket,
    rx: &UdpSocket,
    packets: &[Vec<u8>],
    addrs: &[SocketAddr],
    bufs: &mut [Vec<u8>],
    lens: &mut [usize],
    from: &mut [SocketAddr],
) -> std::io::Result<()> {
    let mut sent = 0;
    while sent < MAX_BATCH {
        sent += send_batch(tx, &packets[sent..], &addrs[sent..]).await?;
    }
    let mut got = 0;
    while got < MAX_BATCH {
        let n = tokio::time::timeout(
            Duration::from_secs(2),
            recv_batch(rx, &mut bufs[..], &mut lens[..], &mut from[..]),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "recv_batch timed out (loopback datagram dropped?)",
            )
        })??;
        got += n;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bump_socket_buffer(sock: &UdpSocket, name: i32) {
    let bytes: i32 = 4 * 1024 * 1024;
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            name,
            &bytes as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let rx = UdpSocket::bind("127.0.0.1:0").await?;
    let tx = UdpSocket::bind("127.0.0.1:0").await?;
    let dest = rx.local_addr()?;
    // Large buffers so a 64 KiB round cannot be dropped between the send
    // and receive halves of the measurement.
    bump_socket_buffer(&rx, libc::SO_RCVBUF);
    bump_socket_buffer(&tx, libc::SO_SNDBUF);

    let packets: Vec<Vec<u8>> = (0..MAX_BATCH).map(|_| vec![0x5a; PAYLOAD]).collect();
    let addrs = vec![dest; MAX_BATCH];
    let mut bufs: Vec<Vec<u8>> = (0..MAX_BATCH).map(|_| vec![0u8; PAYLOAD + 64]).collect();
    let mut lens = vec![0usize; MAX_BATCH];
    let mut from = vec![SocketAddr::from(([0, 0, 0, 0], 0)); MAX_BATCH];

    let warm = round(&tx, &rx, &packets, &addrs, &mut bufs, &mut lens, &mut from).await;
    warm?;

    let start = Instant::now();
    for _ in 0..BATCHES {
        round(&tx, &rx, &packets, &addrs, &mut bufs, &mut lens, &mut from).await?;
    }
    let elapsed = start.elapsed();

    let total = (BATCHES * MAX_BATCH) as f64;
    let secs = elapsed.as_secs_f64();
    println!(
        "sendmmsg+recvmmsg {:>4}-packet batches: {:8.0} ns/packet  {:>8.1} kpps  {:>7.1} MB/s",
        MAX_BATCH,
        elapsed.as_nanos() as f64 / total,
        total / secs / 1e3,
        total * PAYLOAD as f64 / secs / 1e6,
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("mmsg_bench is a Linux-only benchmark");
}
