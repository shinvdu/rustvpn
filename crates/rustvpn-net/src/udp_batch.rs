//! Batched UDP syscalls: recvmmsg/sendmmsg on Linux, single-packet
//! fallback elsewhere.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub const MAX_BATCH: usize = 64;

/// One queued datagram plus its destination.
pub type BatchItem = (Vec<u8>, SocketAddr);
/// Handle used by peers to hand datagrams to the shared batcher.
pub type UdpBatchSender = mpsc::Sender<BatchItem>;

#[cfg(target_os = "linux")]
pub async fn recv_batch(
    socket: &UdpSocket,
    bufs: &mut [Vec<u8>],
    lens: &mut [usize],
    addrs: &mut [SocketAddr],
) -> std::io::Result<usize> {
    use tokio::io::Interest;
    let count = bufs.len().min(lens.len()).min(addrs.len()).min(MAX_BATCH);
    if count == 0 {
        return Ok(0);
    }
    socket
        .async_io(Interest::READABLE, || unsafe {
            recv_sys(
                socket,
                &mut bufs[..count],
                &mut lens[..count],
                &mut addrs[..count],
            )
        })
        .await
}

#[cfg(target_os = "linux")]
unsafe fn recv_sys(
    socket: &UdpSocket,
    bufs: &mut [Vec<u8>],
    lens: &mut [usize],
    addrs: &mut [SocketAddr],
) -> std::io::Result<usize> {
    use std::mem::zeroed;
    use std::os::fd::AsRawFd;

    let count = bufs.len();
    debug_assert!(count <= MAX_BATCH);
    // Fixed-size arrays keep the hot path allocation-free.
    let mut msgvec: [libc::mmsghdr; MAX_BATCH] = zeroed();
    let mut iovecs: [libc::iovec; MAX_BATCH] = zeroed();
    let mut storages: [libc::sockaddr_storage; MAX_BATCH] = zeroed();
    // `zeroed()` on an array leaves it zeroed; reuse only the first
    // `count` entries.
    for i in 0..count {
        iovecs[i].iov_base = bufs[i].as_mut_ptr().cast();
        iovecs[i].iov_len = bufs[i].len();
        msgvec[i].msg_hdr.msg_name = (&mut storages[i]) as *mut _ as *mut libc::c_void;
        msgvec[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        msgvec[i].msg_hdr.msg_iov = &mut iovecs[i];
        msgvec[i].msg_hdr.msg_iovlen = 1;
    }
    let ret = libc::recvmmsg(
        socket.as_raw_fd(),
        msgvec.as_mut_ptr(),
        count as u32,
        0,
        std::ptr::null_mut(),
    );
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    for i in 0..ret as usize {
        // A datagram larger than its buffer is reported at full length
        // with MSG_TRUNC; clamp instead of letting the caller slice out
        // of bounds.
        let len = (msgvec[i].msg_len as usize).min(bufs[i].len());
        lens[i] = len;
        addrs[i] = sockaddr_to_socketaddr(&storages[i])
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    }
    Ok(ret as usize)
}

#[cfg(target_os = "linux")]
unsafe fn sockaddr_to_socketaddr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    match storage.ss_family as i32 {
        libc::AF_INET => {
            let sin = &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let sin6 = &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6);
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(sin6.sin6_port),
                u32::from_be(sin6.sin6_flowinfo),
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
pub async fn send_batch(
    socket: &UdpSocket,
    packets: &[Vec<u8>],
    addrs: &[SocketAddr],
) -> std::io::Result<usize> {
    use tokio::io::Interest;
    let count = packets.len().min(addrs.len()).min(MAX_BATCH);
    if count == 0 {
        return Ok(0);
    }
    socket
        .async_io(Interest::WRITABLE, || unsafe {
            send_sys(socket, &packets[..count], &addrs[..count])
        })
        .await
}

#[cfg(target_os = "linux")]
unsafe fn send_sys(
    socket: &UdpSocket,
    packets: &[Vec<u8>],
    addrs: &[SocketAddr],
) -> std::io::Result<usize> {
    use std::mem::zeroed;
    use std::os::fd::AsRawFd;

    let count = packets.len();
    debug_assert!(count <= MAX_BATCH);
    let mut msgvec: [libc::mmsghdr; MAX_BATCH] = zeroed();
    let mut iovecs: [libc::iovec; MAX_BATCH] = zeroed();
    let mut storages: [libc::sockaddr_storage; MAX_BATCH] = zeroed();
    for i in 0..count {
        fill_sockaddr(&addrs[i], &mut storages[i])
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        iovecs[i].iov_base = packets[i].as_ptr() as *mut libc::c_void;
        iovecs[i].iov_len = packets[i].len();
        msgvec[i].msg_hdr.msg_name = (&mut storages[i]) as *mut _ as *mut libc::c_void;
        msgvec[i].msg_hdr.msg_namelen = sockaddr_len(&addrs[i]);
        msgvec[i].msg_hdr.msg_iov = &mut iovecs[i];
        msgvec[i].msg_hdr.msg_iovlen = 1;
    }
    let ret = libc::sendmmsg(socket.as_raw_fd(), msgvec.as_mut_ptr(), count as u32, 0);
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ret as usize)
}

#[cfg(target_os = "linux")]
unsafe fn fill_sockaddr(addr: &SocketAddr, out: &mut libc::sockaddr_storage) -> Option<()> {
    *out = std::mem::zeroed();
    match addr {
        SocketAddr::V4(v4) => {
            let sin = &mut *(out as *mut libc::sockaddr_storage as *mut libc::sockaddr_in);
            sin.sin_family = libc::AF_INET as u16;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            Some(())
        }
        SocketAddr::V6(v6) => {
            let sin6 = &mut *(out as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6);
            sin6.sin6_family = libc::AF_INET6 as u16;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_flowinfo = v6.flowinfo().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_scope_id = v6.scope_id();
            Some(())
        }
    }
}

#[cfg(target_os = "linux")]
fn sockaddr_len(addr: &SocketAddr) -> u32 {
    match addr {
        SocketAddr::V4(_) => std::mem::size_of::<libc::sockaddr_in>() as u32,
        SocketAddr::V6(_) => std::mem::size_of::<libc::sockaddr_in6>() as u32,
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn recv_batch(
    socket: &UdpSocket,
    bufs: &mut [Vec<u8>],
    lens: &mut [usize],
    addrs: &mut [SocketAddr],
) -> std::io::Result<usize> {
    if bufs.is_empty() || lens.is_empty() || addrs.is_empty() {
        return Ok(0);
    }
    let (n, addr) = socket.recv_from(&mut bufs[0]).await?;
    lens[0] = n;
    addrs[0] = addr;
    Ok(1)
}

#[cfg(not(target_os = "linux"))]
pub async fn send_batch(
    socket: &UdpSocket,
    packets: &[Vec<u8>],
    addrs: &[SocketAddr],
) -> std::io::Result<usize> {
    let count = packets.len().min(addrs.len());
    for i in 0..count {
        socket.send_to(&packets[i], addrs[i]).await?;
    }
    Ok(count)
}

/// A single background task that coalesces per-peer datagrams into
/// sendmmsg batches.
pub fn spawn_udp_batcher(socket: Arc<UdpSocket>) -> UdpBatchSender {
    let (tx, mut rx) = mpsc::channel(MAX_BATCH * 8);
    tokio::spawn(async move {
        let mut batch: Vec<(Vec<u8>, SocketAddr)> = Vec::with_capacity(MAX_BATCH);
        loop {
            let Some(first) = rx.recv().await else { break };
            batch.push(first);
            while batch.len() < MAX_BATCH {
                match rx.try_recv() {
                    Ok(item) => batch.push(item),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
            }
            let items = std::mem::take(&mut batch);
            let (mut packets, mut addrs): (Vec<Vec<u8>>, Vec<SocketAddr>) =
                items.into_iter().unzip();
            while !packets.is_empty() {
                match send_batch(&socket, &packets, &addrs).await {
                    Ok(0) => break,
                    Ok(n) => {
                        packets.drain(..n);
                        addrs.drain(..n);
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        tokio::task::yield_now().await;
                    }
                    Err(e) => {
                        // A failure for one destination (e.g. EINVAL on
                        // one address family) must not silently drop
                        // the whole batch: retry individually, then
                        // move on.
                        eprintln!("udp send batch failed, falling back: {e}");
                        for (p, a) in packets.iter().zip(&addrs) {
                            let _ = socket.send_to(p, a).await;
                        }
                        break;
                    }
                }
            }
        }
    });
    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_batch_roundtrip() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = rx.local_addr().unwrap();

        const N: usize = 16;
        let packets: Vec<Vec<u8>> = (0..N)
            .map(|i| {
                let mut p = vec![0u8; 32];
                p[0] = i as u8;
                p[31] = (i as u8).wrapping_mul(7);
                p
            })
            .collect();
        let addrs = vec![dest; N];

        let mut sent = 0;
        while sent < N {
            let n = send_batch(&tx, &packets[sent..], &addrs[sent..])
                .await
                .unwrap();
            assert!(n > 0, "sendmmsg made no progress");
            sent += n;
        }

        let mut bufs: Vec<Vec<u8>> = (0..MAX_BATCH).map(|_| vec![0u8; 256]).collect();
        let mut lens = vec![0usize; MAX_BATCH];
        let mut from = vec![SocketAddr::from(([0, 0, 0, 0], 0)); MAX_BATCH];

        let mut got: Vec<Vec<u8>> = Vec::new();
        while got.len() < N {
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                recv_batch(&rx, &mut bufs, &mut lens, &mut from),
            )
            .await
            .expect("recv_batch timed out")
            .unwrap();
            assert!(n > 0, "recvmmsg made no progress");
            for i in 0..n {
                assert_eq!(from[i], tx.local_addr().unwrap());
                got.push(bufs[i][..lens[i]].to_vec());
            }
        }

        got.sort();
        let mut want = packets;
        want.sort();
        assert_eq!(got, want);
    }
}
