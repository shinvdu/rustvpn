//! io_uring TAP backend (Linux).
//!
//! A dedicated thread owns the TAP file descriptor and an `io_uring`
//! instance.  One read is always kept in flight and outbound frames are
//! submitted as writes.  An eventfd is polled through the ring as well,
//! so the thread sleeps until either a TAP frame arrives or a writer
//! signals new outbound work -- an idle tunnel costs no wakeups.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::mpsc as std_mpsc;

use io_uring::types::Fd;
use io_uring::{opcode, IoUring};
use tokio::sync::mpsc;
use tun::Device;

const READ_ID: u64 = 0;
const WAKE_ID: u64 = u64::MAX;
const MAX_INFLIGHT_WRITES: usize = 128;

/// eventfd used to wake the ring thread when there is outbound data.
struct Signal(OwnedFd);

impl Signal {
    fn new() -> io::Result<Self> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    fn notify(&self) {
        let one = 1u64;
        let _ = unsafe {
            libc::write(
                self.0.as_raw_fd(),
                &one as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
    }

    fn drain(&self) {
        let mut v = 0u64;
        let _ = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                &mut v as *mut u64 as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
    }

    fn fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

pub struct UringTap {
    inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    outbound: Option<std_mpsc::Sender<Vec<u8>>>,
    signal: Signal,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl UringTap {
    pub fn start(device: Device, mtu: usize) -> io::Result<Self> {
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(256);
        let (out_tx, out_rx) = std_mpsc::channel::<Vec<u8>>();
        let signal = Signal::new()?;
        // Same eventfd object (dup shares the counter): writers signal
        // through `signal`, the ring polls the duplicate.
        let thread_signal = Signal(signal.0.try_clone()?);
        // Reserve a little headroom above the configured MTU so TAP
        // frames larger than the negotiated payload are not truncated.
        let read_len = mtu.max(64) + 64;
        let fd = device.as_raw_fd();
        // Build the ring here so a kernel/container without working
        // io_uring makes `start` fail and the caller fall back to the
        // epoll backend instead of spawning a thread that dies later.
        let ring = IoUring::new(256)?;
        let thread = std::thread::Builder::new()
            .name("rustvpn-io-uring-tap".into())
            .spawn(move || {
                uring_thread(ring, fd, device, read_len, in_tx, out_rx, thread_signal)
            })?;
        Ok(Self {
            inbound: tokio::sync::Mutex::new(in_rx),
            outbound: Some(out_tx),
            signal,
            thread: Some(thread),
        })
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rx = self.inbound.lock().await;
        let data = rx
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        if data.len() > buf.len() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        buf[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }

    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        self.outbound
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?
            .send(data.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        self.signal.notify();
        Ok(data.len())
    }
}

impl Drop for UringTap {
    fn drop(&mut self) {
        // Close the outbound channel first so the ring thread observes
        // the disconnection when it wakes, flushes its backlog, and
        // exits promptly instead of sleeping forever.
        self.outbound.take();
        self.signal.notify();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn uring_thread<T: Send + 'static>(
    mut ring: IoUring,
    fd: i32,
    _owner: T,
    read_len: usize,
    in_tx: mpsc::Sender<Vec<u8>>,
    out_rx: std_mpsc::Receiver<Vec<u8>>,
    signal: Signal,
) {
    let mut read_buf = vec![0u8; read_len];
    let mut read_pending = false;
    let mut poll_pending = false;
    let mut pending_writes: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut backlog: VecDeque<Vec<u8>> = VecDeque::new();
    let mut next_id = 1u64;
    let mut closing = false;

    loop {
        // Queue outbound writes (including anything that could not be
        // submitted on a previous iteration).
        while pending_writes.len() + backlog.len() < MAX_INFLIGHT_WRITES {
            if backlog.is_empty() {
                match out_rx.try_recv() {
                    Ok(data) => backlog.push_back(data),
                    Err(std_mpsc::TryRecvError::Empty) => break,
                    Err(std_mpsc::TryRecvError::Disconnected) => {
                        closing = true;
                        break;
                    }
                }
            }
            let data = backlog.pop_front().expect("non-empty above");
            let id = next_id;
            next_id += 1;
            let entry = opcode::Write::new(Fd(fd), data.as_ptr(), data.len() as u32)
                .build()
                .user_data(id);
            if unsafe { ring.submission().push(&entry) }.is_ok() {
                pending_writes.insert(id, data);
            } else {
                backlog.push_front(data);
                break;
            }
        }

        if closing && backlog.is_empty() && pending_writes.is_empty() {
            // Shutdown requested and everything queued has been written.
            break;
        }
        if !closing && !poll_pending {
            let entry = opcode::PollAdd::new(Fd(signal.fd()), libc::POLLIN as u32)
                .build()
                .user_data(WAKE_ID);
            if unsafe { ring.submission().push(&entry) }.is_ok() {
                poll_pending = true;
            }
        }
        if !closing && !read_pending {
            let entry = opcode::Read::new(Fd(fd), read_buf.as_mut_ptr(), read_buf.len() as u32)
                .build()
                .user_data(READ_ID);
            if unsafe { ring.submission().push(&entry) }.is_ok() {
                read_pending = true;
            }
        }

        // Nothing armed and nothing submitted: the ring would block
        // forever.  This only happens if both the TAP and the eventfd
        // failed to enqueue.
        if !read_pending && !poll_pending && pending_writes.is_empty() && backlog.is_empty() {
            break;
        }

        if let Err(e) = ring.submit_and_wait(1) {
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("io_uring submit failed: {e}");
            break;
        }

        let mut broken = false;
        {
            let mut cq = ring.completion();
            cq.sync();
            for cqe in &mut cq {
                let id = cqe.user_data();
                let result = cqe.result();
                match id {
                    READ_ID => {
                        read_pending = false;
                        if result > 0 {
                            let n = result as usize;
                            let _ = in_tx.try_send(read_buf[..n].to_vec());
                        } else if result < 0 && result != -libc::EAGAIN {
                            eprintln!("io_uring TAP read failed: {}", -result);
                            if -result == libc::EBADF || -result == libc::ENODEV {
                                broken = true;
                            }
                        }
                    }
                    WAKE_ID => {
                        poll_pending = false;
                        signal.drain();
                    }
                    _ => {
                        if pending_writes.remove(&id).is_some() && result < 0 {
                            eprintln!("io_uring TAP write failed: {}", -result);
                        }
                    }
                }
            }
        }
        if broken {
            break;
        }
    }
    eprintln!("io_uring TAP thread stopped");
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn socketpair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0i32; 2];
        let ret =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
        assert_eq!(
            ret,
            0,
            "socketpair failed: {}",
            std::io::Error::last_os_error()
        );
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn set_read_timeout(fd: i32, d: Duration) {
        let tv = libc::timeval {
            tv_sec: d.as_secs() as libc::time_t,
            tv_usec: d.subsec_micros() as libc::suseconds_t,
        };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        assert_eq!(ret, 0);
    }

    #[tokio::test]
    async fn uring_roundtrip_and_shutdown() {
        let (ours, theirs) = socketpair();
        let our_fd = ours.as_raw_fd();
        let their_fd = theirs.as_raw_fd();
        set_read_timeout(their_fd, Duration::from_secs(2));

        let (in_tx, mut in_rx) = mpsc::channel(8);
        let (out_tx, out_rx) = std_mpsc::channel::<Vec<u8>>();
        let signal = Signal::new().unwrap();
        let thread_signal = Signal(signal.0.try_clone().unwrap());

        let Ok(ring) = IoUring::new(256) else {
            eprintln!("skipping io_uring test: ring unavailable");
            return;
        };
        let thread = std::thread::spawn(move || {
            uring_thread(ring, our_fd, ours, 256, in_tx, out_rx, thread_signal)
        });

        // Kernel -> ring read.
        let frame = b"tap-frame-in";
        let n =
            unsafe { libc::write(their_fd, frame.as_ptr() as *const libc::c_void, frame.len()) };
        assert_eq!(n as usize, frame.len());
        let got = tokio::time::timeout(Duration::from_secs(2), in_rx.recv())
            .await
            .expect("inbound frame timed out")
            .expect("inbound channel closed");
        assert_eq!(&got, frame);

        // Async writer -> ring -> kernel.
        out_tx.send(b"tap-frame-out".to_vec()).unwrap();
        signal.notify();
        let mut buf = [0u8; 64];
        let n = unsafe { libc::read(their_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        assert!(n > 0, "outbound write did not arrive");
        assert_eq!(&buf[..n as usize], b"tap-frame-out");

        // Dropping the last sender must wake and stop the ring thread.
        drop(out_tx);
        signal.notify();
        let (done_tx, done_rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            let _ = thread.join();
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("io_uring thread did not stop");
    }
}
