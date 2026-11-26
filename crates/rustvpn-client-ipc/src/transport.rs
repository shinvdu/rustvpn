//! Platform transport for the client IPC.
//!
//! * Unix: `SOCK_STREAM` Unix domain socket (`tokio::net::UnixListener` /
//!   `UnixStream`).
//! * Windows: byte-mode named pipe `\\.\pipe\rustvpn-clientd` with an explicit
//!   DACL, `PIPE_REJECT_REMOTE_CLIENTS` and at most 16 instances.
//!
//! The framing, Hello handshake, timeouts and event subscriptions above this
//! module are platform independent.

use std::io;
use std::path::Path;

use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(unix)]
pub type DefaultStream = tokio::net::UnixStream;
#[cfg(windows)]
pub type DefaultStream = tokio::net::windows::named_pipe::NamedPipeClient;

/// Minimal bound required by [`crate::Client`] / [`crate::EventStream`].
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Options for [`Listener::bind`].  `group` is only meaningful on Windows: it
/// names a local group that is granted full access to the pipe instead of the
/// INTERACTIVE group.
#[derive(Clone, Debug, Default)]
pub struct ListenOptions {
    pub group: Option<String>,
}

// ---------------------------------------------------------------------------
// Unix
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod platform {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::ReadBuf;

    pub struct Listener {
        inner: tokio::net::UnixListener,
    }

    impl Listener {
        pub fn bind(path: &Path, _options: &ListenOptions) -> io::Result<Self> {
            let inner = tokio::net::UnixListener::bind(path)?;
            Ok(Self { inner })
        }

        pub async fn accept(&mut self) -> io::Result<Connection> {
            let (stream, _) = self.inner.accept().await?;
            Ok(Connection(stream))
        }
    }

    pub struct Connection(tokio::net::UnixStream);

    impl Connection {
        pub fn peer_cred(&self) -> io::Result<tokio::net::unix::UCred> {
            self.0.peer_cred()
        }
    }

    impl AsyncRead for Connection {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Connection {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    pub async fn connect(path: &Path) -> io::Result<DefaultStream> {
        tokio::net::UnixStream::connect(path).await
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};

    use tokio::io::ReadBuf;
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
    };
    use windows_sys::Win32::Foundation::{ERROR_PIPE_BUSY, HANDLE};

    use crate::windows;

    pub struct Listener {
        path: PathBuf,
        sddl: String,
        server: Option<NamedPipeServer>,
    }

    impl Listener {
        pub fn bind(path: &Path, options: &ListenOptions) -> io::Result<Self> {
            let path = windows::normalize_pipe_path(path)?;
            let group_sid = match options.group.as_deref() {
                Some(group) => Some(windows::group_sid_string(group)?),
                None => None,
            };
            let daemon_user = windows::current_user_sid_string()?;
            let sddl = windows::pipe_sddl(group_sid.as_deref(), Some(&daemon_user));
            let server = create_instance(&path, &sddl, true)?;
            Ok(Self {
                path,
                sddl,
                server: Some(server),
            })
        }

        pub async fn accept(&mut self) -> io::Result<Connection> {
            if self.server.is_none() {
                self.server = Some(create_instance(&self.path, &self.sddl, false)?);
            }
            let server = self
                .server
                .take()
                .expect("a listening instance is always present");
            if let Err(error) = server.connect().await {
                // A failed connect leaves the instance unusable; create a new
                // one for the next accept.
                self.server = create_instance(&self.path, &self.sddl, false).ok();
                return Err(error);
            }
            // Queue the next instance before handing this client to a task;
            // otherwise a client could briefly see "pipe not found".
            match create_instance(&self.path, &self.sddl, false) {
                Ok(next) => self.server = Some(next),
                Err(error) => {
                    self.server = None;
                    return Err(error);
                }
            }
            Ok(Connection(server))
        }
    }

    pub struct Connection(NamedPipeServer);

    impl Connection {
        pub fn peer_pid(&self) -> io::Result<u32> {
            windows::client_process_id(self.0.as_raw_handle() as HANDLE)
        }
    }

    impl AsyncRead for Connection {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Connection {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    fn create_instance(path: &Path, sddl: &str, first: bool) -> io::Result<NamedPipeServer> {
        let (_descriptor, mut attributes) = windows::security_attributes(sddl)?;
        let mut options = ServerOptions::new();
        options
            .pipe_mode(PipeMode::Byte)
            .reject_remote_clients(true)
            .max_instances(windows::MAX_INSTANCES)
            .first_pipe_instance(first);
        // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES pointing at the
        // descriptor above, which stays alive until the call returns.
        unsafe {
            options.create_with_security_attributes_raw(
                path.as_os_str(),
                &mut attributes as *mut _ as *mut c_void,
            )
        }
    }

    pub async fn connect(path: &Path) -> io::Result<NamedPipeClient> {
        let path = windows::normalize_pipe_path(path)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match ClientOptions::new().open(path.as_os_str()) {
                Ok(client) => return Ok(client),
                Err(error)
                    if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                        && Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Server PID for a connected client pipe (M4 server-signature check).
    pub fn server_pid(stream: &DefaultStream) -> io::Result<u32> {
        windows::server_process_id(stream.as_raw_handle() as HANDLE)
    }
}

pub use platform::{connect, Connection, Listener};

#[cfg(windows)]
pub use platform::server_pid as pipe_server_pid;
