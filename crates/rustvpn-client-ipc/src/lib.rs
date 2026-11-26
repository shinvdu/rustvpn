//! Local IPC between the RustVPN client GUI/TUI and `rustvpn-clientd`.
//!
//! The transport is a Unix domain socket on Unix and a named pipe
//! (`\\.\pipe\rustvpn-clientd`) on Windows, carrying 4-byte big-endian
//! length-prefixed JSON.  The GUI only depends on this crate; it does not link
//! the tunnel or cryptography implementation.

use std::path::{Path, PathBuf};

pub mod client;
mod frame;
pub mod proto;
pub mod transport;
#[cfg(windows)]
pub mod windows;

pub use client::{Client, EventStream};
pub use frame::{read_frame, write_frame, FrameError, MAX_FRAME_LEN};
pub use proto::*;

/// Protocol version negotiated by `Hello`.
///
/// v2 adds the `ProfileSpec` tuning fields (`keepalive`/`rekey_*`), the
/// opt-in `kill_switch`/`mss_clamp` flags and the extended status document.
/// Older daemons used `deny_unknown_fields`, so a v2 GUI would otherwise get
/// an opaque deserialisation error rather than a clear version mismatch.
pub const PROTOCOL_VERSION: u32 = 2;

/// Environment override honoured by both the daemon and its clients.
pub const SOCKET_ENV: &str = "RUSTVPN_CLIENTD_SOCKET";

/// Default socket location.
///
/// The daemon prefers the system-wide path when it is running as root;
/// unprivileged runs use the per-user runtime directory.  Clients pick the
/// system path when it already exists, which keeps the GUI working without
/// extra configuration after the system service has been installed.
#[cfg(unix)]
pub fn default_socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os(SOCKET_ENV) {
        return PathBuf::from(path);
    }
    let system = PathBuf::from("/run/rustvpn-client/client.sock");
    if system.exists() {
        return system;
    }
    user_runtime_dir().join("rustvpn").join("client.sock")
}

/// On Windows the "socket path" is the named-pipe path.  A bare name in
/// [`SOCKET_ENV`] is expanded to `\\.\pipe\<name>`.
#[cfg(windows)]
pub fn default_socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os(SOCKET_ENV) {
        let path = PathBuf::from(path);
        return windows::normalize_pipe_path(&path).unwrap_or(path);
    }
    PathBuf::from(windows::DEFAULT_PIPE_NAME)
}

/// Candidate socket paths in preference order.
///
/// The GUI uses this instead of resolving once at startup: a system daemon may
/// start after the GUI, and the per-user development daemon uses XDG.
#[cfg(unix)]
pub fn candidate_socket_paths() -> Vec<PathBuf> {
    if let Some(path) = std::env::var_os(SOCKET_ENV) {
        return vec![PathBuf::from(path)];
    }
    let system = PathBuf::from("/run/rustvpn-client/client.sock");
    let user = user_runtime_dir().join("rustvpn").join("client.sock");
    if system == user {
        vec![system]
    } else {
        vec![system, user]
    }
}

/// There is only one daemon endpoint per machine on Windows.
#[cfg(windows)]
pub fn candidate_socket_paths() -> Vec<PathBuf> {
    vec![default_socket_path()]
}

#[cfg(unix)]
fn user_runtime_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
    std::env::temp_dir().join(format!("rustvpn-{user}"))
}

/// Create the socket's parent directory with conservative permissions.
///
/// Windows named pipes have no filesystem parent; this is a no-op there.
pub fn ensure_socket_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(parent)?.permissions();
            let mode = perm.mode() & 0o777;
            // Keep an existing shared runtime directory (for example
            // systemd's /run/rustvpn-client at 0750) intact; otherwise make our
            // private directory owner-only.
            if mode == 0o777 || mode == 0o755 {
                perm.set_mode(0o700);
                std::fs::set_permissions(parent, perm)?;
            }
        }
    }
    #[cfg(windows)]
    let _ = path;
    Ok(())
}
