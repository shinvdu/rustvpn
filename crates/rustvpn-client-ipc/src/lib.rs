//! Local IPC between the RustVPN client GUI/TUI and `rustvpn-clientd`.
//!
//! The transport is a Unix domain socket carrying 4-byte big-endian
//! length-prefixed JSON.  The GUI only depends on this crate; it does not link
//! the tunnel or cryptography implementation.

use std::path::{Path, PathBuf};

pub mod client;
mod frame;
pub mod proto;

pub use client::{Client, EventStream};
pub use frame::{read_frame, write_frame, FrameError, MAX_FRAME_LEN};
pub use proto::*;

/// Protocol version negotiated by `Hello`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Environment override honoured by both the daemon and its clients.
pub const SOCKET_ENV: &str = "RUSTVPN_CLIENTD_SOCKET";

/// Default socket location.
///
/// The daemon prefers the system-wide path when it is running as root;
/// unprivileged runs use the per-user runtime directory.  Clients pick the
/// system path when it already exists, which keeps the GUI working without
/// extra configuration after the system service has been installed.
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
pub fn ensure_socket_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
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
    Ok(())
}
