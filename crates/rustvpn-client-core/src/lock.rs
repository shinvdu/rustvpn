//! Process-wide tunnel lock shared by the CLI and `rustvpn-clientd`.
//!
//! * Unix: an `flock`-ed file.  The OS releases the lock when the file
//!   descriptor closes, including on crashes.
//! * Windows: a named kernel mutex (`Global\RustVPNTunnel`).  The OS releases
//!   the mutex when the owning thread terminates, including a process crash.
//!
//! Metadata (mode/pid/profile/remote) is advisory.  It is written for error
//! messages; the OS object is the source of truth for "is the tunnel in use".

#[cfg(unix)]
use std::path::PathBuf;

pub const LOCK_ENV: &str = "RUSTVPN_TUNNEL_LOCK";

#[cfg(unix)]
#[path = "lock/unix.rs"]
mod imp;
#[cfg(windows)]
#[path = "lock/windows.rs"]
mod imp;

pub use imp::TunnelLock;

/// Character sanitisation for the advisory metadata line.
pub(crate) fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .take(200)
        .collect()
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn candidates() -> Vec<PathBuf> {
    use std::path::Path;
    if let Some(path) = std::env::var_os(LOCK_ENV) {
        return vec![PathBuf::from(path)];
    }
    let system = Path::new("/run/rustvpn-client/tunnel.lock");
    // Once the shared runtime directory exists it is authoritative.  Falling
    // back to a per-user lock here would let the same machine run two tunnels
    // with different locks, defeating the point of the lock.
    if unsafe { libc::geteuid() } == 0 || system.parent().is_some_and(|parent| parent.exists()) {
        return vec![system.to_path_buf()];
    }
    vec![user_lock_path()]
}

#[cfg(unix)]
fn user_lock_path() -> PathBuf {
    let base = if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            PathBuf::from(dir)
        } else {
            fallback_tmp()
        }
    } else {
        fallback_tmp()
    };
    base.join("rustvpn").join("tunnel.lock")
}

#[cfg(unix)]
fn fallback_tmp() -> PathBuf {
    std::env::temp_dir().join(format!("rustvpn-{}", unsafe { libc::geteuid() }))
}
