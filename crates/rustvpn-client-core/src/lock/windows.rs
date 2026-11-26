//! Windows named-mutex implementation of [`super::TunnelLock`].
//!
//! `CreateMutexW` ownership is thread based, and Tokio tasks can migrate
//! between worker threads across `.await` points.  Acquiring and releasing on
//! a dedicated thread keeps `ReleaseMutex` correct.  If the process crashes,
//! the OS abandons the mutex and the next process acquires it with
//! `WAIT_ABANDONED`.

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};

use anyhow::{anyhow, bail, Result};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Threading::{
    CreateMutexW, OpenMutexW, ReleaseMutex, WaitForSingleObject, MUTEX_MODIFY_STATE,
};

use super::{now_unix, sanitize, LOCK_ENV};

const GLOBAL_MUTEX: &str = r"Global\RustVPNTunnel";
const LOCAL_FALLBACK: &str = r"Local\RustVPNTunnel";

#[derive(Debug)]
pub struct TunnelLock {
    release: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
    path: PathBuf,
}

impl TunnelLock {
    pub fn acquire(profile: &str, remote: &str, mode: &str) -> Result<Self> {
        let (name, path) = match env_lock() {
            Some(lock) => lock,
            None => (GLOBAL_MUTEX.to_string(), metadata_path()),
        };
        let explicit = std::env::var_os(LOCK_ENV).is_some();
        match Self::try_acquire(&name, &path, profile, remote, mode) {
            Ok(lock) => Ok(lock),
            Err(LockError::Busy(message)) => bail!("{message}"),
            Err(LockError::NamespaceUnavailable) if !explicit => {
                // A non-elevated console run cannot create objects in the
                // Global namespace and no service owns the mutex.  Fall back
                // to the per-session namespace for development.  A running
                // service always owns the Global mutex, so it is still
                // detected before this fallback.
                match Self::try_acquire(LOCAL_FALLBACK, &path, profile, remote, mode) {
                    Ok(lock) => Ok(lock),
                    Err(LockError::Busy(message)) => bail!("{message}"),
                    Err(LockError::NamespaceUnavailable) => {
                        bail!("cannot create the RustVPN tunnel lock in any namespace")
                    }
                    Err(LockError::Permission(error)) => {
                        Err(anyhow!("open tunnel lock {}: {error}", path.display()))
                    }
                    Err(LockError::Other(error)) => Err(error),
                }
            }
            Err(LockError::NamespaceUnavailable) => {
                bail!("cannot create the configured tunnel lock {name}")
            }
            Err(LockError::Permission(error)) => {
                Err(anyhow!("open tunnel lock {}: {error}", path.display()))
            }
            Err(LockError::Other(error)) => Err(error),
        }
    }

    /// Isolated lock used by tests and future callers: the mutex name is
    /// derived from `path`, so unrelated paths do not contend.
    pub fn acquire_at(path: &Path, profile: &str, remote: &str, mode: &str) -> Result<Self> {
        let name = format!("Local\\RustVPNTunnel-{:016x}", fnv1a(path.as_os_str()));
        match Self::try_acquire(&name, path, profile, remote, mode) {
            Ok(lock) => Ok(lock),
            Err(LockError::Busy(message)) => bail!("{message}"),
            Err(LockError::NamespaceUnavailable) => {
                bail!("cannot create tunnel lock {}", path.display())
            }
            Err(LockError::Permission(error)) => Err(error.into()),
            Err(LockError::Other(error)) => Err(error),
        }
    }

    fn try_acquire(
        name: &str,
        path: &Path,
        profile: &str,
        remote: &str,
        mode: &str,
    ) -> std::result::Result<Self, LockError> {
        let (ready_tx, ready_rx) = mpsc::channel::<std::result::Result<(), LockError>>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let thread_name = name.to_string();
        let thread_metadata = path.to_path_buf();
        let thread = thread::Builder::new()
            .name("rustvpn-tunnel-lock".into())
            .spawn(
                move || match acquire_owned(&thread_name, &thread_metadata) {
                    Ok(handle) => {
                        let _ = ready_tx.send(Ok(()));
                        // Block until the owner drops the lock.  If the sender is
                        // dropped without a message, shut down as well.
                        let _ = release_rx.recv();
                        // SAFETY: this thread acquired the mutex, so it owns it and
                        // may release it.  `handle` is then dropped (CloseHandle).
                        unsafe {
                            ReleaseMutex(handle.as_raw_handle() as HANDLE);
                        }
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                    }
                },
            )
            .map_err(|error| LockError::Other(error.into()))?;

        match ready_rx.recv() {
            Ok(Ok(())) => {
                write_metadata(path, profile, remote, mode);
                Ok(Self {
                    release: Some(release_tx),
                    thread: Some(thread),
                    path: path.to_path_buf(),
                })
            }
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                let _ = thread.join();
                Err(LockError::Other(anyhow!(
                    "tunnel lock thread exited before acquiring the mutex"
                )))
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TunnelLock {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

enum LockError {
    Permission(std::io::Error),
    Busy(String),
    NamespaceUnavailable,
    Other(anyhow::Error),
}

fn acquire_owned(name: &str, metadata: &Path) -> std::result::Result<OwnedHandle, LockError> {
    let wide = wide_nul(name);
    // SAFETY: `wide` is NUL terminated.
    let handle = unsafe { CreateMutexW(ptr::null(), 0, wide.as_ptr()) };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(code) if code == ERROR_ACCESS_DENIED as i32 => open_existing(name, metadata),
            _ => Err(LockError::Other(error.into())),
        };
    }
    // SAFETY: `handle` is a unique handle returned by CreateMutexW.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
    wait_for_ownership(handle.as_raw_handle() as HANDLE, metadata)?;
    Ok(handle)
}

fn open_existing(name: &str, metadata: &Path) -> std::result::Result<OwnedHandle, LockError> {
    let wide = wide_nul(name);
    // SAFETY: `wide` is NUL terminated.
    let handle = unsafe { OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, 0, wide.as_ptr()) };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            // The name does not exist in this namespace: the caller lacks the
            // privilege to create Global objects.  A higher layer decides
            // whether a Local fallback is acceptable.
            Some(code) if code == ERROR_FILE_NOT_FOUND as i32 => {
                Err(LockError::NamespaceUnavailable)
            }
            // The object exists but its DACL denies us: fail closed.
            Some(code) if code == ERROR_ACCESS_DENIED as i32 => {
                Err(LockError::Busy(busy_message(metadata)))
            }
            _ => Err(LockError::Other(error.into())),
        };
    }
    // SAFETY: `handle` is a unique handle returned by OpenMutexW.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
    wait_for_ownership(handle.as_raw_handle() as HANDLE, metadata)?;
    Ok(handle)
}

fn wait_for_ownership(handle: HANDLE, metadata: &Path) -> std::result::Result<(), LockError> {
    // SAFETY: `handle` is a valid mutex handle.
    match unsafe { WaitForSingleObject(handle, 0) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(()),
        WAIT_TIMEOUT => Err(LockError::Busy(busy_message(metadata))),
        _ => Err(LockError::Permission(io::Error::last_os_error())),
    }
}

fn busy_message(metadata: &Path) -> String {
    let owner = std::fs::read_to_string(metadata)
        .map(|text| text.trim().to_string())
        .unwrap_or_default();
    if owner.is_empty() {
        "another RustVPN tunnel is already active".to_string()
    } else {
        format!("another RustVPN tunnel is already active: {owner}")
    }
}

fn env_lock() -> Option<(String, PathBuf)> {
    let value = std::env::var_os(LOCK_ENV)?;
    let path = PathBuf::from(&value);
    let name = if value.to_string_lossy().starts_with(r"Global\")
        || value.to_string_lossy().starts_with(r"Local\")
    {
        value.to_string_lossy().into_owned()
    } else {
        format!("Local\\RustVPNTunnel-{:016x}", fnv1a(&value))
    };
    Some((name, path))
}

fn metadata_path() -> PathBuf {
    if let Some(program_data) = std::env::var_os("ProgramData") {
        let dir = PathBuf::from(program_data).join("RustVPN");
        // The SYSTEM service can create the machine-wide directory.  A normal
        // console user cannot; fall through to a per-user path so the
        // advisory owner information is still available.
        if std::fs::create_dir_all(&dir).is_ok() {
            return dir.join("tunnel.lock");
        }
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let dir = PathBuf::from(local).join("RustVPN");
        if std::fs::create_dir_all(&dir).is_ok() {
            return dir.join("tunnel.lock");
        }
    }
    std::env::temp_dir().join("rustvpn").join("tunnel.lock")
}

fn write_metadata(path: &Path, profile: &str, remote: &str, mode: &str) {
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    let content = format!(
        "mode={mode}\npid={}\nprofile={}\nremote={}\nsince_unix={}\n",
        std::process::id(),
        sanitize(profile),
        sanitize(remote),
        now_unix()
    );
    if let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
    {
        let _ = file.write_all(content.as_bytes());
        let _ = file.flush();
    }
}

fn fnv1a(value: &OsStr) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for unit in value.encode_wide() {
        for byte in unit.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

fn wide_nul(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "rustvpn-lock-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn second_acquire_is_busy_and_release_reopens() {
        let path = path();
        let first = TunnelLock::acquire_at(&path, "office", "vpn:1194", "cli").unwrap();
        let error = TunnelLock::acquire_at(&path, "office", "vpn:1194", "daemon").unwrap_err();
        assert!(error.to_string().contains("already active"), "{error}");
        drop(first);
        let second = TunnelLock::acquire_at(&path, "office", "vpn:1194", "daemon").unwrap();
        drop(second);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn metadata_records_the_owner() {
        let path = path();
        let lock = TunnelLock::acquire_at(&path, "office", "vpn:1194", "cli").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("mode=cli"), "{text}");
        assert!(text.contains("profile=office"), "{text}");
        assert!(text.contains("remote=vpn:1194"), "{text}");
        drop(lock);
        let _ = std::fs::remove_file(path);
    }
}
