//! Unix `flock` implementation of [`super::TunnelLock`].

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use super::{candidates, now_unix, sanitize};

#[derive(Debug)]
pub struct TunnelLock {
    file: File,
    path: PathBuf,
}

impl TunnelLock {
    pub fn acquire(profile: &str, remote: &str, mode: &str) -> Result<Self> {
        let mut last_error = None;
        for path in candidates() {
            match Self::try_acquire(&path, profile, remote, mode) {
                Ok(lock) => return Ok(lock),
                Err(LockError::Permission(error)) => last_error = Some((path, error)),
                Err(LockError::Busy(message)) => bail!("{message}"),
                Err(LockError::Other(error)) => return Err(error),
            }
        }
        match last_error {
            Some((path, error)) => Err(anyhow::anyhow!(
                "open tunnel lock {}: {error}",
                path.display()
            )),
            None => bail!("no tunnel lock path available"),
        }
    }

    pub fn acquire_at(path: &Path, profile: &str, remote: &str, mode: &str) -> Result<Self> {
        match Self::try_acquire(path, profile, remote, mode) {
            Ok(lock) => Ok(lock),
            Err(LockError::Permission(error)) => Err(error.into()),
            Err(LockError::Busy(message)) => bail!("{message}"),
            Err(LockError::Other(error)) => Err(error),
        }
    }

    fn try_acquire(
        path: &Path,
        profile: &str,
        remote: &str,
        mode: &str,
    ) -> std::result::Result<Self, LockError> {
        if let Some(parent) = path.parent() {
            let existed = parent.exists();
            std::fs::create_dir_all(parent).map_err(|error| LockError::Other(error.into()))?;
            if !existed {
                let system = parent == Path::new("/run/rustvpn-client");
                let mode = if system { 0o770 } else { 0o700 };
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(mode));
                if system {
                    if let Some(gid) = group_gid("rustvpn") {
                        let _ = std::os::unix::fs::chown(parent, None, Some(gid));
                    }
                }
            }
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    LockError::Permission(error)
                } else {
                    LockError::Other(error.into())
                }
            })?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                let mut text = String::new();
                let _ = file.read_to_string(&mut text);
                let owner = text.trim();
                let message = if owner.is_empty() {
                    "another RustVPN tunnel is already active".to_string()
                } else {
                    format!("another RustVPN tunnel is already active: {owner}")
                };
                return Err(LockError::Busy(message));
            }
            return Err(LockError::Other(error.into()));
        }

        let metadata = format!(
            "mode={mode}\npid={}\nprofile={}\nremote={}\nsince_unix={}\n",
            std::process::id(),
            sanitize(profile),
            sanitize(remote),
            now_unix()
        );
        let write = (|| -> std::io::Result<()> {
            file.set_len(0)?;
            file.seek(SeekFrom::Start(0))?;
            file.write_all(metadata.as_bytes())?;
            file.flush()
        })();
        if let Err(error) = write {
            let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            return Err(LockError::Other(error.into()));
        }
        adjust_lock_permissions(path, &file);
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TunnelLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

enum LockError {
    Permission(std::io::Error),
    Busy(String),
    Other(anyhow::Error),
}

fn adjust_lock_permissions(path: &Path, _file: &File) {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        if let Some(gid) = group_gid("rustvpn") {
            let _ = std::os::unix::fs::chown(path, None, Some(gid));
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660));
            return;
        }
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    } else {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

fn group_gid(name: &str) -> Option<u32> {
    let groups = std::fs::read_to_string("/etc/group").ok()?;
    for line in groups.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(name) {
            let _password = fields.next();
            return fields.next()?.parse().ok();
        }
    }
    None
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
        assert!(error.to_string().contains("already active"));
        drop(first);
        let second = TunnelLock::acquire_at(&path, "office", "vpn:1194", "daemon").unwrap();
        drop(second);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn parent_directory_is_private() {
        let dir = path();
        let path = dir.join("nested").join("tunnel.lock");
        let lock = TunnelLock::acquire_at(&path, "p", "r", "cli").unwrap();
        let mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
        drop(lock);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_symlink_lock_file() {
        let dir = path();
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        std::fs::write(&target, b"do not truncate").unwrap();
        let link = dir.join("lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(TunnelLock::acquire_at(&link, "p", "r", "cli").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"do not truncate");
        let _ = std::fs::remove_dir_all(dir);
    }
}
