//! Windows network guard.
//!
//! The heavy lifting is platform-neutral in [`super::winplan`]; this module
//! supplies the Windows-only pieces:
//!
//! * an absolute `powershell.exe` runner (never `cmd.exe`, never `PATH`);
//! * a state store under `%ProgramData%\RustVPN` with a DACL restricted to
//!   SYSTEM + Administrators;
//! * a process creation-time probe so a PID-reused state file is not treated
//!   as live;
//! * the public [`NetworkGuard`] wrapper used by `engine.rs`.
//!
//! TCP MSS clamping and a kill switch are **not** implemented on Windows.  A
//! `kill_switch` profile is rejected (the engine also rejects it before
//! reaching this module); MSS is reported as not applied.

use std::ffi::OsStr;
use std::io;
use std::net::SocketAddr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustvpn_client_ipc::ProfileSpec;
use tokio::process::Command;
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, HLOCAL,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::winplan::{
    self, CleanupReport, InstallContext, OwnerProbe, OwnerToken, PersistedState, StateStore,
    WinCommand, WinRunner,
};
use super::NetOptions;

const POWERSHELL_ENV: &str = "RUSTVPN_POWERSHELL_BIN";
const STATE_DIR_ENV: &str = "RUSTVPN_STATE_DIR";
/// Restrict the state directory/file to SYSTEM and Administrators only.
const STATE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
const POWERSHELL_TIMEOUT: Duration = Duration::from_secs(30);

/// Absolute PowerShell executable.
pub struct PowerShellRunner {
    exe: PathBuf,
}

impl PowerShellRunner {
    pub fn new() -> Result<Self> {
        if let Some(path) = std::env::var_os(POWERSHELL_ENV) {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                bail!("{POWERSHELL_ENV} must be an absolute path, got {path:?}");
            }
            return Ok(Self { exe: path });
        }
        let root = std::env::var_os("SystemRoot")
            .ok_or_else(|| anyhow!("SystemRoot is not set; cannot locate powershell.exe"))?;
        let root = PathBuf::from(root);
        if !root.is_absolute() {
            bail!("SystemRoot {root:?} is not absolute");
        }
        let exe = root
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if !exe.is_file() {
            bail!("PowerShell not found at {}", exe.display());
        }
        Ok(Self { exe })
    }
}

impl WinRunner for PowerShellRunner {
    fn run<'a>(&'a self, command: &'a WinCommand) -> winplan::RunnerFuture<'a, Result<String>> {
        Box::pin(async move {
            let script = winplan::script_for(command);
            let mut process = Command::new(&self.exe);
            process
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    &script,
                ])
                .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
                .kill_on_drop(true);
            let output = tokio::time::timeout(POWERSHELL_TIMEOUT, process.output())
                .await
                .map_err(|_| {
                    anyhow!(
                        "PowerShell command timed out after {}s",
                        POWERSHELL_TIMEOUT.as_secs()
                    )
                })?
                .with_context(|| format!("run {}", self.exe.display()))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                let detail = if stderr.trim().is_empty() {
                    stdout.trim()
                } else {
                    stderr.trim()
                };
                bail!("PowerShell command failed ({}): {detail}", output.status);
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        })
    }
}

/// Process creation time in FILETIME units, distinguishing "dead" from
/// "inaccessible".  An inaccessible process is treated as alive so cleanup is
/// conservative.
fn creation_time(pid: u32) -> Option<u64> {
    if pid == 0 {
        return Some(0);
    }
    let handle: HANDLE = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        let code = unsafe { GetLastError() };
        if code == ERROR_INVALID_PARAMETER {
            return None; // no such process
        }
        return Some(u64::MAX); // access denied / unknown: do not claim it is dead
    }
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    let ok = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(handle);
    }
    if ok == 0 {
        return Some(u64::MAX);
    }
    Some((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

pub struct WinOwnerProbe;

impl WinOwnerProbe {
    pub fn current() -> OwnerToken {
        let pid = std::process::id();
        OwnerToken {
            pid,
            started: creation_time(pid).unwrap_or(0),
        }
    }
}

impl OwnerProbe for WinOwnerProbe {
    fn is_alive(&self, owner: &OwnerToken) -> bool {
        if owner.pid == 0 {
            return false;
        }
        match creation_time(owner.pid) {
            None => false,
            Some(u64::MAX) => true,
            Some(_) if owner.started == 0 => true,
            Some(started) => started == owner.started,
        }
    }
}

// ---------------------------------------------------------------------------
// ACL-restricted state files
// ---------------------------------------------------------------------------

fn wide(path: &Path) -> Vec<u16> {
    OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn sddl_security_descriptor() -> Result<PSECURITY_DESCRIPTOR> {
    let sddl: Vec<u16> = OsStr::new(STATE_SDDL)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            windows_sys::Win32::Security::Authorization::SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || descriptor.is_null() {
        return Err(io::Error::last_os_error()).context("build the state-file security descriptor");
    }
    Ok(descriptor)
}

fn apply_restrictive_acl(path: &Path) -> Result<()> {
    let descriptor = sddl_security_descriptor()?;
    let mut present = 0;
    let mut dacl: *mut windows_sys::Win32::Security::ACL = std::ptr::null_mut();
    let mut defaulted = 0;
    let ok =
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) };
    if ok == 0 || present == 0 || dacl.is_null() {
        unsafe {
            LocalFree(descriptor as HLOCAL);
        }
        bail!("the state-file security descriptor has no DACL");
    }
    let wide_path = wide(path);
    let rc = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    unsafe {
        LocalFree(descriptor as HLOCAL);
    }
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32))
            .with_context(|| format!("set the restrictive ACL on {}", path.display()));
    }
    Ok(())
}

pub(crate) fn ensure_secure_state_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    apply_restrictive_acl(dir)
}

/// Write a state file with the restrictive DACL applied before publishing the
/// final name.  The temporary file is created by `std::fs::write` and the ACL
/// is tightened immediately; the final rename publishes only the exact bytes.
pub(crate) fn write_secure_file(path: &Path, data: &[u8]) -> io::Result<()> {
    std::fs::write(path, data)?;
    apply_restrictive_acl(path).map_err(|error| io::Error::other(format!("{error:#}")))?;
    Ok(())
}

fn default_state_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(STATE_DIR_ENV) {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            bail!("{STATE_DIR_ENV} must be an absolute path, got {path:?}");
        }
        return Ok(path);
    }
    let base = std::env::var_os("ProgramData")
        .ok_or_else(|| anyhow!("ProgramData is not set; cannot locate the state directory"))?;
    let base = PathBuf::from(base);
    if !base.is_absolute() {
        bail!("ProgramData {base:?} is not absolute");
    }
    Ok(base.join("RustVPN"))
}

pub(crate) struct SecureStateStore {
    inner: winplan::FileStateStore,
}

impl SecureStateStore {
    pub fn new() -> Result<Self> {
        let dir = default_state_dir()?;
        ensure_secure_state_dir(&dir)?;
        Ok(Self {
            inner: winplan::FileStateStore::new(dir),
        })
    }
}

impl StateStore for SecureStateStore {
    fn load(&self) -> Result<Option<PersistedState>> {
        self.inner.load()
    }
    fn save(&self, state: &PersistedState) -> Result<()> {
        self.inner.save(state)
    }
    fn clear(&self) -> Result<()> {
        self.inner.clear()
    }
    fn path(&self) -> PathBuf {
        self.inner.path()
    }
}

// ---------------------------------------------------------------------------
// Public guard
// ---------------------------------------------------------------------------

/// A failed install that may have applied some state.
///
/// Rollback is deferred: the engine stops the peer tasks and Wintun reader
/// first, then calls [`Self::rollback`], then closes the adapter, then runs
/// [`ConnectionCleanup::finish`].
pub struct InstallFailure {
    pub error: anyhow::Error,
    /// Present when the failure happened after some state was applied.
    ///
    /// Boxed: `NetworkGuard` is large, and keeping it inline made the
    /// `Result` returned by [`NetworkGuard::install`] pay for it (clippy
    /// `result_large_err`).
    pub guard: Option<Box<NetworkGuard>>,
}

impl InstallFailure {
    fn before(error: anyhow::Error) -> Self {
        Self { error, guard: None }
    }

    pub fn message(&self) -> String {
        format!("{:#}", self.error)
    }

    /// Roll back the partial state after the data plane has been stopped.
    ///
    /// Only non-route state is removed before the close.  The recorded routes,
    /// address and state file are kept for the next connect/daemon start,
    /// which removes them while no Wintun session exists.
    pub async fn rollback(self) -> ConnectionCleanup {
        match self.guard {
            Some(guard) => guard.begin_connection_teardown().await,
            None => ConnectionCleanup::none(),
        }
    }
}

/// Phase-1 cleanup result for a Windows connection.
///
/// The disconnect path removes only non-route state.  Route and address
/// cleanup and the state-file clear are deferred to the next connect (before
/// any adapter is opened) or the next daemon start, because removing the
/// anti-loop host route immediately after the Wintun close still stalls the
/// Windows network stack.  This type therefore performs **no** network
/// operation after the adapter close: `netstate.json` stays in place as the
/// pending cleanup record.
#[derive(Default)]
pub struct ConnectionCleanup {
    report: Option<winplan::CleanupReport>,
}

impl ConnectionCleanup {
    pub fn none() -> Self {
        Self::default()
    }

    pub async fn finish_after_close(self, closed: bool) {
        if let Some(report) = self.report {
            for action in &report.actions {
                eprintln!("net: {action}");
            }
            for error in &report.errors {
                eprintln!("warning: Windows pre-close cleanup incomplete: {error}");
            }
        }
        if closed {
            eprintln!(
                "net: host-route cleanup deferred to the next connect/daemon start; \
                 netstate.json kept"
            );
        } else {
            eprintln!(
                "warning: adapter was not closed; network state and netstate.json kept for \
                 the next start"
            );
        }
    }
}

pub struct NetworkGuard {
    runner: PowerShellRunner,
    state: Option<PersistedState>,
}

impl NetworkGuard {
    /// Apply address, routes, DNS/NRPT and the IPv6 block after the handshake.
    ///
    /// `outer` is the resolved server/proxy address.  `inner_mtu` is the
    /// derived interface IP MTU; it is verified against the adapter instead of
    /// being re-derived here.
    ///
    /// On failure the partial state is returned in [`InstallFailure`]; the
    /// caller must stop the data plane before rolling it back.
    pub async fn install(
        spec: &ProfileSpec,
        outer: Option<SocketAddr>,
        inner_mtu: usize,
        options: NetOptions,
    ) -> std::result::Result<Self, InstallFailure> {
        let runner = PowerShellRunner::new().map_err(InstallFailure::before)?;
        let store = SecureStateStore::new().map_err(InstallFailure::before)?;
        let probe = WinOwnerProbe;
        match winplan::install_with_partial(
            InstallContext {
                runner: &runner,
                store: &store,
                probe: &probe,
                owner: WinOwnerProbe::current(),
            },
            spec,
            outer,
            inner_mtu,
            options,
        )
        .await
        {
            Ok(state) => Ok(Self {
                runner,
                state: Some(state),
            }),
            Err(partial) => {
                let guard = partial.state.map(|state| {
                    Box::new(Self {
                        runner,
                        state: Some(*state),
                    })
                });
                Err(InstallFailure {
                    error: partial.error,
                    guard,
                })
            }
        }
    }

    /// Phase 1 of the ordered Windows teardown: remove only non-route state.
    ///
    /// The engine stops the peer tasks and the Wintun reader before calling
    /// this, then closes the adapter.
    ///
    /// * NRPT, DNS, the interface metric and the IPv6 firewall block are
    ///   removed here;
    /// * no route and no address is touched while the Wintun session is open;
    ///   the adapter close removes the Wintun address and its connected/
    ///   default/split routes;
    /// * **no** `Remove-NetRoute` is issued after the close either: the
    ///   anti-loop host route and the state file are kept for the next connect
    ///   (before opening an adapter) or the next daemon start, which run the
    ///   full cleanup with no Wintun session present.
    pub async fn begin_connection_teardown(mut self) -> ConnectionCleanup {
        let Some(state) = self.state.take() else {
            return ConnectionCleanup::none();
        };
        let report = winplan::cleanup_non_route_state_with(&self.runner, &state).await;
        ConnectionCleanup {
            report: Some(report),
        }
    }

    /// Windows MSS clamping is deferred; never claim it was applied.
    pub fn mss_applied(&self) -> bool {
        false
    }

    /// Windows kill switch is deferred and rejected at install time.
    pub fn kill_switch_applied(&self) -> bool {
        false
    }
}

/// Remove RustVPN-owned network state left by a crashed daemon.
///
/// Safe to call on every daemon start: a missing state file is a no-op, a
/// state owned by a live process is left alone, and only entries recorded in
/// the state file are removed (each is verified before deletion).
pub async fn cleanup_stale_network() -> Result<CleanupReport> {
    let runner = PowerShellRunner::new()?;
    let store = SecureStateStore::new()?;
    let probe = WinOwnerProbe;
    winplan::cleanup_stale_with(&runner, &store, &probe).await
}

/// Retry cleanup of state owned by this process (normal disconnect/stop).
///
/// Unlike [`cleanup_stale_network`], this never touches state recorded by a
/// different live owner.
pub async fn cleanup_owned_network() -> Result<CleanupReport> {
    let runner = PowerShellRunner::new()?;
    let store = SecureStateStore::new()?;
    winplan::cleanup_owned_with(&runner, &store, &WinOwnerProbe::current()).await
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NetworkGuard>();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_time_distinguishes_current_process_and_missing_pid() {
        let now = creation_time(std::process::id()).expect("current process creation time");
        assert!(now > 0 && now != u64::MAX);
        // PID 0 is never a real process for our purposes.
        assert_eq!(creation_time(0), Some(0));
        // A very unlikely but valid PID that is not running.
        assert!(
            creation_time(u32::MAX - 1).is_none() || creation_time(u32::MAX - 1) == Some(u64::MAX)
        );
    }

    #[test]
    fn owner_probe_compares_creation_time() {
        let probe = WinOwnerProbe;
        let current = WinOwnerProbe::current();
        assert!(probe.is_alive(&current));
        let mut reused = current;
        reused.started = current.started.wrapping_add(1);
        assert!(!probe.is_alive(&reused));
        assert!(!probe.is_alive(&OwnerToken { pid: 0, started: 0 }));
    }

    #[test]
    fn state_sddl_parses_and_restricts_to_system_and_administrators() {
        let descriptor = sddl_security_descriptor().unwrap();
        assert!(!descriptor.is_null());
        unsafe {
            LocalFree(descriptor as HLOCAL);
        }
        assert!(STATE_SDDL.contains(";;;SY"));
        assert!(STATE_SDDL.contains(";;;BA"));
        assert!(!STATE_SDDL.contains(";;;WD"));
        assert!(!STATE_SDDL.contains(";;;BU"));
    }

    #[test]
    fn power_shell_path_is_absolute_and_under_system32() {
        let runner = PowerShellRunner::new().expect("PowerShell on Windows");
        assert!(runner.exe.is_absolute());
        assert!(runner
            .exe
            .components()
            .any(|part| part.as_os_str() == "System32"));
    }
}
