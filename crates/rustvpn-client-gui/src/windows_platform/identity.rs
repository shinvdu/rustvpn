//! Verify the named-pipe server before the GUI sends a passphrase.
//!
//! The transport exposes `Client::server_pid()`; this module resolves that
//! PID's image path with `QueryFullProcessImageNameW`, checks the Authenticode
//! signature with `WinVerifyTrust` (and extracts the signer subject), then
//! applies the platform-independent policy in [`crate::daemon_identity`].
//!
//! Only embedded Authenticode signatures are checked (which is how M5 signs
//! the daemon); catalog-only signatures are treated as unsigned.
//!
//! Residual risk: a valid signature from any CA-issued certificate whose
//! subject contains "RustVPN" is accepted even outside Program Files.  Until
//! M5 pins the release certificate this is weaker than a certificate
//! thumbprint pin; see the status document.
//!
//! M5 note: the installed daemon runs as LocalSystem.  The service process
//! must let an unprivileged GUI open it with `PROCESS_QUERY_LIMITED_INFORMATION`
//! (or provide a signed status channel); otherwise verification fails closed
//! and the standard user cannot connect.  This is deliberately not downgraded
//! to a pipe-DACL-only check.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::Cryptography::{
    CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::daemon_identity::{self, Trust};

/// A successfully verified pipe server.
#[derive(Debug)]
pub struct ProcessImage {
    pub pid: u32,
    /// Resolved image path (Windows form, as returned by the OS).
    pub image: String,
    /// Authenticode signer subject, when the image is signed and trusted.
    pub publisher: Option<String>,
    /// Owner SID of the server process (SYSTEM for the service, the user for
    /// a console daemon).
    pub user_sid: String,
    pub trust: Trust,
}

/// Verify the server process that owns the connected named pipe.
pub fn verify_pipe_server(pid: u32) -> Result<ProcessImage, String> {
    if pid == 0 {
        return Err("named-pipe server PID is zero".into());
    }
    if pid == std::process::id() {
        return Err("named-pipe server is this GUI process".into());
    }
    let image_path = process_image_path(pid)?;
    let image = image_path.to_string_lossy().into_owned();
    let publisher = match authenticode_publisher(&image_path) {
        Ok(publisher) => publisher,
        Err(error) => {
            // An unreadable signature is not proof of absence; fail closed by
            // rejecting the image unless the path itself is trusted.
            eprintln!("Authenticode check failed for {image}: {error}");
            Some("<unreadable signer>".to_string())
        }
    };
    let installed_dirs = installed_daemon_dirs();
    let gui_exe = std::env::current_exe()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let trust = daemon_identity::check_daemon_image(
        &image,
        publisher.as_deref(),
        cfg!(debug_assertions),
        gui_exe.as_deref(),
        &installed_dirs,
    )?;
    let user_sid = rustvpn_client_ipc::windows::process_owner_sid_string(pid)
        .map_err(|error| format!("read the owner SID of the pipe server: {error}"))?;
    let current_sid = rustvpn_client_ipc::windows::current_user_sid_string()
        .map_err(|error| format!("read the current user SID: {error}"))?;
    daemon_identity::check_daemon_user(&user_sid, &current_sid, trust == Trust::Installed)?;
    Ok(ProcessImage {
        pid,
        image,
        publisher,
        user_sid,
        trust,
    })
}

/// Resolve the full Win32 image path for a PID.
pub fn process_image_path(pid: u32) -> Result<PathBuf, String> {
    // SAFETY: `OpenProcess` has no pointer preconditions; the returned handle
    // is checked and owned.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(format!(
            "open server process {pid}: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: `process` is a freshly opened, uniquely owned handle.
    let process = unsafe { OwnedHandle::from_raw_handle(process as RawHandle) };
    let mut buffer = vec![0u16; 32_768];
    let mut size = buffer.len() as u32;
    // SAFETY: the handle is valid and the buffer/size pair is valid for writes.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            process.as_raw_handle() as HANDLE,
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &mut size,
        )
    };
    if ok == 0 {
        return Err(format!(
            "query image path for process {pid}: {}",
            io::Error::last_os_error()
        ));
    }
    let path = String::from_utf16_lossy(&buffer[..size as usize]);
    if path.is_empty() {
        return Err(format!("process {pid} reported an empty image path"));
    }
    Ok(PathBuf::from(path))
}

/// Directory candidates for the M5 installed daemon.
fn installed_daemon_dirs() -> Vec<String> {
    let mut dirs: Vec<String> = Vec::new();
    for variable in ["ProgramW6432", "ProgramFiles"] {
        let Some(root) = std::env::var_os(variable).filter(|value| !value.is_empty()) else {
            continue;
        };
        let text = PathBuf::from(root)
            .join("RustVPN")
            .to_string_lossy()
            .into_owned();
        if !dirs.iter().any(|dir| dir.eq_ignore_ascii_case(&text)) {
            dirs.push(text);
        }
    }
    dirs
}

/// Return the Authenticode signer subject when the image has a trusted
/// signature, or `None` when it is unsigned/untrusted.
fn authenticode_publisher(path: &Path) -> Result<Option<String>, String> {
    let wide = wide_nul(path.as_os_str());
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: ptr::null_mut(),
        pgKnownSubject: ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
        ..Default::default()
    };
    // `file` lives until the WinTrust calls below return.
    data.Anonymous.pFile = &mut file;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `action` and `data` are valid, correctly sized structures.
    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut c_void,
        )
    };
    let publisher = if status == 0 {
        // SAFETY: the state data is valid until the CLOSE action below.
        let signer = unsafe { publisher_from_state(&data) };
        Some(signer.unwrap_or_else(|| "<unknown signer>".to_string()))
    } else {
        // Unsigned, catalog-only or untrusted: not an embedded signature.
        None
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: releases the provider state allocated by the VERIFY action.
    unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut c_void,
        );
    }
    Ok(publisher)
}

/// Extract the first signer's certificate subject from an open WinTrust state.
///
/// # Safety
/// `data.hWVTStateData` must come from a successful `WTD_STATEACTION_VERIFY`
/// call that has not yet been closed.
unsafe fn publisher_from_state(data: &WINTRUST_DATA) -> Option<String> {
    let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
    if provider.is_null() {
        return None;
    }
    let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
    if signer.is_null() {
        return None;
    }
    let cert = WTHelperGetProvCertFromChain(signer, 0);
    if cert.is_null() || (*cert).pCert.is_null() {
        return None;
    }
    let cert_context = (*cert).pCert;
    let required = CertGetNameStringW(
        cert_context,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        ptr::null(),
        ptr::null_mut(),
        0,
    );
    if required <= 1 {
        return None;
    }
    let mut buffer = vec![0u16; required as usize];
    let written = CertGetNameStringW(
        cert_context,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        ptr::null(),
        buffer.as_mut_ptr(),
        required,
    );
    if written == 0 {
        return None;
    }
    let len = buffer
        .iter()
        .position(|&value| value == 0)
        .unwrap_or(written as usize);
    Some(String::from_utf16_lossy(&buffer[..len]))
}

fn wide_nul(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_the_current_process_image_path() {
        let path = process_image_path(std::process::id()).unwrap();
        assert!(path.is_absolute(), "{}", path.display());
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        assert!(name.to_ascii_lowercase().ends_with(".exe"), "{name}");
    }

    #[test]
    fn rejects_pid_zero_and_self() {
        assert!(verify_pipe_server(0).is_err());
        assert!(verify_pipe_server(std::process::id()).is_err());
    }

    #[test]
    fn authenticode_probe_does_not_panic_on_this_test_binary() {
        // The test binary is normally unsigned; the result must be a normal
        // `None` rather than an error or panic.
        let path = process_image_path(std::process::id()).unwrap();
        let publisher = authenticode_publisher(&path).unwrap();
        if let Some(name) = publisher {
            assert!(!name.is_empty(), "empty signer name");
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires an embedded-Authenticode-signed binary"]
    fn authenticode_reads_an_embedded_signature_publisher() {
        // Windows system binaries are usually catalog-signed; WinVerifyTrust's
        // file choice verifies embedded signatures, which is what our own
        // release binaries will carry.
        let candidates = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ];
        let Some(path) = candidates
            .iter()
            .map(PathBuf::from)
            .find(|path| path.exists())
        else {
            return;
        };
        let publisher = authenticode_publisher(&path).unwrap();
        let name = publisher.expect("Edge should have an embedded signature");
        assert!(!name.trim().is_empty(), "empty signer name");
        eprintln!("embedded signer: {name}");
    }
}
