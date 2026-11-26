//! Windows-specific GUI platform helpers.
//!
//! Everything here is compiled only for `x86_64-pc-windows-msvc`.  Unix builds
//! keep their existing XDG/Secret Service behaviour.

mod acl;
mod autostart;
mod identity;

pub use acl::{harden_dir, harden_file};
pub use autostart::{autostart_enabled, set_autostart};
pub use identity::verify_pipe_server;

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BAD_NETPATH, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_NO_DATA,
    ERROR_PIPE_BUSY, ERROR_PIPE_NOT_CONNECTED, ERROR_SEM_TIMEOUT,
};

/// Wintun refuses an interface IP MTU below the classic IPv4 minimum.
pub const MIN_INNER_MTU: usize = 576;

/// Per-user profile directory: `%LOCALAPPDATA%\RustVPN\profiles`.
///
/// Falls back to `%USERPROFILE%\AppData\Local` when `LOCALAPPDATA` is missing
/// (for example in a stripped-down service environment).  The directory is
/// hardened with an owner-only ACL when profiles are written.
pub fn profiles_dir() -> PathBuf {
    profiles_dir_from(
        std::env::var_os("LOCALAPPDATA"),
        std::env::var_os("USERPROFILE"),
    )
}

fn profiles_dir_from(local_appdata: Option<OsString>, user_profile: Option<OsString>) -> PathBuf {
    let root = local_appdata
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            user_profile
                .filter(|value| !value.is_empty())
                .map(|profile| PathBuf::from(profile).join("AppData").join("Local"))
        })
        .unwrap_or_else(std::env::temp_dir);
    root.join("RustVPN").join("profiles")
}

/// Windows UI language id (low 10 bits encode the primary language).
pub fn user_ui_language() -> u16 {
    // SAFETY: `GetUserDefaultUILanguage` takes no arguments and has no
    // preconditions.
    unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() }
}

/// Whether this process was started by the HKCU Run entry.
pub fn start_minimized() -> bool {
    std::env::args_os().skip(1).any(|arg| {
        matches!(
            arg.to_str(),
            Some("--minimized") | Some("--start-minimized")
        )
    })
}

/// Explain a named-pipe connect failure in terms a user can act on.
pub fn describe_connect_error(path: &Path, error: &io::Error) -> String {
    let endpoint = path.display();
    match error.raw_os_error().map(|code| code as u32) {
        Some(ERROR_FILE_NOT_FOUND) => format!(
            "RustVPN service is not installed or not running ({endpoint} was not found). \
             M5 installs the service; for development start `rustvpn-clientd.exe --console`."
        ),
        Some(ERROR_ACCESS_DENIED) => format!(
            "access denied by the named-pipe ACL ({endpoint}); add this Windows account to the \
             local RustVPN group or run the daemon as the same user"
        ),
        Some(ERROR_PIPE_BUSY) => {
            format!("the RustVPN daemon is busy or starting ({endpoint}); retry in a moment")
        }
        Some(ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA | ERROR_BROKEN_PIPE) => {
            format!("the RustVPN daemon closed the named pipe ({endpoint}); check the service log")
        }
        Some(ERROR_SEM_TIMEOUT) => format!(
            "timed out waiting for the RustVPN named pipe ({endpoint}); check the service state"
        ),
        Some(ERROR_BAD_NETPATH) => format!(
            "named pipe {endpoint} is not reachable; remote pipe clients are rejected on Windows"
        ),
        _ => format!("{}: {error}", endpoint),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_app_data_is_the_primary_profile_root() {
        let dir = profiles_dir_from(
            Some(r"C:\Users\tester\AppData\Local".into()),
            Some(r"C:\Users\tester".into()),
        );
        assert_eq!(
            dir,
            PathBuf::from(r"C:\Users\tester\AppData\Local\RustVPN\profiles")
        );
    }

    #[test]
    fn user_profile_is_the_fallback_profile_root() {
        let dir = profiles_dir_from(None, Some(r"C:\Users\tester".into()));
        assert_eq!(
            dir,
            PathBuf::from(r"C:\Users\tester\AppData\Local\RustVPN\profiles")
        );
    }

    #[test]
    fn empty_environment_values_are_ignored() {
        let dir = profiles_dir_from(Some(OsString::new()), Some(r"C:\Users\tester".into()));
        assert_eq!(
            dir,
            PathBuf::from(r"C:\Users\tester\AppData\Local\RustVPN\profiles")
        );
    }

    #[test]
    fn connect_errors_mention_the_service_and_acl() {
        let acl = io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32);
        let text = describe_connect_error(Path::new(r"\\.\pipe\rustvpn-clientd"), &acl);
        assert!(text.contains("RustVPN group"), "{text}");
        assert!(text.contains("access denied"), "{text}");

        let missing = io::Error::from_raw_os_error(ERROR_FILE_NOT_FOUND as i32);
        let text = describe_connect_error(Path::new(r"\\.\pipe\rustvpn-clientd"), &missing);
        assert!(text.contains("not installed or not running"), "{text}");
        assert!(text.contains("--console"), "{text}");
    }
}
