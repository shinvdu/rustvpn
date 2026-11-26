//! Per-user run-at-login via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
//!
//! No machine-wide change and no elevation are required.  The entry starts the
//! GUI with `--minimized`, which hides the window to the tray; it never
//! connects automatically.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
    RRF_RT_REG_SZ,
};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "RustVPN";

/// Whether the HKCU Run entry exists.
pub fn autostart_enabled() -> Result<bool, String> {
    let key = wide_nul(OsStr::new(RUN_KEY));
    let value = wide_nul(OsStr::new(RUN_VALUE));
    let mut size = 0u32;
    // SAFETY: both strings are NUL terminated; with a null data buffer the
    // call only reports the value size.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut size,
        )
    };
    match status {
        ERROR_SUCCESS => Ok(size > 0),
        ERROR_FILE_NOT_FOUND => Ok(false),
        other => Err(format!(
            "read HKCU Run entry: {}",
            io::Error::from_raw_os_error(other as i32)
        )),
    }
}

/// Create or remove the HKCU Run entry.
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    if enabled {
        enable()
    } else {
        disable()
    }
}

fn enable() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let command = autostart_command(&exe);
    let key = wide_nul(OsStr::new(RUN_KEY));
    let value = wide_nul(OsStr::new(RUN_VALUE));
    let command = wide_nul(OsStr::new(&command));

    let mut handle: HKEY = ptr::null_mut();
    // SAFETY: valid NUL-terminated strings and out pointer; HKCU is writable by
    // the current user.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_QUERY_VALUE,
            ptr::null(),
            &mut handle,
            ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "open HKCU Run key: {}",
            io::Error::from_raw_os_error(status as i32)
        ));
    }
    let handle = OwnedKey(handle);
    let bytes = (command.len() * std::mem::size_of::<u16>()) as u32;
    // SAFETY: `command` is a NUL-terminated UTF-16 string; `handle` is live.
    let status = unsafe {
        RegSetValueExW(
            handle.0,
            value.as_ptr(),
            0,
            REG_SZ,
            command.as_ptr().cast::<u8>(),
            bytes,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "write HKCU Run entry: {}",
            io::Error::from_raw_os_error(status as i32)
        ));
    }
    Ok(())
}

fn disable() -> Result<(), String> {
    let key = wide_nul(OsStr::new(RUN_KEY));
    let value = wide_nul(OsStr::new(RUN_VALUE));
    let mut handle: HKEY = ptr::null_mut();
    // SAFETY: valid NUL-terminated strings and out pointer.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut handle,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    if status != ERROR_SUCCESS {
        return Err(format!(
            "open HKCU Run key: {}",
            io::Error::from_raw_os_error(status as i32)
        ));
    }
    let handle = OwnedKey(handle);
    // SAFETY: `handle` is live and `value` is NUL terminated.
    let status = unsafe { RegDeleteValueW(handle.0, value.as_ptr()) };
    match status {
        ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
        other => Err(format!(
            "delete HKCU Run entry: {}",
            io::Error::from_raw_os_error(other as i32)
        )),
    }
}

/// Command line stored in the Run value.  Kept separate for unit testing.
fn autostart_command(exe: &Path) -> String {
    format!("\"{}\" --minimized", exe.display())
}

struct OwnedKey(HKEY);

impl Drop for OwnedKey {
    fn drop(&mut self) {
        // SAFETY: the handle came from RegCreateKeyExW/RegOpenKeyExW and is
        // closed exactly once.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn wide_nul(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn autostart_command_quotes_the_exe_and_starts_minimized() {
        let command =
            autostart_command(Path::new(r"C:\Program Files\RustVPN\rustvpn-client-ui.exe"));
        assert_eq!(
            command,
            r#""C:\Program Files\RustVPN\rustvpn-client-ui.exe" --minimized"#
        );
    }

    #[test]
    fn autostart_command_accepts_paths_with_spaces() {
        let command = autostart_command(&PathBuf::from(r"D:\my apps\rustvpn ui.exe"));
        assert!(command.starts_with('"'));
        assert!(command.ends_with("\" --minimized"));
    }
}
