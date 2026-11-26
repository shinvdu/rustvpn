//! Owner-only ACLs for profile files and directories.
//!
//! Windows has no `chmod`; secrets in `%LOCALAPPDATA%\RustVPN\profiles` are
//! protected with an explicit, inheritance-blocking DACL:
//!
//! * `OW` – owner rights (the current user),
//! * `SY` – LocalSystem,
//! * `BA` – built-in Administrators.
//!
//! No `Everyone`/`Users`/`Authenticated Users` ACE is present, and the DACL is
//! protected (`D:P`) so a permissive parent directory cannot re-open it.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};

const DIR_SDDL: &str = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const FILE_SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";

/// Apply the private directory ACL.
pub fn harden_dir(path: &Path) -> Result<(), String> {
    harden(path, DIR_SDDL)
}

/// Apply the private file ACL.
pub fn harden_file(path: &Path) -> Result<(), String> {
    harden(path, FILE_SDDL)
}

fn harden(path: &Path, sddl: &str) -> Result<(), String> {
    let wide_path = wide_nul(path.as_os_str());
    let wide_sddl = wide_nul(std::ffi::OsStr::new(sddl));
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the SDDL is NUL terminated and `descriptor` is a valid out
    // pointer.  The returned descriptor is owned by us.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(format!(
            "build private ACL for {}: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    let descriptor = OwnedLocal(descriptor);

    let mut present = 0i32;
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut defaulted = 0i32;
    // SAFETY: `descriptor` is a valid absolute security descriptor.
    let ok =
        unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) };
    if ok == 0 || present == 0 || dacl.is_null() {
        return Err(format!(
            "read private ACL for {}: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }

    // SAFETY: `wide_path` is NUL terminated, `dacl` points inside the live
    // descriptor, and this is a file-system object.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(format!(
            "set private ACL on {}: {}",
            path.display(),
            io::Error::from_raw_os_error(status as i32)
        ));
    }
    Ok(())
}

struct OwnedLocal(*mut c_void);

impl Drop for OwnedLocal {
    fn drop(&mut self) {
        // SAFETY: the pointer came from the matching LocalAlloc conversion and
        // is freed exactly once here.
        unsafe {
            LocalFree(self.0 as HLOCAL);
        }
    }
}

fn wide_nul(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rustvpn-acl-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    fn sddl(path: &Path) -> String {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
        };
        use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

        let wide = wide_nul(path.as_os_str());
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: valid NUL-terminated path and out pointer.
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, 0, "GetNamedSecurityInfoW failed");
        let descriptor = OwnedLocal(descriptor);
        let mut text: *mut u16 = ptr::null_mut();
        let mut len = 0u32;
        // SAFETY: descriptor is valid; text is an out pointer owned by LocalAlloc.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                &mut len,
            )
        };
        assert_ne!(ok, 0, "ConvertSecurityDescriptorToString failed");
        let value = unsafe {
            let slice = std::slice::from_raw_parts(text, len as usize);
            let end = slice.iter().position(|&ch| ch == 0).unwrap_or(slice.len());
            String::from_utf16_lossy(&slice[..end])
        };
        // SAFETY: text was allocated by LocalAlloc.
        unsafe {
            LocalFree(text as HLOCAL);
        }
        value
    }

    #[test]
    fn private_directory_acl_has_no_world_or_users_ace() {
        let dir = temp_path("dir");
        fs::create_dir_all(&dir).unwrap();
        harden_dir(&dir).unwrap();
        let text = sddl(&dir).to_ascii_uppercase();
        assert!(text.starts_with("D:P"), "{text}");
        assert!(text.contains(";;;SY)"), "{text}");
        assert!(text.contains(";;;BA)"), "{text}");
        assert!(!text.contains(";;;WD)"), "{text}");
        assert!(!text.contains(";;;AU)"), "{text}");
        assert!(!text.contains(";;;BU)"), "{text}");
        // The owner must still be able to create files in the hardened dir.
        fs::write(dir.join("child.txt"), "ok").unwrap();
        assert_eq!(fs::read_to_string(dir.join("child.txt")).unwrap(), "ok");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn private_file_acl_blocks_inherited_users() {
        let dir = temp_path("file");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("profile.yaml");
        fs::write(&file, "name: test\n").unwrap();
        harden_file(&file).unwrap();
        let text = sddl(&file).to_ascii_uppercase();
        assert!(text.starts_with("D:P"), "{text}");
        assert!(text.contains(";;;SY)"), "{text}");
        assert!(text.contains(";;;BA)"), "{text}");
        assert!(!text.contains(";;;WD)"), "{text}");
        assert!(!text.contains(";;;AU)"), "{text}");
        assert!(!text.contains(";;;BU)"), "{text}");
        // The owner still needs read/write access to the profile file.
        assert_eq!(fs::read_to_string(&file).unwrap(), "name: test\n");
        fs::write(&file, "name: test2\n").unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "name: test2\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_paths_fail_closed() {
        let missing = temp_path("missing");
        assert!(harden_file(&missing).is_err());
    }

    #[test]
    fn sddl_aliases_are_owner_system_and_administrators() {
        for sddl in [DIR_SDDL, FILE_SDDL] {
            assert!(sddl.starts_with("D:P"), "{sddl}");
            assert!(sddl.contains(";;;OW)"), "{sddl}");
            assert!(sddl.contains(";;;SY)"), "{sddl}");
            assert!(sddl.contains(";;;BA)"), "{sddl}");
            assert!(!sddl.contains(";;;WD)"), "{sddl}");
            assert!(!sddl.contains(";;;AN)"), "{sddl}");
        }
    }
}
