//! Platform-independent policy for the Windows named-pipe server identity.
//!
//! The GUI must not send a passphrase to an arbitrary local process that
//! happens to own `\\.\pipe\rustvpn-clientd`.  Before `Connect` is written, the
//! Windows platform layer resolves the pipe server's image path and its
//! Authenticode signer, then this module decides whether that is the daemon we
//! expect.
//!
//! The policy is intentionally string-based and platform independent so it can
//! be unit tested on any host:
//!
//! 1. The image must be named `rustvpn-clientd.exe`.
//! 2. The image must live in the installed `RustVPN` directory (the M5 MSI
//!    location), **or**
//! 3. a valid Authenticode signature with a RustVPN publisher subject is
//!    accepted for portable/signed builds, **or**
//! 4. in debug builds only, an unsigned daemon that is a sibling of this GUI
//!    executable is accepted.  This keeps `cargo run`/`cargo tauri dev` usable
//!    before the service exists.
//!
//! Anything else is rejected.  See the residual-risk note in
//! `docs/windows-client-status.md`: a same-user process that can write to the
//! debug output directory can still satisfy the debug-only sibling rule.

#![cfg_attr(not(windows), allow(dead_code))]

/// Expected daemon file name.
pub const DAEMON_EXE_NAME: &str = "rustvpn-clientd.exe";

/// Case-insensitive substring required in the Authenticode signer subject for
/// a portable signed daemon.  M5 can tighten this to the final certificate
/// subject once the release certificate exists.
pub const PUBLISHER_HINT: &str = "rustvpn";

/// Why an image was accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// Image lives in the installed `Program Files\RustVPN` directory.
    Installed,
    /// Valid Authenticode signature whose subject names RustVPN.
    SignedPublisher,
    /// Debug-only fallback: unsigned daemon beside the GUI executable.
    DebugSibling,
}

impl Trust {
    pub fn as_str(self) -> &'static str {
        match self {
            Trust::Installed => "installed path",
            Trust::SignedPublisher => "signed RustVPN publisher",
            Trust::DebugSibling => "debug sibling binary",
        }
    }
}

/// Decide whether `image` may receive the passphrase.
///
/// `publisher` is the Authenticode signer's simple display name, or `None`
/// when the image is unsigned or its signature is invalid.  All path inputs
/// are Windows paths; they are normalised (strip `\\?\`, `/` -> `\`, ASCII
/// lowercase, strip trailing separators) before comparison so the decision is
/// testable on a non-Windows host.
pub fn check_daemon_image(
    image: &str,
    publisher: Option<&str>,
    debug_build: bool,
    gui_exe: Option<&str>,
    installed_dirs: &[String],
) -> Result<Trust, String> {
    if image.trim().is_empty() {
        return Err("named-pipe server image path is empty".into());
    }
    let normalized = normalize(image);
    if !is_absolute_windows_path(&normalized) {
        return Err(format!(
            "named-pipe server image {image:?} is not an absolute Windows path"
        ));
    }
    let name = file_name(&normalized);
    if !name.eq_ignore_ascii_case(DAEMON_EXE_NAME) {
        return Err(format!(
            "named-pipe server image {image:?} is not {DAEMON_EXE_NAME}"
        ));
    }

    let parent = parent_dir(&normalized);
    if installed_dirs
        .iter()
        .map(|dir| normalize(dir))
        .any(|dir| Some(dir.as_str()) == parent.as_deref())
    {
        return Ok(Trust::Installed);
    }

    if let Some(publisher) = publisher {
        if publisher.to_ascii_lowercase().contains(PUBLISHER_HINT) {
            return Ok(Trust::SignedPublisher);
        }
        return Err(format!(
            "named-pipe server image is signed by {publisher:?}, which is not a RustVPN publisher"
        ));
    }

    if debug_build {
        if let Some(gui) = gui_exe {
            let gui_parent = parent_dir(&normalize(gui));
            if gui_parent.is_some() && gui_parent == parent {
                return Ok(Trust::DebugSibling);
            }
        }
    }

    Err(format!(
        "named-pipe server image {image:?} is neither the installed {DAEMON_EXE_NAME} \
         nor a signed RustVPN binary (install the M5 service or use a signed daemon)"
    ))
}

fn normalize(path: &str) -> String {
    let path = path.trim();
    let path = path
        .strip_prefix(r"\\?\")
        .or_else(|| path.strip_prefix("//?/"))
        .unwrap_or(path);
    let path = path.replace('/', "\\");
    let unc = path.starts_with(r"\\");
    let joined = path
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\\");
    let joined = if unc { format!(r"\\{joined}") } else { joined };
    joined.to_ascii_lowercase()
}

fn is_absolute_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    if path.starts_with(r"\\") {
        return true;
    }
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

fn file_name(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

fn parent_dir(path: &str) -> Option<String> {
    path.rsplit_once('\\').map(|(parent, _)| parent.to_string())
}

/// Whether the pipe server's account may receive the passphrase.
///
/// The image check alone is insufficient: any standard user can execute the
/// installed daemon in console mode.  A real service must be SYSTEM (or the
/// configured service account, which this client does not yet support); a
/// console/portable daemon must run as the same user as the GUI.  The image
/// must already be trusted before a SYSTEM server is accepted.
pub fn check_daemon_user(
    server_user: &str,
    current_user: &str,
    trusted_installed: bool,
) -> Result<(), String> {
    let server_user = server_user.trim();
    let current_user = current_user.trim();
    if server_user.is_empty() || current_user.is_empty() {
        return Err("named-pipe server or GUI user SID is empty".into());
    }
    if server_user.eq_ignore_ascii_case(current_user) {
        return Ok(());
    }
    if trusted_installed && server_user.eq_ignore_ascii_case("S-1-5-18") {
        return Ok(());
    }
    Err(format!(
        "named-pipe server belongs to account {server_user}, not the current user;          refusing to send the passphrase"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed() -> Vec<String> {
        vec![r"C:\Program Files\RustVPN".into()]
    }

    #[test]
    fn accepts_the_installed_daemon_even_when_unsigned() {
        let trust = check_daemon_image(
            r"C:\Program Files\RustVPN\rustvpn-clientd.exe",
            None,
            false,
            Some(r"C:\Program Files\RustVPN\rustvpn-client-ui.exe"),
            &installed(),
        )
        .unwrap();
        assert_eq!(trust, Trust::Installed);
    }

    #[test]
    fn normalizes_extended_prefix_case_and_trailing_separator() {
        for image in [
            r"\\?\C:\Program Files\RustVPN\rustvpn-clientd.exe",
            r"c:/program files/rustvpn/RUSTVPN-CLIENTD.EXE",
            r"C:\Program Files\RustVPN\\rustvpn-clientd.exe",
        ] {
            assert_eq!(
                check_daemon_image(image, None, false, None, &installed()).unwrap(),
                Trust::Installed,
                "{image}"
            );
        }
        // The installed directory spelling itself is normalised too.
        let dirs = vec![r"c:/program files/rustvpn/".to_string()];
        assert_eq!(
            check_daemon_image(
                r"C:\Program Files\RustVPN\rustvpn-clientd.exe",
                None,
                false,
                None,
                &dirs,
            )
            .unwrap(),
            Trust::Installed
        );
    }

    #[test]
    fn accepts_a_signed_rustvpn_binary_outside_program_files() {
        let trust = check_daemon_image(
            r"D:\portable\rustvpn-clientd.exe",
            Some("RustVPN Project"),
            false,
            None,
            &installed(),
        )
        .unwrap();
        assert_eq!(trust, Trust::SignedPublisher);
    }

    #[test]
    fn rejects_a_signed_binary_from_another_publisher() {
        let error = check_daemon_image(
            r"D:\portable\rustvpn-clientd.exe",
            Some("Contoso Ltd"),
            true,
            Some(r"D:\portable\rustvpn-client-ui.exe"),
            &installed(),
        )
        .unwrap_err();
        assert!(error.contains("Contoso"), "{error}");
        assert!(error.contains("not a RustVPN publisher"), "{error}");
    }

    #[test]
    fn allows_an_unsigned_debug_sibling_only_in_debug_builds() {
        let image = r"D:\rustvpn\target\debug\rustvpn-clientd.exe";
        let gui = r"D:\rustvpn\target\debug\rustvpn-client-ui.exe";
        assert_eq!(
            check_daemon_image(image, None, true, Some(gui), &installed()).unwrap(),
            Trust::DebugSibling
        );
        let error = check_daemon_image(image, None, false, Some(gui), &installed()).unwrap_err();
        assert!(error.contains("neither the installed"), "{error}");
    }

    #[test]
    fn rejects_a_debug_sibling_in_a_different_directory() {
        let error = check_daemon_image(
            r"D:\other\rustvpn-clientd.exe",
            None,
            true,
            Some(r"D:\rustvpn\target\debug\rustvpn-client-ui.exe"),
            &installed(),
        )
        .unwrap_err();
        assert!(error.contains("neither the installed"), "{error}");
    }

    #[test]
    fn rejects_wrong_names_relative_paths_and_empty_paths() {
        for image in [
            r"C:\Program Files\RustVPN\evil.exe",
            r"C:\Program Files\RustVPN\rustvpn-clientd.exe.bak",
            r"rustvpn-clientd.exe",
            "",
        ] {
            assert!(
                check_daemon_image(image, None, true, None, &installed()).is_err(),
                "unexpectedly accepted {image:?}"
            );
        }
    }

    #[test]
    fn server_user_must_match_or_be_system_for_installed_service() {
        assert!(check_daemon_user("S-1-5-21-1", "S-1-5-21-1", false).is_ok());
        assert!(check_daemon_user("S-1-5-18", "S-1-5-21-1", true).is_ok());
        assert!(check_daemon_user("S-1-5-18", "S-1-5-21-1", false).is_err());
        assert!(check_daemon_user("S-1-5-21-2", "S-1-5-21-1", true).is_err());
    }
}
