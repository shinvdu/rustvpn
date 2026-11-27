//! Windows named-pipe helpers: path handling, DACL construction and peer
//! identity checks.
//!
//! The transport is a byte-mode named pipe.  Frames are the same 4-byte
//! big-endian length + JSON messages used on Unix.  This module contains the
//! parts that cannot be expressed with `std::path` alone:
//!
//! * normalising a user-supplied pipe name to `\\.\pipe\<name>`,
//! * building an explicit DACL instead of relying on the default descriptor
//!   of the creating process,
//! * deciding whether a connecting process may use the daemon.
//!
//! Threat model: the daemon runs as LocalSystem and can change host network
//! state.  The pipe is restricted to SYSTEM, Administrators, the daemon's own
//! account, and an explicit local group when one is configured.  INTERACTIVE
//! is deliberately never granted: a missing group is a fail-closed condition,
//! not a reason to widen access to every logged-in user.  A client PID is
//! checked against the same policy before the Hello handshake.  A same-user
//! malicious process is still in the trusted set; the pipe DACL cannot
//! distinguish it, and it can also create extra pipe instances because
//! GENERIC_WRITE implies FILE_CREATE_PIPE_INSTANCE on a pipe object.  The
//! GUI therefore also verifies the server image, publisher and token user.

use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, GetLengthSid, GetSecurityDescriptorDacl, GetTokenInformation, TokenGroups,
    TokenUser, WinBuiltinAdministratorsSid, ACL, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE,
    TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Prefix required for a Win32 named-pipe path.
pub const PIPE_PREFIX: &str = r"\\.\pipe\";

/// Default pipe used by `rustvpn-clientd`.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\rustvpn-clientd";

/// Local group preferred for pipe access when the service account is
/// LocalSystem and the group exists.  M5 creates it; until then INTERACTIVE
/// users are allowed instead.
pub const DEDICATED_GROUP: &str = "RustVPN";

/// Maximum number of pipe instances.  A server keeps one extra instance
/// listening while up to 16 clients are connected, so the limit is 17.
pub const MAX_INSTANCES: usize = 17;

const MAX_PIPE_NAME_LEN: usize = 200;

/// `SID_AND_ATTRIBUTES::Attributes` flag for a deny-only group (for example
/// the Administrators SID in a UAC-filtered token).  Deny-only SIDs must not
/// count as membership for an allow decision.
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;

/// Convert a bare pipe name or a full `\\.\pipe\...` path into the canonical
/// Win32 form.  Only the last component is allowed: `\` and `/` inside the
/// name would address a different object namespace.
pub fn normalize_pipe_path(path: &Path) -> io::Result<PathBuf> {
    let text = path.as_os_str().to_string_lossy();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    let name = if let Some(rest) = strip_pipe_prefix(text) {
        rest
    } else {
        text
    };
    if name.is_empty()
        || name.len() > MAX_PIPE_NAME_LEN
        || name.contains(['\\', '/'])
        || name.chars().any(|ch| ch == '\0')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "invalid pipe name {:?}: expected a bare name or {PIPE_PREFIX}<name>",
                path.display()
            ),
        ));
    }
    Ok(PathBuf::from(format!("{PIPE_PREFIX}{name}")))
}

fn strip_pipe_prefix(text: &str) -> Option<&str> {
    let prefix = PIPE_PREFIX.as_bytes();
    let bytes = text.as_bytes();
    if bytes.len() >= prefix.len() && bytes[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&text[prefix.len()..])
    } else {
        None
    }
}

/// Whether a local group with this name exists.
pub fn local_group_exists(name: &str) -> bool {
    group_sid_bytes(name).is_ok()
}

/// SDDL DACL used for the pipe.  `SY` is LocalSystem, `BA` is the built-in
/// Administrators group.  When a dedicated group SID string is supplied it is
/// granted client access; otherwise only the daemon's own user is added.
/// INTERACTIVE is never granted, so a missing group fails closed.
///
/// `daemon_user` is the SID of the account running the daemon.  It is added
/// explicitly so a `--console` daemon started over SSH can be reached by its
/// own user.  For a SYSTEM service the SID is `S-1-5-18` and is already
/// covered by `SY`.
pub fn pipe_sddl(group_sid: Option<&str>, daemon_user: Option<&str>) -> String {
    // SYSTEM/Administrators keep FILE_ALL_ACCESS (they may create instances
    // and manage the object).  Clients get FILE_GENERIC_READ|FILE_GENERIC_WRITE
    // (0x12019F without WRITE_DAC/DELETE).  Note that on a pipe object bit
    // 0x4 is FILE_CREATE_PIPE_INSTANCE and is part of the generic write
    // mapping, so this does not stop an allowed same-user process from
    // creating an extra instance; FIRST_PIPE_INSTANCE blocks a pre-existing
    // squatter at daemon start and the GUI verifies the server identity.
    const CLIENT_RIGHTS: &str = "0x12019F";
    let mut aces = vec!["(A;;FA;;;SY)".to_string(), "(A;;FA;;;BA)".to_string()];
    if let Some(sid) = group_sid {
        aces.push(format!("(A;;{CLIENT_RIGHTS};;;{sid})"));
    }
    if let Some(user) = daemon_user {
        let already_covered = aces.iter().any(|ace| ace.contains(&format!(";;;{user})")))
            || (user == "S-1-5-18" && aces.iter().any(|ace| ace.contains(";;;SY)")));
        if !already_covered {
            aces.push(format!("(A;;{CLIENT_RIGHTS};;;{user})"));
        }
    }
    format!("D:{}", aces.concat())
}

/// SDDL DACL for the daemon **process object**.
///
/// The GUI verifies the named-pipe server before sending a passphrase:
/// it resolves the server PID, opens the process with
/// `PROCESS_QUERY_LIMITED_INFORMATION`, reads the image path with
/// `QueryFullProcessImageNameW` and checks the embedded Authenticode signer.
/// A LocalSystem service process is owned by SYSTEM and is not openable by a
/// standard user by default, so the daemon grants exactly the query right to
/// the same audience as the pipe: the dedicated group when configured,
/// otherwise INTERACTIVE.  SYSTEM and Administrators keep full access because
/// the SCM needs to stop and restart the service.
///
/// This does **not** weaken the GUI's identity policy: it only makes the
/// read-only image query possible, and still exposes no memory, handle
/// duplication or terminate rights to ordinary users.  INTERACTIVE is never
/// granted; without a dedicated group only the daemon's own account can query.
pub fn process_sddl(group_sid: Option<&str>, daemon_user: Option<&str>) -> String {
    let query = format!("(A;;0x{PROCESS_QUERY_LIMITED_INFORMATION:X};;;");
    let mut aces = vec!["(A;;FA;;;SY)".to_string(), "(A;;FA;;;BA)".to_string()];
    if let Some(sid) = group_sid {
        aces.push(format!("{query}{sid})"));
    }
    if let Some(user) = daemon_user {
        let already_covered = aces.iter().any(|ace| ace.contains(&format!(";;;{user})")))
            || (user == "S-1-5-18" && aces.iter().any(|ace| ace.contains(";;;SY)")));
        if !already_covered {
            aces.push(format!("{query}{user})"));
        }
    }
    // `P` keeps this explicit DACL protected from inherited ACEs.
    format!("D:P{}", aces.concat())
}

/// Apply [`process_sddl`] to the current daemon process.
///
/// Called once after argument/config resolution and before the pipe starts
/// serving.  Failure is reported by the caller but is not fatal: the service
/// can still be controlled by Administrators and the GUI fails closed rather
/// than sending a passphrase to an unverified server.
pub fn apply_process_query_acl(group: Option<&str>) -> io::Result<()> {
    let group_sid = match group {
        Some(name) => Some(group_sid_string(name)?),
        None => None,
    };
    let own_user = current_user_sid_string()?;
    let sddl = process_sddl(group_sid.as_deref(), Some(&own_user));
    let (descriptor, _attributes) = security_attributes(&sddl)?;

    let mut present = 0i32;
    let mut defaulted = 0i32;
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `descriptor` is a valid absolute security descriptor that stays
    // alive for the duration of this function.
    let ok =
        unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || dacl.is_null() {
        return Err(io::Error::other("converted SDDL has no DACL"));
    }

    // SAFETY: the pseudo-handle is valid, the DACL belongs to `descriptor`, and
    // only the DACL is changed (owner/group/SACL are left untouched).
    let status = unsafe {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// A security descriptor allocated by `ConvertStringSecurityDescriptorTo...`.
pub(crate) struct SecurityDescriptor(*mut c_void);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the pointer came from `ConvertStringSecurityDescriptor...`
        // and is freed exactly once here with the matching allocator.
        unsafe {
            LocalFree(self.0 as HLOCAL);
        }
    }
}

/// Build `SECURITY_ATTRIBUTES` for a `CreateNamedPipe` call.  The descriptor
/// must stay alive until the create call returns; the caller keeps both.
pub(crate) fn security_attributes(
    sddl: &str,
) -> io::Result<(SecurityDescriptor, SECURITY_ATTRIBUTES)> {
    let wide = wide_nul(sddl);
    let mut descriptor: *mut c_void = ptr::null_mut();
    // SAFETY: `wide` is NUL terminated and `descriptor` is a valid out pointer.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    Ok((SecurityDescriptor(descriptor), attributes))
}

/// Resolve a local group name to its string SID (used inside the SDDL).
pub fn group_sid_string(name: &str) -> io::Result<String> {
    let sid = group_sid_bytes(name)?;
    sid_to_string(&sid)
}

fn group_sid_bytes(name: &str) -> io::Result<Vec<u8>> {
    let name = wide_nul(name);
    let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_len = sid.len() as u32;
    let mut domain = vec![0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut use_type = 0i32;
    // SAFETY: all buffers are valid for the lengths passed in.
    let ok = unsafe {
        windows_sys::Win32::Security::LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut use_type,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // `cbSid` is not consistently updated on success (Windows 10 leaves the
    // input capacity in place), so derive the real length from the SID header.
    // Keeping the 68-byte buffer made the byte comparison in ClientPolicy
    // reject every member of an otherwise valid local group.
    // SAFETY: `sid` contains a SID written by LookupAccountNameW.
    let actual = unsafe { GetLengthSid(sid.as_mut_ptr().cast()) } as usize;
    sid.truncate(actual);
    Ok(sid)
}

fn sid_to_string(sid: &[u8]) -> io::Result<String> {
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is a SID returned by the account lookup.
    let ok = unsafe { ConvertSidToStringSidW(sid.as_ptr() as *mut c_void, &mut text) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `text` points at a NUL-terminated wide string owned by LocalAlloc.
    let value = unsafe {
        let mut len = 0usize;
        while *text.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
    };
    // SAFETY: memory allocated by ConvertSidToStringSidW is released with LocalFree.
    unsafe {
        LocalFree(text as HLOCAL);
    }
    Ok(value)
}

/// Policy evaluated for every connecting pipe client.
#[derive(Debug)]
pub struct ClientPolicy {
    own_user: Vec<u8>,
    allowed: Vec<Vec<u8>>,
}

impl ClientPolicy {
    /// Build the policy.  `group` is an explicit local group name (already
    /// resolved by the daemon).  Without one, only the daemon's own account
    /// and Administrators are allowed; there is no INTERACTIVE fallback.
    pub fn new(group: Option<&str>) -> io::Result<Self> {
        // SAFETY: `GetCurrentProcessId` has no preconditions.
        let own_user = process_user_sid(unsafe { GetCurrentProcessId() })?;
        let mut allowed = vec![well_known_sid(WinBuiltinAdministratorsSid)?];
        if let Some(group) = group {
            allowed.push(group_sid_bytes(group)?);
        }
        Ok(Self { own_user, allowed })
    }

    /// Whether the process may use the daemon.  Denies on any query failure.
    pub fn allows(&self, pid: u32) -> bool {
        self.evaluate(pid).is_ok()
    }

    /// Explain a denied client.  Called only after [`Self::allows`] returned
    /// false, so a successful client never pays for the extra formatting.
    pub fn rejection_reason(&self, pid: u32) -> String {
        match self.evaluate(pid) {
            Ok(()) => "allowed".into(),
            Err(reason) => reason,
        }
    }

    /// Whether the peer token has an enabled Administrators group.  Used for
    /// privileged requests such as Shutdown; a UAC-filtered admin token has
    /// the SID deny-only and is correctly rejected.
    pub fn is_administrator(&self, pid: u32) -> bool {
        let Ok(token) = open_process_token(pid) else {
            return false;
        };
        let Ok(groups) = token_group_sids(&token) else {
            return false;
        };
        let Ok(admin) = well_known_sid(WinBuiltinAdministratorsSid) else {
            return false;
        };
        groups.iter().any(|group| group == &admin)
    }

    fn evaluate(&self, pid: u32) -> Result<(), String> {
        if pid == 0 {
            return Err("client PID is 0".into());
        }
        let token = open_process_token(pid)
            .map_err(|error| format!("cannot open process {pid}: {error}"))?;
        let user = token_user_sid(&token)
            .map_err(|error| format!("cannot read the user SID of process {pid}: {error}"))?;
        if user == self.own_user {
            return Ok(());
        }
        let groups = token_group_sids(&token)
            .map_err(|error| format!("cannot read the group SIDs of process {pid}: {error}"))?;
        if groups
            .iter()
            .any(|group| self.allowed.iter().any(|allowed| allowed == group))
        {
            return Ok(());
        }
        Err(format!(
            "pid {pid} user {} has none of the allowed SIDs [{}] (groups [{}])",
            sid_text(&user),
            self.allowed
                .iter()
                .map(|sid| sid_text(sid))
                .collect::<Vec<_>>()
                .join(", "),
            groups
                .iter()
                .map(|sid| sid_text(sid))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// String SID of the account running this process (used in the pipe DACL).
pub fn current_user_sid_string() -> io::Result<String> {
    // SAFETY: `GetCurrentProcessId` has no preconditions.
    let sid = process_user_sid(unsafe { GetCurrentProcessId() })?;
    sid_to_string(&sid)
}

/// String SID of the account running `pid`.  The GUI uses this together with
/// the image/publisher check before sending a passphrase.
pub fn process_user_sid_string(pid: u32) -> io::Result<String> {
    sid_to_string(&process_user_sid(pid)?)
}

/// PID of the process on the other end of a connected server pipe.
pub(crate) fn client_process_id(pipe: HANDLE) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is a valid connected named-pipe handle.
    let ok = unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

/// PID of the server process for a connected client pipe handle.
pub(crate) fn server_process_id(pipe: HANDLE) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is a valid connected named-pipe handle.
    let ok =
        unsafe { windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId(pipe, &mut pid) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

fn open_process_token(pid: u32) -> io::Result<OwnedHandle> {
    // SAFETY: plain handle-returning call; the handle is checked and owned.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `process` is a freshly opened, uniquely owned handle.
    let process = unsafe { OwnedHandle::from_raw_handle(process as RawHandle) };
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the process handle is valid and `token` is a valid out pointer.
    let ok =
        unsafe { OpenProcessToken(process.as_raw_handle() as HANDLE, TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if token.is_null() {
        return Err(io::Error::other("OpenProcessToken returned a null handle"));
    }
    // SAFETY: `token` is a freshly opened, uniquely owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(token as RawHandle) })
}

fn process_user_sid(pid: u32) -> io::Result<Vec<u8>> {
    let token = open_process_token(pid)?;
    token_user_sid(&token)
}

fn token_user_sid(token: &OwnedHandle) -> io::Result<Vec<u8>> {
    let buffer = token_information(token, TokenUser)?;
    // SAFETY: GetTokenInformation(TokenUser) filled the buffer with a
    // TOKEN_USER whose SID points inside the same allocation.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_bytes(user.User.Sid)
}

fn token_group_sids(token: &OwnedHandle) -> io::Result<Vec<Vec<u8>>> {
    let buffer = token_information(token, TokenGroups)?;
    // SAFETY: GetTokenInformation(TokenGroups) filled the buffer with a
    // TOKEN_GROUPS header followed by GroupCount SID_AND_ATTRIBUTES entries.
    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    let count = groups.GroupCount as usize;
    // SAFETY: the kernel reports `GroupCount` entries in the same allocation.
    let entries = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), count) };
    entries
        .iter()
        .filter(|entry| entry.Attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0)
        .map(|entry| sid_bytes(entry.Sid))
        .collect()
}

/// Ask for a token buffer, using an `usize`-aligned allocation so the
/// `TOKEN_*` structs can be cast safely.
fn token_information(token: &OwnedHandle, class: i32) -> io::Result<Vec<usize>> {
    let mut needed = 0u32;
    // SAFETY: the first call only asks for the required size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            class,
            ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; words];
    let mut written = 0u32;
    // SAFETY: `buffer` is at least `needed` bytes and usize-aligned.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            class,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut written,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer)
}

fn sid_text(sid: &[u8]) -> String {
    sid_to_string(sid).unwrap_or_else(|_| format!("<{} bytes>", sid.len()))
}

fn sid_bytes(sid: PSID) -> io::Result<Vec<u8>> {
    if sid.is_null() {
        return Err(io::Error::other("null SID"));
    }
    // SAFETY: the SID is valid for the duration of the token buffer.
    let len = unsafe { GetLengthSid(sid) } as usize;
    // SAFETY: `len` bytes at `sid` belong to the same allocation.
    Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>() as *const u8, len) }.to_vec())
}

fn well_known_sid(kind: i32) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = buffer.len() as u32;
    // SAFETY: the buffer is SECURITY_MAX_SID_SIZE bytes as required.
    let ok =
        unsafe { CreateWellKnownSid(kind, ptr::null_mut(), buffer.as_mut_ptr().cast(), &mut len) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(len as usize);
    Ok(buffer)
}

fn wide_nul(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_bare_and_full_pipe_names() {
        assert_eq!(
            normalize_pipe_path(Path::new("rustvpn-test")).unwrap(),
            PathBuf::from(r"\\.\pipe\rustvpn-test")
        );
        assert_eq!(
            normalize_pipe_path(Path::new(r"\\.\pipe\rustvpn-test")).unwrap(),
            PathBuf::from(r"\\.\pipe\rustvpn-test")
        );
        // The Win32 namespace is case insensitive.
        assert_eq!(
            normalize_pipe_path(Path::new(r"\\.\PIPE\rustvpn-test")).unwrap(),
            PathBuf::from(r"\\.\pipe\rustvpn-test")
        );
    }

    #[test]
    fn rejects_names_that_escape_the_pipe_namespace() {
        assert!(normalize_pipe_path(Path::new("")).is_err());
        assert!(normalize_pipe_path(Path::new(r"a\b")).is_err());
        assert!(normalize_pipe_path(Path::new("a/b")).is_err());
        assert!(normalize_pipe_path(Path::new(r"\\.\pipe\a\b")).is_err());
    }

    #[test]
    fn default_dacl_has_no_interactive_world_or_anonymous_ace() {
        let sddl = pipe_sddl(None, None);
        assert!(sddl.contains("(A;;FA;;;SY)"), "{sddl}");
        assert!(sddl.contains("(A;;FA;;;BA)"), "{sddl}");
        assert!(
            !sddl.contains(";;;IU)"),
            "INTERACTIVE must not be granted: {sddl}"
        );
        assert!(!sddl.contains("WD"), "world must not be granted: {sddl}");
        assert!(
            !sddl.contains("AN"),
            "anonymous must not be granted: {sddl}"
        );
    }

    #[test]
    fn dedicated_group_replaces_interactive_ace() {
        let sddl = pipe_sddl(Some("S-1-5-21-1-2-3-1001"), None);
        assert!(
            sddl.contains("(A;;0x12019F;;;S-1-5-21-1-2-3-1001)"),
            "{sddl}"
        );
        assert!(!sddl.contains("IU"), "{sddl}");
    }

    #[test]
    fn daemon_user_is_added_once_and_is_the_only_client_ace_without_a_group() {
        let sddl = pipe_sddl(None, Some("S-1-5-21-9-9-9-1001"));
        assert!(
            sddl.contains("(A;;0x12019F;;;S-1-5-21-9-9-9-1001)"),
            "{sddl}"
        );
        assert!(!sddl.contains(";;;IU)"), "{sddl}");
        // SYSTEM is already covered by the SY alias.
        let system = pipe_sddl(None, Some("S-1-5-18"));
        assert!(!system.contains(";;;S-1-5-18)"), "{system}");
    }

    #[test]
    fn policy_allows_the_test_process_and_rejects_pid_zero() {
        let policy = ClientPolicy::new(None).unwrap();
        assert!(policy.allows(std::process::id()));
        assert!(!policy.allows(0));
    }

    #[test]
    fn unknown_group_is_rejected_at_configuration_time() {
        assert!(ClientPolicy::new(Some("RustVPN-does-not-exist")).is_err());
    }

    #[test]
    fn process_dacl_has_no_interactive_grant_and_daemon_user_gets_query_only() {
        let sddl = process_sddl(None, Some("S-1-5-21-9-9-9-1001"));
        assert!(sddl.starts_with("D:P"), "{sddl}");
        assert!(sddl.contains("(A;;FA;;;SY)"), "{sddl}");
        assert!(sddl.contains("(A;;FA;;;BA)"), "{sddl}");
        assert!(sddl.contains("(A;;0x1000;;;S-1-5-21-9-9-9-1001)"), "{sddl}");
        assert!(!sddl.contains(";;;IU)"), "{sddl}");
        // No write/terminate-style access for ordinary users.
        assert!(!sddl.contains("0x1F"), "{sddl}");
        assert!(!sddl.contains("WD"), "{sddl}");
        assert!(!sddl.contains("AN"), "{sddl}");
    }

    #[test]
    fn process_dacl_dedicated_group_replaces_interactive() {
        let sddl = process_sddl(Some("S-1-5-21-1-2-3-1001"), None);
        assert!(sddl.contains("(A;;0x1000;;;S-1-5-21-1-2-3-1001)"), "{sddl}");
        assert!(!sddl.contains(";;;IU)"), "{sddl}");
    }

    #[test]
    fn process_dacl_adds_the_daemon_user_once() {
        let sddl = process_sddl(None, Some("S-1-5-21-9-9-9-1001"));
        assert!(
            sddl.matches(";;;S-1-5-21-9-9-9-1001)").count() == 1,
            "{sddl}"
        );
        // SYSTEM is already covered by the SY alias.
        let system = process_sddl(None, Some("S-1-5-18"));
        assert!(!system.contains(";;;S-1-5-18)"), "{system}");
    }

    #[test]
    fn looked_up_sid_bytes_match_the_sid_header_length() {
        // LookupAccountNameW does not reliably update cbSid on success
        // (Windows 10 leaves the input capacity), so group_sid_bytes must derive
        // the length from GetLengthSid.  A trailing zero tail made every byte
        // comparison in ClientPolicy fail for an otherwise valid group.
        let Some(name) = std::env::var_os("USERNAME").filter(|value| !value.is_empty()) else {
            return;
        };
        let Ok(bytes) = group_sid_bytes(&name.to_string_lossy()) else {
            return;
        };
        // SAFETY: `bytes` is a SID written by LookupAccountNameW.
        let header_len = unsafe { GetLengthSid(bytes.as_ptr() as *mut c_void) } as usize;
        assert_eq!(bytes.len(), header_len, "SID has a non-canonical length");
    }
}
