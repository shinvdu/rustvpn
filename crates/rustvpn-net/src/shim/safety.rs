//! Safety envelope for the M1 Windows Wintun adapter.
//!
//! M1 is still a test-milestone implementation: the adapter may only be
//! created/configured inside the isolated `10.88.0.0/24` test subnet, with a
//! prefix no shorter than the subnet itself.  Production addresses, routes,
//! DNS and NRPT configuration stay disabled until the M3 review.  Every check
//! lives here (pure, no Windows dependency) so the adapter layer and its tests
//! share one definition.

use std::io;
use std::net::Ipv4Addr;
use std::path::{Component, Path, PathBuf};

use super::ipv4::in_same_subnet;

/// The dedicated, isolated test subnet. Never change this to a real
/// production subnet: assigning a short prefix creates on-link routes that can
/// blackhole traffic.
pub const TEST_SUBNET: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 0);
/// Prefix length of [`TEST_SUBNET`]. Adapter prefixes must not be shorter.
pub const TEST_SUBNET_PREFIX: u8 = 24;
/// Windows clients should refuse an interface IP MTU below the classic IPv4
/// minimum (RFC 791 requires every host to accept 576-byte datagrams).
pub const WINDOWS_MIN_IP_MTU: usize = 576;
/// Wintun ring bounds (`MIN_RING_CAPACITY`..=`MAX_RING_CAPACITY`).
pub const MIN_RING_CAPACITY: u32 = 128 * 1024;
pub const MAX_RING_CAPACITY: u32 = 64 * 1024 * 1024;
/// Longest adapter name we accept (Wintun uses a 128-char device name).
pub const MAX_ADAPTER_NAME_LEN: usize = 128;

/// Error codes Windows may return when `WintunOpenAdapter` cannot find an
/// adapter with that name.
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PATH_NOT_FOUND: i32 = 3;
const ERROR_NO_SUCH_DEVICE: i32 = 433;
const ERROR_NOT_FOUND: i32 = 1168;

/// Whether `ip` is inside the isolated test subnet.
pub fn in_test_subnet(ip: Ipv4Addr) -> bool {
    in_same_subnet(ip, TEST_SUBNET, TEST_SUBNET_PREFIX)
}

/// Whether an adapter address/prefix combination is inside the isolated test
/// policy: `10.88.0.0/24` with a prefix of /24../32.
pub fn validate_adapter_address(address: Ipv4Addr, prefix_len: u8) -> Result<(), String> {
    if !(TEST_SUBNET_PREFIX..=32).contains(&prefix_len) {
        return Err(format!(
            "prefix length /{prefix_len} is outside the isolated test policy: it must be \
             /{TEST_SUBNET_PREFIX}../32 so the on-link route cannot cover more than \
             {TEST_SUBNET}/{TEST_SUBNET_PREFIX}"
        ));
    }
    if !in_test_subnet(address) {
        return Err(format!(
            "address {address} is outside the isolated test subnet \
             {TEST_SUBNET}/{TEST_SUBNET_PREFIX}; refusing to configure the adapter"
        ));
    }
    let last = address.octets()[3];
    if address.is_unspecified() || address == Ipv4Addr::BROADCAST || last == 0 || last == 255 {
        return Err(format!(
            "address {address} is the test subnet network or broadcast address"
        ));
    }
    Ok(())
}

/// Whether a peer target is a usable on-link address inside [`TEST_SUBNET`].
pub fn validate_peer(peer: Ipv4Addr, our_address: Ipv4Addr) -> Result<(), String> {
    if !in_test_subnet(peer) {
        return Err(format!(
            "peer {peer} is outside the isolated test subnet \
             {TEST_SUBNET}/{TEST_SUBNET_PREFIX}"
        ));
    }
    if peer == our_address {
        return Err(format!(
            "peer {peer} equals the adapter address; pick another address in the test subnet"
        ));
    }
    let last = peer.octets()[3];
    if last == 0 || last == 255 || peer == Ipv4Addr::BROADCAST {
        return Err(format!(
            "peer {peer} is the test subnet network or broadcast address"
        ));
    }
    Ok(())
}

/// The Windows adapter requires a usable IP MTU (>= 576 bytes).
pub fn validate_adapter_mtu(inner_ip_mtu: usize) -> Result<(), String> {
    if inner_ip_mtu < WINDOWS_MIN_IP_MTU {
        return Err(format!(
            "inner IP MTU {inner_ip_mtu} is below the Windows minimum \
             {WINDOWS_MIN_IP_MTU}; refusing to configure the adapter (the wire MTU would \
             produce TCP MSS {} )",
            inner_ip_mtu.saturating_sub(40)
        ));
    }
    Ok(())
}

/// Restrict adapter names to characters that are safe to pass to `netsh` and
/// to the Wintun device name (no quotes, slashes or whitespace).
pub fn validate_adapter_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("adapter name must not be empty".into());
    }
    if name.len() > MAX_ADAPTER_NAME_LEN {
        return Err(format!(
            "adapter name is {} bytes; the maximum is {MAX_ADAPTER_NAME_LEN}",
            name.len()
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!(
            "adapter name {name:?} contains unsupported characters (use ASCII letters, \
             digits, '-', '_' or '.')"
        ));
    }
    Ok(())
}

/// Wintun requires a power-of-two ring between 128 KiB and 64 MiB.
pub fn validate_ring_capacity(capacity: u32) -> Result<(), String> {
    if !(MIN_RING_CAPACITY..=MAX_RING_CAPACITY).contains(&capacity) {
        return Err(format!(
            "ring capacity {capacity} is outside the Wintun range \
             {MIN_RING_CAPACITY}..={MAX_RING_CAPACITY} bytes"
        ));
    }
    if !capacity.is_power_of_two() {
        return Err(format!(
            "ring capacity {capacity} is not a power of two (Wintun requirement)"
        ));
    }
    Ok(())
}

/// Classify a `WintunOpenAdapter` failure. Only "the named adapter does not
/// exist" may fall back to creation; permission, driver and transient errors
/// must be propagated instead of silently creating a second device.
pub fn is_adapter_not_found(os_error: Option<i32>) -> bool {
    matches!(
        os_error,
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_NO_SUCH_DEVICE | ERROR_NOT_FOUND)
    )
}

/// Deterministic per-name adapter GUID. This avoids the fixed-GUID collision
/// where two different `--adapter` names could refer to the same device.
pub fn adapter_guid(name: &str) -> u128 {
    let mut low = fnv1a64(b"rustvpn-windows-shim-guid\0");
    low = fnv1a64_seeded(low, name.as_bytes());
    let mut high = fnv1a64_seeded(0x6c62_272e_07bb_0142, name.as_bytes());
    high = fnv1a64_seeded(high, b"high\0");
    (u128::from(high) << 64) | u128::from(low)
}

fn fnv1a64(data: &[u8]) -> u64 {
    fnv1a64_seeded(0xcbf2_9ce4_8422_2325, data)
}

fn fnv1a64_seeded(mut hash: u64, data: &[u8]) -> u64 {
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Resolve a tool under `<sysroot>\System32` without consulting `PATH` or the
/// current directory. `sysroot` must be absolute (normally `%SystemRoot%`).
pub fn resolve_system32_tool(sysroot: &Path, tool: &str) -> Result<PathBuf, String> {
    if !sysroot.is_absolute() {
        return Err(format!(
            "system root {:?} is not an absolute path; refusing PATH/cwd lookup",
            sysroot.display()
        ));
    }
    if tool.contains(['/', '\\']) {
        return Err(format!(
            "tool name {tool:?} must be a plain file name, not a path"
        ));
    }
    let mut components = Path::new(tool).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => {}
        _ => {
            return Err(format!(
                "tool name {tool:?} must be a plain file name, not a path"
            ))
        }
    }
    Ok(sysroot.join("System32").join(tool))
}

/// Resolve a System32 tool from `%SystemRoot%`. Used for the elevated
/// `netsh.exe` call so the executable cannot be hijacked via `PATH`/cwd.
pub fn system32_tool_from_env(tool: &str) -> Result<PathBuf, String> {
    let root = std::env::var_os("SystemRoot").ok_or_else(|| {
        "SystemRoot is not set; cannot resolve an absolute System32 path".to_string()
    })?;
    resolve_system32_tool(Path::new(&root), tool)
}

/// Classify an `io::Error` by its raw OS error code.
pub fn os_error_code(error: &io::Error) -> Option<i32> {
    error.raw_os_error()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_and_prefix_are_confined_to_the_test_subnet() {
        let good = Ipv4Addr::new(10, 88, 0, 2);
        assert!(validate_adapter_address(good, 24).is_ok());
        assert!(validate_adapter_address(good, 32).is_ok());
        assert!(validate_adapter_address(good, 28).is_ok());

        assert!(validate_adapter_address(good, 8).is_err());
        assert!(validate_adapter_address(good, 1).is_err());
        assert!(validate_adapter_address(good, 23).is_err());
        assert!(validate_adapter_address(good, 33).is_err());

        assert!(validate_adapter_address(Ipv4Addr::new(192, 168, 1, 2), 24).is_err());
        assert!(validate_adapter_address(Ipv4Addr::new(10, 89, 0, 2), 24).is_err());
        assert!(validate_adapter_address(Ipv4Addr::new(10, 88, 0, 0), 24).is_err());
        assert!(validate_adapter_address(Ipv4Addr::new(10, 88, 0, 255), 24).is_err());
    }

    #[test]
    fn peers_must_be_inside_the_test_subnet() {
        let our = Ipv4Addr::new(10, 88, 0, 2);
        assert!(validate_peer(Ipv4Addr::new(10, 88, 0, 3), our).is_ok());
        assert!(validate_peer(our, our).is_err());
        assert!(validate_peer(Ipv4Addr::new(10, 88, 0, 255), our).is_err());
        assert!(validate_peer(Ipv4Addr::new(10, 88, 0, 0), our).is_err());
        assert!(validate_peer(Ipv4Addr::new(10, 88, 1, 3), our).is_err());
        assert!(validate_peer(Ipv4Addr::new(8, 8, 8, 8), our).is_err());
    }

    #[test]
    fn small_inner_mtu_is_rejected() {
        assert!(validate_adapter_mtu(576).is_ok());
        assert!(validate_adapter_mtu(1500).is_ok());
        assert!(validate_adapter_mtu(575).is_err());
        assert!(validate_adapter_mtu(53).is_err());
        assert!(validate_adapter_mtu(0).is_err());
    }

    #[test]
    fn adapter_names_are_restricted() {
        assert!(validate_adapter_name("RustVPN-Spike").is_ok());
        assert!(validate_adapter_name("RustVPN.Spike_1").is_ok());
        assert!(validate_adapter_name("").is_err());
        assert!(validate_adapter_name("bad name").is_err());
        assert!(validate_adapter_name("bad\"name").is_err());
        assert!(validate_adapter_name("bad/name").is_err());
        assert!(validate_adapter_name(&"x".repeat(MAX_ADAPTER_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn ring_capacity_bounds_and_power_of_two() {
        assert!(validate_ring_capacity(128 * 1024).is_ok());
        assert!(validate_ring_capacity(4 * 1024 * 1024).is_ok());
        assert!(validate_ring_capacity(64 * 1024 * 1024).is_ok());
        assert!(validate_ring_capacity(128 * 1024 + 1).is_err());
        assert!(validate_ring_capacity(64 * 1024 * 1024 * 2).is_err());
        assert!(validate_ring_capacity(0).is_err());
        assert!(validate_ring_capacity(3 * 1024 * 1024).is_err());
    }

    #[test]
    fn not_found_classification_is_narrow() {
        assert!(is_adapter_not_found(Some(2)));
        assert!(is_adapter_not_found(Some(3)));
        assert!(is_adapter_not_found(Some(433)));
        assert!(is_adapter_not_found(Some(1168)));
        assert!(!is_adapter_not_found(None));
        assert!(!is_adapter_not_found(Some(5))); // access denied
        assert!(!is_adapter_not_found(Some(31))); // driver failure
        assert!(!is_adapter_not_found(Some(0)));
    }

    #[test]
    fn adapter_guids_are_deterministic_and_name_specific() {
        assert_eq!(adapter_guid("RustVPN-Spike"), adapter_guid("RustVPN-Spike"));
        assert_ne!(adapter_guid("RustVPN-Spike"), adapter_guid("RustVPN-Other"));
        assert_ne!(adapter_guid("RustVPN-Spike"), 0);
        assert_ne!(adapter_guid(""), 0);
    }

    #[test]
    fn system32_tool_resolution_is_absolute_and_under_the_root() {
        #[cfg(windows)]
        let root = Path::new(r"C:\Windows");
        #[cfg(not(windows))]
        let root = Path::new("/windows-root");
        let tool = resolve_system32_tool(root, "netsh.exe").unwrap();
        assert!(tool.is_absolute());
        assert!(tool.starts_with(root));
        assert!(tool.ends_with(Path::new("System32").join("netsh.exe")));

        assert!(resolve_system32_tool(Path::new("relative-root"), "netsh.exe").is_err());
        assert!(resolve_system32_tool(root, "../netsh.exe").is_err());
        assert!(resolve_system32_tool(root, "tools/netsh.exe").is_err());
        assert!(resolve_system32_tool(root, "tools\\netsh.exe").is_err());
        assert!(resolve_system32_tool(root, "").is_err());

        // On a real Windows host, the elevated netsh call must resolve under
        // the actual %SystemRoot%.
        #[cfg(windows)]
        {
            let real = system32_tool_from_env("netsh.exe").expect("SystemRoot is set on Windows");
            let real_root = std::env::var_os("SystemRoot").expect("SystemRoot is set on Windows");
            assert!(real.is_absolute());
            assert!(real.starts_with(Path::new(&real_root)));
            assert!(real.ends_with(Path::new("System32").join("netsh.exe")));
        }
    }

    #[test]
    fn os_error_code_is_preserved() {
        let error = io::Error::from_raw_os_error(5);
        assert_eq!(os_error_code(&error), Some(5));
    }
}
