//! Safety envelope for the Windows Wintun adapter.
//!
//! M3 accepts the profile's real tunnel address (the address is applied by the
//! client core network guard after the handshake).  The adapter still refuses
//! addresses that cannot safely identify a tunnel interface: unspecified,
//! loopback, link-local, multicast/broadcast, prefix `/0`, and (for prefixes
//! shorter than /31) the network/broadcast address itself.  The isolated
//! `10.88.0.0/24` subnet remains the policy for manual smoke tests only.
//!
//! Every check lives here (pure, no Windows dependency) so the adapter layer
//! and its tests share one definition.

use std::io;
use std::net::Ipv4Addr;
use std::path::{Component, Path, PathBuf};

use super::ipv4::in_same_subnet;

/// The dedicated, isolated test subnet used by the manual smoke test.
pub const TEST_SUBNET: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 0);
/// Prefix length of [`TEST_SUBNET`] for the manual smoke test.
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

/// Whether an adapter address/prefix can safely identify a tunnel interface.
///
/// M3 intentionally accepts production addresses; the profile validator and
/// the network guard enforce routing/DNS safety.  Prefix `/0` is rejected
/// because assigning it would create a host-wide on-link route.
pub fn validate_adapter_address(address: Ipv4Addr, prefix_len: u8) -> Result<(), String> {
    if prefix_len == 0 || prefix_len > 32 {
        return Err(format!(
            "prefix length /{prefix_len} cannot identify a tunnel interface (use /1../32)"
        ));
    }
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_multicast()
        || address == Ipv4Addr::BROADCAST
    {
        return Err(format!(
            "address {address} is not a usable unicast tunnel address"
        ));
    }
    if prefix_len <= 30 {
        let mask = u32::MAX << (32 - u32::from(prefix_len));
        let raw = u32::from(address);
        let network = raw & mask;
        let broadcast = network | !mask;
        if raw == network || raw == broadcast {
            return Err(format!(
                "address {address} is the /{prefix_len} network or broadcast address"
            ));
        }
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
    fn address_and_prefix_are_validated_for_a_tunnel_interface() {
        // Production tunnel addresses are accepted in M3.
        let good = Ipv4Addr::new(10, 88, 0, 2);
        for prefix in [1, 8, 16, 23, 24, 28, 31, 32] {
            assert!(validate_adapter_address(good, prefix).is_ok(), "/{prefix}");
        }
        assert!(validate_adapter_address(Ipv4Addr::new(192, 168, 1, 2), 24).is_ok());
        assert!(validate_adapter_address(Ipv4Addr::new(203, 0, 113, 2), 24).is_ok());

        // A /0 on-link route would blackhole the host; /33 is invalid.
        assert!(validate_adapter_address(good, 0).is_err());
        assert!(validate_adapter_address(good, 33).is_err());

        // Network/broadcast addresses are rejected for prefixes shorter than
        // /31; a /31 and /32 can legitimately use those last octets.
        assert!(validate_adapter_address(Ipv4Addr::new(10, 88, 0, 0), 24).is_err());
        assert!(validate_adapter_address(Ipv4Addr::new(10, 88, 0, 255), 24).is_err());
        assert!(validate_adapter_address(Ipv4Addr::new(10, 0, 0, 0), 31).is_ok());
        assert!(validate_adapter_address(Ipv4Addr::new(192, 168, 1, 255), 32).is_ok());

        // Non-unicast / unusable addresses.
        for bad in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
        ] {
            assert!(validate_adapter_address(bad, 24).is_err(), "{bad}");
        }
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
