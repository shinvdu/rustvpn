//! Address, route, DNS and firewall setup for GUI/daemon-managed profiles.
//!
//! The public [`NetworkGuard`] API is identical on every platform; the
//! implementation is split into:
//!
//! * [`linux`]: `ip`/`resolvectl`/nftables, unchanged from the Linux MVP.
//! * [`windows`]: Wintun address, PowerShell NetTCPIP routes, per-interface
//!   DNS, NRPT, an IPv6 leak block and crash-recovery state under
//!   `%ProgramData%\RustVPN`.
//!
//! Linux code must keep behaving exactly as before; Windows deliberately
//! refuses features that cannot yet be implemented fail-closed (kill switch)
//! and reports MSS clamping as not applied instead of pretending otherwise.

/// Optional firewall features applied together with the address/route setup.
///
/// Linux implements them with nftables.  Windows currently implements only the
/// IPv6 leak block (always on for full tunnels); `kill_switch` is rejected and
/// MSS clamping is reported as not applied.
#[derive(Clone, Debug, Default)]
pub struct FirewallOptions {
    /// Clamp IPv4 TCP MSS to this value on the tunnel interface.
    pub mss_v4: Option<usize>,
    /// Clamp IPv6 TCP MSS to this value on the tunnel interface.
    pub mss_v6: Option<usize>,
    /// Install the full-tunnel kill switch (requires `outer`).
    pub kill_switch: bool,
    /// Per-daemon table-name scope (see [`crate::firewall::instance_scope`]).
    pub scope: String,
}

#[derive(Clone, Debug, Default)]
pub struct NetOptions {
    pub firewall: FirewallOptions,
    /// Skip host DNS management; useful inside a network namespace/container
    /// where DNS is managed by the caller.
    pub no_host_dns: bool,
}

#[cfg(unix)]
mod linux;
#[cfg(windows)]
mod windows;
/// Platform-neutral Windows command/route/state planner.
///
/// It is compiled for Linux unit tests too, so route conflict, NRPT, IPv6 and
/// crash-recovery rules are exercised without a Windows host.
#[cfg(any(windows, test))]
pub(crate) mod winplan;

#[cfg(unix)]
pub use linux::{
    bring_link_up, cleanup_stale_firewall, cleanup_stale_ipv6_blackhole, cleanup_stale_mss,
    ConnectionCleanup, InstallFailure, NetworkGuard,
};
#[cfg(windows)]
pub use windows::{
    cleanup_owned_network, cleanup_stale_network, ConnectionCleanup, InstallFailure, NetworkGuard,
};
