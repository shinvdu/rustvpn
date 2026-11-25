//! Shared runtime pieces for the Rust GoVPN daemon.

use std::time::Duration;

pub mod config;
pub mod peer;
pub mod scripts;
pub mod stats;
pub mod tap;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
pub const ENV_IFACE: &str = "GOVPN_IFACE";
pub const ENV_REMOTE: &str = "GOVPN_REMOTE";
