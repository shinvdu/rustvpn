//! Platform facade for the L2/L3 tunnel interface.
//!
//! * Linux keeps the existing TAP implementation: `tun` with `Layer::L2`,
//!   io_uring when available, otherwise the epoll-based [`AsyncDevice`].
//! * Windows uses a Wintun **L3** adapter plus the Ethernet shim in
//!   [`crate::shim`], because RustVPN's wire format carries Ethernet frames.
//!
//! [`Tap::open`] keeps the historical `open(name, mtu)` signature for Linux
//! callers.  Windows callers use [`Tap::open_with_config`], which carries the
//! address/prefix, gateway/DNS hints, transport mode, verifier id and the
//! absolute `wintun.dll` path.

use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use ipnet::IpNet;
use rustvpn_proto::{Mode, MTU_MAX};

use crate::config::MIN_TAP_IP_MTU;
use crate::shim::ethernet::ETH_HEADER_LEN;

#[cfg(not(target_os = "windows"))]
use tun::{AbstractDevice, AsyncDevice, Configuration, Device, Layer};

#[cfg(target_os = "linux")]
use crate::uring_tap::UringTap;

/// Environment override for the absolute `wintun.dll` path.
pub const WINTUN_DLL_ENV: &str = "RUSTVPN_WINTUN_DLL";
/// Packaged/default `wintun.dll` location.  M1 deployments should set
/// [`WINTUN_DLL_ENV`] explicitly during development.
pub const DEFAULT_WINTUN_DLL_PATH: &str = r"C:\Program Files\RustVPN\wintun.dll";

/// Resolve the configured `wintun.dll` path (absolute; the adapter rejects
/// relative paths).
pub fn default_wintun_dll_path() -> PathBuf {
    if let Some(path) = std::env::var_os(WINTUN_DLL_ENV) {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    PathBuf::from(DEFAULT_WINTUN_DLL_PATH)
}

/// Validation errors for a platform-neutral [`TapConfig`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TapConfigError {
    EmptyName,
    NotIpv4Address(String),
    ZeroWireMtu,
    WireMtuOutOfRange { wire_mtu: usize, mode: Mode },
    InnerMtuTooSmall { inner_ip_mtu: usize },
    UnspecifiedGateway,
}

impl fmt::Display for TapConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TapConfigError::EmptyName => write!(f, "interface name must not be empty"),
            TapConfigError::NotIpv4Address(address) => {
                write!(f, "address {address} is not an IPv4 prefix")
            }
            TapConfigError::ZeroWireMtu => write!(
                f,
                "wire MTU must be a positive numeric value; 0/auto is invalid"
            ),
            TapConfigError::WireMtuOutOfRange { wire_mtu, mode } => write!(
                f,
                "wire MTU {wire_mtu} is outside the supported {} range {}..={}",
                mode_label(*mode),
                mode.min_mtu(),
                MTU_MAX
            ),
            TapConfigError::InnerMtuTooSmall { inner_ip_mtu } => write!(
                f,
                "derived inner IP MTU {inner_ip_mtu} is below the minimum {MIN_TAP_IP_MTU}"
            ),
            TapConfigError::UnspecifiedGateway => {
                write!(f, "gateway must not be 0.0.0.0")
            }
        }
    }
}

impl std::error::Error for TapConfigError {}

/// Platform-neutral tunnel-interface configuration.
///
/// The numeric `wire_mtu` is the **two-sided wire contract**: it is never
/// derived from the path and never changed.  The interface MTU is always the
/// derived inner IP MTU:
///
/// ```text
/// inner_ip_mtu = Mode::max_payload(wire_mtu) - 14
/// ```
///
/// Linux ignores the Windows-only fields.  Windows additionally enforces the
/// isolated `10.88.0.0/24` test subnet in M1.
#[derive(Clone, Debug)]
pub struct TapConfig {
    pub name: String,
    /// Numeric wire MTU shared with the server.
    pub wire_mtu: usize,
    /// Transport mode whose payload budget bounds an Ethernet frame.
    pub mode: Mode,
    /// Interface IPv4 address and prefix.
    pub address: IpNet,
    /// Optional gateway hint (not installed by M1 on Windows).
    pub gateway: Option<Ipv4Addr>,
    /// DNS hints (not installed by M1 on Windows).
    pub dns: Vec<Ipv4Addr>,
    /// Verifier id used to derive the shim's stable synthetic MAC.
    pub verifier_id: [u8; 16],
    /// Absolute `wintun.dll` path (Windows only; ignored on Linux).
    pub wintun_dll: PathBuf,
    /// Pinned DLL digest; `None` uses the built-in pin or
    /// `RUSTVPN_WINTUN_SHA256`.
    pub wintun_sha256: Option<[u8; 32]>,
}

impl TapConfig {
    pub fn new(name: impl Into<String>, wire_mtu: usize, mode: Mode, address: IpNet) -> Self {
        Self {
            name: name.into(),
            wire_mtu,
            mode,
            address,
            gateway: None,
            dns: Vec::new(),
            verifier_id: [0u8; 16],
            wintun_dll: default_wintun_dll_path(),
            wintun_sha256: None,
        }
    }

    pub fn with_gateway(mut self, gateway: Option<Ipv4Addr>) -> Self {
        self.gateway = gateway;
        self
    }

    pub fn with_dns(mut self, dns: Vec<Ipv4Addr>) -> Self {
        self.dns = dns;
        self
    }

    pub fn with_verifier_id(mut self, verifier_id: [u8; 16]) -> Self {
        self.verifier_id = verifier_id;
        self
    }

    pub fn with_wintun_dll(mut self, path: impl Into<PathBuf>) -> Self {
        self.wintun_dll = path.into();
        self
    }

    pub fn with_wintun_sha256(mut self, sha256: Option<[u8; 32]>) -> Self {
        self.wintun_sha256 = sha256;
        self
    }

    /// The IPv4 address of [`Self::address`], if it is an IPv4 prefix.
    pub fn ipv4_address(&self) -> Result<Ipv4Addr, TapConfigError> {
        match self.address {
            IpNet::V4(net) => Ok(net.addr()),
            IpNet::V6(_) => Err(TapConfigError::NotIpv4Address(self.address.to_string())),
        }
    }

    pub fn prefix_len(&self) -> u8 {
        self.address.prefix_len()
    }

    /// Derived interface IP MTU.  This is always `max_payload(wire_mtu) - 14`
    /// and never the wire/frame budget itself.
    pub fn inner_ip_mtu(&self) -> Result<usize, TapConfigError> {
        if self.wire_mtu == 0 {
            return Err(TapConfigError::ZeroWireMtu);
        }
        if self.wire_mtu < self.mode.min_mtu() || self.wire_mtu > MTU_MAX {
            return Err(TapConfigError::WireMtuOutOfRange {
                wire_mtu: self.wire_mtu,
                mode: self.mode,
            });
        }
        let inner = self
            .mode
            .max_payload(self.wire_mtu)
            .saturating_sub(ETH_HEADER_LEN);
        if inner < MIN_TAP_IP_MTU {
            return Err(TapConfigError::InnerMtuTooSmall {
                inner_ip_mtu: inner,
            });
        }
        Ok(inner)
    }

    pub fn validate(&self) -> Result<(), TapConfigError> {
        if self.name.trim().is_empty() {
            return Err(TapConfigError::EmptyName);
        }
        self.inner_ip_mtu()?;
        self.ipv4_address()?;
        if self.gateway == Some(Ipv4Addr::UNSPECIFIED) {
            return Err(TapConfigError::UnspecifiedGateway);
        }
        Ok(())
    }
}

fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::Plain => "plain",
        Mode::Noise => "noise",
        Mode::Encless => "encless",
    }
}

enum TapBackend {
    #[cfg(not(target_os = "windows"))]
    Async(AsyncDevice),
    #[cfg(target_os = "linux")]
    Uring(UringTap),
    #[cfg(target_os = "windows")]
    Wintun(crate::shim::windows::WindowsTap),
}

#[derive(Clone)]
pub struct Tap {
    inner: Arc<TapBackend>,
    name: String,
}

impl Tap {
    /// Historical Linux constructor: create an L2 TAP device named `name`.
    ///
    /// Windows has no L2 TAP backend; it must use [`Tap::open_with_config`]
    /// so the address, mode and Wintun DLL are explicit.
    pub fn open(name: &str, mtu: usize) -> io::Result<Self> {
        #[cfg(target_os = "windows")]
        {
            let _ = (name, mtu);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows TAP is an L3 Wintun adapter and requires \
                 Tap::open_with_config(address, mode, verifier id, wintun.dll); \
                 Tap::open(name, mtu) is Linux-only",
            ))
        }
        #[cfg(not(target_os = "windows"))]
        {
            let mut cfg = Configuration::default();
            cfg.tun_name(name).layer(Layer::L2).platform_config(|p| {
                p.ensure_root_privileges(false);
            });
            let dev = Device::new(&cfg)?;
            let actual_name = dev.tun_name().unwrap_or_else(|_| name.to_string());
            let use_uring = std::env::var("GOVPN_IO_URING").as_deref() != Ok("0");
            #[cfg(target_os = "linux")]
            {
                if use_uring && supports_uring() {
                    eprintln!("TAP {}: using io_uring", actual_name);
                    let uring = UringTap::start(dev, mtu)?;
                    return Ok(Self {
                        inner: Arc::new(TapBackend::Uring(uring)),
                        name: actual_name,
                    });
                }
            }
            let _ = use_uring;
            let dev = AsyncDevice::new(dev)?;
            Ok(Self {
                inner: Arc::new(TapBackend::Async(dev)),
                name: actual_name,
            })
        }
    }

    /// Platform facade used by the client engine.
    ///
    /// Linux ignores the Windows-only fields and opens the same TAP backend as
    /// [`Tap::open`]; Windows creates/opens a Wintun adapter and starts the
    /// Ethernet shim + async bridge.
    pub async fn open_with_config(config: &TapConfig) -> io::Result<Self> {
        config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

        #[cfg(target_os = "windows")]
        {
            let config = config.clone();
            let tap = tokio::task::spawn_blocking(move || {
                crate::shim::windows::WindowsTap::open(&config)
            })
            .await
            .map_err(|error| io::Error::other(format!("open Wintun adapter task failed: {error}")))?
            .map_err(|error| io::Error::other(format!("open Wintun adapter: {error}")))?;
            let name = tap.name().to_string();
            Ok(Self {
                inner: Arc::new(TapBackend::Wintun(tap)),
                name,
            })
        }

        #[cfg(not(target_os = "windows"))]
        {
            Self::open(&config.name, config.wire_mtu)
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Stop the platform's dedicated data-plane reader thread **without**
    /// closing the device.
    ///
    /// On Windows the Wintun shim owns a blocking reader thread; it must be
    /// joined before any route/address teardown so no thread is inside a
    /// Wintun read while the network guard runs.  The adapter itself is closed
    /// afterwards by dropping the last [`Tap`] handle.
    ///
    /// Linux has no separate reader thread (peer tasks read the async device
    /// and are cancelled/joined by the session), so this is a no-op there.
    pub fn stop_reader(&self) {
        #[cfg(target_os = "windows")]
        {
            // On Windows this is the only backend variant.
            let TapBackend::Wintun(tap) = self.inner.as_ref();
            tap.stop_reader();
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = self;
        }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.as_ref() {
            #[cfg(not(target_os = "windows"))]
            TapBackend::Async(dev) => dev.recv(buf).await,
            #[cfg(target_os = "linux")]
            TapBackend::Uring(uring) => uring.recv(buf).await,
            #[cfg(target_os = "windows")]
            TapBackend::Wintun(tap) => tap.recv(buf).await,
        }
    }

    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.as_ref() {
            #[cfg(not(target_os = "windows"))]
            TapBackend::Async(dev) => dev.send(buf).await,
            #[cfg(target_os = "linux")]
            TapBackend::Uring(uring) => uring.send(buf),
            #[cfg(target_os = "windows")]
            TapBackend::Wintun(tap) => tap.send(buf),
        }
    }
}

#[cfg(target_os = "linux")]
fn supports_uring() -> bool {
    io_uring::IoUring::new(8).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> IpNet {
        text.parse().unwrap()
    }

    fn config(mode: Mode, wire_mtu: usize) -> TapConfig {
        TapConfig::new("rsvpn0", wire_mtu, mode, address("10.88.0.2/24"))
            .with_gateway(Some(Ipv4Addr::new(10, 88, 0, 1)))
            .with_dns(vec![Ipv4Addr::new(10, 88, 0, 1)])
            .with_verifier_id([7u8; 16])
    }

    #[test]
    fn inner_ip_mtu_is_derived_from_mode_and_never_the_wire_budget() {
        for (mode, wire, inner) in [
            (Mode::Plain, 1515, 1500),
            (Mode::Noise, 1515, 1476),
            (Mode::Encless, 1515, 1492),
            (Mode::Plain, 83, 68),
            (Mode::Noise, 120, 81),
        ] {
            let cfg = config(mode, wire);
            assert_eq!(cfg.inner_ip_mtu().unwrap(), inner, "{mode:?} {wire}");
            assert_ne!(
                cfg.inner_ip_mtu().unwrap(),
                cfg.wire_mtu,
                "the interface MTU must not be the wire budget"
            );
            assert!(
                cfg.inner_ip_mtu().unwrap() + ETH_HEADER_LEN <= cfg.mode.max_payload(cfg.wire_mtu),
                "{mode:?} {wire}"
            );
        }
    }

    #[test]
    fn rejects_zero_out_of_range_and_unusable_configs() {
        assert_eq!(
            config(Mode::Plain, 0).inner_ip_mtu().unwrap_err(),
            TapConfigError::ZeroWireMtu
        );
        for (mode, wire) in [
            (Mode::Plain, 67),
            (Mode::Noise, 119),
            (Mode::Noise, MTU_MAX + 1),
        ] {
            assert!(matches!(
                config(mode, wire).inner_ip_mtu().unwrap_err(),
                TapConfigError::WireMtuOutOfRange { .. }
            ));
        }
        // Plain 68 derives 53, below the shim minimum.
        assert!(matches!(
            config(Mode::Plain, 68).inner_ip_mtu().unwrap_err(),
            TapConfigError::InnerMtuTooSmall { inner_ip_mtu: 53 }
        ));

        let mut cfg = config(Mode::Plain, 1515);
        cfg.name.clear();
        assert_eq!(cfg.validate().unwrap_err(), TapConfigError::EmptyName);

        let mut cfg = config(Mode::Plain, 1515);
        cfg.address = address("2001:db8::1/64");
        assert!(matches!(
            cfg.validate().unwrap_err(),
            TapConfigError::NotIpv4Address(_)
        ));

        let mut cfg = config(Mode::Plain, 1515);
        cfg.gateway = Some(Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            cfg.validate().unwrap_err(),
            TapConfigError::UnspecifiedGateway
        );
    }

    #[test]
    fn valid_profile_shaped_config_is_accepted() {
        let cfg = config(Mode::Noise, 1539);
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.prefix_len(), 24);
        assert_eq!(cfg.ipv4_address().unwrap(), Ipv4Addr::new(10, 88, 0, 2));
    }

    #[test]
    fn platform_neutral_windows_fields_are_carried_but_ignored_here() {
        let cfg = config(Mode::Plain, 1515)
            .with_wintun_dll("/absolute/wintun.dll")
            .with_wintun_sha256(Some([9u8; 32]));
        assert_eq!(cfg.wintun_dll, PathBuf::from("/absolute/wintun.dll"));
        assert_eq!(cfg.wintun_sha256, Some([9u8; 32]));
        assert_eq!(cfg.verifier_id, [7u8; 16]);
        // Validation is platform-neutral; the Windows adapter applies its
        // stricter absolute-path/subnet/576-byte policy.
        assert!(cfg.validate().is_ok());
    }

    #[tokio::test]
    async fn dispatcher_rejects_invalid_config_before_any_platform_io() {
        let cfg = config(Mode::Plain, 0);
        let error = match Tap::open_with_config(&cfg).await {
            Ok(_) => panic!("an invalid config must not open a device"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("wire MTU"), "{error}");
    }

    #[test]
    fn default_dll_path_falls_back_to_the_packaged_location() {
        // Environment overrides are process-global; only assert the fallback
        // shape when the variable is unset.
        if std::env::var_os(WINTUN_DLL_ENV).is_none() {
            let path = default_wintun_dll_path();
            assert_eq!(path, PathBuf::from(DEFAULT_WINTUN_DLL_PATH));
            // A Windows drive path is not "absolute" to a Unix host; the
            // adapter performs the real absolute-path check on Windows.
            #[cfg(target_os = "windows")]
            assert!(path.is_absolute());
        }
    }
}
