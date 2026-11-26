//! Windows Wintun (L3) device behind the platform-neutral [`crate::tap::Tap`].
//!
//! One adapter, the Ethernet shim from [`crate::shim`], and an async bridge.
//! The adapter itself only applies the derived interface MTU; its profile
//! address and all routes/DNS/NRPT/firewall state are installed by the client
//! core network guard after the handshake (M3).  The service/IPC layer is M2.

pub mod adapter;
pub mod verify;

use std::io;
use std::sync::Arc;

use crate::shim::mac;
use crate::shim::{
    arp::ArpConfig, reader_buffer_size, ShimConfig, ShimPump, DEFAULT_INBOUND_CAPACITY,
    DEFAULT_OUTBOUND_CAPACITY,
};
use crate::tap::TapConfig;

use self::adapter::{AdapterConfig, WintunAdapter};

/// Environment override for the pinned Wintun DLL digest (64 hex chars).
pub const WINTUN_SHA256_ENV: &str = "RUSTVPN_WINTUN_SHA256";

/// Raw Wintun device plus Ethernet shim behind `Tap`'s async contract.
///
/// The pump owns a dedicated blocking reader thread; `recv()` awaits a bounded
/// Tokio channel and `send()` locks the shim only briefly.  Neither holds the
/// shim lock across Wintun I/O.
pub struct WindowsTap {
    // Declaration order matters: `pump` must drop before `adapter` so the
    // blocking reader is joined before the Wintun session closes.
    pump: ShimPump,
    adapter: Arc<WintunAdapter>,
    name: String,
}

impl WindowsTap {
    /// Create or open the adapter and start the shim pump.
    pub fn open(cfg: &TapConfig) -> Result<Self, String> {
        let address = cfg.ipv4_address().map_err(|error| error.to_string())?;
        let prefix_len = cfg.prefix_len();
        let inner_ip_mtu = cfg.inner_ip_mtu().map_err(|error| error.to_string())?;
        let wintun_sha256 = resolve_wintun_sha256(cfg)?;

        let adapter_cfg = AdapterConfig {
            name: cfg.name.clone(),
            wintun_file: cfg.wintun_dll.clone(),
            address,
            prefix_len,
            mtu: inner_ip_mtu,
            ring_capacity: 4 * 1024 * 1024,
            tunnel_type: "RustVPN".into(),
            wintun_sha256,
        };
        let adapter = Arc::new(WintunAdapter::open_or_create(&adapter_cfg)?);
        let name = adapter.name().to_string();

        if let Some(version) = adapter.driver_version() {
            eprintln!("wintun {name}: driver {version}, index {}", adapter.index());
        }
        for note in adapter.notes() {
            eprintln!("wintun {name}: {note}");
        }

        let shim_cfg = ShimConfig {
            arp: ArpConfig::new(address, mac::derive(&cfg.verifier_id)),
            prefix_len,
            gateway: cfg.gateway,
            inner_ip_mtu,
            outbound_capacity: DEFAULT_OUTBOUND_CAPACITY,
            wire_mtu: cfg.wire_mtu,
            mode: cfg.mode,
        };
        let device: Arc<dyn crate::shim::L3Device> = adapter.clone();
        let pump = ShimPump::new(
            shim_cfg,
            device,
            DEFAULT_INBOUND_CAPACITY,
            reader_buffer_size(inner_ip_mtu),
        )?;
        // Advertise the synthetic IP/MAC once, right after the adapter exists.
        // The frame is returned by the first `recv()` after the handshake.
        pump.announce_gratuitous_arp();

        Ok(Self {
            pump,
            adapter,
            name,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn adapter(&self) -> &WintunAdapter {
        &self.adapter
    }

    /// OS -> tunnel. Drains shim-internal ARP/outbound frames first, then
    /// awaits an OS packet.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.pump.recv().await? {
            Some(frame) => {
                if frame.len() > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "shim frame {} exceeds TAP buffer {} (wire MTU contract violation)",
                            frame.len(),
                            buf.len()
                        ),
                    ));
                }
                buf[..frame.len()].copy_from_slice(&frame);
                Ok(frame.len())
            }
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Wintun session closed",
            )),
        }
    }

    /// Tunnel -> OS. ARP frames are consumed locally; IPv4 frames are written
    /// to Wintun after the shim lock is released.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.pump.send(buf)?;
        Ok(buf.len())
    }
}

impl Drop for WindowsTap {
    fn drop(&mut self) {
        // Join the blocking reader before the adapter handle is released.
        self.pump.shutdown();
    }
}

fn resolve_wintun_sha256(cfg: &TapConfig) -> Result<[u8; 32], String> {
    if let Some(sha) = cfg.wintun_sha256 {
        return Ok(sha);
    }
    if let Some(value) = std::env::var_os(WINTUN_SHA256_ENV) {
        let value = value.to_string_lossy();
        return verify::parse_sha256_hex(&value).map_err(|error| error.to_string());
    }
    Ok(verify::DEFAULT_WINTUN_SHA256)
}

#[cfg(test)]
mod smoke {
    //! Manual adapter acceptance test (M1 smoke, still valid for M3).
    //!
    //! Run from an **elevated** PowerShell on the Windows host:
    //!
    //! ```powershell
    //! $env:RUSTVPN_WINTUN_DLL = "C:\rustvpn-dev\vendor\wintun\wintun.dll"
    //! $env:CARGO_TARGET_DIR = "D:\rustvpn-dev\target-m1"
    //! cargo test -p rustvpn-net --target x86_64-pc-windows-msvc `
    //!     windows_adapter_smoke -- --ignored --nocapture
    //! ```
    //!
    //! It creates `RustVPN-M1-Smoke` at `10.88.0.2/24` with interface MTU
    //! 1500 (the address is applied explicitly through
    //! [`WintunAdapter::apply_address`], mirroring what the network guard does
    //! after the handshake), verifies that no default route/other route or
    //! interface changed, drops it, and verifies removal and route restoration.
    //! It never touches another adapter, the default route, DNS or the firewall.

    use super::adapter::{AdapterConfig, WintunAdapter};
    use crate::shim::safety;
    use serde_json::Value;
    use std::path::Path;
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, Instant};

    const ADAPTER: &str = "RustVPN-M1-Smoke";
    const ADDRESS: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 88, 0, 2);
    const PREFIX: u8 = 24;
    const INNER_MTU: usize = 1500;
    const PREFIX_TEXT: &str = "10.88.0.0/24";

    fn powershell(script: &str) -> Result<Value, String> {
        let root = std::env::var_os("SystemRoot").ok_or("SystemRoot is not set")?;
        let exe = Path::new(&root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        let output = Command::new(exe)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .output()
            .map_err(|error| format!("run powershell: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "powershell failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|error| format!("parse powershell JSON: {error}"))
    }

    fn as_rows(value: Value) -> Vec<String> {
        let rows = match value {
            Value::Array(rows) => rows,
            Value::Null => Vec::new(),
            other => vec![other],
        };
        let mut rows: Vec<String> = rows.iter().map(|row| row.to_string()).collect();
        rows.sort();
        rows
    }

    fn routes() -> Vec<String> {
        as_rows(
            powershell(
                "Get-NetRoute -AddressFamily IPv4 | \
                 Sort-Object DestinationPrefix,InterfaceIndex,NextHop | \
                 Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric | \
                 ConvertTo-Json -Compress",
            )
            .expect("snapshot IPv4 routes"),
        )
    }

    fn adapters() -> Vec<String> {
        as_rows(
            powershell(
                "Get-NetAdapter -IncludeHidden | Sort-Object ifIndex | \
                 Select-Object ifIndex,Name,InterfaceDescription,Status | \
                 ConvertTo-Json -Compress",
            )
            .expect("snapshot adapters"),
        )
    }

    fn without_routes_on(rows: &[String], ifindex: u32) -> Vec<String> {
        rows.iter()
            .filter(|row| {
                let value: Value = serde_json::from_str(row).expect("route row JSON");
                value.get("InterfaceIndex").and_then(Value::as_u64) != Some(u64::from(ifindex))
            })
            .cloned()
            .collect()
    }

    fn routes_on(rows: &[String], ifindex: u32) -> Vec<Value> {
        rows.iter()
            .filter_map(|row| serde_json::from_str::<Value>(row).ok())
            .filter(|value| {
                value.get("InterfaceIndex").and_then(Value::as_u64) == Some(u64::from(ifindex))
            })
            .collect()
    }

    fn ip_addresses(ifindex: u32) -> Vec<String> {
        as_rows(
            powershell(&format!(
                "Get-NetIPAddress -InterfaceIndex {ifindex} -ErrorAction SilentlyContinue | \
                 Select-Object InterfaceIndex,IPAddress,PrefixLength,PrefixOrigin | \
                 ConvertTo-Json -Compress"
            ))
            .unwrap_or(Value::Null),
        )
    }

    #[test]
    #[ignore = "manual: elevated Windows host, wintun.dll, isolated 10.88.0.0/24"]
    fn windows_adapter_smoke() {
        let dll = std::env::var_os(crate::tap::WINTUN_DLL_ENV).expect(
            "set RUSTVPN_WINTUN_DLL to an absolute wintun.dll path before running this test",
        );
        let before_adapters = adapters();
        let before_routes = routes();
        assert!(
            !before_adapters.iter().any(|row| row.contains(ADAPTER)),
            "a leftover {ADAPTER} adapter exists; remove it with \
             `Remove-NetAdapter -Name {ADAPTER} -Confirm:$false` and retry"
        );

        let cfg = AdapterConfig::new(ADAPTER, dll, ADDRESS, PREFIX, INNER_MTU);
        let adapter = WintunAdapter::open_or_create(&cfg).expect("create M1 adapter");
        adapter
            .apply_address(ADDRESS, PREFIX)
            .expect("apply the isolated test address");
        let index = adapter.index();
        assert!(adapter.created(), "the smoke adapter must be newly created");
        assert_eq!(adapter.mtu().unwrap(), INNER_MTU, "interface MTU");
        assert!(
            adapter.addresses().contains(&std::net::IpAddr::V4(ADDRESS)),
            "adapter addresses {:?}",
            adapter.addresses()
        );

        // No default route and no changes to any other interface/route.  The
        // implicit connected route can appear a moment after the static
        // address assignment, so allow a short settle window.
        let mut during_routes = routes();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline
            && !routes_on(&during_routes, index).iter().any(|row| {
                row.get("DestinationPrefix").and_then(Value::as_str) == Some(PREFIX_TEXT)
            })
        {
            thread::sleep(Duration::from_millis(200));
            during_routes = routes();
        }
        let on_adapter = routes_on(&during_routes, index);
        eprintln!(
            "smoke: adapter index {index}, mtu {:?}, addresses {:?}, unix routes {:?}, \
             adapter routes {on_adapter:?}, ip config {:?}",
            adapter.mtu(),
            adapter.addresses(),
            during_routes,
            ip_addresses(index)
        );
        for row in &on_adapter {
            assert_ne!(
                row.get("DestinationPrefix").and_then(Value::as_str),
                Some("0.0.0.0/0"),
                "M1 must not install a default route: {row}"
            );
        }
        assert!(
            on_adapter.iter().any(
                |row| row.get("DestinationPrefix").and_then(Value::as_str) == Some(PREFIX_TEXT)
            ),
            "expected the implicit connected {PREFIX_TEXT} route; adapter routes {on_adapter:?}"
        );
        assert_eq!(
            without_routes_on(&during_routes, index),
            before_routes,
            "creating the M1 adapter changed other route entries"
        );

        // Real data plane: the OS must route one UDP datagram into Wintun
        // (read direction) and accept an injected reply (write direction).
        let data = adapter.udp_round_trip(
            std::net::Ipv4Addr::new(10, 88, 0, 3),
            5555,
            Duration::from_secs(2),
        );
        eprintln!("smoke: data plane {data:?}");
        assert!(
            data.read_len.is_some(),
            "OS->Wintun read direction failed: {data:?}"
        );
        assert!(
            data.write_len.is_some(),
            "Wintun->OS write direction failed: {data:?}"
        );

        let report = adapter.close();
        assert_eq!(report.name, ADAPTER);
        assert!(report.created);
        assert!(
            !report.persisted,
            "created adapter was not removed on close"
        );

        // Route removal can lag adapter teardown briefly.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let after_routes = routes();
            let leftover = !routes_on(&after_routes, index).is_empty();
            if !leftover || Instant::now() >= deadline {
                assert!(!leftover, "routes on adapter index {index} survived close");
                assert_eq!(
                    without_routes_on(&after_routes, index),
                    before_routes,
                    "closing the adapter changed other route entries"
                );
                break;
            }
            thread::sleep(Duration::from_millis(200));
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let after_adapters = adapters();
            let gone = !after_adapters.iter().any(|row| row.contains(ADAPTER));
            if gone || Instant::now() >= deadline {
                assert!(gone, "{ADAPTER} still exists after close");
                assert_eq!(after_adapters, before_adapters, "other adapters changed");
                break;
            }
            thread::sleep(Duration::from_millis(200));
        }

        // The M1 socket/route policy helpers must have accepted the safe test
        // address; this also documents the enforced envelope.
        assert_eq!(safety::TEST_SUBNET_PREFIX, PREFIX);
    }
}
