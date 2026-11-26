//! CLI entry point for the Phase 0 Windows Ethernet shim spike.
//!
//! * `--self-test` runs pure codec/ARP/MTU checks on any platform.
//! * `--smoke-test` (Windows only) creates the isolated `RustVPN-Spike`
//!   Wintun adapter, reads/writes one packet and closes it.

use std::env;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
#[cfg(windows)]
use std::time::Duration;

use rustvpn_windows_shim::mac;
use rustvpn_windows_shim::mtu::{self, Mode, OuterFamily, OuterTransport, WireMtu};
use rustvpn_windows_shim::safety;
use rustvpn_windows_shim::selftest;
use rustvpn_windows_shim::wintun_verify;

#[cfg(windows)]
use rustvpn_windows_shim::wintun_adapter::{AdapterConfig, WintunAdapter};

const DEFAULT_WINTUN_FILE: &str = r"C:\rustvpn-dev\vendor\wintun\wintun.dll";
const DEFAULT_ADAPTER: &str = "RustVPN-Spike";
const DEFAULT_ADDRESS: &str = "10.88.0.2";
const DEFAULT_PEER: &str = "10.88.0.3";

struct Options {
    help: bool,
    self_test: bool,
    smoke_test: bool,
    wintun_file: PathBuf,
    adapter: String,
    address: Ipv4Addr,
    prefix_len: u8,
    wire_mtu: usize,
    mode: Mode,
    gateway: Option<Ipv4Addr>,
    verifier: String,
    peer: Ipv4Addr,
    peer_port: u16,
    ring_capacity: u32,
    wintun_sha256: Option<[u8; 32]>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            help: false,
            self_test: false,
            smoke_test: false,
            wintun_file: PathBuf::from(DEFAULT_WINTUN_FILE),
            adapter: DEFAULT_ADAPTER.to_string(),
            address: Ipv4Addr::new(10, 88, 0, 2),
            prefix_len: 24,
            wire_mtu: 1515,
            mode: Mode::Plain,
            gateway: None,
            verifier: "phase0-spike".to_string(),
            peer: Ipv4Addr::new(10, 88, 0, 3),
            peer_port: 45123,
            ring_capacity: 4 * 1024 * 1024,
            wintun_sha256: None,
        }
    }
}

impl Options {
    fn parse(args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut options = Self::default();
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            let mut value = || args.next().ok_or_else(|| format!("{arg} requires a value"));
            match arg.as_str() {
                "--help" | "-h" => options.help = true,
                "--self-test" => options.self_test = true,
                "--smoke-test" => options.smoke_test = true,
                "--wintun-file" => options.wintun_file = PathBuf::from(value()?),
                "--adapter" => options.adapter = value()?,
                "--address" => {
                    options.address = value()?.parse().map_err(|e| format!("--address: {e}"))?
                }
                "--prefix" => {
                    options.prefix_len = value()?.parse().map_err(|e| format!("--prefix: {e}"))?
                }
                "--wire-mtu" => {
                    options.wire_mtu = value()?.parse().map_err(|e| format!("--wire-mtu: {e}"))?
                }
                "--mode" => options.mode = Mode::from_str(&value()?)?,
                "--gateway" => {
                    let raw = value()?;
                    if raw == "none" {
                        options.gateway = None;
                    } else {
                        options.gateway = Some(raw.parse().map_err(|e| format!("--gateway: {e}"))?);
                    }
                }
                "--verifier" => options.verifier = value()?,
                "--peer" => options.peer = value()?.parse().map_err(|e| format!("--peer: {e}"))?,
                "--peer-port" => {
                    options.peer_port = value()?.parse().map_err(|e| format!("--peer-port: {e}"))?
                }
                "--ring-capacity" => {
                    options.ring_capacity = value()?
                        .parse()
                        .map_err(|e| format!("--ring-capacity: {e}"))?
                }
                "--wintun-sha256" => {
                    let raw = value()?;
                    options.wintun_sha256 = Some(
                        wintun_verify::parse_sha256_hex(&raw)
                            .map_err(|e| format!("--wintun-sha256: {e}"))?,
                    );
                }
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        Ok(options)
    }

    /// Enforce the isolated-test-subnet policy before any adapter work.
    fn validate(&self) -> Result<(), String> {
        safety::validate_adapter_name(&self.adapter)?;
        safety::validate_adapter_address(self.address, self.prefix_len)?;
        safety::validate_peer(self.peer, self.address)?;
        if self.peer_port == 0 {
            return Err("--peer-port must be non-zero".into());
        }
        safety::validate_ring_capacity(self.ring_capacity)?;
        #[cfg(windows)]
        if !self.wintun_file.is_absolute() {
            return Err(format!(
                "--wintun-file {:?} must be an absolute path",
                self.wintun_file.display()
            ));
        }
        Ok(())
    }
}

fn main() -> ExitCode {
    let options = match Options::parse(env::args().skip(1)) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("error: {error}");
            usage();
            return ExitCode::from(2);
        }
    };
    if options.help || (!options.self_test && !options.smoke_test) {
        usage();
        return ExitCode::SUCCESS;
    }

    if let Err(error) = options.validate() {
        eprintln!("error: {error}");
        usage();
        return ExitCode::from(2);
    }

    let mut exit = ExitCode::SUCCESS;

    if options.self_test {
        let report = selftest::run();
        for name in &report.passed {
            println!("[PASS] {name}");
        }
        for name in &report.failed {
            println!("[FAIL] {name}");
        }
        println!(
            "self-test: {} passed, {} failed",
            report.passed.len(),
            report.failed.len()
        );
        if !report.is_ok() {
            exit = ExitCode::from(1);
        }
    }

    if options.smoke_test {
        let wire = match mtu::from_wire(options.mode, options.wire_mtu) {
            Ok(wire) => wire,
            Err(error) => {
                eprintln!("error: {error}");
                return ExitCode::from(2);
            }
        };
        // P2-1: the adapter/smoke path must refuse a useless inner MTU
        // (Plain wire 68 yields a 53-byte IP MTU and TCP MSS 13/0).
        if let Err(error) = safety::validate_adapter_mtu(wire.inner_ip_mtu) {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
        print_plan(&options, &wire);
        let smoke = run_smoke(&options, &wire);
        if !smoke {
            exit = ExitCode::from(1);
        }
    }

    exit
}

fn print_plan(options: &Options, wire: &WireMtu) {
    let synthetic_mac = mac::derive(options.verifier.as_bytes());
    println!("RustVPN Windows Ethernet shim - Phase 0 spike");
    println!("{}", wire.log_line());
    println!(
        "synthetic MAC: {synthetic_mac} (derived from verifier id {:?})",
        options.verifier
    );
    println!(
        "adapter plan: name={:?} address={}/{} mtu={} (no gateway, no default route)",
        options.adapter, options.address, options.prefix_len, wire.inner_ip_mtu
    );
    if let Some(warning) = wire.windows_recommendation() {
        eprintln!("warning: {warning}");
    }
    if let Some(warning) = mtu::encless_capacity_warning(
        options.mode,
        options.wire_mtu,
        1500, // conservative underlay assumption for the spike
        OuterFamily::V4,
        OuterTransport::Udp,
    ) {
        eprintln!("warning: {warning}");
    }
    if let Some(gateway) = options.gateway {
        println!("shim next-hop gateway={gateway} (ARP only; never configured on Windows)");
    }
}

#[cfg(windows)]
fn run_smoke(options: &Options, wire: &WireMtu) -> bool {
    println!("wintun dll: {}", options.wintun_file.display());
    println!(
        "wintun sha256 (expected): {}",
        wintun_verify::to_hex(
            &options
                .wintun_sha256
                .unwrap_or(wintun_verify::DEFAULT_WINTUN_SHA256)
        )
    );
    println!(
        "wire contract: mode={} wire_mtu={} -> inner_ip_mtu={}",
        options.mode, options.wire_mtu, wire.inner_ip_mtu
    );

    let mut cfg = AdapterConfig::new(
        options.adapter.clone(),
        options.wintun_file.clone(),
        options.address,
        options.prefix_len,
        wire.inner_ip_mtu,
    );
    cfg.ring_capacity = options.ring_capacity;
    if let Some(sha256) = options.wintun_sha256 {
        cfg.wintun_sha256 = sha256;
    }

    let adapter = match WintunAdapter::open_or_create(&cfg) {
        Ok(adapter) => adapter,
        Err(error) => {
            eprintln!("adapter setup FAILED: {error}");
            return false;
        }
    };

    println!(
        "adapter opened: name={:?} index={} created={} driver={} mtu={:?} addresses={:?}",
        adapter.name(),
        adapter.index(),
        adapter.created(),
        adapter.driver_version().unwrap_or("unknown"),
        adapter.mtu(),
        adapter.addresses()
    );
    for note in adapter.notes() {
        println!("note: {note}");
    }

    println!(
        "data-plane probe: UDP to {}:{} within {}/{}",
        options.peer,
        options.peer_port,
        safety::TEST_SUBNET,
        safety::TEST_SUBNET_PREFIX
    );
    let report = adapter.udp_round_trip(options.peer, options.peer_port, Duration::from_secs(2));
    println!("socket bound: {:?}", report.bound);
    println!("OS->Wintun send: {:?} bytes", report.sent);
    println!(
        "Wintun read: {:?} bytes ({})",
        report.read_len,
        report
            .read_detail
            .as_deref()
            .unwrap_or("no matching packet")
    );
    println!("Wintun write: {:?} bytes", report.write_len);
    println!("UDP round trip: {:?}", report.round_trip_ok);
    for note in &report.notes {
        println!("note: {note}");
    }

    let persisted = adapter.close();
    if persisted {
        println!(
            "cleanup: adapter {:?} still exists after close; manual deletion may be required \
             (Remove-NetAdapter -Name {:?} -Confirm:$false)",
            options.adapter, options.adapter
        );
    } else {
        println!(
            "cleanup: adapter {:?} was removed when the last handle closed",
            options.adapter
        );
    }

    let ok = report.success();
    println!(
        "smoke result: {} (read={} write={}; socket round-trip is best effort and may be \
         filtered by the Windows firewall)",
        if ok { "PASS" } else { "FAIL" },
        report.read_len.is_some(),
        report.write_len.is_some()
    );
    ok
}

#[cfg(not(windows))]
fn run_smoke(_options: &Options, _wire: &WireMtu) -> bool {
    eprintln!("--smoke-test requires Windows (Wintun); this host is not Windows");
    false
}

fn usage() {
    println!(
        "RustVPN Windows Ethernet shim - Phase 0 spike\n\
         \n\
         USAGE: windows-shim-spike [OPTIONS]\n\
         \n\
         OPTIONS:\n\
           --self-test              run pure codec/ARP/MTU checks (any platform)\n\
           --smoke-test             create/read/write/close the isolated Wintun adapter (Windows)\n\
           --wintun-file <PATH>     wintun.dll path (default {DEFAULT_WINTUN_FILE})\n\
           --adapter <NAME>         adapter name (default {DEFAULT_ADAPTER})\n\
           --address <IPv4>         test address in 10.88.0.0/24 (default {DEFAULT_ADDRESS})\n\
           --prefix <LEN>           prefix length, 24..=32 only (default 24)\n\
           --wire-mtu <N>           numeric wire MTU contract (default 1515; inner MTU\n\
                                    must be >= {})\n\
           --mode <plain|noise|encless>  transport mode (default plain)\n\
           --gateway <IPv4|none>    shim ARP next hop only; never set on Windows\n\
           --verifier <ID>          verifier id used to derive the synthetic MAC\n\
           --peer <IPv4>            on-link peer in 10.88.0.0/24 (default {DEFAULT_PEER})\n\
           --peer-port <N>          UDP probe port (default 45123, must be non-zero)\n\
           --ring-capacity <N>      Wintun ring bytes (128 KiB..64 MiB, power of two)\n\
           --wintun-sha256 <HEX>    override the pinned wintun.dll SHA-256 (still verified)\n\
           -h, --help               show this help\n\
         \n\
         SAFETY: only the named adapter in 10.88.0.0/24 is touched, with a prefix\n\
         of at least /24. Addresses/peers outside the test subnet, short prefixes,\n\
         small inner MTUs and a mismatched wintun.dll hash are rejected before any\n\
         adapter work. No default route, DNS, firewall, existing adapter or VPN\n\
         state is modified.",
        safety::WINDOWS_MIN_IP_MTU
    );
}
