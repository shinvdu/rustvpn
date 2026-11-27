//! Minimal, replaceable Wintun adapter wrapper (Windows only).
//!
//! This module only knows how to create/open the adapter, apply the interface
//! MTU (and, for the smoke test, an address), start a session and move IP
//! packets.  The Ethernet shim lives in [`crate::shim`]; swapping this file for
//! the `tun` crate or a service-owned adapter must not affect it.
//!
//! Milestone M3 split: the adapter is created/opened with the derived
//! interface MTU only.  Its profile address/prefix is applied by the client
//! core network guard **after** the handshake succeeds, together with routes,
//! DNS, NRPT and the IPv6 block, so a failed handshake cannot add on-link
//! routes or DNS before the tunnel exists.  This module therefore never
//! touches the default route, global DNS, NRPT or firewall rules itself.  The
//! DLL must be absolute and SHA-256 pinned.
//!
//! [`WintunAdapter::apply_address`] remains available for the isolated smoke
//! test and for callers that own the adapter lifecycle; the daemon does not
//! call it at open time.

use std::ffi::OsStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use wintun_bindings::{Adapter, Session, Wintun};

use crate::shim::safety;
use crate::shim::windows::verify;

use crate::shim::ipv4::{checksum, prefix_to_mask, udp_checksum, Ipv4Header};

/// Wintun requires a power-of-two ring between MIN and MAX; 4 MiB is the
/// value used by the upstream examples.
const DEFAULT_RING_CAPACITY: u32 = 4 * 1024 * 1024;
/// How long a single blocking read waits before the reader re-checks stop.
const RECV_POLL: Duration = Duration::from_millis(50);

#[derive(Clone, Debug)]
pub struct AdapterConfig {
    pub name: String,
    pub wintun_file: PathBuf,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    /// Interface IP MTU.  Must be the derived inner IP MTU, never the wire
    /// frame budget.
    pub mtu: usize,
    pub ring_capacity: u32,
    pub tunnel_type: String,
    /// Pinned SHA-256 of the `wintun.dll` that is about to be loaded.
    pub wintun_sha256: [u8; 32],
}

impl AdapterConfig {
    pub fn new(
        name: impl Into<String>,
        wintun_file: impl Into<PathBuf>,
        address: Ipv4Addr,
        prefix_len: u8,
        mtu: usize,
    ) -> Self {
        Self {
            name: name.into(),
            wintun_file: wintun_file.into(),
            address,
            prefix_len,
            mtu,
            ring_capacity: DEFAULT_RING_CAPACITY,
            tunnel_type: "RustVPN".into(),
            wintun_sha256: verify::DEFAULT_WINTUN_SHA256,
        }
    }

    /// Enforce the address, MTU, ring, name and DLL-path policy before any
    /// adapter or network state is touched.
    pub fn validate(&self) -> Result<(), String> {
        safety::validate_adapter_name(&self.name)?;
        safety::validate_adapter_address(self.address, self.prefix_len)?;
        safety::validate_adapter_mtu(self.mtu)?;
        safety::validate_ring_capacity(self.ring_capacity)?;
        if self.tunnel_type.is_empty() {
            return Err("tunnel type must not be empty".into());
        }
        if !self.wintun_file.is_absolute() {
            return Err(format!(
                "wintun DLL path {:?} must be absolute (no PATH/cwd lookup)",
                self.wintun_file.display()
            ));
        }
        Ok(())
    }
}

/// What happened when the adapter was closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterCloseReport {
    pub name: String,
    /// The adapter was created by this process (vs. opened pre-existing).
    pub created: bool,
    /// Wintun still reports the adapter after the last handle closed.  A
    /// created adapter should be removed automatically; `true` means the
    /// caller must remove it manually.
    pub persisted: bool,
}

pub struct WintunAdapter {
    wintun: Wintun,
    adapter: Option<Arc<Adapter>>,
    session: Option<Arc<Session>>,
    name: String,
    index: u32,
    created: bool,
    driver_version: Option<String>,
    address: Ipv4Addr,
    /// Informational notes collected during configuration (enable status,
    /// pre-existing adapter, etc.).
    notes: Vec<String>,
    closed: bool,
}

impl WintunAdapter {
    /// Load `wintun.dll`, create or open the adapter, apply the derived
    /// interface MTU, bring it up and start a session.  The profile address is
    /// applied separately (after the handshake, by the network guard).
    pub fn open_or_create(cfg: &AdapterConfig) -> Result<Self, String> {
        cfg.validate()?;

        // Absolute path + pinned SHA-256 before any code is loaded.  The file
        // handle is held with FILE_SHARE_READ so the bytes cannot be swapped
        // between hashing and LoadLibrary.
        let _dll_guard = verify::open_verified_wintun_dll(&cfg.wintun_file, &cfg.wintun_sha256)
            .map_err(|e| e.to_string())?;
        let wintun = unsafe { wintun_bindings::load_from_path(&cfg.wintun_file) }
            .map_err(|e| format!("load wintun.dll from {}: {e}", cfg.wintun_file.display()))?;
        drop(_dll_guard);

        let mut notes = Vec::new();
        // Only "adapter not found" may fall back to creation; permission,
        // driver and transient errors are propagated instead of creating a
        // second device.
        let exists = adapter_exists(&wintun, &cfg.name)?;
        let (adapter, created) = if exists {
            let adapter = Adapter::open(&wintun, &cfg.name)
                .map_err(|e| format!("open existing Wintun adapter {:?}: {e}", cfg.name))?;
            notes.push(format!(
                "adapter {:?} already existed; it was opened, not created \
                 (WintunCloseAdapter will not remove a pre-existing adapter)",
                cfg.name
            ));
            (adapter, false)
        } else {
            let adapter = Adapter::create(
                &wintun,
                &cfg.name,
                &cfg.tunnel_type,
                Some(safety::adapter_guid(&cfg.name)),
            )
            .map_err(|e| format!("create Wintun adapter {:?}: {e}", cfg.name))?;
            (adapter, true)
        };

        let name = adapter.get_name().unwrap_or_else(|_| cfg.name.clone());
        // M3: only the derived interface MTU is configured here.  The profile
        // address, routes, DNS/NRPT and IPv6 block are installed by the client
        // core network guard after the handshake, so a failed handshake cannot
        // add an on-link route or change the resolver.
        notes.push(format!(
            "adapter {:?} opened with MTU {}; address {}/{} and network state are applied after \
             the handshake",
            name, cfg.mtu, cfg.address, cfg.prefix_len
        ));

        let (enabled, detail) = enable_interface(&name);
        if !enabled {
            // Observed on the Phase 0 host: `netsh interface set interface
            // admin=enable` exits 1 for a Wintun adapter that was already
            // brought up by assigning the static address.  The data-plane
            // probe is the authoritative check, so this is informational.
            notes.push(format!(
                "netsh admin=enable returned non-zero for {name:?} ({detail}); \
                 the interface may already be usable, continuing"
            ));
        }

        adapter
            .set_mtu(cfg.mtu)
            .map_err(|e| format!("set MTU {} on {:?}: {e}", cfg.mtu, name))?;

        let index = adapter
            .get_adapter_index()
            .map_err(|e| format!("resolve adapter index for {:?}: {e}", name))?;
        let session = adapter
            .start_session(cfg.ring_capacity)
            .map_err(|e| format!("start Wintun session on {:?}: {e}", name))?;
        let driver_version = wintun_bindings::get_running_driver_version(&wintun)
            .ok()
            .map(|version| version.to_string());

        Ok(Self {
            wintun,
            adapter: Some(adapter),
            session: Some(session),
            name,
            index,
            created,
            driver_version,
            address: cfg.address,
            notes,
            closed: false,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn created(&self) -> bool {
        self.created
    }

    pub fn driver_version(&self) -> Option<&str> {
        self.driver_version.as_deref()
    }

    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Apply an address/prefix to the adapter.
    ///
    /// The daemon does **not** call this at open time: the client core network
    /// guard installs the profile address after the handshake.  The smoke test
    /// uses it to exercise the OS data plane in the isolated test subnet.
    pub fn apply_address(&self, address: Ipv4Addr, prefix_len: u8) -> Result<(), String> {
        let adapter = self
            .adapter
            .as_ref()
            .ok_or_else(|| "adapter already closed".to_string())?;
        let mask = prefix_to_mask(prefix_len)
            .ok_or_else(|| format!("invalid prefix length {prefix_len}"))?;
        adapter
            .set_network_addresses_tuple(IpAddr::V4(address), IpAddr::V4(mask), None)
            .map_err(|e| format!("set address {address}/{prefix_len} on {:?}: {e}", self.name))
    }

    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    pub fn mtu(&self) -> Result<usize, String> {
        self.adapter
            .as_ref()
            .ok_or_else(|| "adapter already closed".to_string())?
            .get_mtu()
            .map_err(|e| e.to_string())
    }

    pub fn addresses(&self) -> Vec<IpAddr> {
        self.adapter
            .as_ref()
            .and_then(|adapter| adapter.get_addresses().ok())
            .unwrap_or_default()
    }

    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let session = self.session.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Wintun session is closed")
        })?;
        match session.try_recv(buf) {
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn recv_timeout(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(n) = self.try_recv(buf)? {
                return Ok(Some(n));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(RECV_POLL.min(Duration::from_millis(10)));
        }
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let session = self.session.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Wintun session is closed")
        })?;
        session.send(buf)
    }

    /// Close the session and adapter and report whether the adapter survived
    /// the close.  If it did, manual cleanup is required.
    pub fn close(mut self) -> AdapterCloseReport {
        self.shutdown_session();
        self.drop_adapter();
        let persisted = self.adapter_still_exists();
        self.closed = true;
        AdapterCloseReport {
            name: self.name.clone(),
            created: self.created,
            persisted,
        }
    }

    fn shutdown_session(&mut self) {
        if let Some(session) = self.session.take() {
            let _ = session.shutdown();
            drop(session);
        }
    }

    fn drop_adapter(&mut self) {
        if let Some(adapter) = self.adapter.take() {
            // Adapter::drop calls WintunCloseAdapter. Wintun removes the
            // device when it was created with WintunCreateAdapter.
            drop(adapter);
        }
    }

    fn adapter_still_exists(&self) -> bool {
        for _ in 0..5 {
            match Adapter::open(&self.wintun, &self.name) {
                Ok(adapter) => {
                    drop(adapter);
                    return true;
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        false
    }
}

impl Drop for WintunAdapter {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        self.shutdown_session();
        self.drop_adapter();
        if self.created {
            eprintln!(
                "wintun adapter {:?}: closed; adapters created by WintunCreateAdapter are \
                 removed when the last handle closes",
                self.name
            );
        } else {
            eprintln!(
                "wintun adapter {:?}: closed; a pre-existing adapter was opened, not removed",
                self.name
            );
        }
    }
}

/// Whether the named Wintun adapter currently exists.
///
/// `wintun-bindings`' `Adapter::open` hides the OS error, so the raw
/// `WintunOpenAdapter` entry point is called once to recover the error code.
/// Only genuine "not found" codes are reported as `Ok(false)`; everything else
/// (access denied, driver failure, transient errors) is returned as an error
/// so the caller never creates a second adapter by accident.
fn adapter_exists(wintun: &Wintun, name: &str) -> Result<bool, String> {
    let wide: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe { wintun.WintunOpenAdapter(wide.as_ptr()) };
    if handle.is_null() {
        let code = io::Error::last_os_error().raw_os_error();
        if safety::is_adapter_not_found(code) {
            Ok(false)
        } else {
            Err(format!(
                "WintunOpenAdapter({name:?}) failed with OS error {code:?}; refusing to treat \
                 it as 'adapter not found' (permission/driver errors must be fixed, not masked \
                 by creating a new adapter)"
            ))
        }
    } else {
        // The handle is only used for the existence probe.
        unsafe { wintun.WintunCloseAdapter(handle) };
        Ok(true)
    }
}

/// Invoke `%SystemRoot%\System32\netsh.exe` by absolute path so an elevated
/// process cannot be hijacked via `PATH` or the current directory.
fn enable_interface(name: &str) -> (bool, String) {
    let netsh = match safety::system32_tool_from_env("netsh.exe") {
        Ok(path) => path,
        Err(error) => return (false, error),
    };
    let output = Command::new(&netsh)
        .args([
            "interface",
            "set",
            "interface",
            &format!("name={name}"),
            "admin=enable",
        ])
        .output();
    match output {
        Ok(output) => {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            (
                output.status.success(),
                if detail.is_empty() {
                    format!("exit status {}", output.status)
                } else {
                    detail
                },
            )
        }
        Err(e) => (false, e.to_string()),
    }
}

#[derive(Debug, Default)]
pub struct DataPlaneReport {
    pub bound: Option<String>,
    pub sent: Option<usize>,
    pub read_len: Option<usize>,
    pub read_detail: Option<String>,
    pub write_len: Option<usize>,
    pub round_trip_ok: Option<bool>,
    pub notes: Vec<String>,
}

impl DataPlaneReport {
    /// Both directions were exercised (one read and one accepted write).
    pub fn success(&self) -> bool {
        self.read_len.is_some() && self.write_len.is_some()
    }
}

impl WintunAdapter {
    /// Exercise the adapter data plane on the isolated test subnet:
    ///
    /// 1. bind a UDP socket to the adapter address and send one datagram to
    ///    `peer`: the OS must route it into Wintun (read direction);
    /// 2. inject a matching UDP reply into Wintun and receive it on the socket
    ///    (write direction + loopback round trip, best effort under the
    ///    Windows firewall).
    pub fn udp_round_trip(
        &self,
        peer: Ipv4Addr,
        peer_port: u16,
        timeout: Duration,
    ) -> DataPlaneReport {
        let mut report = DataPlaneReport::default();
        let bind_addr = SocketAddrV4::new(self.address, 0);
        let bind_deadline = Instant::now() + Duration::from_secs(5);
        let socket = loop {
            match UdpSocket::bind(bind_addr) {
                Ok(socket) => break Some(socket),
                Err(e) => {
                    if Instant::now() >= bind_deadline {
                        report.notes.push(format!("bind {bind_addr} failed: {e}"));
                        break None;
                    }
                    thread::sleep(Duration::from_millis(200));
                }
            }
        };
        let Some(socket) = socket else {
            return report;
        };
        let local = socket
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| bind_addr.to_string());
        report.bound = Some(local);
        let _ = socket.set_read_timeout(Some(timeout));

        let payload = b"rustvpn-m1-out";
        match socket.send_to(payload, SocketAddrV4::new(peer, peer_port)) {
            Ok(n) => report.sent = Some(n),
            Err(e) => {
                report
                    .notes
                    .push(format!("send UDP to {peer}:{peer_port} failed: {e}"));
                return report;
            }
        }

        let deadline = Instant::now() + timeout;
        let mut buf = vec![0u8; 2048];
        let mut observed_source_port = None;
        let mut ignored_non_ipv4 = 0usize;
        let mut ignored_other_ipv4 = 0usize;
        while Instant::now() < deadline {
            match self.recv_timeout(&mut buf, Duration::from_millis(100)) {
                Ok(Some(n)) => match Ipv4Header::parse(&buf[..n]) {
                    Ok(header) if header.protocol == 17 => {
                        let udp = header.payload();
                        if udp.len() >= 8 {
                            let src_port = u16::from_be_bytes([udp[0], udp[1]]);
                            let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
                            if header.dst == peer && dst_port == peer_port {
                                report.read_len = Some(n);
                                report.read_detail = Some(format!(
                                    "IPv4 {} -> {} UDP {} -> {} ({} bytes)",
                                    header.src,
                                    header.dst,
                                    src_port,
                                    dst_port,
                                    header.payload().len()
                                ));
                                observed_source_port = Some(src_port);
                                break;
                            }
                        }
                        ignored_other_ipv4 += 1;
                    }
                    Ok(_) => ignored_other_ipv4 += 1,
                    Err(_) => ignored_non_ipv4 += 1,
                },
                Ok(None) => {}
                Err(e) => {
                    report.notes.push(format!("Wintun read failed: {e}"));
                    break;
                }
            }
        }
        if ignored_non_ipv4 > 0 {
            report.notes.push(format!(
                "ignored {ignored_non_ipv4} non-IPv4 Wintun packet(s): IPv6 is not carried by this shim"
            ));
        }
        if ignored_other_ipv4 > 0 {
            report.notes.push(format!(
                "ignored {ignored_other_ipv4} unrelated IPv4 Wintun packet(s)"
            ));
        }

        if let Some(destination_port) = observed_source_port {
            // Give Windows a moment to install the outbound UDP flow state
            // (firewall/conntrack) before injecting the matching reply.
            thread::sleep(Duration::from_millis(250));
            let reply = build_udp_ipv4(
                peer,
                self.address,
                peer_port,
                destination_port,
                b"rustvpn-m1-in",
            );
            match self.send(&reply) {
                Ok(n) => {
                    report.write_len = Some(n);
                    match socket.recv_from(&mut buf) {
                        Ok((n, from)) => {
                            let ok = n == b"rustvpn-m1-in".len() && &buf[..n] == b"rustvpn-m1-in";
                            report.round_trip_ok = Some(ok);
                            if !ok {
                                report
                                    .notes
                                    .push(format!("unexpected UDP reply from {from}: {} bytes", n));
                            }
                        }
                        Err(e) => {
                            report.round_trip_ok = Some(false);
                            report.notes.push(format!(
                                "injected UDP reply was not delivered to the socket: {e}"
                            ));
                        }
                    }
                }
                Err(e) => report.notes.push(format!("Wintun write failed: {e}")),
            }
        } else {
            // The read direction did not produce an OS packet (routing or
            // firewall problem). Still prove the write API accepts a packet.
            let injected = build_udp_ipv4(peer, self.address, peer_port, 9, b"write-only-probe");
            match self.send(&injected) {
                Ok(n) => report.write_len = Some(n),
                Err(e) => report.notes.push(format!("Wintun write failed: {e}")),
            }
            report.notes.push(
                "no OS->Wintun packet observed; check the connected route and firewall".into(),
            );
        }
        report
    }
}

/// Adapter behind [`crate::shim::ShimPump`]: a bounded blocking read and an
/// atomic per-packet write, both outside the shim lock.
impl crate::shim::L3Device for WintunAdapter {
    fn recv_packet(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        self.recv_timeout(buf, RECV_POLL)
    }

    fn send_packet(&self, packet: &[u8]) -> io::Result<usize> {
        self.send(packet)
    }
}

fn build_udp_ipv4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[6] = 0x40; // DF
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let ip_sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let udp = &mut packet[20..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let udp_sum = udp_checksum(src, dst, &packet[20..]);
    packet[26..28].copy_from_slice(&udp_sum.to_be_bytes());
    packet
}
