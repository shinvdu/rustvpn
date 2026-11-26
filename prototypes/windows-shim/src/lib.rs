//! Phase 0 reference implementation of the RustVPN Ethernet shim for Windows.
//!
//! The simulated wire format is GoVPN 5.7 `DATA`: plain Ethernet frames. A
//! Windows Wintun adapter is L3 only, so this crate implements the missing L2
//! pieces:
//!
//! * IPv4 <-> Ethernet frame codec (padding stripping via `total_length`).
//! * A bounded ARP state machine used to synthesize the next-hop MAC.
//! * Wire-MTU -> inner-IP-MTU / TCP MSS arithmetic.
//!
//! Everything in this crate is deliberately independent of the RustVPN
//! workspace so it can be produced while the P0 MTU/API fixes are in flight.
//! This is **not** production code: see the README for integration notes.

pub mod arp;
pub mod ethernet;
pub mod ipv4;
pub mod mac;
pub mod mtu;
pub mod safety;
pub mod selftest;
pub mod shim;
pub mod wintun_verify;

#[cfg(windows)]
pub mod wintun_adapter;
