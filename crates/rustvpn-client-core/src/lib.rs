//! Shared client engine: profile validation, session establishment, the
//! reconnect state machine and Linux network configuration.
//!
//! The CLI links this crate directly and does not use the daemon or IPC.  The
//! GUI talks to `rustvpn-clientd`, which also links this crate.

pub mod engine;
pub mod lock;
pub mod netcfg;
pub mod profile;
pub mod session;

pub use engine::{Command, Engine};
pub use lock::TunnelLock;
pub use netcfg::NetworkGuard;
pub use profile::ValidatedProfile;
pub use session::{resolve_endpoints, start_session, Endpoints, Session, SessionEnd};
