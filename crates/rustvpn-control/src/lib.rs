//! Local control protocol between `rustvpn-server` and the optional
//! `rustvpn-admind` process.
//!
//! The protocol is deliberately small: length-prefixed JSON over a Unix
//! domain socket.  The socket's file permissions and an optional peer
//! credential check are the authentication boundary; there is no HTTP and no
//! network listener.

pub mod client;
pub mod frame;
pub mod proto;

pub use frame::{read_frame, write_frame, FrameError, MAX_FRAME_LEN};
pub use proto::*;

use std::time::{SystemTime, UNIX_EPOCH};

/// Wire protocol version.  Bump the major number on breaking changes.
pub const PROTOCOL_VERSION: u32 = 1;

pub fn id_hex(id: &[u8; 16]) -> String {
    hex::encode(id)
}

pub fn mode_name(noise: bool, encless: bool) -> &'static str {
    if encless {
        "encless"
    } else if noise {
        "noise"
    } else {
        "plain"
    }
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn rfc3339(seconds: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
