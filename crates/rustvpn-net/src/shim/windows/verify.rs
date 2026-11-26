//! `wintun.dll` loading policy.
//!
//! M1 refuses to load a DLL that is not at an absolute path or whose SHA-256
//! does not match the pinned value.  This is still a development-milestone
//! control: the M2 service must additionally pin code-signing/catalog
//! metadata, own the file with ACLs and re-verify before each load.

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

/// SHA-256 of the Wintun 0.14.1 `amd64/wintun.dll` release binary.
pub const DEFAULT_WINTUN_SHA256: [u8; 32] = [
    0xe5, 0xda, 0x84, 0x47, 0xdc, 0x2c, 0x32, 0x0e, 0xdc, 0x0f, 0xc5, 0x2f, 0xa0, 0x18, 0x85, 0xc1,
    0x03, 0xde, 0x8c, 0x11, 0x84, 0x81, 0xf6, 0x83, 0x64, 0x3c, 0xac, 0xc3, 0x22, 0x0d, 0xaf, 0xce,
];

/// Human-readable hex form of [`DEFAULT_WINTUN_SHA256`].
pub const DEFAULT_WINTUN_SHA256_HEX: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DllPinError {
    RelativePath(String),
    NotAFile(String),
    Io(String),
    BadHex { value: String, reason: String },
    HashMismatch { expected: String, actual: String },
}

impl fmt::Display for DllPinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DllPinError::RelativePath(path) => write!(
                f,
                "wintun DLL path {path:?} is not absolute; refusing relative/cwd lookup"
            ),
            DllPinError::NotAFile(path) => write!(f, "wintun DLL path {path:?} is not a file"),
            DllPinError::Io(message) => write!(f, "cannot read wintun DLL: {message}"),
            DllPinError::BadHex { value, reason } => {
                write!(f, "invalid SHA-256 {value:?}: {reason}")
            }
            DllPinError::HashMismatch { expected, actual } => write!(
                f,
                "wintun DLL SHA-256 mismatch: expected {expected}, got {actual}; refusing to load \
                 (override only with --wintun-sha256 after verifying the binary yourself)"
            ),
        }
    }
}

impl std::error::Error for DllPinError {}

/// Parse 64 hex characters (case-insensitive, surrounding whitespace allowed).
///
/// Works on bytes so a non-ASCII input of the right byte length cannot panic
/// on a UTF-8 boundary.
pub fn parse_sha256_hex(text: &str) -> Result<[u8; 32], DllPinError> {
    let trimmed = text.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() != 64 {
        return Err(DllPinError::BadHex {
            value: text.to_string(),
            reason: format!("expected 64 hex characters, got {}", bytes.len()),
        });
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        let high = hex_value(bytes[index * 2])?;
        let low = hex_value(bytes[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, DllPinError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(DllPinError::BadHex {
            value: String::from_utf8_lossy(&[byte]).into_owned(),
            reason: format!("byte 0x{byte:02x} is not a hex digit"),
        }),
    }
}

/// Lower-case hex representation.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// SHA-256 of a file's contents.
pub fn sha256_file(path: &Path) -> Result<[u8; 32], DllPinError> {
    let mut file =
        fs::File::open(path).map_err(|e| DllPinError::Io(format!("{}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| DllPinError::Io(format!("{}: {e}", path.display())))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

/// Ensure the DLL is an absolute path to a regular file and that its SHA-256
/// matches the pinned value.
pub fn verify_wintun_dll(path: &Path, expected: &[u8; 32]) -> Result<(), DllPinError> {
    if !path.is_absolute() {
        return Err(DllPinError::RelativePath(path.display().to_string()));
    }
    let metadata =
        fs::metadata(path).map_err(|e| DllPinError::Io(format!("{}: {e}", path.display())))?;
    if !metadata.is_file() {
        return Err(DllPinError::NotAFile(path.display().to_string()));
    }
    let actual = sha256_file(path)?;
    if &actual != expected {
        return Err(DllPinError::HashMismatch {
            expected: to_hex(expected),
            actual: to_hex(&actual),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "rustvpn-shim-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        path.push(unique);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(contents).unwrap();
        path
    }

    #[test]
    fn default_hex_matches_default_bytes() {
        assert_eq!(
            parse_sha256_hex(DEFAULT_WINTUN_SHA256_HEX).unwrap(),
            DEFAULT_WINTUN_SHA256
        );
        assert_eq!(to_hex(&DEFAULT_WINTUN_SHA256), DEFAULT_WINTUN_SHA256_HEX);
        assert_eq!(
            parse_sha256_hex(&DEFAULT_WINTUN_SHA256_HEX.to_uppercase()).unwrap(),
            DEFAULT_WINTUN_SHA256
        );
    }

    #[test]
    fn parse_rejects_bad_hex() {
        assert!(matches!(
            parse_sha256_hex("xy"),
            Err(DllPinError::BadHex { .. })
        ));
        assert!(matches!(
            parse_sha256_hex(&"0".repeat(63)),
            Err(DllPinError::BadHex { .. })
        ));
        let bad = format!("{}zz", "0".repeat(62));
        assert!(matches!(
            parse_sha256_hex(&bad),
            Err(DllPinError::BadHex { .. })
        ));

        // 32 * 2 bytes of non-ASCII text used to be sliced on a UTF-8
        // boundary; it must be rejected, not panic.
        let wide = "é".repeat(32);
        assert_eq!(wide.len(), 64);
        assert!(matches!(
            parse_sha256_hex(&wide),
            Err(DllPinError::BadHex { .. })
        ));
    }

    #[test]
    fn empty_file_matches_the_well_known_sha256() {
        let path = temp_file("empty", b"");
        let hash = sha256_file(&path).unwrap();
        assert_eq!(
            to_hex(&hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn verification_enforces_absolute_path_and_hash() {
        let path = temp_file("pinned", b"hello wintun");
        let expected = sha256_file(&path).unwrap();
        assert!(verify_wintun_dll(&path, &expected).is_ok());

        let wrong = [0u8; 32];
        assert!(matches!(
            verify_wintun_dll(&path, &wrong),
            Err(DllPinError::HashMismatch { .. })
        ));

        let relative = Path::new("relative/wintun.dll");
        assert!(matches!(
            verify_wintun_dll(relative, &expected),
            Err(DllPinError::RelativePath(_))
        ));

        let directory = std::env::temp_dir();
        assert!(verify_wintun_dll(&directory, &expected).is_err());

        let missing = std::env::temp_dir().join("rustvpn-shim-test-does-not-exist.dll");
        assert!(verify_wintun_dll(&missing, &expected).is_err());

        let _ = fs::remove_file(path);
    }
}
