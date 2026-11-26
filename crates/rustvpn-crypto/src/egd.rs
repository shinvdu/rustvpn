//! Optional EGD (entropy gathering daemon) socket reader.
//!
//! Implements GoVPN's `EGDRand`: connect, send {0x02, len}, read exactly
//! len bytes, close.

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use rand_core::{Error, RngCore};

pub struct EgDRng {
    path: PathBuf,
}

impl EgDRng {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[cfg(unix)]
    fn fill(&self, dest: &mut [u8]) -> Result<(), Error> {
        let mut off = 0;
        while off < dest.len() {
            let chunk = (dest.len() - off).min(255);
            let mut stream = UnixStream::connect(&self.path)
                .map_err(|_| Error::from(core::num::NonZeroU32::new(1).unwrap()))?;
            stream
                .write_all(&[0x02, chunk as u8])
                .map_err(|_| Error::from(core::num::NonZeroU32::new(1).unwrap()))?;
            stream
                .read_exact(&mut dest[off..off + chunk])
                .map_err(|_| Error::from(core::num::NonZeroU32::new(1).unwrap()))?;
            off += chunk;
        }
        Ok(())
    }

    /// EGD is a Unix-domain-socket protocol and has no Windows transport.
    ///
    /// Windows builds still compile the type so shared session code links, but
    /// every read fails instead of silently substituting another entropy
    /// source.  EGD is optional and not used by the Windows client.
    #[cfg(not(unix))]
    fn fill(&self, _dest: &mut [u8]) -> Result<(), Error> {
        // Keep the configured path observable so the field is not dead code on
        // Windows; the error is intentionally generic (no entropy substituted).
        let _ = &self.path;
        Err(Error::from(core::num::NonZeroU32::new(1).unwrap()))
    }
}

impl RngCore for EgDRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill(dest).expect("EGD read failed");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill(dest)
    }
}
