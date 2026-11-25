//! Linux TAP device creation (IFF_TAP without packet information).
//!
//! Uses io_uring when available; falls back to `tun`'s epoll-based
//! `AsyncDevice` otherwise (or when `GOVPN_IO_URING=0`).

use std::io;
use std::sync::Arc;

use tun::{AbstractDevice, AsyncDevice, Configuration, Device, Layer};

#[cfg(target_os = "linux")]
use crate::uring_tap::UringTap;

enum TapBackend {
    Async(AsyncDevice),
    #[cfg(target_os = "linux")]
    Uring(UringTap),
}

#[derive(Clone)]
pub struct Tap {
    inner: Arc<TapBackend>,
    name: String,
}

impl Tap {
    pub fn open(name: &str, mtu: usize) -> io::Result<Self> {
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

    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.as_ref() {
            TapBackend::Async(dev) => dev.recv(buf).await,
            #[cfg(target_os = "linux")]
            TapBackend::Uring(uring) => uring.recv(buf).await,
        }
    }

    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.as_ref() {
            TapBackend::Async(dev) => dev.send(buf).await,
            #[cfg(target_os = "linux")]
            TapBackend::Uring(uring) => uring.send(buf),
        }
    }
}

#[cfg(target_os = "linux")]
fn supports_uring() -> bool {
    io_uring::IoUring::new(8).is_ok()
}
