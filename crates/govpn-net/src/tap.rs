//! Linux TAP device creation (IFF_TAP without packet information).

use std::io;
use std::sync::Arc;

use tun::{AbstractDevice, AsyncDevice, Configuration, Device, Layer};

#[derive(Clone)]
pub struct Tap {
    dev: Arc<AsyncDevice>,
    name: String,
}

impl Tap {
    pub fn open(name: &str, mtu: usize) -> io::Result<Self> {
        let mut cfg = Configuration::default();
        let _ = mtu;
        cfg.tun_name(name).layer(Layer::L2).platform_config(|p| {
            p.ensure_root_privileges(false);
        });
        let dev = Device::new(&cfg)?;
        let actual_name = dev.tun_name().unwrap_or_else(|_| name.to_string());
        let dev = AsyncDevice::new(dev)?;
        Ok(Self {
            dev: Arc::new(dev),
            name: actual_name,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.dev.recv(buf).await
    }

    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.dev.send(buf).await
    }
}
