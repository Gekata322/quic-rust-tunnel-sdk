//! Linux TUN interface: an L3 kernel tunnel for real routing.
//!
//! Opens `/dev/net/tun`; the `TUNSETIFF` ioctl registers the device with
//! `IFF_TUN | IFF_NO_PI` (no packet-info prefix — raw IP packets). Requires
//! privileges: `CAP_NET_ADMIN` or running as root.
//!
//! The server's production mode does not work without TUN — use
//! `--tun tunnel0`; loopback mode (`tun_name: None`) bypasses the TUN and
//! echoes packets back.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;

/// Path to the TUN control device in Linux.
const TUN_DEVICE: &str = "/dev/net/tun";
/// The TUNSETIFF ioctl: assign an interface name to an open fd.
const TUNSETIFF: libc_ulong = 0x400454CA;
/// ifreq flags: L3 TUN mode + no packet-info prefix.
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
/// TUN read buffer size (the default MTU stays under 1500, 2x headroom).
const READ_BUFFER: usize = 4096;

/// Architecture compatibility: on aarch64 the ioctl request has type u32,
/// on x86_64 it is ulong (u64). The name mirrors libc: non-camel-case allowed.
#[allow(non_camel_case_types)]
#[cfg(target_pointer_width = "64")]
type libc_ulong = u64;
#[cfg(target_pointer_width = "32")]
type libc_ulong = u32;

/// The ifreq structure for the ioctl (interface name + flags; the rest zeros).
#[repr(C)]
struct IfReq {
    name: [u8; 16],
    flags: u16,
    // The other ifreq fields are unused: TUNSETIFF writes the name and flags;
    // pad to the canonical 40-byte size so the stack cannot overflow.
    _pad: [u8; 22],
}

extern "C" {
    fn ioctl(fd: i32, request: libc_ulong, arg: *mut IfReq) -> i32;
}

/// An up TUN interface. Keeps the fd open; on drop the fd closes and the
/// interface disappears (the address/routes are printed by the server at startup).
pub struct TunDevice {
    inner: AsyncFd<std::fs::File>,
    name: String,
}

impl TunDevice {
    /// Creates a TUN interface named `name` (up to 15 chars, IFNAMSIZ-1).
    pub fn open(name: &str) -> io::Result<Self> {
        if name.len() > 15 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("interface name {name:?} is longer than 15 characters (IFNAMSIZ-1)"),
            ));
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_DEVICE)
            .map_err(|err| {
                let hint = match err.kind() {
                    io::ErrorKind::NotFound => "no /dev/net/tun: is the tun module loaded?",
                    io::ErrorKind::PermissionDenied => {
                        "missing permissions: root or CAP_NET_ADMIN required"
                    }
                    _ => "check TUN support in the kernel",
                };
                io::Error::new(err.kind(), format!("{err}: {hint}"))
            })?;

        let mut req = IfReq {
            name: [0u8; 16],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };
        req.name[..name.len()].copy_from_slice(name.as_bytes());

        // SAFETY: the fd is valid, req is a correctly aligned repr(C) ifreq
        // structure; TUNSETIFF fills `name` with the actual interface name.
        let result = unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, &mut req) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let actual = {
            let end = req.name.iter().position(|b| *b == 0).unwrap_or(req.name.len());
            String::from_utf8_lossy(&req.name[..end]).into_owned()
        };

        Ok(Self {
            // AsyncFd::register requires unsafe and manual interest; for
            // read/write mode over File the standard new is fine (tokio PR #8587).
            #[allow(deprecated)]
            inner: AsyncFd::new(file)?,
            name: actual,
        })
    }

    /// The actual interface name (the kernel may have adjusted it).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reads one IP packet from the TUN (asynchronously blocks until one arrives).
    pub async fn read_packet(&self) -> io::Result<Vec<u8>> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| {
                let mut buf = vec![0u8; READ_BUFFER];
                // &File implements Read: read without mut access to the AsyncFd.
                let len = inner.get_ref().read(&mut buf)?;
                if len == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TUN closed"));
                }
                buf.truncate(len);
                Ok(buf)
            }) {
                Ok(result) => return result,
                // Not ready yet: readable().await will sleep again until the fd is ready.
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes an IP packet into the TUN (a client packet bound outside/to the server).
    pub async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().write_all(packet)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Raw file descriptor (for building custom readers).
    pub fn raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_layout_matches_kernel_expectations() {
        // name[16] + flags + pad = 40 bytes = sizeof(struct ifreq) on linux-x86_64.
        let req = IfReq { name: [0u8; 16], flags: 0, _pad: [0u8; 22] };
        let size = std::mem::size_of_val(&req);
        assert_eq!(size, 40, "sizeof(ifreq) must be 40 for TUNSETIFF");
    }
}
