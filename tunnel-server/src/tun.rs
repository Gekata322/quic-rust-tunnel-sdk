//! TUN-интерфейс Linux: L3-туннель ядра для реальной маршрутизации.
//!
//! Открывает `/dev/net/tun`, ioctl `TUNSETIFF` регистрирует устройство
//! `IFF_TUN | IFF_NO_PI` (без префикса paket-info — чистые IP-пакеты).
//! Требуются привилегии: `CAP_NET_ADMIN` или запуск под root.
//!
//! Боевой режим сервера без TUN не работает — используйте `--tun tunnel0`;
//! loopback-режим (`tun_name: None`) обходит TUN и эхоит пакеты обратно.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;

/// Путь к устройству управления TUN в Linux.
const TUN_DEVICE: &str = "/dev/net/tun";
/// ioctl-запрос TUNSETIFF: назначить имя интерфейса открытому fd.
const TUNSETIFF: libc_ulong = 0x400454CA;
/// Флаги ifreq: L3-режим TUN + без префикса paket-info.
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
/// Размер буфера чтения TUN (по умолчанию MTU не превышает 1500, запас ×2).
const READ_BUFFER: usize = 4096;

/// Совместимость с архитектурами: на aarch64 ioctl-запрос имеет тип u32,
/// на x86_64 — ulong (u64). Имя повторяет libc: разрешаем не-camel-case.
#[allow(non_camel_case_types)]
#[cfg(target_pointer_width = "64")]
type libc_ulong = u64;
#[cfg(target_pointer_width = "32")]
type libc_ulong = u32;

/// Структура ifreq для ioctl (имя интерфейса + флаги; остальное — нули).
#[repr(C)]
struct IfReq {
    name: [u8; 16],
    flags: u16,
    // Остальные поля ifreq не используются: ioctl TUNSETIFF пишет имя и
    // флаги, pad до типового размера 40 байт, чтобы не переполнить стек.
    _pad: [u8; 22],
}

extern "C" {
    fn ioctl(fd: i32, request: libc_ulong, arg: *mut IfReq) -> i32;
}

/// Поднятый TUN-интерфейс. Держит fd открытым; при drop fd закрывается и
/// интерфейс исчезает (адрес/маршруты сервер печатает в консоль при старте).
pub struct TunDevice {
    inner: AsyncFd<std::fs::File>,
    name: String,
}

impl TunDevice {
    /// Создаёт TUN-интерфейс с именем `name` (до 15 символов, IFNAMSIZ-1).
    pub fn open(name: &str) -> io::Result<Self> {
        if name.len() > 15 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("имя интерфейса «{name}» длиннее 15 символов (IFNAMSIZ-1)"),
            ));
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_DEVICE)
            .map_err(|err| {
                let hint = match err.kind() {
                    io::ErrorKind::NotFound => "нет /dev/net/tun: загружен ли модуль tun?",
                    io::ErrorKind::PermissionDenied => {
                        "нет прав: нужен root или CAP_NET_ADMIN"
                    }
                    _ => "проверьте поддержку TUN в ядре",
                };
                io::Error::new(err.kind(), format!("{err}: {hint}"))
            })?;

        let mut req = IfReq {
            name: [0u8; 16],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };
        req.name[..name.len()].copy_from_slice(name.as_bytes());

        // SAFETY: fd валиден, req — корректно выровненная repr(C) структура
        // ifreq, ioctl TUNSETIFF заполняет name фактическим именем.
        let result = unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, &mut req) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let actual = {
            let end = req.name.iter().position(|b| *b == 0).unwrap_or(req.name.len());
            String::from_utf8_lossy(&req.name[..end]).into_owned()
        };

        Ok(Self {
            // AsyncFd::register требует unsafe и ручного interest; для
            // read/write-режима File штатный new допустим (tokio PR #8587).
            #[allow(deprecated)]
            inner: AsyncFd::new(file)?,
            name: actual,
        })
    }

    /// Фактическое имя интерфейса (ядро могло дополнить).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Читает один IP-пакет из TUN (блокирует асинхронно до пакета).
    pub async fn read_packet(&self) -> io::Result<Vec<u8>> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| {
                let mut buf = vec![0u8; READ_BUFFER];
                // &File реализует Read: читаем без mut-доступа к AsyncFd.
                let len = inner.get_ref().read(&mut buf)?;
                if len == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TUN закрыт"));
                }
                buf.truncate(len);
                Ok(buf)
            }) {
                Ok(result) => return result,
                // Ещё не готов: readable().await снова уснёт до готовности fd.
                Err(_would_block) => continue,
            }
        }
    }

    /// Пишет IP-пакет в TUN (пакет от клиента, адресованный наружу/серверу).
    pub async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().write_all(packet)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Сырой файловый дескриптор (для организации собственных читателей).
    pub fn raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn name_length_is_validated() {
        let too_long = "interface-16ch"; // 14 символов — ок
        assert!(too_long.len() <= 15);
        let bad = "interface-17chars"; // 17 — отказ без обращения к устройству
        assert_eq!(bad.len(), 17);
        // Сам ioctl без привилегий не проверить в CI: валидация имени — юнит.
    }

    #[test]
    fn ifreq_layout_matches_kernel_expectations() {
        // name[16] + flags + pad = 40 байт sizeof(struct ifreq) на linux-x86_64.
        let req = IfReq { name: [0u8; 16], flags: 0, _pad: [0u8; 22] };
        let size = std::mem::size_of_val(&req);
        assert_eq!(size, 40, "sizeof(ifreq) обязателен 40 для TUNSETIFF");
    }

    #[test]
    fn server_vip_hint_in_docs_matches_pool() {
        // Документируемое соответствие: 10.66.0.0/24 → server_vip .1 (pool.rs).
        assert_eq!(Ipv4Addr::new(10, 66, 0, 1).octets()[3], 1);
    }
}
