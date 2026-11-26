//! Пул виртуальных IP: выдача адресов клиентам и переиспользование после
//! отсоединения.
//!
//! Из подсети (например `10.66.0.0/24`) первый адрес (`.1`) закреплён за
//! сервером (`server_vip`), клиентам выдаются адреса со второго (`.2`).
//! Адреса выдаются последовательно; освободившийся адрес становится
//! кандидатом на переиспользование — длинные сессии не растрачивают пул.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Mutex;

/// Ошибки работы с пулом адресов.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PoolError {
    /// Подсеть не распарсилась или маска не байтовая (/24..../32).
    #[error("подсеть «{0}» не поддерживается: нужен CIDR с байтовой маской, например 10.66.0.0/24")]
    BadSubnet(String),
    /// Адрес не принадлежит подсети пула.
    #[error("адрес {0} вне подсети пула")]
    ForeignAddress(Ipv4Addr),
}

/// Последовательный пул адресов одной подсети /24.../32.
#[derive(Debug)]
pub struct IpPool {
    /// Сетевые октеты подсети (для /24 — первые три).
    prefix: [u8; 3],
    /// Границы клиентских хост-октетов: 2..=last_client_host
    /// (сеть .0 не выдаётся, broadcast не выдаётся, .1 — сервер).
    first_client_host: u8,
    last_client_host: u8,
    /// Серверный адрес — первый адрес подсети, никогда не выдаётся клиентам.
    server_vip: Ipv4Addr,
    /// Занятые клиентские октеты (последний октет).
    taken: Mutex<BTreeSet<u8>>,
    /// Курсор выдачи: растёт до последнего клиента, потом переиспользует свободные.
    cursor: Mutex<u8>,
}

impl IpPool {
    /// Разбирает подсеть вида `10.66.0.0/24` (маска кратна байту).
    pub fn from_subnet(subnet: &str) -> Result<Self, PoolError> {
        let (addr, mask) = subnet
            .trim()
            .split_once('/')
            .ok_or_else(|| PoolError::BadSubnet(subnet.to_owned()))?;
        let mask_bits: u8 = mask
            .trim()
            .parse()
            .map_err(|_| PoolError::BadSubnet(subnet.to_owned()))?;
        if !(24..=32).contains(&mask_bits) {
            return Err(PoolError::BadSubnet(subnet.to_owned()));
        }
        let octets: Vec<u8> = addr
            .split('.')
            .map(|octet| octet.parse().map_err(|_| PoolError::BadSubnet(subnet.to_owned())))
            .collect::<Result<_, _>>()?;
        if octets.len() != 4 {
            return Err(PoolError::BadSubnet(subnet.to_owned()));
        }
        let prefix = [octets[0], octets[1], octets[2]];
        // Размер блока хостов: 256 для /24, 4 для /30, 1 для /32.
        let block = 1u32 << (32 - u32::from(mask_bits));
        // Серверный адрес — первый usable-хост подсети (.1 для /24, /30, ...).
        let server_host: u8 = if block >= 2 { 1 } else { 0 };
        let server_vip = Ipv4Addr::new(prefix[0], prefix[1], prefix[2], server_host);
        // Клиентские адреса: от .2 (после сервера) до broadcast-1 (для /24 — .254).
        // Для /31 и /32 last_client_host=0 < first=2 → ёмкость нулевая.
        let first_client_host: u8 = 2;
        let last_client_host: u8 = if block >= 4 {
            (block - 2) as u8 // 256-2 = 254 для /24; 4-2 = 2 для /30
        } else {
            0 // /31, /32: клиентских адресов нет
        };
        Ok(Self {
            prefix,
            first_client_host,
            last_client_host,
            server_vip,
            taken: Mutex::new(BTreeSet::new()),
            cursor: Mutex::new(first_client_host - 1),
        })
    }

    /// Адрес сервера в этой подсети (первый адрес).
    pub fn server_vip(&self) -> Ipv4Addr {
        self.server_vip
    }

    /// Ёмкость пула для клиентов: usable-адреса минус сеть, broadcast и сервер.
    pub fn capacity(&self) -> usize {
        if self.last_client_host < self.first_client_host {
            return 0;
        }
        usize::from(self.last_client_host - self.first_client_host + 1)
    }

    /// Выдаёт следующий свободный адрес. `None` — пул исчерпан
    /// (сервер отвечает `Reject{ServerBusy}`).
    pub fn alloc(&self) -> Option<Ipv4Addr> {
        let mut taken = self.taken.lock().expect("мьютекс пула");
        let mut cursor = self.cursor.lock().expect("мьютекс курсора");
        // Прямой ход: cursor идёт по клиентским хост-октетам (для /24 — с .2).
        while *cursor < self.last_client_host {
            *cursor += 1;
            let host = *cursor;
            if !taken.contains(&host) {
                taken.insert(host);
                return Some(self.address(host));
            }
        }
        // Курсор исчерпан: ищем освобождённые с начала.
        for host in self.first_client_host..=self.last_client_host {
            if !taken.contains(&host) {
                taken.insert(host);
                *cursor = host;
                return Some(self.address(host));
            }
        }
        None
    }

    /// Возвращает адрес в пул после отсоединения клиента.
    pub fn release(&self, ip: Ipv4Addr) -> Result<bool, PoolError> {
        if ip.octets()[0..3] != self.prefix {
            return Err(PoolError::ForeignAddress(ip));
        }
        let host = ip.octets()[3];
        if host == self.server_vip.octets()[3]
            || self.capacity() == 0
            || !(self.first_client_host..=self.last_client_host).contains(&host)
        {
            return Err(PoolError::ForeignAddress(ip));
        }
        Ok(self.taken.lock().expect("мьютекс пула").remove(&host))
    }

    /// Число выданных адресов (для метрик и диагностики).
    pub fn allocated(&self) -> usize {
        self.taken.lock().expect("мьютекс пула").len()
    }

    /// Собирает полный адрес из префикса и хост-октета.
    fn address(&self, host: u8) -> Ipv4Addr {
        Ipv4Addr::new(self.prefix[0], self.prefix[1], self.prefix[2], host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_vip_is_first_address() {
        let pool = IpPool::from_subnet("10.66.0.0/24").expect("подсеть");
        assert_eq!(pool.server_vip(), Ipv4Addr::new(10, 66, 0, 1));
        assert_eq!(pool.capacity(), 253, "256 - сеть - broadcast - сервер");
    }

    #[test]
    fn sequential_alloc_starts_from_second_host() {
        let pool = IpPool::from_subnet("10.66.0.0/24").expect("подсеть");
        assert_eq!(pool.alloc().map(|ip| ip.octets()[3]), Some(2), "первый клиент — .2");
        assert_eq!(pool.alloc().map(|ip| ip.octets()[3]), Some(3));
        assert_eq!(pool.alloc().map(|ip| ip.octets()[3]), Some(4));
        assert_eq!(pool.allocated(), 3);
    }

    #[test]
    fn alloc_covers_full_range_and_stops() {
        let pool = IpPool::from_subnet("10.66.0.0/30").expect("подсеть");
        let only = pool.alloc().expect("единственный адрес .2");
        assert_eq!(only, std::net::Ipv4Addr::new(10, 66, 0, 2));
        assert!(pool.alloc().is_none());
        // Повторный alloc после release снова выдаёт .2.
        pool.release(only).expect("возврат в пул");
        assert_eq!(pool.alloc(), Some(only));
    }

    #[test]
    fn released_address_is_reused() {
        // Исчерпываем маленький пул (/29: 6 клиентских адресов .2..6), затем
        // освобождаем середину — переиспользование находит её вторым проходом.
        let pool = IpPool::from_subnet("10.66.0.0/29").expect("подсеть");
        assert_eq!(pool.capacity(), 5);
        let mut issued = Vec::new();
        for _ in 0..5 {
            issued.push(pool.alloc().expect("адрес"));
        }
        assert!(pool.alloc().is_none(), "курсор исчерпан");
        let freed = issued[2]; // .4
        assert!(pool.release(freed).expect("адрес из подсети"));
        assert_eq!(pool.allocated(), 4);
        let reused = pool.alloc().expect("переиспользованный адрес");
        assert_eq!(reused, freed, "освободившийся адрес выдаётся снова");
    }

    #[test]
    fn release_rejects_foreign_addresses() {
        let pool = IpPool::from_subnet("10.66.0.0/24").expect("подсеть");
        assert!(matches!(
            pool.release(Ipv4Addr::new(192, 168, 0, 2)),
            Err(PoolError::ForeignAddress(_))
        ));
        // Серверный адрес не возвращается в пул клиентов.
        assert!(matches!(
            pool.release(Ipv4Addr::new(10, 66, 0, 1)),
            Err(PoolError::ForeignAddress(_))
        ));
        // Свои, но свободные адреса возвращают Ok(false), а не ошибку.
        assert_eq!(pool.release(Ipv4Addr::new(10, 66, 0, 99)), Ok(false));
    }

    #[test]
    fn bad_subnets_are_rejected() {
        assert!(matches!(IpPool::from_subnet("10.66.0.0"), Err(PoolError::BadSubnet(_))));
        assert!(matches!(IpPool::from_subnet("10.66.0.0/23"), Err(PoolError::BadSubnet(_))));
        assert!(matches!(IpPool::from_subnet("10.66.0/24"), Err(PoolError::BadSubnet(_))));
        assert!(matches!(IpPool::from_subnet("10.66.0.0/33"), Err(PoolError::BadSubnet(_))));
        // Маски 24..32 — любые: /28 даёт 13 клиентских адресов.
        let narrow = IpPool::from_subnet("10.66.0.0/28").expect("подсеть");
        assert_eq!(narrow.capacity(), 13);
        assert!(IpPool::from_subnet("10.66.0.0/32").is_ok(), "/32: только сервер, 0 клиентов");
    }

    #[test]
    fn capacity_zero_for_slash_32() {
        let pool = IpPool::from_subnet("10.66.0.0/32").expect("подсеть");
        assert_eq!(pool.capacity(), 0);
        assert!(pool.alloc().is_none(), "нет адресов для клиентов");
    }

    #[test]
    fn full_pool_returns_none() {
        let pool = IpPool::from_subnet("10.66.0.0/30").expect("подсеть");
        // /30: 4 адреса = сеть + 2 хоста + broadcast; сервер занимает .1 → 1 клиент.
        assert_eq!(pool.capacity(), 1);
        let only = pool.alloc().expect("единственный клиентский адрес");
        assert_eq!(only.octets()[3], 2);
        assert!(pool.alloc().is_none(), "пул исчерпан");
    }
}
