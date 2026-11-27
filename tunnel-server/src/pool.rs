//! Virtual IP pool: assigning addresses to clients and reuse after
//! disconnection.
//!
//! In the subnet (e.g. `10.66.0.0/24`) the first address (`.1`) is reserved
//! for the server (`server_vip`); clients get addresses starting from the
//! second one (`.2`). Addresses are issued sequentially; a freed address
//! becomes a reuse candidate — long sessions do not exhaust the pool.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Mutex;

/// Address pool errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PoolError {
    /// The subnet did not parse or the mask is not byte-aligned (/24..../32).
    #[error("subnet {0:?} is not supported: a CIDR with a byte-aligned mask is required, e.g. 10.66.0.0/24")]
    BadSubnet(String),
    /// The address does not belong to the pool subnet.
    #[error("address {0} is outside the pool subnet")]
    ForeignAddress(Ipv4Addr),
}

/// Sequential address pool of a single /24.../32 subnet.
#[derive(Debug)]
pub struct IpPool {
    /// Network octets of the subnet (the first three for /24).
    prefix: [u8; 3],
    /// Client host-octet bounds: 2..=last_client_host
    /// (the network .0 is not issued, neither is the broadcast, .1 is the server).
    first_client_host: u8,
    last_client_host: u8,
    /// Server address — the first address of the subnet, never issued to clients.
    server_vip: Ipv4Addr,
    /// Taken client host octets (the last octet).
    taken: Mutex<BTreeSet<u8>>,
    /// Issuing cursor: grows to the last client, then reuses freed addresses.
    cursor: Mutex<u8>,
}

impl IpPool {
    /// Parses a subnet like `10.66.0.0/24` (mask is a multiple of a byte).
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
        // Host block size: 256 for /24, 4 for /30, 1 for /32.
        let block = 1u32 << (32 - u32::from(mask_bits));
        // The server address is the first usable host of the subnet (.1 for /24, /30, ...).
        let server_host: u8 = if block >= 2 { 1 } else { 0 };
        let server_vip = Ipv4Addr::new(prefix[0], prefix[1], prefix[2], server_host);
        // Client addresses: from .2 (after the server) to broadcast-1 (.254 for /24).
        // For /31 and /32 last_client_host=0 < first=2 → zero capacity.
        let first_client_host: u8 = 2;
        let last_client_host: u8 = if block >= 4 {
            (block - 2) as u8 // 256-2 = 254 for /24; 4-2 = 2 for /30
        } else {
            0 // /31, /32: no client addresses
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

    /// The server address in this subnet (the first one).
    pub fn server_vip(&self) -> Ipv4Addr {
        self.server_vip
    }

    /// Pool capacity for clients: usable addresses minus network, broadcast and server.
    pub fn capacity(&self) -> usize {
        if self.last_client_host < self.first_client_host {
            return 0;
        }
        usize::from(self.last_client_host - self.first_client_host + 1)
    }

    /// Issues the next free address. `None` — the pool is exhausted
    /// (the server answers `Reject{ServerBusy}`).
    pub fn alloc(&self) -> Option<Ipv4Addr> {
        let mut taken = self.taken.lock().expect("pool mutex");
        let mut cursor = self.cursor.lock().expect("cursor mutex");
        // Forward pass: the cursor walks the client host octets (from .2 for /24).
        while *cursor < self.last_client_host {
            *cursor += 1;
            let host = *cursor;
            if !taken.contains(&host) {
                taken.insert(host);
                return Some(self.address(host));
            }
        }
        // The cursor is exhausted: scan for freed addresses from the start.
        for host in self.first_client_host..=self.last_client_host {
            if !taken.contains(&host) {
                taken.insert(host);
                *cursor = host;
                return Some(self.address(host));
            }
        }
        None
    }

    /// Returns an address to the pool after a client disconnects.
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
        Ok(self.taken.lock().expect("pool mutex").remove(&host))
    }

    /// Number of issued addresses (for metrics and diagnostics).
    pub fn allocated(&self) -> usize {
        self.taken.lock().expect("pool mutex").len()
    }

    /// Builds the full address from the prefix and the host octet.
    fn address(&self, host: u8) -> Ipv4Addr {
        Ipv4Addr::new(self.prefix[0], self.prefix[1], self.prefix[2], host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_vip_is_first_address() {
        let pool = IpPool::from_subnet("10.66.0.0/24").expect("subnet");
        assert_eq!(pool.server_vip(), Ipv4Addr::new(10, 66, 0, 1));
        assert_eq!(pool.capacity(), 253, "256 - network - broadcast - server");
    }

    #[test]
    fn sequential_alloc_starts_from_second_host() {
        let pool = IpPool::from_subnet("10.66.0.0/24").expect("subnet");
        assert_eq!(pool.alloc().map(|ip| ip.octets()[3]), Some(2), "the first client gets .2");
        assert_eq!(pool.alloc().map(|ip| ip.octets()[3]), Some(3));
        assert_eq!(pool.alloc().map(|ip| ip.octets()[3]), Some(4));
        assert_eq!(pool.allocated(), 3);
    }

    #[test]
    fn alloc_covers_full_range_and_stops() {
        let pool = IpPool::from_subnet("10.66.0.0/30").expect("subnet");
        let only = pool.alloc().expect("the single address .2");
        assert_eq!(only, std::net::Ipv4Addr::new(10, 66, 0, 2));
        assert!(pool.alloc().is_none());
        // A repeated alloc after release issues .2 again.
        pool.release(only).expect("returned to the pool");
        assert_eq!(pool.alloc(), Some(only));
    }

    #[test]
    fn released_address_is_reused() {
        // Exhaust a small pool (/29: 5 client addresses .2..6), then free the
        // middle one — reuse finds it on the second pass.
        let pool = IpPool::from_subnet("10.66.0.0/29").expect("subnet");
        assert_eq!(pool.capacity(), 5);
        let mut issued = Vec::new();
        for _ in 0..5 {
            issued.push(pool.alloc().expect("address"));
        }
        assert!(pool.alloc().is_none(), "the cursor is exhausted");
        let freed = issued[2]; // .4
        assert!(pool.release(freed).expect("address from the subnet"));
        assert_eq!(pool.allocated(), 4);
        let reused = pool.alloc().expect("reused address");
        assert_eq!(reused, freed, "the freed address is issued again");
    }

    #[test]
    fn release_rejects_foreign_addresses() {
        let pool = IpPool::from_subnet("10.66.0.0/24").expect("subnet");
        assert!(matches!(
            pool.release(Ipv4Addr::new(192, 168, 0, 2)),
            Err(PoolError::ForeignAddress(_))
        ));
        // The server address is never returned to the client pool.
        assert!(matches!(
            pool.release(Ipv4Addr::new(10, 66, 0, 1)),
            Err(PoolError::ForeignAddress(_))
        ));
        // Own but free addresses return Ok(false), not an error.
        assert_eq!(pool.release(Ipv4Addr::new(10, 66, 0, 99)), Ok(false));
    }

    #[test]
    fn bad_subnets_are_rejected() {
        assert!(matches!(IpPool::from_subnet("10.66.0.0"), Err(PoolError::BadSubnet(_))));
        assert!(matches!(IpPool::from_subnet("10.66.0.0/23"), Err(PoolError::BadSubnet(_))));
        assert!(matches!(IpPool::from_subnet("10.66.0/24"), Err(PoolError::BadSubnet(_))));
        assert!(matches!(IpPool::from_subnet("10.66.0.0/33"), Err(PoolError::BadSubnet(_))));
        // Masks 24..32 are all valid: /28 gives 13 client addresses.
        let narrow = IpPool::from_subnet("10.66.0.0/28").expect("subnet");
        assert_eq!(narrow.capacity(), 13);
        assert!(IpPool::from_subnet("10.66.0.0/32").is_ok(), "/32: server only, 0 clients");
    }

    #[test]
    fn capacity_zero_for_slash_32() {
        let pool = IpPool::from_subnet("10.66.0.0/32").expect("subnet");
        assert_eq!(pool.capacity(), 0);
        assert!(pool.alloc().is_none(), "no addresses for clients");
    }

    #[test]
    fn full_pool_returns_none() {
        let pool = IpPool::from_subnet("10.66.0.0/30").expect("subnet");
        // /30: 4 addresses = network + 2 hosts + broadcast; the server takes .1 → 1 client.
        assert_eq!(pool.capacity(), 1);
        let only = pool.alloc().expect("the only client address");
        assert_eq!(only.octets()[3], 2);
        assert!(pool.alloc().is_none(), "the pool is exhausted");
    }
}
