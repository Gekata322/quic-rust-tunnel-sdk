//! Routing table: an assigned virtual address → the send channel of the
//! concrete client.
//!
//! On registration a session puts the `mpsc::Sender` of its send task here;
//! packets addressed to that `vip` (from other clients or from the TUN) go
//! through the channel. `unregister` is idempotent on the (address, sender)
//! pair: a live client cannot be overwritten by a dead session's channel.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use tokio::sync::mpsc;

/// "Assigned address → client send queue".
#[derive(Debug, Default)]
pub struct RoutingTable {
    clients: Mutex<HashMap<Ipv4Addr, mpsc::Sender<Vec<u8>>>>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a client: address → the send channel of its task.
    /// Registering the same address again overwrites the old entry (a dead
    /// session lost its channel before the new one came up).
    pub fn register(&self, vip: Ipv4Addr, sender: mpsc::Sender<Vec<u8>>) {
        self.clients.lock().expect("table mutex").insert(vip, sender);
    }

    /// Removes the registration; returns `true` only if the entry belonged to
    /// exactly this session (another session's entry cannot be erased).
    pub fn unregister(&self, vip: Ipv4Addr, sender: &mpsc::Sender<Vec<u8>>) -> bool {
        let mut clients = self.clients.lock().expect("table mutex");
        match clients.get(&vip) {
            Some(existing) if existing.same_channel(sender) => {
                clients.remove(&vip);
                true
            }
            _ => false,
        }
    }

    /// Where to route a packet addressed to `dst`; `None` — the address was
    /// not issued to anyone (the packet goes to the TUN/outside or is garbage).
    pub fn route(&self, dst: Ipv4Addr) -> Option<mpsc::Sender<Vec<u8>>> {
        self.clients.lock().expect("table mutex").get(&dst).cloned()
    }

    /// Number of active clients in the table.
    pub fn active(&self) -> usize {
        self.clients.lock().expect("table mutex").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender_pair() -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        mpsc::channel(8)
    }

    fn vip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 66, 0, last)
    }

    #[tokio::test]
    async fn register_and_route() {
        let table = RoutingTable::new();
        let (tx, mut rx) = sender_pair();
        table.register(vip(2), tx);
        assert_eq!(table.active(), 1);

        let routed = table.route(vip(2)).expect("client registered");
        routed.send(vec![0xDE]).await.expect("channel alive");
        assert_eq!(rx.recv().await, Some(vec![0xDE]));

        assert!(table.route(vip(9)).is_none(), "an unassigned address is not routed");
    }

    #[tokio::test]
    async fn unregister_removes_only_own_entry() {
        let table = RoutingTable::new();
        let (old_tx, _old_rx) = sender_pair();
        let (new_tx, _new_rx) = sender_pair();

        table.register(vip(2), old_tx.clone());
        // A "dead" session tries to unregister a live client by address:
        // someone else's entry is not removed.
        assert!(!table.unregister(vip(2), &new_tx), "must not remove someone else's entry");
        assert!(table.route(vip(2)).is_some(), "the live client stays routable");
        // Correct removal by its own channel:
        assert!(table.unregister(vip(2), &old_tx));
        assert!(table.route(vip(2)).is_none());
        // A repeated removal is a no-op.
        assert!(!table.unregister(vip(2), &old_tx));
        let _ = new_tx;
    }

    #[tokio::test]
    async fn reregistration_replaces_dead_session() {
        let table = RoutingTable::new();
        let (old_tx, old_rx) = sender_pair();
        let (new_tx, mut new_rx) = sender_pair();

        table.register(vip(3), old_tx.clone());
        drop(old_rx); // dead session: reading has ended
        table.register(vip(3), new_tx.clone());
        assert_eq!(table.active(), 1, "an overwrite, not a duplicate");

        new_tx.send(vec![1]).await.expect("the new channel is alive");
        assert_eq!(new_rx.recv().await, Some(vec![1]));
    }
}
