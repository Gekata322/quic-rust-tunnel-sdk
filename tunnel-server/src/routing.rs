//! Таблица маршрутизации: выданный виртуальный адрес → канал отправки
//! конкретному клиенту.
//!
//! Сессия клиента при регистрации кладёт сюда `mpsc::Sender` своей задачи
//! отправки; пакеты, адресованные этому `vip` (от других клиентов или из
//! TUN), уходят по каналу. `unregister` идемпотентен по паре (адрес,
//! отправитель): затереть живого клиента каналом мёртвой сессии нельзя.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use tokio::sync::mpsc;

/// «Выданный адрес → очередь отправки клиенту».
#[derive(Debug, Default)]
pub struct RoutingTable {
    clients: Mutex<HashMap<Ipv4Addr, mpsc::Sender<Vec<u8>>>>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Регистрирует клиента: адрес → канал его задачи отправки.
    /// Повторная регистрация того же адреса перезаписывает старую запись
    /// (мёртвая сессия успела потерять канал раньше, чем новая поднялась).
    pub fn register(&self, vip: Ipv4Addr, sender: mpsc::Sender<Vec<u8>>) {
        self.clients.lock().expect("мьютекс таблицы").insert(vip, sender);
    }

    /// Снимает регистрацию; возвращает `true`, только если запись
    /// принадлежала именно этой сессии (чужую запись затереть нельзя).
    pub fn unregister(&self, vip: Ipv4Addr, sender: &mpsc::Sender<Vec<u8>>) -> bool {
        let mut clients = self.clients.lock().expect("мьютекс таблицы");
        match clients.get(&vip) {
            Some(existing) if existing.same_channel(sender) => {
                clients.remove(&vip);
                true
            }
            _ => false,
        }
    }

    /// Куда адресовать пакет с получателем `dst`; `None` — адрес не выдан
    /// никому (пакет в TUN/наружу или мусор).
    pub fn route(&self, dst: Ipv4Addr) -> Option<mpsc::Sender<Vec<u8>>> {
        self.clients.lock().expect("мьютекс таблицы").get(&dst).cloned()
    }

    /// Число активных клиентов в таблице.
    pub fn active(&self) -> usize {
        self.clients.lock().expect("мьютекс таблицы").len()
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

        let routed = table.route(vip(2)).expect("клиент зарегистрирован");
        routed.send(vec![0xDE]).await.expect("канал жив");
        assert_eq!(rx.recv().await, Some(vec![0xDE]));

        assert!(table.route(vip(9)).is_none(), "невыданный адрес не маршрутизируется");
    }

    #[tokio::test]
    async fn unregister_removes_only_own_entry() {
        let table = RoutingTable::new();
        let (old_tx, _old_rx) = sender_pair();
        let (new_tx, _new_rx) = sender_pair();

        table.register(vip(2), old_tx.clone());
        // «Мёртвая» сессия пытается снять регистрацию живого клиента по адресу:
        // чужая запись не снимается.
        assert!(!table.unregister(vip(2), &new_tx), "чужую запись снимать нельзя");
        assert!(table.route(vip(2)).is_some(), "живой клиент остаётся маршрутизируемым");
        // Правильное снятие своим каналом:
        assert!(table.unregister(vip(2), &old_tx));
        assert!(table.route(vip(2)).is_none());
        // Повторное снятие — уже ничего.
        assert!(!table.unregister(vip(2), &old_tx));
        let _ = new_tx;
    }

    #[tokio::test]
    async fn reregistration_replaces_dead_session() {
        let table = RoutingTable::new();
        let (old_tx, old_rx) = sender_pair();
        let (new_tx, mut new_rx) = sender_pair();

        table.register(vip(3), old_tx.clone());
        drop(old_rx); // мёртвая сессия: чтение закончилось
        table.register(vip(3), new_tx.clone());
        assert_eq!(table.active(), 1, "перезапись, а не дубль");

        new_tx.send(vec![1]).await.expect("новый канал жив");
        assert_eq!(new_rx.recv().await, Some(vec![1]));
    }

    #[test]
    fn empty_table_routes_nothing() {
        let table = RoutingTable::new();
        assert_eq!(table.active(), 0);
        assert!(table.route(vip(2)).is_none());
    }
}
