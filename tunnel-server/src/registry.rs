//! Live token registry: the immutable startup store plus hot admin changes.
//!
//! `tunnel_proto::auth::TokenStore` is loaded once at startup and never
//! changes; the admin API must add tokens and revoke them while the server
//! runs. [`TokenRegistry`] keeps the store's verification semantics — a
//! linear scan over entries with a constant-time token comparison — so an
//! unknown `client_id` stays indistinguishable from a wrong token by timing.
//!
//! Changes are in-memory only: the token file and `TUNNEL_TOKENS` are never
//! rewritten, so a server restart reverts to the file state. Persistence is
//! the operator's deployment concern (roadmap: an append-only audit log).

use std::sync::RwLock;

use tunnel_proto::auth::{TokenEntry, TokenStore, const_time_eq};

/// Thread-safe registry of partner credentials: `verify`/`limit_of` mirror
/// [`TokenStore`], `upsert`/`remove` serve the admin API.
#[derive(Debug, Default)]
pub struct TokenRegistry {
    entries: RwLock<Vec<TokenEntry>>,
}

impl TokenRegistry {
    /// Builds the registry from the startup store.
    pub fn from_store(store: &TokenStore) -> Self {
        Self {
            entries: RwLock::new(store.entries().to_vec()),
        }
    }

    /// Constant-time check of a client_id/token pair (same semantics as
    /// `TokenStore::verify`).
    pub fn verify(&self, client_id: &str, token: &str) -> bool {
        self.entries
            .read()
            .expect("registry lock")
            .iter()
            .any(|entry| {
                entry.client_id == client_id
                    && const_time_eq(token.as_bytes(), entry.token.as_bytes())
            })
    }

    /// The data-plane bandwidth cap of `client_id` in Mbps; `None` —
    /// unlimited (or unknown client — consult only after `verify`).
    pub fn limit_of(&self, client_id: &str) -> Option<u32> {
        self.entries
            .read()
            .expect("registry lock")
            .iter()
            .find(|entry| entry.client_id == client_id)
            .and_then(|entry| entry.rate_limit_mbps)
    }

    /// Inserts a new entry or replaces the one with the same `client_id`.
    /// Returns `true` when an existing entry was replaced. Live sessions of
    /// that client are untouched — revocation is a separate call.
    pub fn upsert(&self, entry: TokenEntry) -> bool {
        let mut entries = self.entries.write().expect("registry lock");
        match entries
            .iter_mut()
            .find(|existing| existing.client_id == entry.client_id)
        {
            Some(slot) => {
                *slot = entry;
                true
            }
            None => {
                entries.push(entry);
                false
            }
        }
    }

    /// Removes every entry of `client_id`; returns the first removed one,
    /// `None` when the client is unknown.
    pub fn remove(&self, client_id: &str) -> Option<TokenEntry> {
        let mut entries = self.entries.write().expect("registry lock");
        let first = entries
            .iter()
            .position(|entry| entry.client_id == client_id)?;
        let removed = entries.remove(first);
        entries.retain(|entry| entry.client_id != client_id);
        Some(removed)
    }

    /// Number of stored entries (admin `/stats`).
    pub fn len(&self) -> usize {
        self.entries.read().expect("registry lock").len()
    }

    /// True when the registry holds no tokens.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> TokenStore {
        TokenStore::from_entries(vec![
            TokenEntry {
                client_id: "partner-a".to_owned(),
                token: "tok-a".to_owned(),
                rate_limit_mbps: Some(10),
            },
            TokenEntry {
                client_id: "partner-b".to_owned(),
                token: "tok-b".to_owned(),
                rate_limit_mbps: None,
            },
        ])
    }

    #[test]
    fn verify_and_limit_of_mirror_the_store() {
        let registry = TokenRegistry::from_store(&store());
        assert!(registry.verify("partner-a", "tok-a"));
        assert!(registry.verify("partner-b", "tok-b"));
        assert!(!registry.verify("partner-a", "tok-b"), "wrong token");
        assert!(!registry.verify("unknown", "tok-a"));
        assert_eq!(registry.limit_of("partner-a"), Some(10));
        assert_eq!(registry.limit_of("partner-b"), None, "no cap configured");
        assert_eq!(registry.limit_of("unknown"), None);
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn upsert_inserts_new_and_replaces_known_client() {
        let registry = TokenRegistry::from_store(&store());

        let replaced = registry.upsert(TokenEntry {
            client_id: "partner-c".to_owned(),
            token: "tok-c".to_owned(),
            rate_limit_mbps: Some(5),
        });
        assert!(!replaced, "a new client is created, not replaced");
        assert!(registry.verify("partner-c", "tok-c"));
        assert_eq!(registry.limit_of("partner-c"), Some(5));

        let replaced = registry.upsert(TokenEntry {
            client_id: "partner-c".to_owned(),
            token: "tok-c2".to_owned(),
            rate_limit_mbps: None,
        });
        assert!(replaced, "an existing client is replaced");
        assert!(!registry.verify("partner-c", "tok-c"), "the old token is gone");
        assert!(registry.verify("partner-c", "tok-c2"));
        assert_eq!(registry.limit_of("partner-c"), None, "the cap is replaced too");
        assert_eq!(registry.len(), 3, "the total count stays stable on replace");
    }

    #[test]
    fn remove_revokes_and_reports_unknown_clients() {
        let registry = TokenRegistry::from_store(&store());

        let removed = registry.remove("partner-a").expect("known client");
        assert_eq!(removed.client_id, "partner-a");
        assert!(!registry.verify("partner-a", "tok-a"), "revoked");
        assert_eq!(registry.len(), 1);

        assert!(
            registry.remove("partner-a").is_none(),
            "a second removal finds nothing"
        );
        assert!(registry.remove("unknown").is_none());

        // Duplicates (possible from a hand-edited file) are all removed.
        registry.upsert(TokenEntry {
            client_id: "dup".to_owned(),
            token: "d1".to_owned(),
            rate_limit_mbps: None,
        });
        registry.upsert(TokenEntry {
            client_id: "dup".to_owned(),
            token: "d2".to_owned(),
            rate_limit_mbps: None,
        });
        registry.upsert(TokenEntry {
            client_id: "dup".to_owned(),
            token: "d3".to_owned(),
            rate_limit_mbps: None,
        });
        assert!(registry.remove("dup").is_some());
        assert!(!registry.verify("dup", "d2"), "every duplicate is gone");
        assert!(!registry.verify("dup", "d3"));
    }

    #[test]
    fn empty_registry_rejects_everything() {
        let registry = TokenRegistry::default();
        assert!(registry.is_empty());
        assert!(!registry.verify("any", "thing"));
        assert_eq!(registry.limit_of("any"), None);
    }
}
