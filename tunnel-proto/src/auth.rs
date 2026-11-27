//! B2B auth tokens: plaintext storage, constant-time verification.
//!
//! Sources are `client_id:token[:rate_limit_mbps]` entries:
//! - file: one entry per line, `#` starts a comment;
//! - `TUNNEL_TOKENS` env var: comma-separated entries
//!   (`"partner-a:tok-1:10mbps,partner-b:tok-2"`).
//!
//! The bandwidth cap is optional: `client_id:token` authorizes a client
//! without any data-plane limit. A bare number (`:10`) means Mbps as well.
//! An entry with an unparsable limit is dropped entirely — a typo must not
//! turn into a silently unlimited client.
//!
//! Tokens are held in memory as plain text (MVP: rotation and HMAC are
//! roadmap items), but verification runs in **constant time** — response
//! latency never hints at how long a matched prefix is.

/// One stored partner credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenEntry {
    /// Partner identifier sent in `Hello`.
    pub client_id: String,
    /// Shared secret compared in constant time.
    pub token: String,
    /// Data-plane bandwidth cap for this client, Mbps; `None` — unlimited.
    /// The server consults it only after `verify` succeeded.
    pub rate_limit_mbps: Option<u32>,
}

/// Store of partner credentials loaded from a file or the environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenStore {
    entries: Vec<TokenEntry>,
}

impl TokenStore {
    /// Builds the store from ready `(client_id, token)` pairs without limits
    /// (tests, programmatic setup).
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self {
            entries: pairs
                .into_iter()
                .map(|(client_id, token)| TokenEntry {
                    client_id,
                    token,
                    rate_limit_mbps: None,
                })
                .collect(),
        }
    }

    /// Builds the store from full entries, limits included.
    pub fn from_entries(entries: Vec<TokenEntry>) -> Self {
        Self { entries }
    }

    /// Reads entries from a file line by line, skipping `#` comments and
    /// blank lines. Values are trimmed.
    pub fn from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::from_entries(parse_entries(&text)))
    }

    /// Reads `TUNNEL_TOKENS` (`"a:t1,b:t2:5mbps"`); `None` when unset or empty.
    pub fn from_env() -> Option<Self> {
        std::env::var("TUNNEL_TOKENS")
            .ok()
            .filter(|text| !text.trim().is_empty())
            .map(|text| Self::from_entries(parse_entries(&text)))
    }

    /// Constant-time check of a client_id/token pair.
    ///
    /// Unknown `client_id` returns `false` exactly like a wrong token, so the
    /// server never reveals which identifier exists.
    pub fn verify(&self, client_id: &str, token: &str) -> bool {
        self.entries.iter().any(|entry| {
            entry.client_id == client_id && const_eq(token.as_bytes(), entry.token.as_bytes())
        })
    }

    /// The data-plane bandwidth cap of `client_id` in Mbps; `None` — unlimited.
    /// Consult only after `verify` succeeded: this lookup does not
    /// authenticate and does not hide which identifiers exist.
    pub fn limit_of(&self, client_id: &str) -> Option<u32> {
        self.entries
            .iter()
            .find(|entry| entry.client_id == client_id)
            .and_then(|entry| entry.rate_limit_mbps)
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the store holds no tokens (an empty store rejects everyone).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Stored entries, limits included (diagnostics and tests).
    pub fn entries(&self) -> &[TokenEntry] {
        &self.entries
    }

    /// Stored `(client_id, token)` pairs (diagnostics and tests).
    pub fn pairs(&self) -> Vec<(String, String)> {
        self.entries
            .iter()
            .map(|entry| (entry.client_id.clone(), entry.token.clone()))
            .collect()
    }
}

/// Parses `client_id:token[:mbps]` entries from lines or a comma-separated
/// string, skipping `#` comments and empty entries. Entries with an
/// unparsable limit are dropped: a typo must not become a silent upgrade
/// to unlimited.
fn parse_entries(text: &str) -> Vec<TokenEntry> {
    text.lines()
        .flat_map(|line| line.split(','))
        .map(|piece| match piece.split_once('#') {
            Some((before, _)) => before,
            None => piece,
        })
        .filter_map(|piece| parse_entry(piece.trim()))
        .collect()
}

/// Splits one entry into at most three `:`-separated fields
/// (`client_id`, `token`, optional bandwidth). A fieldless or empty entry
/// is not stored.
fn parse_entry(piece: &str) -> Option<TokenEntry> {
    let mut fields = piece.splitn(3, ':');
    let client_id = fields.next()?.trim();
    let token = fields.next()?.trim();
    if client_id.is_empty() || token.is_empty() {
        return None;
    }
    let rate_limit_mbps = match fields.next() {
        // An unparsable limit (`?` on None) drops the whole entry: a typo
        // must not become a silently unlimited client.
        Some(spec) => Some(parse_bandwidth(spec)?),
        None => None,
    };
    Some(TokenEntry {
        client_id: client_id.to_owned(),
        token: token.to_owned(),
        rate_limit_mbps,
    })
}

/// Parses a bandwidth spec — `"10mbps"` or a bare `"10"` — into Mbps.
/// Case-insensitive; `0` is rejected (the file format has no "block this
/// client" value; revocation means removing the line).
fn parse_bandwidth(spec: &str) -> Option<u32> {
    let normalized = spec.trim().to_ascii_lowercase();
    let digits = normalized.strip_suffix("mbps").unwrap_or(&normalized).trim();
    let mbps = digits.parse::<u32>().ok()?;
    (mbps > 0).then_some(mbps)
}

/// Constant-time byte-slice equality: XOR accumulates over the whole length;
/// the only early exit is a length mismatch (lengths are not secret).
fn const_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |diff, (x, y)| diff | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_known_pair_and_rejects_others() {
        let store = TokenStore::from_pairs(vec![
            ("partner-a".to_owned(), "tok-1".to_owned()),
            ("partner-b".to_owned(), "tok-2".to_owned()),
        ]);
        assert!(store.verify("partner-a", "tok-1"));
        assert!(store.verify("partner-b", "tok-2"));
        assert!(!store.verify("partner-a", "tok-2"), "wrong token");
        assert!(
            !store.verify("unknown", "tok-1"),
            "unknown id must not leak via timing hints"
        );
        assert!(!store.verify("", ""), "empty values");
        // A matching token prefix must not authenticate: comparison is exact.
        assert!(!store.verify("partner-a", "tok"));
    }

    #[test]
    fn parse_from_file_format() {
        let text = "# partner example\nexample-ios: b2b-live-a1b2c3d4\n\
                    \nexample-android:b2b-live-e5f6g7h8 # inline comment\n\
                    garbage-line-without-colon\n";
        let store = TokenStore::from_entries(parse_entries(text));
        assert_eq!(store.len(), 2, "comments and garbage are dropped");
        assert!(store.verify("example-ios", "b2b-live-a1b2c3d4"));
        assert!(store.verify("example-android", "b2b-live-e5f6g7h8"));
        assert!(
            store.entries().iter().all(|entry| entry.rate_limit_mbps.is_none()),
            "no suffix means no limit"
        );
    }

    #[test]
    fn parse_from_env_format() {
        let store = TokenStore::from_entries(parse_entries("ci-client:ci-token, py: py-token"));
        assert_eq!(store.len(), 2, "commas separate entries");
        assert!(store.verify("ci-client", "ci-token"));
        assert!(store.verify("py", "py-token"));
        assert!(!store.verify("py", "ci-token"));
    }

    #[test]
    fn bandwidth_suffix_is_parsed_into_limits() {
        let store = TokenStore::from_entries(parse_entries(
            "a:tok:10mbps\nb:tok2:5\nC:tok3:2MBPS # case-insensitive suffix",
        ));
        assert_eq!(store.len(), 3);
        assert_eq!(store.limit_of("a"), Some(10), "the documented suffix form");
        assert_eq!(store.limit_of("b"), Some(5), "a bare number means Mbps too");
        assert_eq!(store.limit_of("C"), Some(2), "the suffix is case-insensitive");
        // Authentication is unaffected by the limit field.
        assert!(store.verify("a", "tok"));
    }

    #[test]
    fn malformed_bandwidth_drops_the_whole_entry() {
        let store = TokenStore::from_entries(parse_entries(
            "a:tok:abc\nb:tok:0\nc:tok:\nd:tok:10.5\ne:tok:20mbps",
        ));
        assert_eq!(store.len(), 1, "only the valid entry survives");
        assert!(store.verify("e", "tok"));
        assert_eq!(store.limit_of("e"), Some(20));
    }

    #[test]
    fn token_may_not_contain_extra_colons() {
        let store = TokenStore::from_entries(parse_entries("a:b:c:d\ne:f"));
        assert_eq!(store.len(), 1, "four fields is malformed and dropped");
        assert!(store.verify("e", "f"));
    }

    #[test]
    fn limit_of_matches_verify_semantics() {
        let store = TokenStore::from_pairs(vec![("a".to_owned(), "t".to_owned())]);
        assert_eq!(store.limit_of("a"), None, "no suffix means unlimited");
        assert_eq!(store.limit_of("unknown"), None);
    }

    #[test]
    fn const_eq_covers_length_and_content() {
        assert!(const_eq(b"abc", b"abc"));
        assert!(!const_eq(b"abc", b"abd"));
        assert!(!const_eq(b"abc", b"abcd"));
        assert!(const_eq(b"", b""));
    }

    #[test]
    fn empty_store_rejects_everything() {
        let store = TokenStore::default();
        assert!(store.is_empty());
        assert!(!store.verify("any", "thing"));
    }
}
