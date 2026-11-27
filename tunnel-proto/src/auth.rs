//! B2B auth tokens: plaintext storage, constant-time verification.
//!
//! Sources are `client_id:token` pairs:
//! - file: one pair per line, `#` starts a comment;
//! - `TUNNEL_TOKENS` env var: comma-separated pairs
//!   (`"partner-a:tok-1,partner-b:tok-2"`).
//!
//! Tokens are held in memory as plain text (MVP: rotation and HMAC are
//! roadmap items), but verification runs in **constant time** — response
//! latency never hints at how long a matched prefix is.

/// Store of `(client_id, token)` pairs loaded from a file or the environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenStore {
    entries: Vec<(String, String)>,
}

impl TokenStore {
    /// Builds the store from ready pairs (tests, programmatic setup).
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self { entries: pairs }
    }

    /// Reads `"client_id:token"` pairs from a file line by line, skipping
    /// `#` comments and blank lines. Values are trimmed.
    pub fn from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::from_pairs(parse_pairs(&text)))
    }

    /// Reads `TUNNEL_TOKENS` (`"a:t1,b:t2"`); `None` when unset or empty.
    pub fn from_env() -> Option<Self> {
        std::env::var("TUNNEL_TOKENS")
            .ok()
            .filter(|text| !text.trim().is_empty())
            .map(|text| Self::from_pairs(parse_pairs(&text)))
    }

    /// Constant-time check of a client_id/token pair.
    ///
    /// Unknown `client_id` returns `false` exactly like a wrong token, so the
    /// server never reveals which identifier exists.
    pub fn verify(&self, client_id: &str, token: &str) -> bool {
        self.entries
            .iter()
            .any(|(id, stored)| id == client_id && const_eq(token.as_bytes(), stored.as_bytes()))
    }

    /// Number of stored pairs.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the store holds no tokens (an empty store rejects everyone).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Stored pairs (diagnostics and tests).
    pub fn pairs(&self) -> &[(String, String)] {
        &self.entries
    }
}

/// Parses `client_id:token` pairs from lines or a comma-separated string,
/// skipping `#` comments and empty entries.
fn parse_pairs(text: &str) -> Vec<(String, String)> {
    text.lines()
        .flat_map(|line| line.split(','))
        .map(|piece| match piece.split_once('#') {
            Some((before, _)) => before,
            None => piece,
        })
        .filter_map(|piece| piece.trim().split_once(':'))
        .map(|(id, token)| (id.trim().to_owned(), token.trim().to_owned()))
        .filter(|(id, token)| !id.is_empty() && !token.is_empty())
        .collect()
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
        assert!(!store.verify("unknown", "tok-1"), "unknown id must not leak via timing hints");
        assert!(!store.verify("", ""), "empty values");
        // A matching token prefix must not authenticate: comparison is exact.
        assert!(!store.verify("partner-a", "tok"));
    }

    #[test]
    fn parse_from_file_format() {
        let text = "# partner example\nexample-ios: b2b-live-a1b2c3d4\n\
                    \nexample-android:b2b-live-e5f6g7h8 # inline comment\n\
                    garbage-line-without-colon\n";
        let store = TokenStore::from_pairs(parse_pairs(text));
        assert_eq!(store.len(), 2, "comments and garbage are dropped");
        assert!(store.verify("example-ios", "b2b-live-a1b2c3d4"));
        assert!(store.verify("example-android", "b2b-live-e5f6g7h8"));
    }

    #[test]
    fn parse_from_env_format() {
        let store = TokenStore::from_pairs(parse_pairs("ci-client:ci-token, py: py-token"));
        assert_eq!(store.len(), 2, "commas separate pairs");
        assert!(store.verify("ci-client", "ci-token"));
        assert!(store.verify("py", "py-token"));
        assert!(!store.verify("py", "ci-token"));
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
