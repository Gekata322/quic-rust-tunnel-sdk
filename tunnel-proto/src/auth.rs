//! B2B-токены авторизации: хранение в открытом виде, сравнение за
//! константное время.
//!
//! Формат источника — пары `client_id:token`:
//! - файл: одна пара на строку, `#` — комментарий до конца строки;
//! - переменная окружения `TUNNEL_TOKENS`: пары через запятую
//!   (`"partner-a:tok-1,partner-b:tok-2"`).
//!
//! Токен в памяти лежит открытым текстом (MVP: rotация и HMAC — на
//! роадмапе), но сравнение выполняется за **константное время** —
//! время ответа сервера не подсказывает переборщиком длину совпавшего
//! префикса.

/// Хранилище пар `(client_id, token)`, поднятых из файла или окружения.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenStore {
    entries: Vec<(String, String)>,
}

impl TokenStore {
    /// Собирает хранилище из готовых пар (unit-тесты, конфигурация из кода).
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self { entries: pairs }
    }

    /// Читает пары из файла: `"client_id:token"` построчно, `#`-комментарии
    /// и пустые строки пропускаются. Значения обрезаются по пробелам.
    pub fn from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::from_pairs(parse_pairs(&text)))
    }

    /// Читает `TUNNEL_TOKENS` (`"a:t1,b:t2"`); `None`, если переменной нет.
    pub fn from_env() -> Option<Self> {
        std::env::var("TUNNEL_TOKENS")
            .ok()
            .filter(|text| !text.trim().is_empty())
            .map(|text| Self::from_pairs(parse_pairs(&text)))
    }

    /// Проверка пары client_id/token за константное время.
    /// Неизвестный client_id — ложь, как и неверный токен (не раскрываем,
    /// существует ли идентификатор).
    pub fn verify(&self, client_id: &str, token: &str) -> bool {
        self.entries
            .iter()
            .any(|(id, stored)| id == client_id && const_eq(token.as_bytes(), stored.as_bytes()))
    }

    /// Число пар в хранилище.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Пустое ли хранилище (сервер без токенов никого не пустит).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Пары (для тестов и диагностики конфигурации).
    pub fn pairs(&self) -> &[(String, String)] {
        &self.entries
    }
}

/// Разбирает текст с парами `client_id:token` (строки или через запятую).
/// `#`-комментарии и пустые записи пропускаются.
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

/// Сравнение байтовых срезов за константное время: XOR-накопление по всей
/// длине, ранний выход только по разнице длин (длина не секрет).
fn const_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_known_pair() {
        let store = TokenStore::from_pairs(vec![
            ("partner-a".to_owned(), "tok-1".to_owned()),
            ("partner-b".to_owned(), "tok-2".to_owned()),
        ]);
        assert!(store.verify("partner-a", "tok-1"));
        assert!(store.verify("partner-b", "tok-2"));
        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
    }

    #[test]
    fn verify_rejects_wrong_token_without_leaking_id() {
        let store = TokenStore::from_pairs(vec![("partner-a".to_owned(), "tok-1".to_owned())]);
        assert!(!store.verify("partner-a", "tok-2"), "неверный токен");
        assert!(!store.verify("unknown", "tok-1"), "неизвестный id");
        assert!(!store.verify("", ""), "пустые значения");
        // Совпадающий префикс токена не пускает: сравнение точное.
        assert!(!store.verify("partner-a", "tok"));
    }

    #[test]
    fn parse_from_file_format() {
        let text = "# партнёр «example»\nexample-ios: b2b-live-a1b2c3d4\n\
                    \nexample-android:b2b-live-e5f6g7h8 # инлайн-комментарий\n\
                    мусорная-строка-без-двоеточия\n";
        let store = TokenStore::from_pairs(parse_pairs(text));
        assert_eq!(store.len(), 2, "комментарии и мусор отброшены");
        assert!(store.verify("example-ios", "b2b-live-a1b2c3d4"));
        assert!(store.verify("example-android", "b2b-live-e5f6g7h8"));
    }

    #[test]
    fn parse_from_env_format() {
        let store = TokenStore::from_pairs(parse_pairs("ci-client:ci-token, py: py-token"));
        assert_eq!(store.len(), 2, "запятые разделяют пары");
        assert!(store.verify("ci-client", "ci-token"));
        assert!(store.verify("py", "py-token"));
        assert!(!store.verify("py", "ci-token"));
    }

    #[test]
    fn const_eq_behaves() {
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
