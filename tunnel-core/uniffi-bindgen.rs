//! Утилита генерации FFI-биндингов uniffi для партнёрских SDK.
//!
//! Одна команда генерирует привязки сразу для трёх языков:
//! ```bash
//! cargo build -p tunnel-core
//! cargo run -p tunnel-core --bin uniffi-bindgen -- \
//!     generate-all --library target/debug/libtunnel_core.so --out-dir bindings
//! ```
//! Результат: `bindings/kotlin/`, `bindings/swift/`, `bindings/python/`.
//!
//! Отдельный язык — стандартный CLI uniffi:
//! ```bash
//! cargo run -p tunnel-core --bin uniffi-bindgen -- \
//!     generate --library <lib> --language swift --out-dir <dir>
//! ```

use std::process::Command;

/// Языки, генерируемые `generate-all`; порядок — как в `dist/` SDK.
const LANGUAGES: [&str; 3] = ["kotlin", "swift", "python"];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("generate-all") {
        std::process::exit(generate_all(&args));
    }
    uniffi::uniffi_bindgen_main()
}

/// `generate-all --library <путь> --out-dir <каталог>`: генерирует биндинги
/// для всех поддерживаемых языков в подкаталоги по имени языка.
/// Реализация — вызовы стандартного CLI через `current_exe`: надёжнее, чем
/// программный API uniffi_bindgen, при апгрейдах версии.
fn generate_all(args: &[String]) -> i32 {
    let mut library = None;
    let mut out_dir = None;
    let mut iterator = args.iter();
    while let Some(arg) = iterator.next() {
        match arg.as_str() {
            "--library" => library = iterator.next().cloned(),
            "--out-dir" => out_dir = iterator.next().cloned(),
            _ => {}
        }
    }
    let (Some(library), Some(out_dir)) = (library, out_dir) else {
        eprintln!("использование: uniffi-bindgen generate-all --library <libtunnel_core.so> --out-dir <dir>");
        return 2;
    };

    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            eprintln!("не удалось определить путь к uniffi-bindgen: {err}");
            return 1;
        }
    };

    for language in LANGUAGES {
        let lang_dir = format!("{out_dir}/{language}");
        println!("uniffi-bindgen: генерирую {language} → {lang_dir}");
        let status = Command::new(&exe)
            .args([
                "generate",
                "--library",
                &library,
                "--language",
                language,
                "--out-dir",
                &lang_dir,
            ])
            .status();
        match status {
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!("uniffi-bindgen: {language} завершился с ошибкой ({status})");
                return 1;
            }
            Err(err) => {
                eprintln!("uniffi-bindgen: не удалось запустить генерацию {language}: {err}");
                return 1;
            }
        }
    }
    println!("uniffi-bindgen: готово → {out_dir}/{{kotlin,swift,python}} (из {library})");
    0
}
