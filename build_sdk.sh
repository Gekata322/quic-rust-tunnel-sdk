#!/usr/bin/env bash
#
# Сборка коммерческого SDK `tunnel-core`: релизные библиотеки + биндинги
# для Swift (iOS/macOS), Kotlin (Android) и Python → готовая папка dist/.
#
# Использование:
#   ./build_sdk.sh                 # тесты + release-сборка + биндинги + dist/
#   ./build_sdk.sh --skip-tests    # без прогона тестов (быстрая пересборка)
#
# Результат (см. dist/README.md и INTEGRATION.md):
#   dist/lib/<host-triple>/        libtunnel_core.so/.dylib + libtunnel_core.a
#   dist/android/kotlin/           биндинги Kotlin (+ jniLibs/<abi>/*.so)
#   dist/ios/                      TunnelCore.swift + FFI.h + modulemap
#   dist/python/                   tunnel_core.py + libtunnel_core.so
#   dist/SHA256SUMS                контрольные суммы артефактов

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SKIP_TESTS=false
[[ "${1:-}" == "--skip-tests" ]] && SKIP_TESTS=true

# Тулчейн Rust: если rustc нет в PATH, пробуем типовые расположения rustup
# (в песочнице тулчейн лежит в <repo>/../../.cargo/bin; локально — ~/.cargo/bin).
if ! command -v rustc >/dev/null 2>&1; then
    for candidate in "$SCRIPT_DIR/../../.cargo/bin" "$HOME/.cargo/bin"; do
        if [[ -x "$candidate/rustc" ]]; then
            export PATH="$candidate:$PATH"
            break
        fi
    done
fi
if [[ -z "${RUSTUP_HOME:-}" && -d "$SCRIPT_DIR/../../.rustup" ]]; then
    export RUSTUP_HOME="$SCRIPT_DIR/../../.rustup"
fi
if [[ -z "${CARGO_HOME:-}" && -d "$SCRIPT_DIR/../../.cargo" ]]; then
    export CARGO_HOME="$SCRIPT_DIR/../../.cargo"
fi
if ! command -v rustc >/dev/null 2>&1; then
    echo "rustc не найден: установите Rust через rustup или задайте PATH." >&2
    exit 1
fi

# Артефакты сборки — вне каталога проекта (в dist/ не должно попадать target/).
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
    if [[ -d "$SCRIPT_DIR/../../tunnel-target" ]]; then
        export CARGO_TARGET_DIR="$SCRIPT_DIR/../../tunnel-target"
    else
        export CARGO_TARGET_DIR="$SCRIPT_DIR/target"
    fi
fi

TARGET_DIR="${CARGO_TARGET_DIR:-$SCRIPT_DIR/target}"
REL="$TARGET_DIR/release"
DIST="$SCRIPT_DIR/dist"
TMP_BINDINGS="$DIST/.bindings-tmp"

HOST_TRIPLE="$(rustc -Vv | sed -n 's/^host: //p')"

# Имя нативной библиотеки зависит от платформы.
OS="$(uname -s)"
case "$OS" in
    Linux)  SHARED_LIB="libtunnel_core.so" ;;
    Darwin) SHARED_LIB="libtunnel_core.dylib" ;;
    *)      SHARED_LIB="tunnel_core.dll" ;;
esac

echo "==> [1/5] Тесты клиентского ядра"
if [[ "$SKIP_TESTS" == true ]]; then
    echo "    пропущены (--skip-tests)"
else
    cargo test --release -p tunnel-core --lib
fi

echo "==> [2/5] Релизная сборка библиотеки (host: $HOST_TRIPLE)"
cargo build --release -p tunnel-core

echo "==> [3/5] Генерация биндингов: Kotlin + Swift + Python (одной командой)"
rm -rf "$DIST"
mkdir -p "$DIST" "$TMP_BINDINGS"
# Биндинги генерируются из debug-сборки: в release у нас strip = "symbols",
# а uniffi ищет метаданные API в библиотеке по symbol table — стрипнутый .so
# метаданных не содержит. Состав биндингов от профиля сборки не зависит,
# checksum'ы API совпадают с release-библиотекой.
cargo build -p tunnel-core
cargo run --release -p tunnel-core --bin uniffi-bindgen -- \
    generate-all --library "$TARGET_DIR/debug/$SHARED_LIB" --out-dir "$TMP_BINDINGS"

echo "==> [4/5] Раскладка dist/"

# --- Android: Kotlin-биндинги + JNI-библиотеки ---
mkdir -p "$DIST/android/kotlin" "$DIST/android/jniLibs"
cp -r "$TMP_BINDINGS/kotlin/uniffi" "$DIST/android/kotlin/uniffi"
# Хост-сборка как проверочная (x86_64-эмулятор); боевые ABI — см. ниже.
mkdir -p "$DIST/android/jniLibs/x86_64"
cp "$REL/$SHARED_LIB" "$DIST/android/jniLibs/x86_64/"
# Если установлен NDK-таргет — собираем arm64 сразу.
if rustup target list --installed 2>/dev/null | grep -q "^aarch64-linux-android$"; then
    echo "    android: сборка arm64-v8a"
    cargo build --release -p tunnel-core --target aarch64-linux-android
    mkdir -p "$DIST/android/jniLibs/arm64-v8a"
    cp "$TARGET_DIR/aarch64-linux-android/release/$SHARED_LIB" \
        "$DIST/android/jniLibs/arm64-v8a/"
else
    echo "    android: таргет aarch64-linux-android не установлен — arm64 соберите с NDK (см. INTEGRATION.md)"
fi

# --- iOS/macOS: Swift-биндинги ---
mkdir -p "$DIST/ios"
cp "$TMP_BINDINGS/swift/"*.swift "$TMP_BINDINGS/swift/"*.h "$TMP_BINDINGS/swift/"*.modulemap "$DIST/ios/"

# --- Python: пакет + нативная библиотека рядом (её ищет loader) ---
mkdir -p "$DIST/python"
cp "$TMP_BINDINGS/python/tunnel_core.py" "$DIST/python/"
cp "$REL/$SHARED_LIB" "$DIST/python/"

# --- Нативные библиотеки для хост-платформы ---
mkdir -p "$DIST/lib/$HOST_TRIPLE"
cp "$REL/$SHARED_LIB" "$DIST/lib/$HOST_TRIPLE/"
[[ -f "$REL/libtunnel_core.a" ]] && cp "$REL/libtunnel_core.a" "$DIST/lib/$HOST_TRIPLE/"

rm -rf "$TMP_BINDINGS"

# --- Указатель на дистрибутив ---
cat > "$DIST/README.md" <<'EOF'
# tunnel-core SDK — дистрибутив

Состав и подключение — см. `INTEGRATION.md` в корне репозитория.

| Каталог | Содержимое |
|---|---|
| `lib/<host-triple>/` | Нативные библиотеки хост-платформы: `libtunnel_core.so`/`.dylib` (динамическая) и `libtunnel_core.a` (статическая) |
| `android/kotlin/` | Kotlin-биндинги (`uniffi/tunnel_core/tunnel_core.kt`) |
| `android/jniLibs/` | Нативные библиотеки по ABI (`x86_64` — эмулятор с хоста; `arm64-v8a` — при установленном NDK-таргете) |
| `ios/` | Swift-биндинг `tunnel_core.swift`, C-заголовок `tunnel_coreFFI.h`, `tunnel_coreFFI.modulemap` |
| `python/` | `tunnel_core.py` + `libtunnel_core.so` (loader ищет библиотеку рядом с .py) |

Минимальные требования: iOS 13+ / Android 8+ / Python 3.9+, UTF-8 локаль.
API — пять методов управления (`new`/`connect`/`disconnect`/`get_telemetry`/
`set_status_callback`) плюс data plane (`send_packet`/`recv_packet`) и
`on_network_changed`.
EOF

echo "==> [5/5] Контрольные суммы"
# Питон-кэш от локальных прогонов не должен попадать в дистрибутив и SHA.
find "$DIST" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
(cd "$DIST" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS)

echo
echo "Готово. Состав dist/:"
find "$DIST" -type f | sed "s|$DIST/||" | sort | while read -r f; do
    printf '  %s (%s)\n' "$f" "$(du -h "$DIST/$f" | cut -f1)"
done
echo
echo "Интеграция: INTEGRATION.md (Swift / Kotlin / Python)."
