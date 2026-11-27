#!/usr/bin/env bash
#
# Builds the commercial SDK `tunnel-core`: release libraries + bindings for
# Swift (iOS/macOS), Kotlin (Android) and Python → a ready dist/ folder.
#
# Usage:
#   ./build_sdk.sh                 # tests + release build + bindings + dist/
#   ./build_sdk.sh --skip-tests    # skip the test run (fast rebuild)
#
# Result (see dist/README.md and INTEGRATION.md):
#   dist/lib/<host-triple>/        libtunnel_core.so/.dylib + libtunnel_core.a
#   dist/android/kotlin/           Kotlin bindings (+ jniLibs/<abi>/*.so)
#   dist/ios/                      TunnelCore.swift + FFI.h + modulemap
#   dist/python/                   tunnel_core.py + libtunnel_core.so
#   dist/SHA256SUMS                artifact checksums

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SKIP_TESTS=false
[[ "${1:-}" == "--skip-tests" ]] && SKIP_TESTS=true

# Rust toolchain: if rustc is not in PATH, try the common rustup locations
# (in the sandbox the toolchain lives in <repo>/../../.cargo/bin; locally — ~/.cargo/bin).
if ! command -v rustc >/dev/null 2>&1; then
    for candidate in "$SCRIPT_DIR/../../.cargo/bin" "$HOME/.cargo/bin"; do
        if [[ -x "$candidate/rustc" ]]; then
            export PATH="$candidate:$PATH"
            break
        fi
    done
done
if [[ -z "${RUSTUP_HOME:-}" && -d "$SCRIPT_DIR/../../.rustup" ]]; then
    export RUSTUP_HOME="$SCRIPT_DIR/../../.rustup"
fi
if [[ -z "${CARGO_HOME:-}" && -d "$SCRIPT_DIR/../../.cargo" ]]; then
    export CARGO_HOME="$SCRIPT_DIR/../../.cargo"
fi
if ! command -v rustc >/dev/null 2>&1; then
    echo "rustc not found: install Rust via rustup or set PATH." >&2
    exit 1
fi

# Build artifacts live outside the project directory (target/ must not land in dist/).
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

# The native library name depends on the platform.
OS="$(uname -s)"
case "$OS" in
    Linux)  SHARED_LIB="libtunnel_core.so" ;;
    Darwin) SHARED_LIB="libtunnel_core.dylib" ;;
    *)      SHARED_LIB="tunnel_core.dll" ;;
esac

echo "==> [1/5] Client core tests"
if [[ "$SKIP_TESTS" == true ]]; then
    echo "    skipped (--skip-tests)"
else
    cargo test --release -p tunnel-core --lib
fi

echo "==> [2/5] Release build of the library (host: $HOST_TRIPLE)"
cargo build --release -p tunnel-core

echo "==> [3/5] Binding generation: Kotlin + Swift + Python (one command)"
rm -rf "$DIST"
mkdir -p "$DIST" "$TMP_BINDINGS"
# Bindings are generated from the debug build: in release we have strip = "symbols",
# and uniffi looks up the API metadata in the library via the symbol table — a
# stripped .so carries no metadata. The binding contents do not depend on the
# build profile; the API checksums match the release library.
cargo build -p tunnel-core
cargo run --release -p tunnel-core --bin uniffi-bindgen -- \
    generate-all --library "$TARGET_DIR/debug/$SHARED_LIB" --out-dir "$TMP_BINDINGS"

echo "==> [4/5] Laying out dist/"

# --- Android: Kotlin bindings + JNI libraries ---
mkdir -p "$DIST/android/kotlin" "$DIST/android/jniLibs"
cp -r "$TMP_BINDINGS/kotlin/uniffi" "$DIST/android/kotlin/uniffi"
# Host build as a verification one (x86_64 emulator); production ABIs — see below.
mkdir -p "$DIST/android/jniLibs/x86_64"
cp "$REL/$SHARED_LIB" "$DIST/android/jniLibs/x86_64/"
# If the NDK target is installed, build arm64 right away.
if rustup target list --installed 2>/dev/null | grep -q "^aarch64-linux-android$"; then
    echo "    android: building arm64-v8a"
    cargo build --release -p tunnel-core --target aarch64-linux-android
    mkdir -p "$DIST/android/jniLibs/arm64-v8a"
    cp "$TARGET_DIR/aarch64-linux-android/release/$SHARED_LIB" \
        "$DIST/android/jniLibs/arm64-v8a/"
else
    echo "    android: the aarch64-linux-android target is not installed — build arm64 with the NDK (see INTEGRATION.md)"
fi

# --- iOS/macOS: Swift bindings ---
mkdir -p "$DIST/ios"
cp "$TMP_BINDINGS/swift/"*.swift "$TMP_BINDINGS/swift/"*.h "$TMP_BINDINGS/swift/"*.modulemap "$DIST/ios/"

# --- Python: package + native library next to it (the loader searches there) ---
mkdir -p "$DIST/python"
cp "$TMP_BINDINGS/python/tunnel_core.py" "$DIST/python/"
cp "$REL/$SHARED_LIB" "$DIST/python/"

# --- Native libraries for the host platform ---
mkdir -p "$DIST/lib/$HOST_TRIPLE"
cp "$REL/$SHARED_LIB" "$DIST/lib/$HOST_TRIPLE/"
[[ -f "$REL/libtunnel_core.a" ]] && cp "$REL/libtunnel_core.a" "$DIST/lib/$HOST_TRIPLE/"

rm -rf "$TMP_BINDINGS"

# --- Distribution pointer ---
cat > "$DIST/README.md" <<'EOF'
# tunnel-core SDK — distribution

Contents and integration — see `INTEGRATION.md` in the repository root.

| Directory | Contents |
|---|---|
| `lib/<host-triple>/` | Host platform native libraries: `libtunnel_core.so`/`.dylib` (dynamic) and `libtunnel_core.a` (static) |
| `android/kotlin/` | Kotlin bindings (`uniffi/tunnel_core/tunnel_core.kt`) |
| `android/jniLibs/` | Native libraries per ABI (`x86_64` — emulator from the host; `arm64-v8a` — with the NDK target installed) |
| `ios/` | Swift binding `tunnel_core.swift`, C header `tunnel_coreFFI.h`, `tunnel_coreFFI.modulemap` |
| `python/` | `tunnel_core.py` + `libtunnel_core.so` (the loader looks for the library next to the .py) |

Minimum requirements: iOS 13+ / Android 8+ / Python 3.9+, UTF-8 locale.
The API is five control methods (`new`/`connect`/`disconnect`/`get_telemetry`/
`set_status_callback`) plus the data plane (`send_packet`/`recv_packet`) and
`on_network_changed`.
EOF

echo "==> [5/5] Checksums"
# The Python cache from local runs must not land in the distribution or the SHA.
find "$DIST" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
(cd "$DIST" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS)

echo
echo "Done. dist/ contents:"
find "$DIST" -type f | sed "s|$DIST/||" | sort | while read -r f; do
    printf '  %s (%s)\n' "$f" "$(du -h "$DIST/$f" | cut -f1)"
done
echo
echo "Integration: INTEGRATION.md (Swift / Kotlin / Python)."
