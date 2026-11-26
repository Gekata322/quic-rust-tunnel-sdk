🌐 **English** | [🇷🇺 Русский](README.ru.md)

# tunnel-mvp — Commercial B2B Tunnel SDK in Rust

A secure tunnel for embedding into client applications (iOS / Android /
Desktop / Python) and for deploying a server on Linux. The transport is QUIC
(`quinn` + `rustls`) on top of the `tokio` async runtime. Partners receive a
ready-to-ship SDK: native libraries + Swift/Kotlin/Python bindings from
`dist/` (see **[INTEGRATION.md](INTEGRATION.md)** — integration takes ~10
lines of code per language).

## Components

| Crate / file | Purpose |
| --- | --- |
| `tunnel-proto` | Shared protocol: control messages (bincode + length prefix), IP-packet framing for QUIC datagrams, IPv4 header parsing, constant-time token verification, telemetry counters |
| `tunnel-core` | **SDK core** (`cdylib`/`staticlib`), FFI via `uniffi`: five control methods (`new`/`connect`/`disconnect`/`get_telemetry`/`set_status_callback`), QUIC client with a pinned server certificate, exponential-backoff reconnect, RTT ping, poll-based packet exchange |
| `tunnel-server` | Server: B2B token authentication (file/env), virtual-IP pool with address reuse, routing table, Linux TUN interface, loopback mode for tests |
| `build_sdk.sh` | One-command SDK build: release libraries + bindings → `dist/` |
| `INTEGRATION.md` | Embedding guide with examples (Swift / Kotlin / Python) |

## SDK: Public API of the Client Core

```text
TunnelClient(config)          create the client (config is validated up front)
  .connect()                  start the engine: connect, retries, keepalive
  .disconnect()               graceful shutdown (non-blocking)
  .get_telemetry()            bytes_sent, bytes_received, ping_ms (RTT)
  .set_status_callback(cb)    Connected { mtu, vip } / Reconnecting / Disconnected
  .send_packet(bytes) -> bool data plane: platform TUN → tunnel
  .recv_packet(timeout)       data plane: tunnel → platform TUN
  .on_network_changed()       hint on Wi-Fi ↔ cellular switch
```

The status callback is delivered from the core's internal threads **without
duplicates**; the current status arrives right after registration. A network
switch after a disconnect is reported as `Reconnecting`; `disconnect()` and
permanent errors (rejected token, incompatible version) are reported as
`Disconnected`. In `Connected{mtu, vip}` the partner receives the platform
TUN parameters: the interface MTU and the client address assigned by the
server (every outgoing packet must carry `src = vip` — the server enforces
anti-spoofing).

Config: the required fields are `server_host`, `server_port`, `auth_token`,
`pinned_server_cert_der`; the rest have recommended defaults at the binding
level (Kotlin/Swift/Python), so a minimal integration takes four parameters.

## Build and Verification

```bash
cargo test  --workspace      # 84 tests: protocol, core, server + E2E (server ↔ client)
cargo build -p tunnel-core   # lib + cdylib (.so) + staticlib (.a)
cargo build -p tunnel-server # the tunnel-server binary

./build_sdk.sh               # SDK in one command → dist/ (see dist/README.md)
./build_sdk.sh --skip-tests  # rebuild without running the tests
```

`build_sdk.sh` builds the release library, generates bindings for all three
languages with a single command (`uniffi-bindgen generate-all`), populates
`dist/` (`lib/<triple>/`, `android/{kotlin,jniLibs}`, `ios/`, `python/`) and
writes `SHA256SUMS`. If the `aarch64-linux-android` target is installed,
`arm64-v8a` is included as well; the iOS static library is built on macOS
(`aarch64-apple-ios`).

## Running the Server

```bash
# Token file: one "client_id:token" pair per line, '#' starts a comment.
cat > tokens.txt <<'EOF'
# partner "example"
example-ios: b2b-live-a1b2c3d4
example-android: b2b-live-e5f6g7h8
EOF

# Production mode: TUN + certificate export for client-side pinning
tunnel-server --listen 0.0.0.0:4433 --tokens tokens.txt \
    --tun tunnel0 --pool 10.66.0.0/24 --mtu 1280 \
    --server-name tunnel.example.com --export-cert tunnel-root.der

# Loopback mode (no CAP_NET_ADMIN privileges): echo only to the server's own
# address — for client checks and CI. Tokens can come from an environment variable.
TUNNEL_TOKENS="ci-client:ci-token" tunnel-server --listen 127.0.0.1:4433 --env-tokens
```

To route client traffic to the outside world (right after startup with
`--tun` the server prints these commands with the actual values):

```bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.66.0.0/24 ! -o tunnel0 -j MASQUERADE
iptables -A FORWARD -i tunnel0 -j ACCEPT
iptables -A FORWARD -o tunnel0 -j ACCEPT
```

The client takes `tunnel-root.der` (DER) as `pinned_server_cert_der` and
`tunnel.example.com` as `server_name` (it must match the certificate SAN);
the assigned address reaches the partner via the `Connected { mtu, vip }`
callback — it is used to configure the platform TUN. Packets carrying a
sender address other than the client's own are dropped by the server
(anti-spoofing).

Tokens are kept in memory in plain text and compared in constant time
(`tunnel_proto::auth`); HMAC tokens with rotation and issuance through a
partner broker are on the roadmap. The server certificate in the MVP is
self-signed (`rcgen`) — replace it with the partner's CA certificate for
production deployments.

## Regenerating Bindings

Bindings for all languages are generated with a **single command** (the API
metadata is read from the library; in the release profile it is stripped out,
so generation runs from a debug build — `build_sdk.sh` already accounts for
this):

```bash
cargo build -p tunnel-core
cargo run -p tunnel-core --bin uniffi-bindgen -- \
    generate-all --library "$CARGO_TARGET_DIR/debug/libtunnel_core.so" \
    --out-dir bindings            # → bindings/{kotlin,swift,python}/
```

For a single language use the standard uniffi CLI: `generate --library <lib>
--language swift --out-dir <dir>`. The up-to-date generated bindings live in
`bindings/`; they are shipped to the partner via `dist/`.

## Status

- [x] Step 1 — workspace, `tunnel-proto` (messages, frames, IPv4, auth, metrics)
- [x] Step 2 — `tunnel-core`: QUIC client, FFI (`TunnelClient`), reconnect with
  backoff, network-change handling; integration test against a local QUIC
  server; generated bindings
- [x] Step 3 — `tunnel-server`: tokens, IP pool, routing table, TUN,
  loopback mode; server ↔ client E2E tests (echo, multiple clients, reject)
- [x] Step 4 — commercial SDK: 5-method API + status callback
  (`Connected`/`Reconnecting`/`Disconnected`), telemetry with ping, config
  defaults at the FFI boundary; `uniffi-bindgen generate-all`
  (Kotlin/Swift/Python); `build_sdk.sh` → `dist/`; `INTEGRATION.md`;
  Python-binding smoke test against a live server

### Known Limitations

- IPv6: `KIND_IPV6` frames are accepted, but v6 routing is not implemented —
  in TUN mode they are forwarded as is, in loopback mode they are dropped.
- The server does not recompute IP checksums (that is the core's job);
  the loopback echo only rewrites the addresses in the header.
- The real TUN loop is not exercised in CI (no `CAP_NET_ADMIN`): the TUN path
  is covered by component unit tests, the E2E runs through loopback mode.
- Android/iOS targets in the distribution are limited by the build
  environment: `arm64-v8a` is built when the NDK target is available,
  iOS is built on macOS (see INTEGRATION.md).
- On the roadmap: per-client rate limiting, token rotation, QUIC connection
  migration between interfaces, Prometheus-format metrics.

## Commercial Licensing & Custom Integration

The project source code is distributed under **GNU AGPL-3.0**
(see [LICENSE](LICENSE)): you are free to use, study and modify the code
subject to the copyleft obligations, including the duty to publish the
sources of your modifications when the product is used over a network
(section 13 of the license). This protects the project from being embedded
into closed commercial products for free.

For companies that need to embed the SDK into a **proprietary product
without disclosing their own source code**, an alternative **commercial
license** is available (dual-licensing). Custom integration services are
also offered: SDK builds for your platforms and ABIs, protocol adaptations
for your infrastructure, priority support and SLA.

**Contacts to discuss the terms:**

- Telegram: **@gekata4**
- Email: **lotedru@gmail.com**

Please mention your product name, target platforms and expected usage
volumes in your message — licensing terms will follow within 1–2 business
days.
