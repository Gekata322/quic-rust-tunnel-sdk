🌐 **English** | [🇷🇺 Русский](README.ru.md)

# tunnel — Commercial B2B Tunnel SDK in Rust

Partners embed your product's connectivity into their applications, but
their traffic must egress through *your* infrastructure: one token per
partner, one virtual address per client, traffic that is QUIC end-to-end
and that a middlebox cannot fingerprint as anything but noise. That is the
problem this repository solves, in three deployable pieces:

- **`tunnel-core`** — the client SDK (iOS / Android / Desktop / Python):
  five control methods, a pinned-server-certificate QUIC session,
  exponential-backoff reconnects, connection migration on network changes
  (RFC 9000 — the VIP and the data plane survive a Wi-Fi ↔ cellular switch).
- **`tunnel-server`** — the Linux server: B2B token authentication,
  a virtual-IP pool, an idle-session reaper, per-client bandwidth caps,
  hot token revocation over an HTTP admin API, and NAT-ready TUN mode.
- **`tunnel-cli`** — a SOCKS5 proxy for desktop machines: any SOCKS5-capable
  application goes through the tunnel with **no root and no TUN device** —
  a userspace TCP/IP stack (smoltcp) turns the tunnel's raw IP packets back
  into TCP streams.

The transport is QUIC (`quinn` + `rustls`) on `tokio`. Partners receive a
ready-to-ship SDK: native libraries + Swift/Kotlin/Python bindings from
`dist/` (see **[INTEGRATION.md](INTEGRATION.md)** — integration takes ~10
lines of code per language).

## Components (repository map)

| Crate / file | Purpose |
| --- | --- |
| `tunnel-proto` | Shared protocol: control messages (bincode + length prefix), IP-packet framing for QUIC datagrams, IPv4 header parsing, constant-time token verification, telemetry counters |
| `tunnel-core` | **SDK core** (`cdylib`/`staticlib`), FFI via `uniffi`: five control methods (`new`/`connect`/`disconnect`/`get_telemetry`/`set_status_callback`), QUIC client with a pinned server certificate, exponential-backoff reconnect, QUIC connection migration, RTT ping, poll-based packet exchange |
| `tunnel-server` | Server: token auth (file/env + admin API), virtual-IP pool with address reuse, idle-session reaper (45 s), token-bucket bandwidth caps (`client:token:10mbps`), routing table, Linux TUN interface, loopback mode for CI |
| `tunnel-cli` | Desktop client: SOCKS5 listener on `127.0.0.1:1080`, userspace TCP/IP stack over the tunnel's packet queues, periodic status/RTT/throughput reporting — no root required |
| `build_sdk.sh` | One-command SDK build: release libraries + bindings → `dist/` |
| `INTEGRATION.md` | Embedding guide with examples (Swift / Kotlin / Python) |

## Quick Start (15 lines, no root on the client)

```bash
# ── server (Linux, once): TUN mode; it prints the exact NAT commands ──
TUNNEL_TOKENS="demo:demo-token" tunnel-server --listen 0.0.0.0:443 --env-tokens \
    --tun tunnel0 --pool 10.66.0.0/24 --server-name tunnel.example.com \
    --export-cert tunnel-root.der
sysctl -w net.ipv4.ip_forward=1                 # printed by the server above,
iptables -t nat -A POSTROUTING -s 10.66.0.0/24 ! -o tunnel0 -j MASQUERADE  # with real values

# ── client (macOS / Windows / Linux — an unprivileged user) ──
tunnel-cli --server tunnel.example.com:443 --cert tunnel-root.der --token demo-token
# info: tunnel connected vip=10.66.0.2 mtu=1280
# info: tunnel is up; the SOCKS5 listener is opening on 127.0.0.1:1080
# info: tunnel stats status=connected ping=Some("41 ms") down=1.2 KiB/s ...

# ── any SOCKS5 application now egresses through your server ──
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me/   # shows the server's IP
```

Embedding the SDK instead of running the CLI: `TunnelClient` + a platform
TUN — see **[INTEGRATION.md](INTEGRATION.md)**.

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
cargo test  --workspace      # 120 tests: protocol, core, server, CLI + E2E
cargo build -p tunnel-core   # lib + cdylib (.so) + staticlib (.a)
cargo build -p tunnel-server # the tunnel-server binary
cargo build -p tunnel-cli    # the tunnel-cli binary

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
# Token file: one "client_id:token[:mbps]" pair per line, '#' starts a
# comment; the optional suffix caps the client's bandwidth (token bucket).
cat > tokens.txt <<'EOF'
# partner "example"
example-ios: b2b-live-a1b2c3d4
example-android: b2b-live-e5f6g7h8:10mbps
EOF

# Production mode: TUN + certificate export for client-side pinning
tunnel-server --listen 0.0.0.0:4433 --tokens tokens.txt \
    --tun tunnel0 --pool 10.66.0.0/24 --mtu 1280 \
    --server-name tunnel.example.com --export-cert tunnel-root.der

# HTTP admin API (loopback only, X-Admin-Key protected):
#   POST   /tokens              {"client_id": "...", "token": "...", "mbps": 10}
#   DELETE /tokens/{client_id}  hot revocation — kicks live sessions
#   GET    /stats               live session/IPAM/traffic counters
TUNNEL_TOKENS="ci-client:ci-token" tunnel-server --listen 127.0.0.1:4433 --env-tokens \
    --admin-listen 127.0.0.1:8080 --admin-key operator-secret

# Loopback mode (no --tun, no CAP_NET_ADMIN): echo only to the server's own
# address — for client checks and CI.
```

A session silent for 45 seconds is reaped by the server (the connection is
closed and the address returns to the pool); capped clients have their
excess datagrams dropped, not queued.

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

## Non-Goals

This is a focused tunnel, not a general-purpose VPN framework:

- **No anonymous/public VPN product.** Clients authenticate with per-partner
  B2B tokens; there is no user registration, billing or captive portal.
- **No dynamic routing mesh.** One server per deployment; clients get one
  address from a flat IPv4 pool.
- **No plugin transport layer.** QUIC with a pinned certificate is the only
  transport; traffic shaping (伪装) is explicitly out of scope.
- **No kernel-bypass performance work.** The MVP targets partner-grade
  throughput on stock `quinn`; io_uring/XDP remains future work.
- **The server does not manage the host firewall** — it prints the exact
  `iptables`/`sysctl` commands instead of mutating the operator's system.

## Known Limitations

- IPv6: `KIND_IPV6` frames are accepted, but v6 routing is not implemented —
  in TUN mode they are forwarded as is, in loopback mode they are dropped.
- `tunnel-cli` resolves domain names with the system resolver — DNS does not
  traverse the tunnel in this version (CONNECT with an IP literal always
  works; DNS-over-tunnel is on the roadmap).
- The server does not recompute IP checksums (that is the stack's job); the
  loopback echo only rewrites the addresses in the header.
- A closed TCP session lingers in TIME_WAIT for 10 s (smoltcp's bound) —
  the ephemeral port space (16 384 ports) absorbs normal proxy churn.
- The real TUN loop is not exercised in CI (no `CAP_NET_ADMIN`): the TUN path
  is covered by component unit tests, the E2E runs through loopback mode and
  inter-client routing.
- Android/iOS targets in the distribution are limited by the build
  environment: `arm64-v8a` is built when the NDK target is available,
  iOS is built on macOS (see INTEGRATION.md).
- On the roadmap: DNS-over-tunnel, token rotation/HMAC issuance via a
  partner broker, Prometheus-format metrics, IPv6 data plane.

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
