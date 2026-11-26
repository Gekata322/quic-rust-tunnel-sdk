🌐 **English** | [🇷🇺 Русский](INTEGRATION.ru.md)

# INTEGRATION — Embedding `tunnel-core` into a Third-Party Application

The SDK = native library + generated bindings (`dist/`). Session control is
**five methods**; everything else is packet exchange:

| Method | Purpose |
|---|---|
| `TunnelClient(config)` | create the client; the config is validated right away |
| `connect()` | start the engine: connect, retries, keepalive (idempotent) |
| `disconnect()` | shut down gracefully (non-blocking, idempotent) |
| `get_telemetry()` | `bytes_sent`, `bytes_received`, `ping_ms` (RTT of the last ping/pong) |
| `set_status_callback(cb)` | `Connected` / `Reconnecting` / `Disconnected` notifications |

Plus the data plane: `send_packet(bytes) -> bool` (non-blocking; `false` —
the queue is full, the packet was dropped), `recv_packet(timeout_ms) -> bytes?`
(call from a **background** thread) and `on_network_changed()` (a hint when
the device switches Wi-Fi ↔ LTE).

---

## 1. Installing the Artifacts

| Platform | What to copy | Where |
|---|---|---|
| **iOS / macOS** | `dist/ios/tunnel_core.swift`, `tunnel_coreFFI.h`, `tunnel_coreFFI.modulemap` + `dist/lib/<triple>/libtunnel_core.a` | into the Xcode target (Swift + bridging/modulemap), the library into Link Binary |
| **Android** | `dist/android/kotlin/uniffi/` → `app/src/main/java/`, `dist/android/jniLibs/<abi>/` → `app/src/main/jniLibs/` | Gradle picks them up automatically |
| **Python** | `dist/python/tunnel_core.py` **and** `dist/python/libtunnel_core.so` — into one directory | the directory must be on `sys.path`/`PYTHONPATH` (the loader looks for the library next to the `.py`) |

`dist/android/jniLibs` contains the ABIs built in this environment
(`x86_64` — emulator). Production ABIs are built like this:

```bash
rustup target add aarch64-linux-android        # + Android NDK in PATH
./build_sdk.sh                                  # builds arm64-v8a itself
# iOS — on macOS: rustup target add aarch64-apple-ios && cargo build --release -p tunnel-core --target aarch64-apple-ios
```

Integrity check: `dist/SHA256SUMS` (verify with `cd dist && sha256sum -c SHA256SUMS`).

## 2. Where the Parameters Come From

- `server_host` / `server_port` — the tunnel server endpoint (usually `443/UDP`).
- `auth_token` — the B2B token issued by the server operator to the partner.
- `pinned_server_cert_der` — the server DER certificate (`tunnel-server
  --export-cert root.der`); it is the **only** trusted TLS root.
- `server_name` — must match the certificate SAN; by default it is taken
  from `server_host` — set it explicitly if the two differ.
- The remaining fields (`client_id`, timeouts, backoff, keepalive) have
  recommended default values — pass them only deliberately.

---

## 3. Swift (iOS / macOS) — up and running in ~12 lines

```swift
import tunnel_core

final class StatusWatcher: ConnectionStatusCallback {
    func onStatusChange(status: ConnectionStatus) {
        switch status {
        case .connected(let mtu, let vip): print("up: mtu=\(mtu), ip=\(vip)")
        case .reconnecting:                print("reconnecting…")
        case .disconnected:                print("down")
        }
    }
}

let config = TunnelConfig(serverHost: "tunnel.example.com", serverPort: 443,
                          authToken: "b2b-live-…", pinnedServerCertDer: certData)
let client = try TunnelClient(config: config)
client.setStatusCallback(callback: StatusWatcher())
try client.connect()
```

Packet exchange and telemetry:

```swift
// A dedicated thread drains packets from the tunnel into the platform TUN.
DispatchQueue.global().async {
    while let packet = client.recvPacket(timeoutMs: 1000) {
        writeToTun(packet)                       // platform interface
    }
}
try client.sendPacket(packet: ipPacket)          // packet from the TUN, src = vip
let t = client.getTelemetry()                    // bytesSent, bytesReceived, pingMs
// On network change: client.onNetworkChanged(); on shutdown: client.disconnect()
```

## 4. Kotlin (Android) — up and running in ~12 lines

```kotlin
import uniffi.tunnel_core.*

class StatusWatcher : ConnectionStatusCallback {
    override fun onStatusChange(status: ConnectionStatus) {
        when (status) {
            is ConnectionStatus.Connected -> println("up: mtu=${status.mtu}, ip=${status.vip}")
            ConnectionStatus.Reconnecting -> println("reconnecting…")
            ConnectionStatus.Disconnected -> println("down")
        }
    }
}

val config = TunnelConfig(serverHost = "tunnel.example.com", serverPort = 443u,
                          authToken = "b2b-live-…", pinnedServerCertDer = certBytes)
val client = TunnelClient(config = config)
client.setStatusCallback(callback = StatusWatcher())
client.connect()
```

Packet exchange and telemetry:

```kotlin
thread(name = "tunnel-rx") {
    while (true) client.recvPacket(1000u)?.let { writeToTun(it) }
}
client.sendPacket(ipPacket)              // false — queue full, packet dropped
val t = client.getTelemetry()            // bytesSent, bytesReceived, pingMs
client.onNetworkChanged()                // on Wi-Fi ↔ cellular switch
client.disconnect()                      // when stopping the service
```

## 5. Python — up and running in ~10 lines

```python
from tunnel_core import ConnectionStatusCallback, TunnelClient, TunnelConfig

class Watcher(ConnectionStatusCallback):
    def on_status_change(self, status):
        print("status:", status)          # CONNECTED(mtu=1280, vip=10.66.0.2) …

config = TunnelConfig(server_host="tunnel.example.com", server_port=443,
                      auth_token="b2b-live-…", pinned_server_cert_der=cert_der)
client = TunnelClient(config)
client.set_status_callback(Watcher())
client.connect()
print(client.get_telemetry())             # Telemetry(bytes_sent=…, bytes_received=…, ping_ms=…)
```

Packet exchange:

```python
packet = client.recv_packet(1000)         # background thread; None — timeout
ok = client.send_packet(ip_packet)        # False — queue full
client.disconnect()
```

---

## 6. Status Contract

| Status | When it arrives |
|---|---|
| `Disconnected` | the client is created; `connect()` has not been called yet / failed; after `disconnect()`; permanent error |
| `Connected(mtu, vip)` | the session is established. `mtu` — the platform TUN MTU; `vip` — the interface address. **Every outgoing IP packet must carry `src = vip`** — the server drops packets with a foreign sender address as spoofing |
| `Reconnecting` | the connection dropped after a successful session; the engine retries with exponential backoff on its own |

Rules: statuses arrive **without duplicates**; the current status is delivered
right after the callback is registered; the callback is invoked from the
core's internal threads — it must be fast and **must not call SDK methods
within itself**.

## 7. Errors and How to Handle Them

`connect()` and `TunnelClient(config)` throw typed errors
(`CoreException` / `CoreError`): `InvalidConfig`, `InvalidServerCert`,
`AuthRejected`, `ProtocolMismatch`, `ServerBusy`, `ConnectFailed`, `TimedOut`,
`SessionClosed`, `Io`, `Internal`. The first four are permanent: the engine
stops (`Disconnected`, no retries) and the client must be recreated after
the cause is fixed (token, certificate, SDK version). The engine handles the
rest itself by retrying — the partner only needs to watch the statuses.

## 8. Minimal Distribution Check (10 seconds)

```bash
# Terminal 1: the server from the same repository, loopback mode.
cargo build -p tunnel-server
TUNNEL_TOKENS="partner:token" target/debug/tunnel-server \
    --listen 127.0.0.1:4433 --env-tokens \
    --server-name tunnel-server --export-cert root.der

# Terminal 2: the Python example against this server.
PYTHONPATH=dist/python python3 - <<'EOF'
import time
from tunnel_core import ConnectionStatus, ConnectionStatusCallback, TunnelClient, TunnelConfig

class Watcher(ConnectionStatusCallback):
    def __init__(self): self.last = None
    def on_status_change(self, status): self.last = status

watcher = Watcher()
cfg = TunnelConfig(server_host="127.0.0.1", server_name="tunnel-server",
                   server_port=4433, auth_token="token", client_id="partner",
                   pinned_server_cert_der=open("root.der", "rb").read())
client = TunnelClient(cfg)
client.set_status_callback(watcher)
client.connect()
deadline = time.time() + 5
while time.time() < deadline:
    if isinstance(watcher.last, ConnectionStatus.CONNECTED):
        break
    time.sleep(0.05)
else:
    raise SystemExit(f"failed to connect: {watcher.last}")
print(client.get_telemetry())
client.disconnect()
print("INTEGRATION check OK")
EOF
```
