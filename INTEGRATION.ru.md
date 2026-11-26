🌐 [English](INTEGRATION.md) | 🇷🇺 **Русский**

# INTEGRATION — встраивание `tunnel-core` в стороннее приложение

SDK = нативная библиотека + сгенерированные биндинги (`dist/`). Управление
сессией — **пять методов**, остальное — обмен пакетами:

| Метод | Назначение |
|---|---|
| `TunnelClient(config)` | создать клиент; конфиг валидируется сразу |
| `connect()` | запустить движок: подключение, ретраи, keepalive (идемпотентно) |
| `disconnect()` | корректно остановить (не блокирует, идемпотентно) |
| `get_telemetry()` | `bytes_sent`, `bytes_received`, `ping_ms` (RTT последнего ping/pong) |
| `set_status_callback(cb)` | уведомления `Connected` / `Reconnecting` / `Disconnected` |

Плюс data plane: `send_packet(bytes) -> bool` (неблокирующий; `false` — очередь
полна, пакет сброшен), `recv_packet(timeout_ms) -> bytes?` (вызывать из
**фонового** потока) и `on_network_changed()` (подсказка при смене Wi-Fi ↔ LTE).

---

## 1. Установка артефактов

| Платформа | Что скопировать | Куда |
|---|---|---|
| **iOS / macOS** | `dist/ios/tunnel_core.swift`, `tunnel_coreFFI.h`, `tunnel_coreFFI.modulemap` + `dist/lib/<triple>/libtunnel_core.a` | в Xcode-таргет (Swift + bridging/modulemap), библиотека в Link Binary |
| **Android** | `dist/android/kotlin/uniffi/` → `app/src/main/java/`, `dist/android/jniLibs/<abi>/` → `app/src/main/jniLibs/` | Gradle подхватит автоматически |
| **Python** | `dist/python/tunnel_core.py` **и** `dist/python/libtunnel_core.so` — в один каталог | каталог в `sys.path`/`PYTHONPATH` (loader ищет библиотеку рядом с `.py`) |

`dist/android/jniLibs` содержит ABI, собранные в этой среде (`x86_64` —
эмулятор). Боевые ABI собираются так:

```bash
rustup target add aarch64-linux-android        # + Android NDK в PATH
./build_sdk.sh                                  # сам соберёт arm64-v8a
# iOS — на macOS: rustup target add aarch64-apple-ios && cargo build --release -p tunnel-core --target aarch64-apple-ios
```

Контроль целостности: `dist/SHA256SUMS` (проверка — `cd dist && sha256sum -c SHA256SUMS`).

## 2. Откуда взять параметры

- `server_host` / `server_port` — endpoint сервера туннеля (обычно `443/UDP`).
- `auth_token` — B2B-токен, выдаётся оператором сервера партнёру.
- `pinned_server_cert_der` — DER-сертификат сервера (`tunnel-server
  --export-cert root.der`); это **единственный** доверенный корень TLS.
- `server_name` — должен совпадать с SAN сертификата; по умолчанию берётся
  из `server_host` — если они различаются, задайте явно.
- Остальные поля (`client_id`, тайм-ауты, backoff, keepalive) имеют
  рекомендованные значения по умолчанию — передавайте их только сознательно.

---

## 3. Swift (iOS / macOS) — запуск за ~12 строк

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

Обмен пакетами и телеметрия:

```swift
// Отдельный поток выкачивает пакеты из туннеля в платформенный TUN.
DispatchQueue.global().async {
    while let packet = client.recvPacket(timeoutMs: 1000) {
        writeToTun(packet)                       // платформенный интерфейс
    }
}
try client.sendPacket(packet: ipPacket)          // пакет от TUN, src = vip
let t = client.getTelemetry()                    // bytesSent, bytesReceived, pingMs
// При смене сети: client.onNetworkChanged(); при выходе: client.disconnect()
```

## 4. Kotlin (Android) — запуск за ~12 строк

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

Обмен пакетами и телеметрия:

```kotlin
thread(name = "tunnel-rx") {
    while (true) client.recvPacket(1000u)?.let { writeToTun(it) }
}
client.sendPacket(ipPacket)              // false — очередь полна, пакет сброшен
val t = client.getTelemetry()            // bytesSent, bytesReceived, pingMs
client.onNetworkChanged()                // при смене Wi-Fi ↔ cellular
client.disconnect()                      // при остановке сервиса
```

## 5. Python — запуск за ~10 строк

```python
from tunnel_core import ConnectionStatusCallback, TunnelClient, TunnelConfig

class Watcher(ConnectionStatusCallback):
    def on_status_change(self, status):
        print("статус:", status)          # CONNECTED(mtu=1280, vip=10.66.0.2) …

config = TunnelConfig(server_host="tunnel.example.com", server_port=443,
                      auth_token="b2b-live-…", pinned_server_cert_der=cert_der)
client = TunnelClient(config)
client.set_status_callback(Watcher())
client.connect()
print(client.get_telemetry())             # Telemetry(bytes_sent=…, bytes_received=…, ping_ms=…)
```

Обмен пакетами:

```python
packet = client.recv_packet(1000)         # фоновый поток; None — тайм-аут
ok = client.send_packet(ip_packet)        # False — очередь полна
client.disconnect()
```

---

## 6. Контракт статусов

| Статус | Когда приходит |
|---|---|
| `Disconnected` | клиент создан; `connect()` ещё не звали / не удался; после `disconnect()`; постоянная ошибка |
| `Connected(mtu, vip)` | сессия установлена. `mtu` — MTU платформенного TUN; `vip` — адрес интерфейса. **Каждый исходящий IP-пакет обязан иметь `src = vip`** — сервер отбрасывает пакеты с чужим адресом отправителя как спуфинг |
| `Reconnecting` | соединение оборвалось после успешной сессии; движок ретраит с экспоненциальным backoff сам |

Правила: статусы идут **без дубликатов**; после регистрации коллбэка сразу
приходит текущий статус; коллбэк вызывается из внутренних потоков ядра — он
должен быть быстрым и **не вызывать методы SDK внутри себя**.

## 7. Ошибки и их обработка

`connect()` и `TunnelClient(config)` бросают типизированные ошибки
(`CoreException` / `CoreError`): `InvalidConfig`, `InvalidServerCert`,
`AuthRejected`, `ProtocolMismatch`, `ServerBusy`, `ConnectFailed`, `TimedOut`,
`SessionClosed`, `Io`, `Internal`. Первые четыре — постоянные: движок
останавливается (`Disconnected` без ретраев), клиент нужно пересоздать после
исправления причины (токен, сертификат, версия SDK). Остальные движок
обрабатывает сам через ретраи — партнёру достаточно следить за статусами.

## 8. Минимальная проверка дистрибутива (10 секунд)

```bash
# Терминал 1: сервер из того же репозитория, loopback-режим.
cargo build -p tunnel-server
TUNNEL_TOKENS="partner:token" target/debug/tunnel-server \
    --listen 127.0.0.1:4433 --env-tokens \
    --server-name tunnel-server --export-cert root.der

# Терминал 2: Python-пример против этого сервера.
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
    raise SystemExit(f"не подключился: {watcher.last}")
print(client.get_telemetry())
client.disconnect()
print("INTEGRATION check OK")
EOF
```
