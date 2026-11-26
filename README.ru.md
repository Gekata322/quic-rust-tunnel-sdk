🌐 [English](README.md) | 🇷🇺 **Русский**

# tunnel-mvp — коммерческий SDK B2B-туннеля на Rust

Защищённый туннель для встраивания в клиентские приложения (iOS / Android /
Desktop / Python) и развёртывания сервера на Linux. Транспорт — QUIC
(`quinn` + `rustls`), асинхронный рантайм — `tokio`. Партнёру поставляется
готовый SDK: нативные библиотеки + биндинги Swift/Kotlin/Python из `dist/`
(см. **[INTEGRATION.md](INTEGRATION.md)** — интеграция за ~10 строк на языке).

## Компоненты

| Крейт / файл | Назначение |
| --- | --- |
| `tunnel-proto` | Общий протокол: управляющие сообщения (bincode + префикс длины), кадрирование IP-пакетов для QUIC-дейтаграмм, разбор IPv4-заголовка, константная проверка токенов, счётчики телеметрии |
| `tunnel-core` | **Ядро SDK** (`cdylib`/`staticlib`), FFI через `uniffi`: пять методов управления (`new`/`connect`/`disconnect`/`get_telemetry`/`set_status_callback`), QUIC-клиент с pinned-сертификатом, reconnect с экспоненциальной задержкой, RTT-пинг, poll-модель обмена пакетами |
| `tunnel-server` | Сервер: авторизация B2B-токенов (файл/env), пул виртуальных IP с переиспользованием, таблица маршрутизации, TUN-интерфейс Linux, loopback-режим для тестов |
| `build_sdk.sh` | Сборка SDK одной командой: релизные библиотеки + биндинги → `dist/` |
| `INTEGRATION.md` | Инструкция и примеры встраивания (Swift / Kotlin / Python) |

## SDK: публичный API клиентского ядра

```text
TunnelClient(config)          создать клиент (валидация конфига)
  .connect()                  запустить движок: подключение, ретраи, keepalive
  .disconnect()               корректная остановка (не блокирует)
  .get_telemetry()            bytes_sent, bytes_received, ping_ms (RTT)
  .set_status_callback(cb)    Connected { mtu, vip } / Reconnecting / Disconnected
  .send_packet(bytes) -> bool data plane: платформенный TUN → туннель
  .recv_packet(timeout)       data plane: туннель → платформенный TUN
  .on_network_changed()       подсказка при смене Wi-Fi ↔ cellular
```

Коллбэк статуса приходит из внутренних потоков ядра **без дубликатов**; сразу
после регистрации доставляется текущий статус. Смена сети после разрыва
отражается как `Reconnecting`; `disconnect()` и постоянные ошибки (отклонён
токен, несовместимая версия) — как `Disconnected`. В `Connected{mtu, vip}`
партнёру приходят параметры платформенного TUN: MTU интерфейса и выданный
адрес клиента (каждый исходящий пакет обязан иметь `src = vip` — на сервере
анти-спуфинг).

Конфиг: обязательные поля `server_host`, `server_port`, `auth_token`,
`pinned_server_cert_der`; у остальных рекомендованные значения по умолчанию
на уровне биндингов (Kotlin/Swift/Python), поэтому минимальная интеграция —
четыре параметра.

## Сборка и проверка

```bash
cargo test  --workspace      # 84 теста: протокол, ядро, сервер + E2E (сервер ↔ клиент)
cargo build -p tunnel-core   # lib + cdylib (.so) + staticlib (.a)
cargo build -p tunnel-server # бинарник tunnel-server

./build_sdk.sh               # SDK одной командой → dist/ (см. dist/README.md)
./build_sdk.sh --skip-tests  # пересборка без прогона тестов
```

`build_sdk.sh` собирает релизную библиотеку, генерирует биндинги всех трёх
языков одной командой (`uniffi-bindgen generate-all`), раскладывает `dist/`
(`lib/<triple>/`, `android/{kotlin,jniLibs}`, `ios/`, `python/`) и пишет
`SHA256SUMS`. Если установлен таргет `aarch64-linux-android`, туда же
попадает `arm64-v8a`; iOS-статик библиотека собирается на macOS
(`aarch64-apple-ios`).

## Запуск сервера

```bash
# Файл токенов: по строке "client_id:token", '#' — комментарий.
cat > tokens.txt <<'EOF'
# партнёр «example»
example-ios: b2b-live-a1b2c3d4
example-android: b2b-live-e5f6g7h8
EOF

# Боевой режим: TUN + экспорт сертификата для pinning клиента
tunnel-server --listen 0.0.0.0:4433 --tokens tokens.txt \
    --tun tunnel0 --pool 10.66.0.0/24 --mtu 1280 \
    --server-name tunnel.example.com --export-cert tunnel-root.der

# Loopback-режим (без прав CAP_NET_ADMIN): эхо только на адрес сервера —
# проверка клиентов и CI. Токены можно взять из переменной окружения.
TUNNEL_TOKENS="ci-client:ci-token" tunnel-server --listen 127.0.0.1:4433 --env-tokens
```

Для маршрутизации трафика клиентов наружу (сразу после старта с `--tun` сервер
печатает эти команды с фактическими значениями):

```bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.66.0.0/24 ! -o tunnel0 -j MASQUERADE
iptables -A FORWARD -i tunnel0 -j ACCEPT
iptables -A FORWARD -o tunnel0 -j ACCEPT
```

Клиент берёт `tunnel-root.der` (DER) как `pinned_server_cert_der` и
`tunnel.example.com` как `server_name` (должен совпадать с SAN сертификата);
выданный адрес приходит партнёру в коллбэке `Connected { mtu, vip }` — им
настраивается платформенный TUN. Пакеты с чужим адресом отправителя сервер
отбрасывает (анти-спуфинг).

Токены в памяти хранятся в открытом виде и сравниваются за константное время
(`tunnel_proto::auth`); на роадмапе — HMAC-токены с ротацией и выдачей через
брокер партнёра. Сертификат сервера в MVP самоподписанный (`rcgen`) —
для боевого развёртывания замените его сертификатом CA партнёра.

## Регенерация биндингов

Биндинги для всех языков — **одной командой** (метаданные API берутся из
библиотеки; в release-профиле они вырезаются strip'ом, поэтому генерация идёт
из debug-сборки — это уже учтено в `build_sdk.sh`):

```bash
cargo build -p tunnel-core
cargo run -p tunnel-core --bin uniffi-bindgen -- \
    generate-all --library "$CARGO_TARGET_DIR/debug/libtunnel_core.so" \
    --out-dir bindings            # → bindings/{kotlin,swift,python}/
```

Отдельный язык — стандартный CLI uniffi: `generate --library <lib>
--language swift --out-dir <dir>`. Актуальные сгенерированные биндинги лежат
в `bindings/`; в поставку партнёру они попадают через `dist/`.

## Статус

- [x] Шаг 1 — workspace, `tunnel-proto` (сообщения, кадры, IPv4, auth, метрики)
- [x] Шаг 2 — `tunnel-core`: QUIC-клиент, FFI (`TunnelClient`), reconnect с backoff,
  смена сети; интеграционный тест с локальным QUIC-сервером; сгенерированные биндинги
- [x] Шаг 3 — `tunnel-server`: токены, пул IP, таблица маршрутизации, TUN,
  loopback-режим; E2E-тесты сервер ↔ клиент (echo, несколько клиентов, reject)
- [x] Шаг 4 — коммерческий SDK: API из 5 методов + коллбэк статуса
  (`Connected`/`Reconnecting`/`Disconnected`), телеметрия с пингом, дефолты
  конфига на FFI-границе; `uniffi-bindgen generate-all` (Kotlin/Swift/Python);
  `build_sdk.sh` → `dist/`; `INTEGRATION.md`; smoke-тест Python-биндинга
  против боевого сервера

### Известные ограничения

- IPv6: кадры `KIND_IPV6` принимаются, но маршрутизация v6 не реализована —
  в TUN-режиме передаются «как есть», в loopback-режиме дропаются.
- Контрольные суммы IP сервер не пересчитывает (их делает ядро);
  loopback-эхо меняет только адреса в заголовке.
- Реальный TUN-цикл в CI не прогоняется (нет `CAP_NET_ADMIN`): путь TUN
  покрыт юнит-тестами компонентов, E2E идёт через loopback-режим.
- Android/iOS-цели в дистрибутиве ограничены средой сборки: `arm64-v8a`
  собирается при наличии NDK-таргета, iOS — на macOS (см. INTEGRATION.md).
- На роадмапе: per-client rate-limit, ротация токенов, QUIC connection migration
  между интерфейсами, метрики в формате Prometheus.

## Commercial Licensing & Custom Integration

Исходный код проекта распространяется по лицензии **GNU AGPL-3.0**
(см. [LICENSE](LICENSE)): вы можете свободно использовать, изучать и
модифицировать код при условии соблюдения копилефт-обязательств, включая
обязанность публиковать исходные тексты модификаций при сетевом использовании
продукта (раздел 13 лицензии). Это защищает проект от бесплатного встраивания
в закрытые коммерческие продукты.

Для компаний, которым требуется встроить SDK в **проприетарный продукт без
раскрытия собственного исходного кода**, доступна альтернативная
**коммерческая лицензия** (dual-licensing). Также предоставляются услуги по
кастомной интеграции: сборка SDK под ваши платформы и ABI, доработка протокола
под вашу инфраструктуру, приоритетная поддержка и SLA.

**Контакты для обсуждения условий:**

- Telegram: **@gekata4**
- Email: **lotedru@gmail.com**

В письме укажите название продукта, целевые платформы и ожидаемые объёмы
использования — ответ с условиями лицензирования придёт в течение 1–2 рабочих
дней.
