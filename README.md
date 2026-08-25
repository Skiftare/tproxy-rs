# tproxy-rs

Rust-реализация **WEB proxy сервера для Telegram** (протокол v1 по PROTOCOL.md
из telegramdesktop/tproxy-server). Clean-room: по публичной спеке, без копирования Go-кода. MIT.

Что умеет:
- **bridge** — HMAC-SHA256 capability по спеке (`tdesktop-web-proxy-bridge-v1\n<host>`);
- **frame-кодек** — OPEN/DATA/CLOSE/WINDOW/HELLO/WELCOME;
- **карьеры** — `websocket`, `https`, `https-lanes`, `websocket-lanes`;
- **мульти-хост** — один процесс релея обслуживает N сайтов, у каждого свои ключи и своя маска;
- **изоляция ключей** — ключ сайта A не работает на сайте B (capability хэширует hostname);
- **burn** — генератор «сжигания адресов»: YAML → 1 релей + 1 dumb-MTProxy + N масок + keys.zip.

---

## 🏭 Главный инструмент: `burn` (штамповка флота)

Один YAML-файл описывает сколько угодно сайтов и сколько угодно ключей на каждом.
Из него `burn` рендерит **весь** деплой:

- **1 конфиг релея** (multi-host: все сайты в одном процессе);
- **1 dumb-MTProxy** (один контейнер, внутренние порты на каждый ключ, **приватная сеть** —
  наружу не публикуется вообще, клиенты подключаются только через web-proxy);
- **nginx**-блоки;
- **N папок-масок** (`sites/<domain>/index.html`);
- **`keys.zip`** — по файлу на сайт (имя файла = заэкранированный домен), в файле — столько
  ключей, сколько задано для сайта.

```yaml
# burn.yaml
tproxy:
  listen: 127.0.0.1:8091     # релей (за nginx/Caddy)
  carrier: websocket          # websocket | https | https-lanes | websocket-lanes
  mtproxy_container: mtproxy-dumb
  mtproxy_base_port: 9000     # внутренние порты mtproxy стартуют отсюда
  public_root: /srv/burn      # корень, куда лягут папки-маски

sites:
  - domain: site-a.example.com
    keys: 1447                # число → сгенерить 1447 ключей (CSPRNG)

  - domain: site-b.example.com
    keys: [000102030405060708090a0b0c0d0e0f,
           112233445566778899aabbccddeeff00]   # список → использовать как есть

  - domain: site-c.example.net
    keys: 1
```

Запуск:

```bash
cargo build --release

# посмотреть план, ничего не писать
./target/release/burn dry burn.yaml

# сгенерировать артефакты в ./burn-out
./target/release/burn gen burn.yaml --out burn-out

# что получилось
ls burn-out/            # config.json, mtproxy.sys.config, mtproxy-launch.sh,
                        # nginx-tproxy.conf, sites/, keys.zip
```

Готовый флот поднимается так (пример для docker compose):

```yaml
services:
  relay:          # tproxy-rs: 1 контейнер на ВСЕ сайты
    image: debian:bookworm-slim
    volumes:
      - ./burn-out/config.json:/app/config.json:ro
      - ./sites:/svalka:ro
    command: ["/app/tproxy-rs", "-c", "/app/config.json"]
  mtproxy-dumb:   # 1 контейнер, N внутренних портов, НЕ публикуется наружу
    image: seriyps/mtproto-proxy
    entrypoint: ["/opt/mtp_proxy/bin/mtp_proxy", "foreground"]
    volumes:
      - ./burn-out/mtproxy.sys.config:/opt/mtp_proxy/releases/0.1.0/sys.config:ro
    # ВАЖНО: без секции ports: — порты доступны только внутри docker-сети
```

### Как работает один dumb-MTProxy на N ключей

Официальный CLI-старт (`-p -s`) принимает **один** секрет. Но сам MTProxy умеет
список: `sys.config` содержит `{mtproto_proxy, [{ports, [#{port => P, secret => <<"S">>}, ...]}]}`.
`burn` генерит этот `sys.config` со всеми ключами, и он **монтируется поверх**
`/opt/mtp_proxy/releases/0.1.0/sys.config` — один процесс, N портов, все в приватной сети.

### Изоляция ключей

Капабилити bridge = `HMAC-SHA256(secret, "tdesktop-web-proxy-bridge-v1\n<hostname>")`.
Хост вшит в подпись: секрет, сгенерированный для сайта A, даёт кап, который релей
на сайте B **не примет**. Разделение ключей гарантировано протоколом, тест
`site_scoped_isolation` это закрепляет.

---

## 🚀 Простой деплой одного сайта (`deploy.sh`)

Для одного прокси без флота:

```bash
./deploy.sh --hostname my-proxy.example.com                          # секрет сгенерится сам
./deploy.sh --hostname my-proxy.example.com --secret 000102030405060708090a0b0c0d0e0f
./deploy.sh --hostname my-proxy.example.com --carrier https-lanes --secret S1 --secret S2
```

Генерит конфиг, compose (tproxy-rs + mtproxy + Caddy с авто-TLS), поднимает и печатает
Host + секреты.

---

## ⚠️ Cloudflare и подобные CDN — читать обязательно

- **WebSocket и long-poll (все карьеры, кроме `https-lanes`) ломаются за CF-проксированием.**
  Cloudflare буферизует апгрейд/длинные соединения → клиент видит «вечный реконнект»,
  хотя TCP/TLS доходят. Как минимум держи прокси-домен **DNS-only (серое облако)**.
- **`https-lanes`** (короткие POST-запросы вместо одного долгого канала) переживает CF
  заметно лучше — это единственный карьер, который можно пробовать за CF.
- Если прокси-домен совмещён с сайтом на одном hostname — CF-прокси этот домен целиком,
  значит и сайт, и прокси. Разводи на разные поддомены.
- DPI-блокировки (российские провыдера и т.п.) душат долгие WS-соединения даже без CF —
  для устойчивости выбирай `https-lanes` и/или свежие домены.

## Ключи и вход

- **Публичный вход** — один: `https://<hostname>` (это и есть «порт»).
- **Ключей может быть сколько угодно**: каждый ключ — отдельный человек/круг.
- В Telegram: Настройки → Прокси → + → Web Proxy → Host + Secret.

## Сборка

```bash
cargo build --release
# бинари: target/release/tproxy-rs  (релей)
#         target/release/burn       (генератор флота)
cargo test        # 20+ тестов: кодек, изоляция ключей, burn-парсинг
```

## Структура

```
src/
  server.rs    — axum: /api/v1/{session,up,down,ws}, bridge, статика по Host
  config.rs    — Config: hosts[] (hostname + public_dir + secrets), capability_site
  session.rs   — frame-движок, потоки к dumb-MTProxy
  frame.rs     — кодек фреймов
  bridge.rs    — HMAC-capability, Hostname
  bin/burn.rs  — генератор флота из YAML (config + sys.config + nginx + masks + zip)
```

Ядро (config/server/session) — единственное место с протокольной логикой.
`burn` лишь раскладывает YAML в артефакты; эволюция протокола = правки ядра,
генератор не трогаем.

## Лицензия

MIT — см. LICENSE. Свободно: копируй, форкай, штампуй, продавай.