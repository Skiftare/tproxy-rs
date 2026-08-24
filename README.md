# tproxy-rs

Rust-реализация **WEB proxy сервера для Telegram** (протокол v1 по PROTOCOL.md
из telegramdesktop/tproxy-server). Clean-room: по публичной спеке, без копирования Go-кода.

Статус: каркас + bridge (HMAC-SHA256 capability, вектора из спеки ✅) + frame-кодек (✅ 11/11 тестов).
В плане: мультиплексор сессий, карьеры (https/websocket), бэкенд к MTProxy, лимиты, Caddy.


## 🚀 Деплой одной командой

```bash
git clone <репозиторий> tproxy-rs && cd tproxy-rs
./deploy.sh
```

Что делает `deploy.sh`:
- создаёт `deploy/.env` (если нет) со **случайным секретом** (не хардкодит ничего);
- подставляет твой `TPROXY_HOSTNAME` и секрет в конфиг;
- запускает `docker compose` (tproxy-rs + MTProto-proxy + Caddy с авто-TLS для твоего домена);
- печатает Host + Secret для подключения в Telegram.

### Настройка (перед запуском)
1. В DNS укажи `TPROXY_HOSTNAME` → IP этого сервера (A/AAAA).
2. (опционально) отредактируй `deploy/.env`: `TPROXY_HOSTNAME`, `TPROXY_CARRIER`.
3. Маскировку положи в `deploy/site/` (твой сайт — будет отдаваться на всех путях, кроме `?bridge=`).

Секрет **генерируется случайно при первом запуске** и хранится только в `deploy/.env` (в .gitignore). Ничего не захардкожено: hostname, secret, порт, карьер — всё из `.env`/config.

**В Telegram**: Настройки → Прокси → + → Web Proxy → host + secret.
