# tproxy-rs

Rust-реализация **WEB proxy сервера для Telegram** (протокол v1 по PROTOCOL.md
из telegramdesktop/tproxy-server). Clean-room: по публичной спеке, без копирования Go-кода.

Статус: каркас + bridge (HMAC-SHA256 capability, вектора из спеки ✅) + frame-кодек (✅ 11/11 тестов).
В плане: мультиплексор сессий, карьеры (https/websocket), бэкенд к MTProxy, лимиты, Caddy.
