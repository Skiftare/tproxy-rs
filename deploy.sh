#!/bin/sh
# tproxy-rs + MTProto-proxy — ОДНА КОМАНДА для установки Telegram WEB-proxy.
#
# Использование:
#   ./deploy.sh                     # hostname из TPROXY_HOSTNAME или env; секрет сгенерится и напечатается
#   ./deploy.sh my-proxy.example.com   # hostname передаётся явно
#   SECRET=... ./deploy.sh          # или задать секрет вручную (32 hex)
#
# Что делает:
#   1. Берёт hostname (аргумент > TPROXY_HOSTNAME > /etc/hostname? нет — спрашивает).
#   2. Секрет: из SECRET или автоген 32-hex, сохраняет в deploy/.env.
#   3. Подставляет hostname+secret в deploy/config.json (для tproxy-rs).
#   4. Копирует бинарь tproxy-rs (target/release или target2/release) в deploy/bin/.
#   5. Запускает docker compose (tproxy-rs + mtproxy + Caddy auto-TLS).
#   6. Печатает Host + Secret для подключения в Telegram.
set -e
cd "$(dirname "$0")"

# ---- hostname ----
HOSTNAME="${1:-$TPROXY_HOSTNAME}"
if [ -z "$HOSTNAME" ]; then
  HOSTNAME="$(python3 -c "
import urllib.request
print(urllib.request.urlopen('https://ifconfig.me', timeout=8).read().decode().strip())
" 2>/dev/null || true)"
fi
if [ -z "$HOSTNAME" ]; then
  echo "Не смог определить hostname. Укажи его: ./deploy.sh my-proxy.example.com" >&2
  exit 1
fi

# ---- секрет ----
if [ -n "$SECRET" ]; then
  [ ${#SECRET} -eq 32 ] || { echo "SECRET должен быть 32 hex символа (16 байт)." >&2; exit 1; }
else
  if [ -f deploy/.env ]; then
    S=$(grep '^TPROXY_SECRET=' deploy/.env 2>/dev/null | tail -1 | cut -d= -f2)
    [ -n "$S" ] && SECRET="$S"
  fi
fi
if [ -z "$SECRET" ]; then
  SECRET="$(python3 -c 'import secrets;print(secrets.token_hex(16))' 2>/dev/null || openssl rand -hex 16 2>/dev/null)"
  [ -n "$SECRET" ] || { echo "Не могу сгенерировать секрет (нужен python3 или openssl)." >&2; exit 1; }
fi

# ---- .env ----
mkdir -p deploy
cat > deploy/.env <<EOF
TPROXY_HOSTNAME=${HOST}
TPROXY_SECRET=${SECRET}
EOF

# ---- config.json из примера ----
sed -e "s/__TPROXY_HOSTNAME__/${HOST}/g" -e "s/__TPROXY_SECRET__/${SECRET}/g" \
    deploy/config.example.json > deploy/config.json

# ---- бинарь tproxy-rs (откуда бы ни собирали) ----
BIN=""
for cand in target/release/tproxy-rs target2/release/tproxy-rs ../target2/release/tproxy-rs; do
  if [ -f "$cand" ]; then BIN="$cand"; break; fi
done
if [ -z "$BIN" ]; then
  echo "Не найден собранный бинарь tproxy-rs. Собери: cargo build --release (см. README)." >&2
  exit 1
fi
cp "$BIN" deploy/tproxy-rs-bin

# ---- docker compose ----
docker compose -f deploy/docker-compose.yml up -d --build

echo ""
echo "==============================================================="
echo "  ГОТОВО! Telegram WEB-proxy развёрнут."
echo "==============================================================="
echo "  Host:   ${HOST}"
echo "  Secret: ${SECRET}"
echo ""
echo "  В Telegram: Settings → Data and storage → Proxy → + →"
echo "  Web Proxy → Host: ${HOST}  Secret: ${SECRET}"
echo "  Маскировка: папка deploy/site (положи свой сайт)."
echo "==============================================================="