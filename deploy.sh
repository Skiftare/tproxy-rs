#!/bin/bash
# tproxy-rs + MTProto-proxy — развёртывание Telegram WEB-proxy ОДНОЙ КОМАНДОЙ,
# БЕЗ редактирования конфиг-файлов. Всё через аргументы.
#
# Использование:
#   ./deploy.sh --hostname my-proxy.example.com --secret <hex32>
#   ./deploy.sh --hostname my-proxy.example.com            # секрет сгенерится, напечатается
#   ./deploy.sh --hostname my-proxy.example.com \
#              --secret <hex1> --secret <hex2> --secret <hex3>   # НЕСКОЛЬКО ключей
#   ./deploy.sh                                      # hostname из TPROXY_HOSTNAME или спросят
#
# Секреты можно задавать многократно: каждый --secret становится отдельным
# ключом web-proxy, под каждый поднимается свой MTProto-бэкенд (внутренний порт).
# Один публичный вход (hostname:443), сколько угодно ключей для разных людей.
#
set -e
cd "$(dirname "$0")"

# ---- mass-режим: --mass <yaml> [--dry-run] ----
MASS_FILE=""; MASS_DRY=""
for a in "$@"; do
  case "$a" in
    --mass) MASS_FILE="next";;
    --mass=*) MASS_FILE="${a#*=}";;
    --dry-run) MASS_DRY="--dry-run";;
    *) if [ "$MASS_FILE" = "next" ]; then MASS_FILE="$a"; fi;;
  esac
done
if [ -n "$MASS_FILE" ] && [ "$MASS_FILE" != "next" ]; then
  BIN=""
  for cand in target/release/tproxy-rs target2/release/tproxy-rs ../target2/release/tproxy-rs; do
    [ -f "$cand" ] && { BIN="$cand"; break; }
  done
  if [ -z "$BIN" ]; then
    echo "Нет собранного tproxy-rs. Собери: cargo build --release" >&2
    exit 1
  fi
  exec "$BIN" mass "$MASS_FILE" --out ./mass $MASS_DRY
fi

# ---- разбор аргументов: --hostname, --secret (повторяемый) ----
HOSTNAME=""
SECRETS=()
CARRIER=""
NEXT_HOST=""; NEXT_SEC=""; NEXT_CARRIER=""
for a in "$@"; do
  case "$a" in
    -h|--hostname)   NEXT_HOST="hostname";;
    --hostname=*)    HOSTNAME="${a#*=}";;
    -s|--secret)     NEXT_SECRET="secret";;
    --secret=*)      SECRETS+=("${a#*=}");;
    -c|--carrier)    NEXT_CARRIER="carrier";;
    --carrier=*)     CARRIER="${a#*=}";;
    *)
      if [ "$NEXT_HOST" = "hostname" ]; then HOSTNAME="$a"; NEXT_HOST=""; fi
      if [ "$NEXT_SECRET" = "secret" ]; then SECRETS+=("$a"); NEXT_SECRET=""; fi
      if [ "$NEXT_CARRIER" = "carrier" ]; then CARRIER="$a"; NEXT_CARRIER=""; fi
      ;;
  esac
done
[ -z "$CARRIER" ] && CARRIER="${TPROXY_CARRIER:-websocket}"

# ---- если hostname пуст, берём из env или stdout —---
[ -z "$HOSTNAME" ] && HOSTNAME="${TPROXY_HOSTNAME:-}"
if [ -z "$HOSTNAME" ]; then
  HOSTNAME="$(python3 -c "
import urllib.request
print(urllib.request.urlopen('https://ifconfig.me', timeout=8).read().decode().strip())
" 2>/dev/null || true)"
fi
[ -z "$HOSTNAME" ] && { echo "Не задан hostname. Укажи: ./deploy.sh --hostname my-proxy.example.com" >&2; exit 1; }

# ---- секреты: из --secret, или сгенерить один ----
if [ -z "$SECRETS" ]; then
  gen(){ python3 -c 'import secrets;print(secrets.token_hex(16))' 2>/dev/null || openssl rand -hex 16; }
  S="$(gen)"
  [ -n "$S" ] || { echo "Не могу сгенерить secret (нужен python3/openssl)." >&2; exit 1; }
  SECRETS=("$S")
fi
for s in $SECRETS; do
  [ ${#s} -eq 32 ] || { echo "Секрет '$s' — не 32 hex (16 байт)." >&2; exit 1; }
done

# ---- .env ----
mkdir -p deploy
cat > deploy/.env <<EOF
TPROXY_HOSTNAME=${HOSTNAME}
TPROXY_SECRET=${SECRETS[0]}       # первый — основной
EOF

# ---- например, конкретная: под какое количество бэкендов генерим compose ----
N=${#SECRETS[@]}

# ---- config.json для tproxy-rs (все секреты + бэкенды по ним) ----
{
  echo '{'
  echo '  "public_hostname": "'${HOSTNAME}'",'
  echo '  "listen": "0.0.0.0:8091",'
  echo '  "admin_listen": "127.0.0.1:8092",'
  echo '  "public_dir": "/app/site",'
  echo '  "mtproxy_addr": "mtproxy:2398",'
  echo '  "secret_hex": "'${SECRETS[0]}'",'
  echo '  "carrier_mode": "'${CARRIER}'",'
  echo '  "backends": ['
  i=0
  for s in $SECRETS; do
    comma=""
    [ $i -lt $((N-1)) ] && comma=","
    echo "    {\"secret_hex\": \"$s\", \"mtproxy_addr\": \"mtproxy-$((i+1)):$((2398+i+1))\"}$comma"
    i=$((i+1))
  done
  echo '  ]'
  echo '}'
} > deploy/config.json

# ---- docker-compose: tproxy-rs + по одному mtproxy на секрет + Caddy (авто-TLS) ----
{
  echo 'services:'
  echo '  tproxy-rs:'
  echo '    image: debian:bookworm-slim'
  echo '    container_name: tproxy-rs'
  echo '    restart: unless-stopped'
  echo '    command: ["/app/tproxy-rs", "-c", "/app/config.json"]'
  echo '    environment:'
  echo '      TPROXY_HOSTNAME: "'${HOSTNAME}'"'
  echo '      TPROXY_SECRET: "'${SECRETS[0]}'"'
  echo '      TPROXY_SITE_DIR: /app/public'
  echo '    volumes:'
  echo '      - ./tproxy-rs-bin:/app/tproxy-rs:ro'
  echo '      - ./config.json:/app/config.json:ro'
  echo '      - ./site:/app/public:ro'
  echo '  mtproxy:'
  echo '    image: seriyps/mtproto-proxy'
  echo '    container_name: mtproxy'
  echo '    restart: unless-stopped'
  echo '    command: ["-p", "2398", "-s", "'${SECRETS[0]}'", "-t", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]'
  i=1
  for s in $(echo "${SECRETS[@]:1}" 2>/dev/null); do
    echo "  mtproxy-$((i+1)):"
    echo "    image: seriyps/mtproto-proxy"
    echo "    container_name: mtproxy-$((i+1))"
    echo "    restart: unless-stopped"
    echo "    expose:"
    echo "      - \"$((2398+i))\""
    echo '    command: ["-p", "'"$((2398+i))"'", "-s", "'$s'", "-t", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]'
    i=$((i+1))
  done
  echo '  caddy:'
  echo '    image: caddy:2'
  echo '    container_name: caddy'
  echo '    restart: unless-stopped'
  echo '    ports:'
  echo '      - "80:80"'
  echo '      - "443:443"'
  echo '    environment:'
  echo '      CADDY_HOSTNAME: "'${HOSTNAME}'"'
  echo '    volumes:'
  echo '      - ./Caddyfile:/etc/caddy/Caddyfile:ro'
  echo '      - ./site:/srv/site:ro'
  echo 'volumes:'
  echo '  caddy_data:'
  echo '  caddy_config:'
} > deploy/docker-compose.yml

# ---- бинарь tproxy-rs ----
BIN=""
for cand in target/release/tproxy-rs target2/release/tproxy-rs ../target2/release/tproxy-rs; do
  [ -f "$cand" ] && { BIN="$cand"; break; }
done
[ -z "$BIN" ] && { echo "Нет собранного tproxy-rs. Собери: cargo build --release" >&2; exit 1; }
cp "$BIN" deploy/tproxy-rs-bin

# ---- старт ----
docker compose -f deploy/docker-compose.yml up -d --build

echo ""
echo "======================================================================"
echo "  ГОТОВО! Telegram WEB-proxy развернут."
echo "  Вход один:  ${HOSTNAME}"
echo "----------------------------------------------------------------------"
i=1
for s in $SECRETS; do
  echo "  Secret ${i}: ${s}"
  i=$((i+1))
done
echo "======================================================================"