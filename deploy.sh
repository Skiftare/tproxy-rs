#!/bin/sh
# tproxy-rs + MTProto-proxy — 1-командный деплой.
# Использование: ./deploy.sh
#
# Что делает:
#  1. Если нет deploy/.env — создаёт из deploy/.env.example и генерирует СЛУЧАЙНЫЙ секрет.
#  2. Подставляет hostname/секрет в config.json (для tproxy-rs).
#  3. Запускает docker compose (tproxy-rs + mtproxy).
#  4. Печатает параметры для подключения в Telegram.

set -e
cd "$(dirname "$0")"

if [ ! -f deploy/.env ]; then
  cp deploy/.env.example deploy/.env
  # случайный секрет: 16 байт = 32 hex (hex, 0-9a-f)
  gen_hex() { python3 -c "import secrets;print(secrets.token_hex(16))" 2>/dev/null || openssl rand -hex 16 2>/dev/null; }
  SECRET="${TPROXY_SECRET:-$(gen_hex)}"
  if [ -z "$SECRET" ]; then
    echo "ОШИБКА: нет способа сгенерировать секрет. Задай TPROXY_SECRET в deploy/.env (32 hex)."
    exit 1
  fi
  # записать секрет в deploy/.env
  if grep -q '^TPROXY_SECRET=' deploy/.env; then
    : # пользователь мог задать
  else
    echo "TPROXY_SECRET=$SECRET" >> deploy/.env
  fi
  echo ">>> Создан deploy/.env со случайным секретом."
fi

# загрузить переменные
. ./deploy/.env
HOSTNAME="${TPROXY_HOSTNAME:?Задай TPROXY_HOSTNAME в deploy/.env}"
[[ -z "$TPROXY_SECRET" ]] && TPROXY_SECRET="$(grep '^TPROXY_SECRET=' deploy/.env | tail -1 | cut -d= -f2)"
SECRET="${TPROXY_SECRET}"

# config.json для tproxy-rs (все параметры из env, никаких хардкодов)
mkdir -p site
cat > deploy/config.json <<EOF
{
  "public_hostname": "${HOSTNAME}",
  "listen": "0.0.0.0:8091",
  "admin_listen": "127.0.0.1:8092",
  "public_dir": "/app/public",
  "mtproxy_addr": "mtproxy:2398",
  "secret_hex": "${SECRET}",
  "carrier_mode": "${TPROXY_CARRIER:-websocket}"
EOF

# docker compose старт
docker compose -f deploy/docker-compose.yml up -d --build 2>&1 | tail -5

echo ""
echo "======================================================="
echo "  ГОТОВО! WEB-прокси Telegram развёрнут."
echo "======================================================="
echo "  Host: ${HOSTNAME}"
echo "  Secret (32 hex): ${SECRET}"
echo ""
echo "  В Telegram: Настройки → Данные и память → Прокси → + Добавить"
echo "  → Web Proxy → введи host и secret."
echo ""
echo "  Маскировка: папка ./site (положи сюда свой сайт)."
echo "======================================================="