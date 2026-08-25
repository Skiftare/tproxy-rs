# tproxy-rs

[![CI build](https://github.com/Skiftare/tproxy-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Skiftare/tproxy-rs/actions/workflows/ci.yml)
[![tests](https://img.shields.io/github/actions/workflow/status/Skiftare/tproxy-rs/ci.yml?branch=main&label=tests)](https://github.com/Skiftare/tproxy-rs/actions/workflows/ci.yml)
[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Skiftare/tproxy-rs/main/badges/coverage.json&style=flat)](https://github.com/Skiftare/tproxy-rs/actions/workflows/ci.yml)

A Rust implementation of the **Telegram WEB proxy server** (protocol v1 per
PROTOCOL.md from telegramdesktop/tproxy-server). Clean-room: built against the
public spec, no Go code copied. MIT.

What it does:
- **bridge** — HMAC-SHA256 capability per spec (`tdesktop-web-proxy-bridge-v1\n<host>`);
- **frame codec** — OPEN/DATA/CLOSE/WINDOW/HELLO/WELCOME;
- **carriers** — `websocket` (works), `https-lanes` (**NOT working in the current Rust implementation**), `https`, `websocket-lanes` (experimental);
- **multi-host** — one relay process serves N sites, each with its own keys and mask;
- **key isolation** — a key minted for site A does not work on site B (capability hashes the hostname);
- **burn** — the "address burning" generator: YAML becomes 1 relay + 1 dumb MTProxy + N masks + keys.zip.

---

## Main tool: `burn` (fleet stamping)

One YAML file describes any number of sites and any number of keys per site.
`burn` renders the **entire** deployment from it:

- **1 relay config** (multi-host: all sites in a single process);
- **1 dumb-MTProxy** (one container, one internal port per key, **private network** —
  never published outward; clients connect only through the web-proxy);
- **nginx** blocks;
- **N mask folders** (`sites/<domain>/index.html`);
- **`keys.zip`** — one file per site (filename = escaped domain), each file holds
  as many keys as configured for that site.

```yaml
# burn.yaml
tproxy:
  listen: 127.0.0.1:8091     # relay (behind nginx/Caddy)
  carrier: websocket          # websocket | https | https-lanes | websocket-lanes
  mtproxy_container: mtproxy-dumb
  mtproxy_base_port: 9000     # internal mtproxy ports start here
  public_root: /srv/burn      # root for mask folders

sites:
  - domain: site-a.example.com
    keys: 1447                # number: generate 1447 keys (CSPRNG)

  - domain: site-b.example.com
    keys: [000102030405060708090a0b0c0d0e0f,
           112233445566778899aabbccddeeff00]   # list: use as-is

  - domain: site-c.example.net
    keys: 1
```

Run:

```bash
cargo build --release

# print the plan without writing anything
./target/release/burn dry burn.yaml

# generate artifacts into ./burn-out
./target/release/burn gen burn.yaml --out burn-out

# what you get
ls burn-out/            # config.json, mtproxy.sys.config, mtproxy-launch.sh,
                        # nginx-tproxy.conf, sites/, keys.zip
```

Bringing the fleet up (docker compose example):

```yaml
services:
  relay:          # tproxy-rs: 1 container for ALL sites
    image: debian:bookworm-slim
    volumes:
      - ./burn-out/config.json:/app/config.json:ro
      - ./sites:/svalka:ro
    command: ["/app/tproxy-rs", "-c", "/app/config.json"]
  mtproxy-dumb:   # 1 container, N internal ports, NOT published
    image: seriyps/mtproto-proxy
    entrypoint: ["/opt/mtp_proxy/bin/mtp_proxy", "foreground"]
    volumes:
      - ./burn-out/mtproxy.sys.config:/opt/mtp_proxy/releases/0.1.0/sys.config:ro
    # IMPORTANT: no ports: section — ports are reachable only inside the docker network
```

### How one dumb-MTProxy serves N keys

The official CLI entrypoint (`-p -s`) takes **one** secret. But MTProxy itself
supports a list: `sys.config` holds `{mtproto_proxy, [{ports, [#{port => P, secret => <<"S">>}, ...]}]}`.
`burn` generates this `sys.config` with all keys, and it is **mounted over**
`/opt/mtp_proxy/releases/0.1.0/sys.config` — one process, N ports, all in the private network.

### Key isolation

Bridge capability = `HMAC-SHA256(secret, "tdesktop-web-proxy-bridge-v1\n<hostname>")`.
The hostname is embedded in the signature: a secret generated for site A produces
a capability the relay on site B **rejects**. Key separation is guaranteed by the
protocol; the `site_scoped_isolation` test enforces it.

---

## Simple single-site deploy (`deploy.sh`)

For one proxy without a fleet:

```bash
./deploy.sh --hostname my-proxy.example.com                          # secret auto-generated
./deploy.sh --hostname my-proxy.example.com --secret 000102030405060708090a0b0c0d0e0f
./deploy.sh --hostname my-proxy.example.com --carrier websocket --secret S1 --secret S2
```

It generates the config, compose (tproxy-rs + mtproxy + Caddy with auto-TLS),
brings it up, and prints Host + secrets.

---

## Cloudflare and similar CDNs — read this first

- **WebSocket breaks behind a CF proxy.** Cloudflare buffers the upgrade/long-lived
  connections, so the client sees "endless reconnect" even though TCP/TLS reach the
  origin. The only reliable setup is **DNS-only (grey cloud)** for the proxy domain.
- `https-lanes` is advertised in the spec as a CF workaround, but **it is NOT
  implemented in the current relay** (see "What it does"). Don't rely on it; if you
  need CF bypass, improve the core.
- If the proxy domain shares a hostname with the site, CF proxies that hostname
  entirely — put the site and the proxy on separate subdomains.
- DPI blocking (ISPs, etc.) chokes long WS connections even without CF —
  for resilience use fresh domains and/or rotate keys often.

## Keys and entry

- **Public entry** — one: `https://<hostname>` (that IS the "port").
- **Unlimited keys**: each key is a separate person/circle.
- In Telegram: Settings, Proxy, +, Web Proxy, Host + Secret.

## Build

```bash
cargo build --release
# binaries: target/release/tproxy-rs  (relay)
#           target/release/burn       (fleet generator)
cargo test        # 20+ tests: codec, key isolation, burn parsing
```

## Layout

```
src/
  server.rs    - axum: /api/v1/{session,up,down,ws}, bridge, per-Host static
  config.rs    - Config: hosts[] (hostname + public_dir + secrets), capability_site
  session.rs   - frame engine, streams to the dumb MTProxy
  frame.rs     - frame codec
  bridge.rs    - HMAC capability, Hostname
  bin/burn.rs  - fleet generator from YAML (config + sys.config + nginx + masks + zip)
```

The core (config/server/session) is the only place with protocol logic.
`burn` merely turns YAML into artifacts; protocol evolution = core edits,
the generator stays untouched.

## License

MIT — see LICENSE. Free to copy, fork, stamp, sell.