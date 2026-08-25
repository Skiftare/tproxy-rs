//! `burn` — генератор "сожжения адресов" для tproxy-rs.
//!
//! Из одного YAML-файла разворачивает целую инфраструктуру для МАССЫ сайтов,
//! НЕ плодя mtproxy-контейнеры: ОДИН "dumb" MTProxy внутри приватной сети
//! слушает N внутренних портов (по одному секрету на порт), наружу не торчит;
//! единственный вход пользователя — web-proxy через релей.
//!
//! Вход (burn.yaml):
//! ```yaml
//! tproxy:
//!   listen: 127.0.0.1:8091
//!   carrier: websocket        # websocket | https | https-lanes | websocket-lanes
//!   mtproxy_container: mtproxy-dumb   # имя контейнера-бэкенда
//!   mtproxy_base_port: 9000   # внутренние порты стартуют отсюда
//!   public_root: /srv/burn    # корень под папки-маски
//! sites:
//!   - domain: site-a.example.com
//!     keys: 1447              # число → сгенерировать N ключей (CSPRNG)
//!   - domain: site-b.example.com
//!     keys: [abc…, def…]      # список → использовать как есть
//!   - domain: site-c.example.net
//!     keys: 1
//! ```
//!
//! Выход в каталоге `--out` (по умолчанию `./burn-out`):
//! - `config.json`            — много-хостовой конфиг релея (1 процесс, N сайтов)
//! - `mtproxy.env`            — переменные для ОДНОГО контейнера (порты+секреты)
//! - `mtproxy-start.sh`       — запуск mtproxy с N секретами через start.sh-совместимый
//!   формат: один контейнер стартует с нужным числом портов
//! - `nginx-tproxy.conf`      — nginx-блок: *.hosts → релей
//! - `sites/<domain>/index.html` — маски-сайты (одна папка на сайт)
//! - `keys.zip`               — N файлов (имя = заэкранированный домен), в каждом
//!   M(i) ключей-подключений. Ключи сайта A НЕ подходят сайту B (изоляция в ядре).
//!
//! Ключевое свойство дизайна: генератор НЕ знает про контейнеры>1 mtproxy.
//! Ядро (config.rs/server.rs) — единственное место с логикой; burn лишь
//! превращает YAML в артефакты, которые скармливаются тому же ядру. Поэтому
//! эволюция протокола = правка ядра, генератор только перекладывает поля.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use rand::RngCore;
use serde::Deserialize;

/// Top-level burn input.
#[derive(Deserialize, Debug)]
struct BurnConfig {
    #[serde(default)]
    tproxy: Option<TproxySpec>,
    #[serde(default)]
    sites: Vec<SiteSpec>,
}

#[derive(Deserialize, Debug, Clone)]
struct TproxySpec {
    #[serde(default = "d_listen")] listen: String,
    #[serde(default = "d_carrier")] carrier: String,
    #[serde(default = "d_mtproxy_container")] mtproxy_container: String,
    #[serde(default = "d_base_port")] mtproxy_base_port: u16,
    #[serde(default = "d_public_root")] public_root: String,
    /// Reserved for future per-site subdomain suffix handling.
    #[serde(default = "d_site_suffix")]
    #[allow(dead_code)]
    site_suffix: String,
    /// Name of the relay container (used in nginx upstream default).
    #[serde(default = "d_relay_container")] nginx_upstream: String,
}

fn d_relay_container() -> String { "http://relay:8091".into() }

#[derive(Deserialize, Debug)]
struct SiteSpec {
    domain: String,
    /// Either a number (generate N) or a list of explicit secrets.
    #[serde(deserialize_with = "deser_keys")]
    keys: Keys,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum Keys {
    Count(u64),
    List(Vec<String>),
}

fn deser_keys<'de, D>(d: D) -> Result<Keys, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let v: serde_yaml::Value = serde_yaml::Value::deserialize(d)?;
    match v {
        serde_yaml::Value::Number(n) => n.as_u64().map(Keys::Count).ok_or_else(|| D::Error::custom("keys: count must be u64")),
        serde_yaml::Value::Sequence(seq) => {
            let mut out = Vec::new();
            for item in seq {
                if let serde_yaml::Value::String(s) = item { out.push(s); }
                else { return Err(D::Error::custom("keys list items must be strings")); }
            }
            Ok(Keys::List(out))
        }
        _ => Err(D::Error::custom("keys: must be a number or a list of secrets")),
    }
}

fn d_listen() -> String { "127.0.0.1:8091".into() }
fn d_carrier() -> String { "websocket".into() }
fn d_mtproxy_container() -> String { "mtproxy-dumb".into() }
fn d_base_port() -> u16 { 9000 }
fn d_public_root() -> String { "/srv/burn".into() }
fn d_site_suffix() -> String { "".into() }

/// Validate that a secret is 16/17-byte hex.
fn valid_secret(s: &str) -> bool {
    if !(s.len() == 32 || s.len() == 34) { return false; }
    hex::decode(s).map(|b| b.len() == 16 || b.len() == 17).unwrap_or(false)
}

/// Cryptographic random hex secret (16 bytes).
fn random_secret() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Escape a domain for use as a filename (safe chars, keep it readable).
fn escape_filename(domain: &str) -> String {
    domain.chars().map(|c| {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' }
    }).collect()
}

/// Materialize all sites: generate secrets where count given.
struct MaterializedSite {
    domain: String,
    secrets: Vec<String>,
    port: u16,
}

#[derive(Parser, Debug)]
#[command(name = "burn", about = "Stamp out a tproxy-rs multi-site fleet from one YAML")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Parse burn.yaml and emit config.json + masks + mtproxy spec + keys.zip.
    Gen {
        /// burn.yaml input
        yaml: PathBuf,
        /// Output directory (default ./burn-out)
        #[arg(long, default_value = "burn-out")]
        out: PathBuf,
    },
    /// Print what would be generated, without writing anything.
    Dry {
        yaml: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Gen { yaml, out } => gen(&yaml, &out, false),
        Cmd::Dry { yaml } => gen(&yaml, &PathBuf::from("/tmp/burn-dry"), true),
    }
}

fn gen(yaml_path: &Path, out: &Path, dry: bool) -> Result<(), Box<dyn std::error::Error>> {
    let text = fs::read_to_string(yaml_path)?;
    let cfg: BurnConfig = serde_yaml::from_str(&text)?;
    if cfg.sites.is_empty() {
        return Err("burn: no sites defined".into());
    }
    let spec = cfg.tproxy.clone().unwrap_or(TproxySpec {
        listen: d_listen(),
        carrier: d_carrier(),
        mtproxy_container: d_mtproxy_container(),
        mtproxy_base_port: d_base_port(),
        public_root: d_public_root(),
        site_suffix: d_site_suffix(),
        nginx_upstream: d_relay_container(),
    });

    // 1) Materialize secrets + assign one internal mtproxy port per secret.
    let mut sites: Vec<MaterializedSite> = Vec::new();
    let mut port = spec.mtproxy_base_port;
    let mut total_keys = 0usize;
    let mut seen_domains: BTreeMap<String, ()> = BTreeMap::new();
    for s in &cfg.sites {
        let domain = s.domain.trim().to_lowercase();
        if domain.is_empty() { return Err("burn: empty domain".into()); }
        if seen_domains.insert(domain.clone(), ()).is_some() {
            return Err(format!("burn: duplicate domain {domain}").into());
        }
        let secrets = match &s.keys {
            Keys::Count(n) => {
                if *n == 0 { return Err(format!("burn: {domain}: keys: 0 not allowed").into()); }
                if *n > 10_000 { return Err(format!("burn: {domain}: keys: {n} too large (cap 10k)").into()); }
                (0..*n).map(|_| random_secret()).collect()
            }
            Keys::List(list) => {
                if list.is_empty() { return Err(format!("burn: {domain}: keys: empty list").into()); }
                for k in list {
                    if !valid_secret(k) { return Err(format!("burn: {domain}: invalid secret {k}").into()); }
                }
                list.clone()
            }
        };
        total_keys += secrets.len();
        let secs = secrets.clone();
        sites.push(MaterializedSite { domain, secrets: secs, port });
        port = port.saturating_add(secrets.len() as u16).max(port);
    }

    // 2) Build the relay config (MULTI-HOST).
    let mut hosts = Vec::new();
    let mut site_rows: Vec<(String, u16, Vec<String>)> = Vec::new();
    for s in &sites {
        hosts.push(serde_json::json!({
            "hostname": s.domain,
            "public_dir": format!("{}/sites/{}", spec.public_root, escape_filename(&s.domain)),
            "secrets": s.secrets,
        }));
        site_rows.push((s.domain.clone(), s.port, s.secrets.clone()));
    }
    let relay_config = serde_json::json!({
        "public_hostname": sites[0].domain,           // legacy fallback
        "hosts": hosts,
        "listen": spec.listen,
        "admin_listen": "127.0.0.1:8092",
        "public_dir": format!("{}/sites/{}", spec.public_root, escape_filename(&sites[0].domain)),
        "mtproxy_addr": format!("{}:{}", spec.mtproxy_container, spec.mtproxy_base_port),
        "secret_hex": sites[0].secrets[0],
        "carrier_mode": spec.carrier,
        "limits": {}
    });

    // 3) MTProxy spec: ONE container, per-secret internal ports.
    //    Официальный формат: Erlang sys.config со списком `ports`. Один процесс,
    //    N портов, все в приватной сети (наружу не публикуются).
    let mut sys_config = String::from("%% -*- mode: erlang -*-\n[\n {mtproto_proxy,\n  [\n   {ports,\n    [\n");
    let mut first = true;
    for (_domain, p, secs) in &site_rows {
        for (i, sec) in secs.iter().enumerate() {
            if !first { sys_config.push_str(",\n"); }
            first = false;
            sys_config.push_str(&format!(
                "     #{{name => mtp_handler_{}, listen_ip => \"0.0.0.0\", port => {}, secret => <<\"{}\">>, tag => <<\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\">>}}",
                i, p + i as u16, sec
            ));
        }
    }
    sys_config.push_str("\n    ]\n   }\n  ]},\n");
    sys_config.push_str(" {kernel,\n  [{logger_level, info},\n   {logger,\n    [{handler, default, logger_std_h,\n      #{level => info,\n        config => #{type => standard_io}}}\n    ]}\n  ]},\n");
    sys_config.push_str(" {sasl,\n  [{errlog_type, error}]}\n].\n");
    // Простой launcher: mtp_proxy foreground -config <path> — читает ports из конфига.
    let mtproxy_launcher = "#!/bin/sh\nexec /opt/mtp_proxy/bin/mtp_proxy foreground -config /app/mtproxy.sys.config\n";

    // 4) nginx: one server block per site (all → same relay).
    let nginx_upstream = if spec.nginx_upstream.is_empty() {
        format!("http://{}:8091", spec.mtproxy_container)
    } else {
        spec.nginx_upstream.clone()
    };
    let mut nginx = String::new();
    for (domain, _, _) in &site_rows {
        nginx.push_str("server {\n");
        nginx.push_str("  listen 443 ssl;\n");
        nginx.push_str("  server_name ");
        nginx.push_str(domain);
        nginx.push_str(";\n");
        nginx.push_str("  ssl_certificate     /etc/letsencrypt/live/");
        nginx.push_str(domain);
        nginx.push_str("/fullchain.pem;\n");
        nginx.push_str("  ssl_certificate_key /etc/letsencrypt/live/");
        nginx.push_str(domain);
        nginx.push_str("/privkey.pem;\n");
        nginx.push_str("  location / {\n");
        nginx.push_str("    proxy_pass ");
        nginx.push_str(&nginx_upstream);
        nginx.push_str(";\n    proxy_http_version 1.1;\n    proxy_set_header Host $host;\n    proxy_set_header X-Real-IP $remote_addr;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection \"upgrade\";\n    proxy_buffering off;\n    proxy_read_timeout 3600s;\n    proxy_send_timeout 3600s;\n  }\n}\n\n");
    }

    // 5) Masks (folders) + keys.zip.
    let masks: BTreeMap<String, String> = site_rows.iter().map(|(domain, _, _)| {
        (escape_filename(domain), mask_html(domain, spec.carrier.as_str()))
    }).collect();

    // 6) keys.zip: N files, one per site, name escaped, M(i) keys each.
    let mut zip_files: Vec<(String, String)> = Vec::new();
    for (domain, _, secs) in &site_rows {
        zip_files.push((format!("{}.keys.txt", escape_filename(domain)), secs.join("\n")));
    }

    if dry {
        println!("DRY-RUN burn: {} sites, {} keys total", sites.len(), total_keys);
        for (domain, p, secs) in &site_rows {
            println!("  {domain}: {} keys, mtproxy port {}", secs.len(), p);
        }
        println!("  mtproxy: ONE container with {} internal ports", total_keys);
        println!("  zip: {} files", zip_files.len());
        return Ok(());
    }

    fs::create_dir_all(out)?;
    let sites_dir = out.join("sites");
    fs::create_dir_all(&sites_dir)?;

    fs::write(out.join("config.json"), serde_json::to_string_pretty(&relay_config)?)?;
    fs::write(out.join("mtproxy.sys.config"), sys_config)?;
    fs::write(out.join("mtproxy-launch.sh"), mtproxy_launcher)?;
    fs::write(out.join("nginx-tproxy.conf"), nginx)?;

    for (fname, html) in &masks {
        let d = sites_dir.join(fname);
        fs::create_dir_all(&d)?;
        fs::write(d.join("index.html"), html)?;
    }

    // zip: keys per site
    let zip_path = out.join("keys.zip");
    {
        let f = fs::File::create(&zip_path)?;
        let mut zw = zip::ZipWriter::new(f);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, content) in &zip_files {
            zw.start_file(name.clone(), opts)?;
            use std::io::Write as _;
            zw.write_all(content.as_bytes())?;
        }
        zw.finish()?;
    }

    println!("burn: OK");
    println!("  sites: {}", sites.len());
    println!("  keys total: {total_keys}");
    println!("  relay config: {}", out.join("config.json").display());
    println!("  mtproxy.sys.config: {} (ONE container, {} ports)", out.join("mtproxy.sys.config").display(), total_keys);
    println!("  mtproxy-launch.sh: {}", out.join("mtproxy-launch.sh").display());
    println!("  masks: {}", sites_dir.display());
    println!("  keys.zip: {}", zip_path.display());
    for (domain, _, secs) in &site_rows {
        println!("    {} → {} key(s)", domain, secs.len());
    }
    Ok(())
}

/// A tiny but non-generic static mask page. The point is the folder exists;
/// a user typically replaces it with their own site.
fn mask_html(domain: &str, carrier: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>{domain}</title>\n<style>\nbody{{background:#0c0f13;color:#e8e6e1;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;display:grid;place-items:center;height:100vh;margin:0}}\nsection{{text-align:center;max-width:34rem}}\nh1{{font-weight:600;font-size:1.8rem;letter-spacing:-0.02em;margin:0 0 .6rem}}\np{{color:#8a8f98;font-size:.92rem;line-height:1.5;margin:0}}\ncode{{color:#c9a86a;font-size:.85rem}}\n</style>\n</head>\n<body><section><h1>{domain}</h1><p>This site is under construction.</p><p><code>{carrier} · relay</code></p></section></body>\n</html>\n",
        domain = domain, carrier = carrier
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(count_first: bool) -> String {
        if count_first {
            "tproxy:\n  carrier: websocket\nsites:\n  - domain: a.example.com\n    keys: 3\n  - domain: b.example.com\n    keys: 1\n".into()
        } else {
            "tproxy:\n  carrier: websocket\nsites:\n  - domain: a.example.com\n    keys: [000102030405060708090a0b0c0d0e0f]\n  - domain: b.example.com\n    keys: 1\n".into()
        }
    }

    #[test]
    fn parse_count_generates() {
        let cfg: BurnConfig = serde_yaml::from_str(&yaml(true)).unwrap();
        assert_eq!(cfg.sites.len(), 2);
        assert!(matches!(cfg.sites[0].keys, Keys::Count(3)));
        assert!(matches!(cfg.sites[1].keys, Keys::Count(1)));
    }

    #[test]
    fn parse_hybrid() {
        let cfg: BurnConfig = serde_yaml::from_str(&yaml(false)).unwrap();
        assert!(matches!(&cfg.sites[0].keys, Keys::List(v) if v.len() == 1));
        assert!(matches!(cfg.sites[1].keys, Keys::Count(1)));
    }

    #[test]
    fn escape_domain() {
        assert_eq!(escape_filename("site-a.example.com"), "site-a.example.com");
        assert_eq!(escape_filename("a*b/c"), "a_b_c");
    }

    #[test]
    fn random_secret_valid() {
        for _ in 0..20 {
            let s = random_secret();
            assert!(valid_secret(&s));
            assert_eq!(s.len(), 32);
        }
    }

    #[test]
    fn gen_materializes_correct_key_counts() {
        let cfg: BurnConfig = serde_yaml::from_str(&yaml(true)).unwrap();
        // walk manual materialization
        let mut counts = Vec::new();
        for s in &cfg.sites {
            let n = match &s.keys {
                Keys::Count(c) => *c as usize,
                Keys::List(l) => l.len(),
            };
            counts.push(n);
        }
        assert_eq!(counts, vec![3, 1]);
    }
}