//! Mass-production mode: stamp out many web-proxy sites from one YAML file.
//!
//! YAML shape:
//! ```yaml
//! isolation: true            # optional, default true (one tproxy-rs container per site)
//! sites:
//!   - domain: proxya.example.com
//!     keys: [9f2b..., 44aa...]  # explicit secrets
//!     mask: site-a/             # optional mask directory
//!   - domain: proxyb.example.com
//!     keys: 12                   # generate 12 CSPRNG secrets
//!     carrier: https-lanes       # optional carrier override
//! ```
//!
//! The plan is rendered deterministically: per site, N secrets -> N MTProto
//! backends (one port each), one tproxy-rs relay, one Caddy entry. Secrets
//! generated from `keys: N` are crypto-strong (rand::rngs::OsRng) and are
//! exported to a chmod-0600 file so they can be handed out.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;

/// One logical proxy site in the mass file.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum KeySpec {
    /// Explicit list of secret hex strings.
    List(Vec<String>),
    /// How many secrets to generate cryptographically.
    Count(usize),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Site {
    /// Public hostname for this proxy site.
    pub domain: String,
    /// Explicit secrets or a count to generate.
    pub keys: KeySpec,
    /// Optional mask-site directory (relative to the mass file).
    #[serde(default)]
    pub mask: Option<String>,
    /// Optional carrier override (websocket | https-lanes | https | websocket-lanes).
    #[serde(default)]
    pub carrier: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MassConfig {
    /// When true, every site gets its own relay container (isolation).
    /// When false, one shared relay serves all sites (fewer containers).
    #[serde(default = "default_isolation")]
    pub isolation: bool,
    /// The sites to deploy.
    pub sites: Vec<Site>,
}

fn default_isolation() -> bool {
    true
}

/// A materialized site: concrete secrets + backend layout ready to render.
#[derive(Debug, Clone)]
pub struct SitePlan {
    pub domain: String,
    pub secrets: Vec<String>,
    pub carrier: String,
    pub mask: Option<PathBuf>,
    /// backend addr -> which secret it serves (port) for the compose/renderer.
    pub backends: Vec<(String, String)>, // (secret_hex, mtproxy_addr)
}

/// Full materialized mass plan.
#[derive(Debug, Clone)]
pub struct MassPlan {
    pub isolation: bool,
    pub sites: Vec<SitePlan>,
}

impl MassConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let cfg: Self =
            serde_yaml::from_str(&raw).map_err(|e| format!("parse YAML {}: {e}", path.display()))?;
        if cfg.sites.is_empty() {
            return Err("mass YAML: no 'sites:' entries".into());
        }
        // Normalize: no isolation field means true (default serde covers it).
        Ok(cfg)
    }

    pub fn materialize(&self, base_dir: &Path) -> Result<MassPlan, String> {
        let mut plan = MassPlan {
            isolation: self.isolation,
            sites: Vec::with_capacity(self.sites.len()),
        };
        let mut seen: std::collections::HashSet<String> = Default::default();
        let mut port = 2398usize; // global port allocator across the whole fleet
        for site in &self.sites {
            let domain = site.domain.trim().to_ascii_lowercase();
            if domain.is_empty() {
                return Err("site with empty domain".into());
            }
            if !seen.insert(domain.clone()) {
                return Err(format!("duplicate domain in mass YAML: {domain}"));
            }
            let secrets: Vec<String> = match &site.keys {
                KeySpec::List(list) => {
                    let mut out = Vec::new();
                    for s in list {
                        let s = s.trim().to_ascii_lowercase();
                        if !valid_secret(&s) {
                            return Err(format!("{domain}: bad secret `{s}`"));
                        }
                        out.push(s);
                    }
                    if out.is_empty() {
                        return Err(format!("{domain}: key list empty"));
                    }
                    out
                }
                KeySpec::Count(n) => {
                    if *n == 0 || *n > 10_000 {
                        return Err(format!("{domain}: keys: {n} out of range (1..=10000)"));
                    }
                    generate_secrets(*n)
                }
            };
            let carrier = site.carrier.clone().unwrap_or_else(|| "websocket".into());
            if !matches!(
                carrier.as_str(),
                "websocket" | "https" | "https-lanes" | "websocket-lanes"
            ) {
                return Err(format!("{domain}: bad carrier `{carrier}`"));
            }
            let mask = site.mask.as_ref().map(|m| {
                let p = PathBuf::from(m);
                if p.is_absolute() { p } else { base_dir.join(&p) }
            });
            // Assign one backend per secret, each on its own container/port.
            let mut backends: Vec<(String, String)> = Vec::with_capacity(secrets.len());
            for s in &secrets {
                backends.push((s.clone(), format!("mtproxy-{port}:{port}")));
                port += 1;
            }
            plan.sites.push(SitePlan {
                domain,
                secrets,
                carrier,
                mask,
                backends,
            });
        }
        Ok(plan)
    }
}

fn valid_secret(s: &str) -> bool {
    if s.len() != 32 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Generate `n` cryptographically strong 16-byte secrets (32 hex chars each).
fn generate_secrets(n: usize) -> Vec<String> {
    let mut rng = OsRng;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        out.push(buf.iter().map(|b| format!("{b:02x}")).collect());
    }
    out
}

impl MassPlan {
    /// Write the secrets + rendered compose to `out_dir`.
    /// Returns list of (domain, secrets) for printing.
    pub fn export(&self, out_dir: &Path) -> Result<Vec<(String, Vec<String>)>, String> {
        fs::create_dir_all(out_dir).map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;
        let mut secrets_file = String::new();
        let mut summary = Vec::with_capacity(self.sites.len());
        for site in &self.sites {
            let line = format!("{}: {}", site.domain, site.secrets.join(" "));
            secrets_file.push_str(&line);
            secrets_file.push('\n');
            summary.push((site.domain.clone(), site.secrets.clone()));
            // compose part per site
            self.render_site_compose(out_dir, site)?;
        }
        // chmod 600 secrets
        let secrets_path = out_dir.join("secrets.txt");
        {
            let mut f = fs::File::create(&secrets_path).map_err(|e| e.to_string())?;
            f.write_all(secrets_file.as_bytes()).map_err(|e| e.to_string())?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secrets_path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod secrets: {e}"))?;
        }
        self.render_compose(out_dir)?;
        self.render_caddyfile(out_dir)?;
        Ok(summary)
    }

    /// Render a single docker-compose that starts the whole fleet.
    fn render_compose(&self, out_dir: &Path) -> Result<(), String> {
        let mut yaml = String::from("services:\n");
        let mut caddy_domains = String::new();
        for (idx, site) in self.sites.iter().enumerate() {
            let relay_name = if self.isolation {
                format!("tproxy-{}", idx + 1)
            } else {
                "tproxy-rs".into()
            };
            // One relay service per site.
            yaml.push_str(&format!(
                "  {relay_name}:\n\
                 \x20    image: debian:bookworm-slim\n\
                 \x20    container_name: {relay_name}\n\
                 \x20    restart: unless-stopped\n\
                 \x20    command: [\"/app/tproxy-rs\", \"-c\", \"/app/config.json\"]\n\
                 \x20    expose: [\"8091\"]\n\
                 \x20    volumes:\n\
                 \x20      - ./tproxy-rs-bin:/app/tproxy-rs:ro\n\
                 \x20      - ./site-{}.json:/app/config.json:ro\n",
                sanitize(&site.domain)
            ));
            if let Some(mask) = &site.mask {
                yaml.push_str(&format!(
                    "      - {}:/app/public:ro\n",
                    mask.to_string_lossy()
                ));
            } else {
                yaml.push_str("      - ./site:/app/public:ro\n");
            }
            // MTProto backend per secret (own port each).
            for (secret, addr) in &site.backends {
                let port: usize = addr.split(':').last().unwrap_or("2398").parse().unwrap_or(2398);
                let cname = format!("mtproxy-{port}");
                yaml.push_str(&format!(
                    "  {cname}:\n\
                     \x20    image: seriyps/mtproto-proxy\n\
                     \x20    container_name: {cname}\n\
                     \x20    restart: unless-stopped\n\
                     \x20    expose: [\"{port}\"]\n\
                     \x20    command: [\"-p\", \"{port}\", \"-s\", \"{secret}\", \"-t\", \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]\n"
                ));
            }
            caddy_domains.push_str(&format!("{} ", site.domain));
        }
        // Caddy: one container fronting all domains.
        yaml.push_str(&format!(
            "  caddy:\n\
             \x20    image: caddy:2\n\
             \x20    container_name: caddy\n\
             \x20    restart: unless-stopped\n\
             \x20    ports: [\"80:80\", \"443:443\"]\n\
             \x20    environment:\n\
             \x20      CADDY_DOMAINS: \"{caddy_domains}\"\n\
             \x20    volumes:\n\
             \x20      - ./Caddyfile:/etc/caddy/Caddyfile:ro\n\
             \x20      - caddy_data:/data\n\
             \x20      - caddy_config:/config\n"
        ));
        yaml.push_str("volumes:\n  caddy_data:\n  caddy_config:\n");
        fs::write(out_dir.join("compose.rendered.yml"), yaml).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Caddyfile that terminates TLS for every domain and proxies to relays.
    fn render_caddyfile(&self, out_dir: &Path) -> Result<(), String> {
        let mut cf = String::new();
        for (idx, site) in self.sites.iter().enumerate() {
            let relay_name = if self.isolation {
                format!("tproxy-{}", idx + 1)
            } else {
                "tproxy-rs".into()
            };
            cf.push_str(&format!("{} {{\n    reverse_proxy {}:8091\n}}\n\n", site.domain, relay_name));
        }
        fs::write(out_dir.join("Caddyfile"), cf).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn render_site_compose(&self, out_dir: &Path, site: &SitePlan) -> Result<(), String> {
        // Write this site's config.json with full multi-backend layout.
        let primary = site.secrets.first().cloned().unwrap_or_default();
        let primary_addr = site
            .backends
            .first()
            .map(|(_, addr)| addr.clone())
            .unwrap_or_else(|| format!("mtproxy-{}:{}", 2398, 2398));
        let config = serde_json::json!({
            "public_hostname": site.domain,
            "listen": "0.0.0.0:8091",
            "admin_listen": "127.0.0.1:8092",
            "public_dir": site.mask.as_ref().map(|p| p.to_string_lossy().into_owned())
                          .unwrap_or_else(|| "/app/site".into()),
            "mtproxy_addr": primary_addr,
            "secret_hex": primary,
            "carrier_mode": site.carrier,
            "backends": site.backends.iter().map(|(s, addr)| serde_json::json!({
                "secret_hex": s,
                "mtproxy_addr": addr,
            })).collect::<Vec<_>>(),
            "limits": {},
        });
        let fname = format!("site-{}.json", sanitize(&site.domain));
        let path = out_dir.join(fname);
        fs::write(&path, serde_json::to_string_pretty(&config).unwrap())
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_yaml_list_and_count() {
        let yaml = r#"
isolation: true
sites:
  - domain: proxya.example.com
    keys: [000102030405060708090a0b0c0d0e0f]
    mask: site-a/
  - domain: proxyb.example.com
    keys: 3
    carrier: https-lanes
"#;
        let cfg: MassConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.isolation, true);
        assert_eq!(cfg.sites.len(), 2);
        assert!(matches!(cfg.sites[0].keys, KeySpec::List(_)));
        assert!(matches!(cfg.sites[1].keys, KeySpec::Count(3)));
        assert_eq!(cfg.sites[1].carrier.as_deref(), Some("https-lanes"));
    }

    #[test]
    fn materialize_generates_secrets() {
        let yaml = "sites:\n  - domain: x.example.com\n    keys: 4\n";
        let cfg: MassConfig = serde_yaml::from_str(yaml).unwrap();
        let plan = cfg.materialize(std::path::Path::new(".")).unwrap();
        assert_eq!(plan.sites.len(), 1);
        let site = &plan.sites[0];
        assert_eq!(site.secrets.len(), 4);
        assert_eq!(site.backends.len(), 4);
        for s in &site.secrets {
            assert!(valid_secret(s));
        }
        // no duplicate secrets
        let mut uniq: std::collections::HashSet<&String> = site.secrets.iter().collect();
        assert_eq!(uniq.len(), 4);
        uniq.clear();
    }

    #[test]
    fn reject_bad_secret() {
        let yaml = "sites:\n  - domain: x\n    keys: [zz]\n";
        let cfg: MassConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.materialize(std::path::Path::new(".")).is_err());
    }
}