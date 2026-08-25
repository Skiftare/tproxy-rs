//! Configuration for tproxy-rs.
//!
//! Mirrors the shape of the official reference `config.example.json` where
//! relevant, but is an independent clean-room design.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::bridge::{verify_bridge_param, Hostname};

/// One web-proxy secret mapped to its own MTProto backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    /// 16/17-byte hex secret this backend serves.
    pub secret_hex: String,
    /// "host:port" of the stock MTProxy that knows this secret.
    pub mtproxy_addr: String,
}

/// A single site (masking site + its secrets) served by a multi-host relay.
/// The relay can serve MANY sites from one process; each site has its own
/// public hostname, its own mask directory and its own secrets. Because the
/// bridge capability is HMAC'd over `hostname`, a secret generated for site A
/// never validates on site B — keys are site-scoped by construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    /// Canonical lowercase hostname of this site (no scheme, no port).
    pub hostname: String,
    /// Directory with this site's own masking page.
    pub public_dir: PathBuf,
    /// Every secret (hex) that belongs to THIS site only.
    pub secrets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Canonical lowercase hostname that serves the public site + bridge.
    /// Legacy single-site mode. When `hosts` is non-empty this is ignored
    /// except as the fallback for `resolve_site`.
    pub public_hostname: String,
    /// Multi-site list. When present, the relay serves each of these hosts,
    /// each with its own mask dir and secrets. Backward compatible: if empty,
    /// the relay behaves exactly like the legacy single-site config.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<Site>,
    /// Loopback listen address for the relay gateway (Caddy terminates TLS).
    pub listen: String,
    /// Loopback admin listener (metrics, health).
    pub admin_listen: String,
    /// Directory with the public site (masking). Served from memory at startup.
    /// Legacy single-site override used when `hosts` is empty.
    pub public_dir: PathBuf,
    /// MTProxy backend address (stock MTProxy on the same host).
    /// The "dumb" backend: one container, many internal ports, one per secret.
    pub mtproxy_addr: String,
    /// 16-byte (or 17-byte with leading `dd`) secret, hex-encoded.
    /// Legacy single-site mode.
    pub secret_hex: String,
    /// Optional additional secrets (each 16/17-byte hex).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_hexes: Vec<String>,
    /// Multi-backend routing: each web-proxy secret maps to its own MTProto
    /// backend port. Legacy single-site mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backends: Vec<Backend>,
    /// Carrier profile selected by the bridge page: https | https-lanes | websocket | websocket-lanes.
    pub carrier_mode: String,
    /// Limits.
    pub limits: Limits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub max_frame_payload: usize,
    pub max_pending_per_session: usize,
    pub max_streams_per_session: usize,
    pub max_sessions_global: usize,
    pub new_sessions_per_minute: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            public_hostname: "proxy.example.com".into(),
            hosts: Vec::new(),
            listen: "127.0.0.1:8080".into(),
            admin_listen: "127.0.0.1:8081".into(),
            public_dir: PathBuf::from("public"),
            mtproxy_addr: "127.0.0.1:2398".into(),
            secret_hex: String::new(),
            secret_hexes: Vec::new(),
            backends: Vec::new(),
            carrier_mode: "https".into(),
            limits: Limits::default(),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_payload: 1 << 20,
            max_pending_per_session: 32 << 20,
            max_streams_per_session: 128,
            max_sessions_global: 128,
            new_sessions_per_minute: 600,
        }
    }
}

impl Config {
    /// All hostnames this relay serves (ordered, no port).
    pub fn all_hostnames(&self) -> Vec<String> {
        if !self.hosts.is_empty() {
            self.hosts.iter().map(|s| s.hostname.clone()).collect()
        } else {
            vec![self.public_hostname.clone()]
        }
    }

    /// Resolve site config for a hostname. Returns None if the host is not
    /// served by this relay (relay answers only its own hosts).
    pub fn resolve_site(&self, host: &str) -> Option<Site> {
        let h = host.trim().to_lowercase();
        if !self.hosts.is_empty() {
            self.hosts
                .iter()
                .find(|s| s.hostname.eq_ignore_ascii_case(&h))
                .cloned()
        } else if h.eq_ignore_ascii_case(&self.public_hostname) {
            Some(Site {
                hostname: self.public_hostname.clone(),
                public_dir: self.public_dir.clone(),
                secrets: self.all_secret_hexes(),
            })
        } else {
            None
        }
    }

    /// Every secret hex this site owns. For site-scoped isolation this is the
    /// ONLY source of truth: a capability is valid for a host only if its
    /// secret belongs to that host's list.
    pub fn site_secret_hexes(&self, host: &str) -> Vec<String> {
        match self.resolve_site(host) {
            Some(s) => s.secrets.clone(),
            None => Vec::new(),
        }
    }

    /// Decode a secret hex to bytes (16 or 17 byte). None if invalid.
    fn decode_secret(hexstr: &str) -> Option<Vec<u8>> {
        let h = hexstr.trim();
        let bytes = hex::decode(h).ok()?;
        if bytes.len() == 16 || bytes.len() == 17 {
            Some(bytes)
        } else {
            None
        }
    }

    /// All secrets configured anywhere (legacy union, for bootstrap/global use).
    pub fn all_secret_hexes(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.secret_hex.is_empty() {
            out.push(self.secret_hex.clone());
        }
        out.extend(self.secret_hexes.iter().filter(|s| !s.is_empty()).cloned());
        for b in &self.backends {
            if !b.secret_hex.is_empty() {
                out.push(b.secret_hex.clone());
            }
        }
        out
    }

    /// Given a bridge capability, return the site whose secret validates it.
    /// Iterates ALL sites; each site only accepts its OWN secrets. Returns the
    /// (site, secret_hex) pair on success. This is the isolation core: a key
    /// minted for site A is rejected on site B.
    pub fn capability_site(&self, host: &str, provided: &str) -> Option<(String, String)> {
        let secret_hexes = self.site_secret_hexes(host);
        for sec in &secret_hexes {
            if let Some(bytes) = Self::decode_secret(sec) {
                if crate::bridge::verify_bridge_param(
                    &crate::bridge::Hostname(host.to_string()),
                    &bytes,
                    provided,
                ) {
                    // Also resolve which backend addr to use (legacy path or
                    // per-secret backends). Keep it simple: use the global
                    // mtproxy_addr for now; backends may be layered later.
                    let _ = self.backend_for_secret(sec);
                    return Some((host.to_string(), sec.clone()));
                }
            }
        }
        None
    }

    /// Decode ALL configured secrets (primary + extras), skipping empties.
    /// Fails if every secret is empty/invalid.
    pub fn secret_bytes_list(&self) -> Result<Vec<Vec<u8>>, String> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut candidates: Vec<String> = Vec::new();
        let primary = self.secret_hex.trim();
        if !primary.is_empty() {
            candidates.push(primary.to_string());
        }
        for s in self.secret_hexes.clone() {
            if !s.is_empty() {
                candidates.push(s.clone());
            }
        }
        for b in self.backends.clone() {
            if !b.secret_hex.is_empty() {
                candidates.push(b.secret_hex.clone());
            }
        }
        if candidates.is_empty() {
            return Err("no secret_hex or secret_hexes configured".into());
        }
        for c in candidates {
            let h = c.trim();
            if h.is_empty() {
                continue;
            }
            let bytes = hex::decode(h).map_err(|e| {
                format!(
                    "bad secret '{}': {e}",
                    h.chars().take(8).collect::<String>()
                )
            })?;
            if !(bytes.len() == 16 || bytes.len() == 17) {
                // skip invalid, don't hard-fail the whole list
                continue;
            }
            out.push(bytes);
        }
        if out.is_empty() {
            return Err("no valid 16/17-byte secret in secret_hex/secret_hexes".into());
        }
        Ok(out)
    }

    /// Resolve the MTProto backend address for a given secret hex.
    /// Multi-backend mode: match in `backends`; otherwise fall back to `mtproxy_addr`.
    pub fn backend_for_secret(&self, secret_hex: &str) -> String {
        for b in &self.backends {
            if b.secret_hex.eq_ignore_ascii_case(secret_hex) {
                return b.mtproxy_addr.clone();
            }
        }
        self.mtproxy_addr.clone()
    }

    /// Given a bridge capability, return the backend address whose secret
    /// validates it. Multi-backend: check each `backends` entry; also accept a
    /// capability from `secret_hex`/`secret_hexes` routed to the global backend.
    pub fn capability_backend(&self, host: &Hostname, provided: &str) -> Option<String> {
        // iterate all secret candidates -> backend addr, with per-secret
        // `backends` entries taking priority over the global `mtproxy_addr`.
        let mut pairs: Vec<(Vec<u8>, String)> = Vec::new();
        for b in &self.backends {
            if let Ok(sb) = hex::decode(&b.secret_hex) {
                if sb.len() == 16 || sb.len() == 17 {
                    pairs.push((sb, b.mtproxy_addr.clone()));
                }
            }
        }
        if let Ok(primary) = hex::decode(self.secret_hex.trim()) {
            if primary.len() == 16 || primary.len() == 17 {
                pairs.push((primary, self.mtproxy_addr.clone()));
            }
        }
        for s in &self.secret_hexes {
            if let Ok(b) = hex::decode(s) {
                if b.len() == 16 || b.len() == 17 {
                    pairs.push((b, self.mtproxy_addr.clone()));
                }
            }
        }
        for (bytes, addr) in pairs {
            if verify_bridge_param(host, &bytes, provided) {
                return Some(addr);
            }
        }
        None
    }

    /// Backward-compat: the single primary secret as bytes (first entry).
    pub fn secret_bytes(&self) -> Result<Vec<u8>, String> {
        let all = self.secret_bytes_list()?;
        Ok(all[0].clone())
    }
}
impl Config {
    /// Override config fields from environment variables (deploy-friendly).
    /// Priority: env > config.json > defaults.
    pub fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("TPROXY_SECRET") {
            if !v.is_empty() {
                self.secret_hex = v;
            }
        }
        if let Ok(v) = std::env::var("TPROXY_SECRETS") {
            if !v.is_empty() {
                self.secret_hexes = v
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect::<Vec<String>>();
            }
        }
        if let Ok(v) = std::env::var("TPROXY_HOSTNAME") {
            if !v.is_empty() {
                self.public_hostname = v;
            }
        }
        if let Ok(v) = std::env::var("TPROXY_LISTEN") {
            if !v.is_empty() {
                self.listen = v;
            }
        }
        if let Ok(v) = std::env::var("TPROXY_CARRIER") {
            if !v.is_empty() {
                self.carrier_mode = v;
            }
        }
        if let Ok(v) = std::env::var("TPROXY_MPROXY") {
            if !v.is_empty() {
                self.mtproxy_addr = v;
            }
        }
        if let Ok(v) = std::env::var("TPROXY_SITE_DIR") {
            if !v.is_empty() {
                self.public_dir = PathBuf::from(v);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn parse_secret() {
        let mut c = Config::default();
        c.secret_hex = "000102030405060708090a0b0c0d0e0f".into();
        assert_eq!(c.secret_bytes().unwrap().len(), 16);
        c.secret_hex = "dd000102030405060708090a0b0c0d0e0f".into();
        assert_eq!(c.secret_bytes().unwrap().len(), 17);
        c.secret_hex = "zz".into();
        assert!(c.secret_bytes().is_err());
    }

    #[test]
    fn multi_backend_routing() {
        use crate::bridge::{bridge_capability, Hostname};
        let mut c = Config::default();
        c.public_hostname = "proxy.example.com".into();
        let host = Hostname("proxy.example.com".into());
        // primary secret -> global backend
        c.secret_hex = "000102030405060708090a0b0c0d0e0f".into();
        c.backends = vec![
            Backend {
                secret_hex: "000102030405060708090a0b0c0d0e0f".into(),
                mtproxy_addr: "mtproxy-a:2398".into(),
            },
            Backend {
                secret_hex: "112233445566778899aabbccddeeff00".into(),
                mtproxy_addr: "mtproxy-b:2399".into(),
            },
        ];
        let s2 = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let cap_a = bridge_capability(&host, &s2);
        // capability for secret A -> backend-a
        assert_eq!(
            c.capability_backend(&host, &cap_a).unwrap_or_default(),
            "mtproxy-a:2398"
        );
        // unknown secret -> none
        let bad = hex::decode("ffffffffffffffffffffffffffffffff").unwrap();
        let cap_bad = bridge_capability(&host, &bad);
        assert!(c.capability_backend(&host, &cap_bad).is_none());
    }

    #[test]
    fn site_scoped_isolation() {
        use crate::bridge::bridge_capability;
        let mut c = Config::default();
        c.carrier_mode = "websocket".into();
        c.listen = "127.0.0.1:8091".into();
        c.admin_listen = "127.0.0.1:8092".into();
        c.mtproxy_addr = "mtproxy-dumb:8080".into();
        let sec_a = "000102030405060708090a0b0c0d0e0f".to_string();
        let sec_b = "112233445566778899aabbccddeeff00".to_string();
        c.hosts = vec![
            Site {
                hostname: "site-a.example.com".into(),
                public_dir: PathBuf::from("sites/a"),
                secrets: vec![sec_a.clone()],
            },
            Site {
                hostname: "site-b.example.com".into(),
                public_dir: PathBuf::from("sites/b"),
                secrets: vec![sec_b.clone()],
            },
        ];
        let ha = crate::bridge::Hostname("site-a.example.com".into());
        let hb = crate::bridge::Hostname("site-b.example.com".into());
        let cap_a = bridge_capability(&ha, &hex::decode(&sec_a).unwrap());
        let cap_b = bridge_capability(&hb, &hex::decode(&sec_b).unwrap());
        // A-секрет проходит на A
        assert!(c.capability_site("site-a.example.com", &cap_a).is_some());
        // B-секрет проходит на B
        assert!(c.capability_site("site-b.example.com", &cap_b).is_some());
        // A-секрет НЕ проходит на B (изоляция ключей)
        assert!(c.capability_site("site-b.example.com", &cap_a).is_none());
        // B-секрет НЕ проходит на A
        assert!(c.capability_site("site-a.example.com", &cap_b).is_none());
        // resolve_site отдаёт правильную маску
        assert_eq!(
            c.resolve_site("site-a.example.com").unwrap().public_dir,
            PathBuf::from("sites/a")
        );
        assert!(c.resolve_site("unknown.example.com").is_none());
    }
}
