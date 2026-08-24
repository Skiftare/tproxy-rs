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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Canonical lowercase hostname that serves the public site + bridge.
    pub public_hostname: String,
    /// Loopback listen address for the relay gateway (Caddy terminates TLS).
    pub listen: String,
    /// Loopback admin listener (metrics, health).
    pub admin_listen: String,
    /// Directory with the public site (masking). Served from memory at startup.
    pub public_dir: PathBuf,
    /// MTProxy backend address (stock MTProxy on the same host).
    pub mtproxy_addr: String,
    /// 16-byte (or 17-byte with leading `dd`) secret, hex-encoded.
    /// Single primary secret. Multi-secret deployments can additionally list
    /// extra keys in `secret_hexes` below; the relay accepts any of them.
    pub secret_hex: String,
    /// Optional additional secrets (each 16/17-byte hex). The bridge accepts a
    /// client whose capability derives from ANY of `secret_hex` + `secret_hexes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_hexes: Vec<String>,
    /// Multi-backend routing: each web-proxy secret maps to its own MTProto
    /// backend port. The relay accepts a client whose bridge capability derives
    /// from `secret_hex` and routes its streams to `mtproxy_addr`.
    /// When empty, everything uses `mtproxy_addr` (single-backend mode).
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
            let bytes = hex::decode(h).map_err(|e| format!("bad secret '{}': {e}", h.chars().take(8).collect::<String>()))?;
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
        if let Ok(v) = std::env::var("TPROXY_SECRET") { if !v.is_empty() { self.secret_hex = v; } }
        if let Ok(v) = std::env::var("TPROXY_SECRETS") { if !v.is_empty() { self.secret_hexes = v.split(',').filter(|s| !s.is_empty()).map(|s| String::from(s)).collect::<Vec<String>>(); } }
        if let Ok(v) = std::env::var("TPROXY_HOSTNAME") { if !v.is_empty() { self.public_hostname = v; } }
        if let Ok(v) = std::env::var("TPROXY_LISTEN") { if !v.is_empty() { self.listen = v; } }
        if let Ok(v) = std::env::var("TPROXY_CARRIER") { if !v.is_empty() { self.carrier_mode = v; } }
        if let Ok(v) = std::env::var("TPROXY_MPROXY") { if !v.is_empty() { self.mtproxy_addr = v; } }
        if let Ok(v) = std::env::var("TPROXY_SITE_DIR") { if !v.is_empty() { self.public_dir = PathBuf::from(v); } }
    }
}


#[cfg(test)]
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
            Backend { secret_hex: "000102030405060708090a0b0c0d0e0f".into(),
                      mtproxy_addr: "mtproxy-a:2398".into() },
            Backend { secret_hex: "112233445566778899aabbccddeeff00".into(),
                      mtproxy_addr: "mtproxy-b:2399".into() },
        ];
        let s2 = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let cap_a = bridge_capability(&host, &s2);
        // capability for secret A -> backend-a
        assert_eq!(c.capability_backend(&host, &cap_a).unwrap_or_default(), "mtproxy-a:2398");
        // unknown secret -> none
        let bad = hex::decode("ffffffffffffffffffffffffffffffff").unwrap();
        let cap_bad = bridge_capability(&host, &bad);
        assert!(c.capability_backend(&host, &cap_bad).is_none());
    }


}