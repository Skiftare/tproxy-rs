//! Configuration for tproxy-rs.
//!
//! Mirrors the shape of the official reference `config.example.json` where
//! relevant, but is an independent clean-room design.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    pub secret_hex: String,
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
    pub fn secret_bytes(&self) -> Result<Vec<u8>, String> {
        let h = self.secret_hex.trim();
        if h.is_empty() {
            return Err("secret_hex is empty".into());
        }
        let bytes = hex::decode(h).map_err(|e| format!("bad secret_hex: {e}"))?;
        if !(bytes.len() == 16 || bytes.len() == 17) {
            return Err("secret_hex must be 16 or 17 bytes".into());
        }
        Ok(bytes)
    }
}
impl Config {
    /// Override config fields from environment variables (deploy-friendly).
    /// Priority: env > config.json > defaults.
    pub fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("TPROXY_SECRET") { if !v.is_empty() { self.secret_hex = v; } }
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


}