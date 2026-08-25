//! Bridge capability computation and verification per "WEB proxy protocol v1"
//! (PROTOCOL.md of telegramdesktop/tproxy-server).
//!
//! Clean-room implementation from the public protocol document, not from sources.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Frozen v1 domain-separation label (from PROTOCOL.md).
const BRIDGE_CONTEXT_PREFIX: &str = "tdesktop-web-proxy-bridge-v1\n";

/// A canonical lowercase ASCII/IDNA hostname. Kept as bytes for hashing.
///
/// `Hostname` is newtype so callers can't mix it up with arbitrary strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hostname(pub String);

/// Derive the 43-character unpadded base64url bridge capability.
///
/// ```text
/// context = UTF-8("tdesktop-web-proxy-bridge-v1\n" + H)
/// bridge  = base64url_no_padding(HMAC-SHA256(key=S, message=context))
/// ```
pub fn bridge_capability(host: &Hostname, secret_bytes: &[u8]) -> String {
    let mut ctx = Vec::with_capacity(BRIDGE_CONTEXT_PREFIX.len() + host.0.len());
    ctx.extend_from_slice(BRIDGE_CONTEXT_PREFIX.as_bytes());
    ctx.extend_from_slice(host.0.as_bytes());

    let mut mac = Hmac::<Sha256>::new_from_slice(secret_bytes).expect("HMAC accepts any key len");
    mac.update(&ctx);
    let tag = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(tag)
}

/// Verify an incoming `?bridge=` parameter against the expected capability.
///
/// Returns `true` only on the exact canonical capability. Constant-time-ish
/// comparison (base64 strings) to avoid trivial timing oracle.
pub fn verify_bridge_param(host: &Hostname, secret_bytes: &[u8], provided: &str) -> bool {
    let expected = bridge_capability(host, secret_bytes);
    // constant time compare
    if provided.len() != expected.len() {
        return false;
    }
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Verify a bridge capability against ANY of several secrets (multi-secret).
/// Returns true if at least one configured secret yields the capability.
pub fn verify_bridge_param_any(host: &Hostname, secrets: &[Vec<u8>], provided: &str) -> bool {
    for s in secrets {
        if verify_bridge_param(host, s, provided) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors from PROTOCOL.md.
    const HOST: &str = "proxy.example.com";
    const SECRET: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const SECRET_DD: [u8; 17] = [
        0xdd, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f,
    ];

    #[test]
    fn vector_plain() {
        assert_eq!(
            bridge_capability(&Hostname(HOST.into()), &SECRET),
            "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk"
        );
    }

    #[test]
    fn vector_dd() {
        assert_eq!(
            bridge_capability(&Hostname(HOST.into()), &SECRET_DD),
            "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA"
        );
    }

    #[test]
    fn verify_ok_and_bad() {
        let cap = bridge_capability(&Hostname(HOST.into()), &SECRET);
        assert!(verify_bridge_param(&Hostname(HOST.into()), &SECRET, &cap));
        assert!(!verify_bridge_param(
            &Hostname(HOST.into()),
            &SECRET,
            &cap[..40]
        ));
        assert!(!verify_bridge_param(
            &Hostname(HOST.into()),
            &SECRET,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!verify_bridge_param(
            &Hostname(HOST.into()),
            &SECRET_DD,
            &cap
        ));
    }

    #[test]
    fn len_is_43() {
        assert_eq!(bridge_capability(&Hostname(HOST.into()), &SECRET).len(), 43);
    }
}
