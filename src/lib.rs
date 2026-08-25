//! tproxy-rs — Rust implementation of the Telegram WEB proxy server.
//!
//! Protocol: "WEB proxy protocol v1" (PROTOCOL.md of telegramdesktop/tproxy-server).
//! Clean-room from the public spec. The relay multiplexes MTProxy-transformed
//! Telegram connections carried over a WebView HTTPS/WebSocket transport and
//! proxies each logical stream to a stock MTProxy on the same host.

pub mod bridge;
pub mod config;
pub mod frame;
pub mod mass;
pub mod relay;
pub mod server;
pub mod session;

pub use bridge::{bridge_capability, verify_bridge_param, verify_bridge_param_any, Hostname};
pub use config::Config;
pub use frame::{decode_batch, Frame, FrameError, TYPE_BYE, TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, TYPE_OPEN, TYPE_PING, TYPE_PONG, TYPE_WELCOME, TYPE_WINDOW};
pub use session::{run_session_loop, Session, SessionLimits, SessionMsg};