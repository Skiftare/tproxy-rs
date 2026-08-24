//! Relay: session multiplexer -> TCP to stock MTProxy.
//!
//! Placeholder for the session/stream machinery. The frame codec and bridge
//! are implemented; the multiplexer and TCP backend land in the next step.

/// Backend address for one logical stream (a stock MTProxy listener).
pub type BackendAddr = String;
