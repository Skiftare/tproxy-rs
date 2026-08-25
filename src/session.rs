//! Session and stream multiplexer for the WEB proxy relay.
//!
//! A relay session is authenticated with a bearer token obtained from a
//! short-lived bootstrap token. Within a session, logical streams (one per
//! Telegram MTProxy connection) are multiplexed. Each stream maps to one TCP
//! connection to the configured stock MTProxy.
//!
//! Frames consumed: `HELLO`, `OPEN`, `DATA`, `WINDOW`, `CLOSE`, `PONG`.
//! Frames produced: `WELCOME`, `PING`, `DATA`, `WINDOW`, `CLOSE`, `BYE`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::frame::{
    Frame, TYPE_BYE, TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, TYPE_OPEN, TYPE_PONG, TYPE_WELCOME,
    TYPE_WINDOW,
};

/// A logical stream bound to one backend TCP connection.
#[allow(dead_code)]
struct Stream {
    id: u32,
    tx: OwnedWriteHalf,
    rx: OwnedReadHalf,
}

/// Limits for session/stream abuse control.
#[derive(Debug, Clone)]
pub struct SessionLimits {
    pub max_streams_per_session: usize,
    pub max_pending_per_session: usize,
    pub max_pending_items_per_session: usize,
    pub max_frame_payload: usize,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_streams_per_session: 128,
            max_pending_per_session: 32 << 20,
            max_pending_items_per_session: 16384,
            max_frame_payload: 1 << 20,
        }
    }
}

/// Outbound message: a frame batch or a stream's raw bytes for the backend.
#[derive(Clone)]
pub enum SessionMsg {
    Frame(Frame),
    StreamData { id: u32, data: Vec<u8> },
    StreamClose { id: u32 },
}

/// A single relay session. Holds per-stream backend connections and an mpsc
/// channel toward the carrier (which owns the client-facing transport).
pub struct Session {
    id: u64,
    // stream_id -> backend writer
    streams: HashMap<u32, OwnedWriteHalf>,
    // stream_id -> inbound data waiting to be pumped (bounded by limits)
    #[allow(dead_code)]
    pending: HashMap<u32, Vec<u8>>,
    limits: SessionLimits,
    tx_to_carrier: mpsc::Sender<SessionMsg>,
    // backend address for new streams
    backend: String,
}

impl Session {
    pub fn new(
        id: u64,
        tx_to_carrier: mpsc::Sender<SessionMsg>,
        backend: String,
        limits: SessionLimits,
    ) -> Self {
        Self {
            id,
            streams: HashMap::new(),
            pending: HashMap::new(),
            limits,
            tx_to_carrier,
            backend,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    /// Handle one frame from the client.
    pub async fn handle_frame(&mut self, f: Frame) -> Result<(), String> {
        match f.ty {
            TYPE_HELLO => {
                // Client greeting: byte 01 expected; respond WELCOME.
                if f.stream_id != 0 {
                    return Err("HELLO with nonzero stream".into());
                }
                self.tx_to_carrier
                    .send(SessionMsg::Frame(Frame::new(TYPE_WELCOME, 0, vec![])))
                    .await
                    .map_err(|e| e.to_string())
            }
            TYPE_OPEN => {
                if f.stream_id == 0 {
                    return Err("OPEN on stream 0".into());
                }
                if self.streams.contains_key(&f.stream_id) {
                    return Err(format!("duplicate OPEN {}", f.stream_id));
                }
                eprintln!(
                    "[debug] OPEN stream={} backend={}",
                    f.stream_id, self.backend
                );
                if self.streams.len() >= self.limits.max_streams_per_session {
                    return Err("max streams reached".into());
                }
                // Open backend TCP to MTProxy.
                let conn = TcpStream::connect(&self.backend).await.map_err(|e| {
                    eprintln!("[debug] OPEN connect FAIL: {e}");
                    format!("backend connect: {e}")
                })?;
                eprintln!("[debug] OPEN connected to {}", self.backend);
                let (rx, tx) = conn.into_split();
                self.streams.insert(f.stream_id, tx);
                let id = f.stream_id;
                let tx = self.tx_to_carrier.clone();
                // Spawn reader task: pump backend -> carrier DATA frames.
                tokio::spawn(async move {
                    let mut rx = rx;
                    let mut buf = vec![0u8; 65536];
                    loop {
                        match rx.read(&mut buf).await {
                            Ok(0) | Err(_) => {
                                eprintln!("[debug] stream {id} backend EOF/err -> StreamClose");
                                let _ = tx.send(SessionMsg::StreamClose { id }).await;
                                break;
                            }
                            Ok(n) => {
                                eprintln!("[debug] stream {id} backend read {n}B -> StreamData");
                                if tx
                                    .send(SessionMsg::StreamData {
                                        id,
                                        data: buf[..n].to_vec(),
                                    })
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                });
                Ok(())
            }
            TYPE_DATA => {
                let Some(tx) = self.streams.get_mut(&f.stream_id) else {
                    return Err(format!("DATA on unknown stream {}", f.stream_id));
                };
                eprintln!(
                    "[debug] DATA stream={} payload={}B -> backend",
                    f.stream_id,
                    f.payload.len()
                );
                tx.write_all(&f.payload)
                    .await
                    .map_err(|e| format!("backend write: {e}"))?;
                Ok(())
            }
            TYPE_WINDOW => Ok(()), // flow control credit, accepted
            TYPE_CLOSE => {
                self.streams.remove(&f.stream_id);
                Ok(())
            }
            TYPE_PONG => Ok(()), // heartbeat echo, no action needed
            other => Err(format!("unexpected frame type {other:#x}")),
        }
    }

    /// Close all streams and emit BYE.
    pub async fn shutdown(&mut self) {
        self.streams.clear();
        let _ = self
            .tx_to_carrier
            .send(SessionMsg::Frame(Frame::new(TYPE_BYE, 0, vec![])))
            .await;
    }
}

/// Handle one carrier connection: read frames, drive the session.
pub async fn run_session_loop(
    session_id: u64,
    backend: String,
    limits: SessionLimits,
    mut rx_frames: mpsc::Receiver<Frame>,
    tx_to_carrier: mpsc::Sender<SessionMsg>,
) -> Result<(), String> {
    let mut session = Session::new(session_id, tx_to_carrier.clone(), backend, limits);
    while let Some(f) = rx_frames.recv().await {
        if f.ty == TYPE_BYE {
            break;
        }
        session.handle_frame(f).await?;
    }
    session.shutdown().await;
    Ok(())
}

// Keep compile-clean placeholder for unused types under multi-arch builds.
#[allow(dead_code)]
fn _unused(_: Duration, _: Arc<Mutex<u8>>, _: OwnedReadHalf) {}
