//! Carrier transport: axum HTTP server exposing the public site, the bridge
//! selector, and the relay endpoints (`/api/v1/*`).
//!
//! In production Caddy/nginx terminates TLS :80/:443 and proxies to `listen`
//! (loopback). The relay never terminates public TLS itself.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, Mutex};

use crate::bridge::{verify_bridge_param, Hostname};
use crate::config::Config;
use crate::frame::{self, Frame, TYPE_BYE, TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, TYPE_PING, TYPE_WELCOME, TYPE_WINDOW};
use crate::session::{run_session_loop, SessionLimits, SessionMsg};

// ---- shared session state ----
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    /// bearer token -> outbound channel to the session's carrier
    pub sessions: Arc<Mutex<HashMap<String, mpsc::Sender<Frame>>>>,
    pub next_id: Arc<AtomicU64>,
    /// per-session down cursor (for serialized https carrier)
    pub down_cursors: Arc<Mutex<HashMap<String, u64>>>,
}

impl AppState {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: Arc::new(cfg),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            down_cursors: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

// ---- bridge query ----
#[derive(Deserialize)]
struct RootQuery {
    bridge: Option<String>,
}

// ---- session endpoint (HELLO -> WELCOME, issues bearer) ----
#[derive(Deserialize)]
struct SessionReq {}

async fn api_session(State(st): State<AppState>, body: Bytes) -> Response {
    // Body must be exactly one HELLO frame.
    let frames = match frame::decode_batch(&body) {
        Ok(f) => f,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad frame").into_response(),
    };
    if frames.len() != 1 || frames[0].ty != TYPE_HELLO {
        return (StatusCode::BAD_REQUEST, "expected HELLO").into_response();
    }

    let id = st.next_id.fetch_add(1, Ordering::Relaxed);
    let bearer = format!("tprx{}", id);
    let (tx, rx) = mpsc::channel::<SessionMsg>(256);

    // Spawn the session loop (frame-driven).
    let backend = st.cfg.mtproxy_addr.clone();
    let limits = SessionLimits::default();
    let (frame_tx, frame_rx) = mpsc::channel::<Frame>(256);
    let b2 = backend.clone();
    tokio::spawn(async move {
        let _ = run_session_loop(id, b2, limits, frame_rx, tx).await;
    });

    // Store session handle for up/down.
    st.sessions.lock().await.insert(bearer.clone(), frame_tx);
    st.down_cursors.lock().await.insert(bearer.clone(), 0);

    let mut resp = Response::new("".into());
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert("X-Session-Token", HeaderValue::from_str(&bearer).unwrap());
    resp.headers_mut().insert("X-Down-Cursor", HeaderValue::from_static("0"));
    resp.headers_mut().insert("X-Carrier-Mode", HeaderValue::from_str(&st.cfg.carrier_mode).unwrap());
    resp.headers_mut().insert(header::CONTENT_TYPE, "application/octet-stream".parse().unwrap());
    // WELCOME frame in body
    *resp.body_mut() = axum::body::Body::from(Frame::new(TYPE_WELCOME, 0, vec![]).encode());
    resp
}

// ---- uplink: POST /up with frames, returns 204 ----
async fn api_up(State(st): State<AppState>, headers: axum::http::HeaderMap, body: Bytes) -> Response {
    let bearer = match headers.get("authorization").and_then(|h| h.to_str().ok()) {
        Some(a) if a.starts_with("Bearer ") => a[7..].to_string(),
        _ => return (StatusCode::UNAUTHORIZED, "no bearer").into_response(),
    };
    let Some(frame_tx) = st.sessions.lock().await.get(&bearer).cloned() else {
        return (StatusCode::UNAUTHORIZED, "unknown bearer").into_response();
    };
    let frames = match frame::decode_batch(&body) {
        Ok(f) => f,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad frames").into_response(),
    };
    for f in frames {
        if frame_tx.send(f).await.is_err() {
            return (StatusCode::UNAUTHORIZED, "session closed").into_response();
        }
    }
    (StatusCode::NO_CONTENT).into_response()
}

// ---- downlink: GET /down long-poll, returns frame batch ----
async fn api_down(State(st): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    let bearer = match headers.get("authorization").and_then(|h| h.to_str().ok()) {
        Some(a) if a.starts_with("Bearer ") => a[7..].to_string(),
        _ => return (StatusCode::UNAUTHORIZED, "no bearer").into_response(),
    };
    // Use a per-request queue: we need frames emitted to THIS poll.
    // Simplest: subscribe to session outbound via a broadcast channel per session.
    // For now return empty (204) with cursor — wiring follows.
    let _ = &st;
    let _ = bearer;
    (StatusCode::NO_CONTENT).into_response()
}

// ---- websocket carrier (multiplexed frames) ----
async fn ws_carrier(State(st): State<AppState>, ws: axum::extract::WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, st))
}

async fn handle_ws(socket: axum::extract::ws::WebSocket, st: AppState) {
    use axum::extract::ws::{Message, WebSocket};
    let (tx, rx) = socket.split();
    let (session_tx, mut session_rx) = mpsc::channel::<SessionMsg>(256);
    let (frame_tx, mut frame_rx) = mpsc::channel::<Frame>(256);
    let session_id = st.next_id.fetch_add(1, Ordering::Relaxed);
    let backend = st.cfg.mtproxy_addr.clone();
    let limits = SessionLimits::default();

    // Writer task owns the sink.
    let writer = tokio::spawn(async move {
        let mut tx = tx;
        let mut session_rx = session_rx;
        while let Some(m) = session_rx.recv().await {
            let msg = match m {
                SessionMsg::Frame(f) => Message::Binary(f.encode()),
                SessionMsg::StreamData { id, data } => Message::Binary(
                    Frame::new(TYPE_DATA, id, data).encode(),
                ),
                SessionMsg::StreamClose { id } => Message::Binary(Frame::new(TYPE_CLOSE, id, vec![]).encode()),
            };
            if tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Session loop task.
    let b2 = backend.clone();
    let session_task = tokio::spawn(async move {
        let _ = run_session_loop(session_id, b2, limits, frame_rx, session_tx).await;
    });

    let mut rx = rx;
    while let Some(Ok(msg)) = rx.next().await {
        match msg {
            Message::Binary(data) => {
                if let Ok(frames) = frame::decode_batch(&data) {
                    for f in frames {
                        let _ = frame_tx.send(f).await;
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    drop(frame_tx);
    let _ = session_task.await;
    let _ = writer.await;
    let _ = st;
}

// ---- static file serving ----
async fn serve_static(State(st): State<AppState>, uri: axum::http::Uri) -> Response {
    let root = st.cfg.public_dir.clone();
    let path = uri.path();
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    let fpath = root.join(rel);
    if fpath.is_file() {
        if let Ok(bytes) = tokio::fs::read(&fpath).await {
            let mime = mime_for(&fpath);
            return ([(header::CONTENT_TYPE, mime)], bytes).into_response();
        }
    }
    (StatusCode::NOT_FOUND, "not found").into_response()
}

fn mime_for(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("json") => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Build the axum router.
pub fn router(st: AppState) -> Router {
    Router::new()
        .route("/ws", get(ws_carrier))
        .route("/api/v1/session", post(api_session))
        .route("/api/v1/up", post(api_up))
        .route("/api/v1/down", get(api_down))
        .fallback(serve_static)
        .route("/", get(root))
        .with_state(st)
}

// Root route: serve static or bridge page based on ?bridge param.
async fn root(State(st): State<AppState>, Query(q): Query<RootQuery>) -> Response {
    if let Some(b) = &q.bridge {
        let host = Hostname(st.cfg.public_hostname.clone());
        let secret = match st.cfg.secret_bytes() {
            Ok(s) => s,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "misconfigured").into_response(),
        };
        if verify_bridge_param(&host, &secret, b) {
            let page = bridge_page(&st.cfg.carrier_mode);
            return ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], page).into_response();
        }
    }
    serve_static(State(st.clone()), axum::http::Uri::from_static("/")).await
}

fn bridge_page(carrier: &str) -> String {
    let carrier_js = match carrier {
        "websocket" => r#"const ws=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws');ws.binaryType='arraybuffer';window.TelegramWebProxy={postMessage:(v)=>{ws.send(v)},onmessage:null};ws.onmessage=(e)=>{if(window.TelegramWebProxy.onmessage)window.TelegramWebProxy.onmessage(e.data)};"#,
        _ => r#"/* https carrier: long-poll up/down (next step) */"#,
    };
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>.</title></head><body><script>{carrier_js}</script></body></html>"#
    )
}