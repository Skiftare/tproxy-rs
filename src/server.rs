//! Carrier transport: axum HTTP server exposing the public site, the bridge
//! selector, and the relay endpoints (`/api/v1/*`).
//!
//! In production Caddy terminates TLS :80/:443 and proxies to `listen`
//! (loopback). The relay never terminates public TLS itself.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Query, State};
use futures_util::{SinkExt, StreamExt};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::bridge::{verify_bridge_param, Hostname};
use crate::config::Config;
use crate::frame::TYPE_BYE;
use crate::session::{run_session_loop, SessionLimits, SessionMsg};

// ---- shared session state ----
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub sessions: Arc<tokio::sync::Mutex<std::collections::HashMap<u64, tokio::sync::mpsc::Sender<crate::session::SessionMsg>>>>,
    pub next_session_id: Arc<std::sync::atomic::AtomicU64>,
}

impl AppState {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: Arc::new(cfg),
            sessions: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            next_session_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }
}

// ---- bridge query ----
#[derive(Deserialize)]
struct RootQuery {
    bridge: Option<String>,
}

// ---- bootstrap request/response ----
#[derive(Deserialize)]
struct BootstrapReq {
    // optional; token exchange in later step
    #[serde(default)]
    _nonce: String,
}

#[derive(Serialize)]
struct BootstrapResp {
    bearer: String,
    #[serde(rename = "carrier_mode")]
    carrier_mode: String,
    session_id: u64,
}

async fn relay_bootstrap(State(st): State<AppState>, payload: Json<BootstrapReq>) -> Response {
    // One-shot bootstrap exchange: mint a session id + carrier profile.
    let id = st.next_session_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let bearer = format!("tprx{}", id);
    Json(BootstrapResp {
        bearer: bearer.clone(),
        carrier_mode: st.cfg.carrier_mode.clone(),
        session_id: id,
    })
    .into_response()
}

// ---- frame mux endpoints (placeholder wiring for HTTPS carrier) ----
async fn relay_up(State(st): State<AppState>) -> Response {
    // HTTPS serialized carrier up/ endpoints will multiplex frames here.
    let _ = st;
    (StatusCode::NOT_IMPLEMENTED, "up lane not implemented yet").into_response()
}

async fn relay_down(State(st): State<AppState>) -> Response {
    let _ = st;
    (StatusCode::NOT_IMPLEMENTED, "down lane not implemented yet").into_response()
}

// ---- websocket carrier ----
async fn ws_carrier(State(st): State<AppState>, ws: axum::extract::WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, st))
}

async fn handle_ws(socket: axum::extract::ws::WebSocket, st: AppState) {
    use axum::extract::ws::{Message, WebSocket};
    let (tx, rx) = socket.split();
    let (session_tx, session_rx) = tokio::sync::mpsc::channel::<SessionMsg>(256);
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<crate::frame::Frame>(256);
    let session_id = st.next_session_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let backend = st.cfg.mtproxy_addr.clone();
    let limits = SessionLimits::default();

    // Writer task owns the sink; reads from the session mpsc.
    let writer = tokio::spawn(async move {
        let mut tx = tx;
        let mut session_rx = session_rx;
        while let Some(m) = session_rx.recv().await {
            let msg = match m {
                SessionMsg::Frame(f) => Message::Binary(f.encode()),
                SessionMsg::StreamData { id, data } => Message::Binary(
                    crate::frame::Frame::new(crate::frame::TYPE_DATA, id, data).encode(),
                ),
                SessionMsg::StreamClose { id } => Message::Binary(
                    crate::frame::Frame::new(crate::frame::TYPE_CLOSE, id, vec![]).encode(),
                ),
            };
            if tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Reader loop in this task; parse frames and feed the session.
    let mut rx = rx;
    while let Some(Ok(msg)) = rx.next().await {
        match msg {
            Message::Binary(data) => {
                if let Ok(frames) = crate::frame::decode_batch(&data) {
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
    drop(writer);
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
            return ([(axum::http::header::CONTENT_TYPE, mime)], bytes).into_response();
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
        .route("/api/v1/bootstrap", post(relay_bootstrap))
        .route("/api/v1/up", post(relay_up))
        .route("/api/v1/down", get(relay_down))
        .fallback(serve_static)
        .route("/", get(root))
        .with_state(st.clone())
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
            // Bridge page: minimal JS that establishes the carrier session.
            let page = bridge_page(&st.cfg.carrier_mode);
            return ([(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")], page).into_response();
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

// Silence unused warnings for placeholder endpoints while wiring progresses.
#[allow(dead_code)]
fn _unused(_: PathBuf, _: crate::frame::Frame) {}