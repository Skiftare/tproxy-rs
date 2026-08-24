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
use axum::routing::{get, post, delete};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{broadcast, mpsc, Mutex};

use crate::bridge::{verify_bridge_param, verify_bridge_param_any, Hostname};
use sha2::{Digest, Sha256};
use crate::config::Config;
use crate::frame::{self, Frame, TYPE_BYE, TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, TYPE_PING, TYPE_WELCOME, TYPE_WINDOW};
use crate::session::{run_session_loop, SessionLimits, SessionMsg};

// ---- shared session state ----
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    /// bearer token -> inbound channel to the session (up frames)
    pub sessions: Arc<Mutex<HashMap<String, mpsc::Sender<Frame>>>>,
    /// bearer token -> outbound broadcast (frames the session emits: down/WELCOME)
    pub out_channels: Arc<Mutex<HashMap<String, broadcast::Sender<SessionMsg>>>>,
    /// bearer token -> MTProto backend address (multi-secret routing)
    pub session_backends: Arc<Mutex<HashMap<String, String>>>,
    /// one-time bootstrap tokens issued to bridge pages; value = backend addr
    pub bootstraps: Arc<std::sync::Mutex<HashMap<String, String>>>,
    pub next_id: Arc<AtomicU64>,
    /// per-session down cursor (for serialized https carrier)
    pub down_cursors: Arc<Mutex<HashMap<String, u64>>>,
}

impl AppState {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: Arc::new(cfg),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            out_channels: Arc::new(Mutex::new(HashMap::new())),
            session_backends: Arc::new(Mutex::new(HashMap::new())),
            bootstraps: Arc::new(std::sync::Mutex::new(HashMap::new())),
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


/// Bootstrap capability = bridge capability for this host+secret (simplified).


// DELETE /api/v1/session: close/abandon a session (client teardown).
async fn api_session_delete(State(st): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    let bearer = match headers.get("authorization").and_then(|h| h.to_str().ok()) {
        Some(a) if a.starts_with("Bearer ") => a[7..].to_string(),
        _ => return (StatusCode::UNAUTHORIZED, "no bearer").into_response(),
    };
    st.sessions.lock().await.remove(&bearer);
    st.out_channels.lock().await.remove(&bearer);
    st.down_cursors.lock().await.remove(&bearer);
    println!("[session] DELETE {}", &bearer[..bearer.len().min(8)]);
    (StatusCode::NO_CONTENT).into_response()
}

async fn api_session(State(st): State<AppState>, headers: axum::http::HeaderMap, body: Bytes) -> Response {
    // Bootstrap capability passed as Authorization: Bearer <bootstrap>.
    let bearer = match headers.get("authorization").and_then(|h| h.to_str().ok()) {
        Some(a) if a.starts_with("Bearer ") => a[7..].to_string(),
        _ => return (StatusCode::UNAUTHORIZED, "no bootstrap").into_response(),
    };
    let bootstrap_addr = {
        let mut bs = st.bootstraps.lock().unwrap();
        bs.remove(&bearer)
    };
    if bootstrap_addr.is_none() {
        println!("[ws] session REJECTED bearer={}...", &bearer[..bearer.len().min(8)]);
        return (StatusCode::UNAUTHORIZED, "bad bootstrap").into_response();
    }
    println!("[ws] session accepted bearer={}...", &bearer[..bearer.len().min(8)]);
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
    let (out_tx, _out_rx) = broadcast::channel::<SessionMsg>(256);

    // Spawn the session loop (frame-driven). The session's outbound (SessionMsg)
    // is forwarded into the broadcast for /down (https) or ws writer.
    let backend = bootstrap_addr.unwrap_or_else(|| st.cfg.mtproxy_addr.clone());
    let limits = SessionLimits::default();
    st.session_backends.lock().await.insert(bearer.clone(), backend.clone());
    let (frame_tx, frame_rx) = mpsc::channel::<Frame>(256);
    let b2 = backend.clone();
    let out_tx2 = out_tx.clone();
    tokio::spawn(async move {
        let mut rx = rx;
        while let Some(m) = rx.recv().await {
            let _ = out_tx2.send(m);
        }
    });
    tokio::spawn(async move {
        let _ = run_session_loop(id, b2, limits, frame_rx, tx).await;
    });

    // Store session handle for up/down.
    st.sessions.lock().await.insert(bearer.clone(), frame_tx);
    st.out_channels.lock().await.insert(bearer.clone(), out_tx);
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
    println!("[up] POST /api/v1/up body={}B", body.len());
    let bearer = match headers.get("authorization").and_then(|h| h.to_str().ok()) {
        Some(a) if a.starts_with("Bearer ") => a[7..].to_string(),
        _ => return (StatusCode::UNAUTHORIZED, "no bearer").into_response(),
    };
    let Some(frame_tx) = st.sessions.lock().await.get(&bearer).cloned() else {
        println!("[up] unknown bearer {}", &bearer[..bearer.len().min(8)]);
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
    let seq = headers.get("x-up-seq").and_then(|h| h.to_str().ok()).unwrap_or("").to_string();
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    resp.headers_mut().insert("X-Up-Ack", HeaderValue::from_str(&seq).unwrap());
    resp
}

// ---- downlink: GET /down long-poll, returns frame batch ----
async fn api_down(State(st): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    println!("[down] GET /api/v1/down");
    let bearer = match headers.get("authorization").and_then(|h| h.to_str().ok()) {
        Some(a) if a.starts_with("Bearer ") => a[7..].to_string(),
        _ => return (StatusCode::UNAUTHORIZED, "no bearer").into_response(),
    };
    let Some(out) = st.out_channels.lock().await.get(&bearer).cloned() else {
        return (StatusCode::UNAUTHORIZED, "unknown bearer").into_response();
    };
    // 404 if no out channel? Not here. Subscribe and wait for frames.
    let mut rx = out.subscribe();
    let mut payload: Vec<u8> = Vec::new();
    let mut got = false;
    for _ in 0..8 {
        match tokio::time::timeout(std::time::Duration::from_millis(120), rx.recv()).await {
            Ok(Ok(m)) => {
                match m {
                    SessionMsg::Frame(f) => payload.extend_from_slice(&f.encode()),
                    SessionMsg::StreamData { id, data } => payload.extend_from_slice(
                        &Frame::new(TYPE_DATA, id, data).encode()),
                    SessionMsg::StreamClose { id } => payload.extend_from_slice(
                        &Frame::new(TYPE_CLOSE, id, vec![]).encode()),
                }
                got = true;
            }
            _ => break,
        }
    }
    if !got {
        // long-poll wait for the first frame (up to 25s)
        match tokio::time::timeout(std::time::Duration::from_secs(25), rx.recv()).await {
            Ok(Ok(m)) => {
                match m {
                    SessionMsg::Frame(f) => payload.extend_from_slice(&f.encode()),
                    SessionMsg::StreamData { id, data } => payload.extend_from_slice(
                        &Frame::new(TYPE_DATA, id, data).encode()),
                    SessionMsg::StreamClose { id } => payload.extend_from_slice(
                        &Frame::new(TYPE_CLOSE, id, vec![]).encode()),
                }
            }
            _ => return (StatusCode::NO_CONTENT).into_response(),
        }
    }
    let cursor = {
        let mut cursors = st.down_cursors.lock().await;
        let c = cursors.get(&bearer).copied().unwrap_or(0) + payload.len() as u64;
        cursors.insert(bearer.clone(), c);
        c
    };
    let mut resp = Response::new(axum::body::Body::from(payload));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert("X-Down-Cursor", HeaderValue::from_str(&cursor.to_string()).unwrap());
    resp.headers_mut().insert(header::CONTENT_TYPE, "application/octet-stream".parse().unwrap());
    resp
}

// ---- websocket carrier (multiplexed frames) ----
async fn ws_carrier(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    ws: axum::extract::WebSocketUpgrade,
) -> Response {
    // Echo back the client's Sec-WebSocket-Protocol (subprotocol), e.g. "tproxy-v1.<token>".
    let proto = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string());
    println!("[ws] upgrade requested, subprotocol={:?}", proto);
    match proto {
        Some(p) => {
            // Extract the session bearer from "tproxy-v1.<token>" subprotocol.
            let token = p.split('.').skip(1).next().unwrap_or("").to_string();
            let backend = {
                let sb = st.session_backends.lock().await;
                sb.get(&token).cloned().unwrap_or(st.cfg.mtproxy_addr.clone())
            };
            // axum 0.7 websocket protocols need 'static str; proxy context lives
            // as long as the process, so leaking the subprotocol string is fine.
            let leaked: &'static str = Box::leak(p.clone().into_boxed_str());
            ws.protocols([leaked]).on_upgrade(move |socket| handle_ws(socket, st, backend))
        }
        None => {
            let backend = st.cfg.mtproxy_addr.clone();
            ws.on_upgrade(move |socket| handle_ws(socket, st, backend))
        }
    }
}

async fn handle_ws(socket: axum::extract::ws::WebSocket, st: AppState, backend: String) {
    use axum::extract::ws::{Message, WebSocket};
    let (tx, rx) = socket.split();
    let (session_tx, mut session_rx) = mpsc::channel::<SessionMsg>(256);
    let (frame_tx, mut frame_rx) = mpsc::channel::<Frame>(256);
    let session_id = st.next_id.fetch_add(1, Ordering::Relaxed);
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
                    println!("[ws] frames: {:?}", frames.iter().map(|x| (x.ty, x.stream_id)).collect::<Vec<_>>());
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
        .route("/api/v1/ws", get(ws_carrier))
        .route("/api/v1/session", post(api_session))
        .route("/api/v1/session", delete(api_session_delete))
        .route("/api/v1/up", post(api_up))
        .route("/api/v1/down", post(api_down))
        .fallback(serve_static)
        .route("/", get(root))
        .with_state(st)
}

// Root route: serve static or bridge page based on ?bridge param.
async fn root(State(st): State<AppState>, Query(q): Query<RootQuery>) -> Response {
    println!("[http] GET / bridge={}", q.bridge.as_deref().unwrap_or("").chars().take(8).collect::<String>());
    if let Some(b) = &q.bridge {
        let host = Hostname(st.cfg.public_hostname.clone());
        match st.cfg.capability_backend(&host, b) {
            Some(addr) => {
                let page = bridge_page(&st, &addr);
                return ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], page).into_response();
            }
            None => {}
        }
    }
    serve_static(State(st.clone()), axum::http::Uri::from_static("/")).await
}




fn bridge_page(st: &AppState, backend_addr: &str) -> String {
    let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let bcounter = st.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let soup = format!("{}-{}", ms, bcounter);
    let nonce = hex::encode(Sha256::digest(format!("n{}", soup).as_bytes()));
    let bootstrap = hex::encode(Sha256::digest(format!("b{}", soup).as_bytes()));
    {
        let mut bs = st.bootstraps.lock().unwrap();
        if bs.len() > 8192 { bs.clear(); }
        bs.insert(bootstrap.clone(), backend_addr.to_string());
    }
    let origin = format!("https://{}", st.cfg.public_hostname);
    let html = "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>Connection</title>\n</head>\n<body>\n<script nonce=\"__NONCE__\">\n(()=>{\n'use strict';\nconst relayOrigin=__ORIGIN__,bootstrap=__BOOTSTRAP__,carrierMode=__CARRIER_MODE__;\nconst fragment=location.hash,androidNonce=/^#android=([A-Za-z0-9_-]{43})$/.exec(fragment)?.[1]||'';\nhistory.replaceState(null,'',location.pathname);\nlet initialized=false,closed=false,port=null,sessionToken='',createStarted=false;\nlet queuedBytes=0,queuedItems=0,pollController=null,webSocket=null,webSocketTimer=0;\nconst pending=[],upPending=[],lanes=new Map(),closedLanes=new Set(),closedLaneOrder=[];\nconst queueLimit=33554432,queueItemLimit=16384,closedLaneLimit=4096;\nconst laneQueueLimit=8388608,laneItemLimit=1024,batchLimit=__BATCH_LIMIT__;\nlet upSequence=1,downCursor='0',upRunning=false;\nconst status=state=>{if(port&&!closed)port.postMessage({t:'status',state})};\nconst pause=milliseconds=>new Promise(resolve=>setTimeout(resolve,milliseconds));\nconst options=(method,token,body,headers,signal,keepalive)=>({\n method,body,signal,keepalive:!!keepalive,mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',\n headers:Object.assign(token?{Authorization:'Bearer '+token}:{},body?{'Content-Type':'application/octet-stream'}:{},headers||{})\n});\nconst bufferedBytes=()=>{\n let total=webSocket&&webSocket.readyState===WebSocket.OPEN?webSocket.bufferedAmount:0;\n if(carrierMode==='websocket-lanes')for(const lane of lanes.values())if(lane.socket&&lane.socket.readyState===WebSocket.OPEN)total+=lane.socket.bufferedAmount;\n return total;\n};\nfunction reserve(data,lane){\n if(!data.byteLength||queuedBytes+bufferedBytes()>queueLimit-data.byteLength||queuedItems>=queueItemLimit)return false;\n if(lane&&(lane.bytes>laneQueueLimit-data.byteLength||lane.items>=laneItemLimit))return false;\n queuedBytes+=data.byteLength;queuedItems++;\n if(lane){lane.bytes+=data.byteLength;lane.items++}\n return true;\n}\nfunction release(bytes,items,lane){\n queuedBytes-=bytes;queuedItems-=items;\n if(lane){lane.bytes-=bytes;lane.items-=items}\n}\nfunction splitFrames(value){\n const view=new DataView(value),result=[];let offset=0;\n while(offset<value.byteLength){\n  if(value.byteLength-offset<8||result.length>=4096)throw new Error('invalid frame batch');\n  const type=view.getUint8(offset),id=(view.getUint8(offset+1)<<16)|(view.getUint8(offset+2)<<8)|view.getUint8(offset+3);\n  const size=view.getUint32(offset+4),end=offset+8+size;\n  if((type===2&&!size)||size>1048576||end>value.byteLength)throw new Error('invalid frame');\n  result.push({type,id,data:offset===0&&end===value.byteLength?value:value.slice(offset,end)});offset=end;\n }\n if(!result.length)throw new Error('empty frame batch');\n return result;\n}\nfunction frameBound(value,maxFrames,maxBytes){\n const view=new DataView(value);let offset=0,frames=0;\n while(offset<value.byteLength){\n  if(value.byteLength-offset<8)throw new Error('invalid frame batch');\n  const size=view.getUint32(offset+4),end=offset+8+size;\n  if(end>value.byteLength)throw new Error('invalid frame');\n  if(frames>0&&(frames>=maxFrames||end>maxBytes))break;\n  frames++;offset=end;\n }\n return {frames,bytes:offset};\n}\nfunction joinPending(values,lane){\n // The relay rejects a body with more than 4096 frames or more than\n // batchLimit bytes, so never let a single request carry more than that:\n // pack whole queued items until the next one would overflow, and split a\n // first item that on its own exceeds either bound at a frame boundary,\n // pushing the remainder back to the front of the queue as its own item.\n let total=0,count=0,frames=0;\n while(count<values.length){\n  const bound=frameBound(values[count],4096,batchLimit);\n  const whole=bound.bytes===values[count].byteLength;\n  if(count===0&&!whole){\n   const head=new Uint8Array(values[0],0,bound.bytes).slice();\n   values[0]=values[0].slice(bound.bytes);\n   queuedItems++;if(lane)lane.items++;\n   return {body:head.buffer,total:bound.bytes,count:1};\n  }\n  if(count!==0&&(total+values[count].byteLength>batchLimit||frames+bound.frames>4096))break;\n  total+=values[count].byteLength;frames+=bound.frames;count++;\n }\n const joined=new Uint8Array(total);let offset=0;\n for(const data of values.splice(0,count)){joined.set(new Uint8Array(data),offset);offset+=data.byteLength}\n return {body:joined.buffer,total,count};\n}\nfunction retryAfterMs(response){\n const header=response.headers.get('Retry-After');\n if(!header)return 0;\n const seconds=Number(header);\n if(Number.isFinite(seconds)&&seconds>=0)return Math.min(seconds*1000,30000);\n const when=Date.parse(header);\n if(Number.isFinite(when)){const delta=when-Date.now();return delta>0?Math.min(delta,30000):0}\n return 0;\n}\nasync function request(path,makeOptions){\n let delay=250,attempt=0;const deadline=Date.now()+90000;\n while(true){\n  const requestOptions=makeOptions(),controller=new AbortController();\n  const external=requestOptions.signal,abort=()=>controller.abort();\n  if(external)external.addEventListener('abort',abort,{once:true});\n  requestOptions.signal=controller.signal;\n  const timer=setTimeout(abort,90000);\n  let wait=0,serviceUnavailable=false;\n  try{\n   const response=await fetch(relayOrigin+path,requestOptions);\n   if(response.status!==503)return response;\n   serviceUnavailable=true;wait=retryAfterMs(response);\n   await response.arrayBuffer();\n  }catch(error){if(closed||(external&&external.aborted))throw error;attempt++;if(attempt===9)throw new Error('carrier retry limit reached')}\n  finally{clearTimeout(timer);if(external)external.removeEventListener('abort',abort)}\n  if(serviceUnavailable&&Date.now()>=deadline)throw new Error('carrier retry limit reached');\n  status('reconnecting');\n  const backoff=wait||(delay+Math.floor(Math.random()*Math.max(1,delay/4)));\n  await pause(backoff);\n  if(!serviceUnavailable)delay=Math.min(delay*2,5000);\n }\n}\nfunction fail(){\n if(closed)return;\n status('failed');\n if(port)port.postMessage({t:'close'});\n close(true);\n}\nasync function createSession(first){\n try{\n  status('connecting');\n  const response=await request('/api/v1/session',()=>options('POST',bootstrap,first));\n  if(response.status!==200||response.headers.get('X-Carrier-Mode')!==carrierMode)throw new Error('session creation rejected');\n  sessionToken=response.headers.get('X-Session-Token')||'';\n  downCursor=response.headers.get('X-Down-Cursor')||'0';\n  if(!sessionToken)throw new Error('missing session token');\n  if(closed){fetch(relayOrigin+'/api/v1/session',options('DELETE',sessionToken,null,null,undefined,true)).catch(()=>{});return}\n  const welcome=await response.arrayBuffer();\n  if(carrierMode==='websocket')await openWebSocket();\n  if(closed){fetch(relayOrigin+'/api/v1/session',options('DELETE',sessionToken,null,null,undefined,true)).catch(()=>{});return}\n  port.postMessage(welcome,[welcome]);\n  status('connected');\n  for(const data of pending.splice(0)){release(data.byteLength,1,null);queueCarrier(data)}\n  if(carrierMode==='https')poll();\n  else if(carrierMode==='https-lanes')pollLane(ensureLane(0));\n }catch(error){fail()}\n}\nfunction queueCarrier(data){\n try{\n  if(carrierMode==='https')queueUp(data);\n  else if(carrierMode==='https-lanes')for(const value of splitFrames(data))queueLane(value);\n  else if(carrierMode==='websocket')queueWebSocket(data);\n  else for(const value of splitFrames(data))queueWebSocketLane(value);\n }catch(error){fail()}\n}\nfunction queueUp(data){\n if(!reserve(data,null)){fail();return}\n upPending.push(data);runUp();\n}\nasync function runUp(){\n if(upRunning)return;\n upRunning=true;\n try{\n  while(!closed&&sessionToken&&upPending.length){\n   const batch=joinPending(upPending,null),sequence=String(upSequence);\n   const response=await request('/api/v1/up',()=>options('POST',sessionToken,batch.body,{'X-Up-Seq':sequence}));\n   if(response.status!==204||response.headers.get('X-Up-Ack')!==sequence)throw new Error('uplink rejected');\n   release(batch.total,batch.count,null);port.postMessage({t:'traffic',up:batch.total,down:0});upSequence++;\n  }\n }catch(error){fail()}\n finally{upRunning=false;if(!closed&&sessionToken&&upPending.length)runUp()}\n}\nasync function poll(){\n while(!closed&&sessionToken){\n  try{\n   pollController=new AbortController();\n   const response=await request('/api/v1/down',()=>options('POST',sessionToken,null,{'X-Down-Cursor':downCursor},pollController.signal));\n   if(response.status===204){status('connected');continue}\n   if(response.status!==200)throw new Error('downlink rejected');\n   const next=response.headers.get('X-Down-Cursor')||'',data=await response.arrayBuffer();\n   if(!next||!data.byteLength)throw new Error('invalid downlink response');\n   if(closed)return;\n   port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);downCursor=next;status('connected');\n  }catch(error){if(!closed)fail();return}\n }\n}\nfunction ensureLane(id){\n let lane=lanes.get(id);\n if(!lane){lane={id,sequence:1,cursor:'0',pending:[],bytes:0,items:0,running:false,polling:false,socket:null,timer:0,opened:false,localClosed:false,remoteClosed:false,finished:false};lanes.set(id,lane)}\n return lane;\n}\nfunction rememberLaneClosed(id){\n if(!id||closedLanes.has(id))return;\n if(closedLaneOrder.length===closedLaneLimit)closedLanes.delete(closedLaneOrder.shift());\n closedLanes.add(id);closedLaneOrder.push(id);\n}\nfunction queueLane(value){\n let lane=lanes.get(value.id);\n if(!lane&&(value.type===2||value.type===3||value.type===4))return;\n if(!lane&&closedLanes.has(value.id))throw new Error('closed lane was reused');\n if(!lane&&value.type!==1)throw new Error('lane did not begin with OPEN');\n lane=lane||ensureLane(value.id);\n if(!reserve(value.data,lane)){fail();return}\n lane.pending.push(value.data);runLaneUp(lane);\n}\nasync function runLaneUp(lane){\n if(lane.running)return;\n lane.running=true;\n try{\n  while(!closed&&sessionToken&&lane.pending.length){\n   const batch=joinPending(lane.pending,lane),sequence=String(lane.sequence),laneID=String(lane.id);\n   const response=await request('/api/v1/up',()=>options('POST',sessionToken,batch.body,{'X-Up-Seq':sequence,'X-Lane-ID':laneID}));\n   if(response.status!==204||response.headers.get('X-Up-Ack')!==sequence)throw new Error('lane uplink rejected');\n   release(batch.total,batch.count,lane);port.postMessage({t:'traffic',up:batch.total,down:0});lane.sequence++;\n   if(!lane.polling)pollLane(lane);\n  }\n }catch(error){fail()}\n finally{lane.running=false;if(!closed&&sessionToken&&lane.pending.length)runLaneUp(lane)}\n}\nasync function pollLane(lane){\n if(lane.polling)return;\n lane.polling=true;\n try{\n  while(!closed&&sessionToken&&lanes.get(lane.id)===lane){\n   const controller=new AbortController(),laneID=String(lane.id);\n   lane.controller=controller;\n   const response=await request('/api/v1/down',()=>options('POST',sessionToken,null,{'X-Down-Cursor':lane.cursor,'X-Lane-ID':laneID},controller.signal));\n   if(response.status===204){\n    if(response.headers.get('X-Lane-Closed')==='1'){lanes.delete(lane.id);rememberLaneClosed(lane.id);return}\n    status('connected');continue;\n   }\n   if(response.status!==200)throw new Error('lane downlink rejected');\n   const next=response.headers.get('X-Down-Cursor')||'',data=await response.arrayBuffer();\n   if(!next||!data.byteLength)throw new Error('invalid lane downlink response');\n   for(const value of splitFrames(data))if(value.id!==lane.id)throw new Error('cross-lane frame');\n   if(closed)return;\n   port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data]);lane.cursor=next;status('connected');\n  }\n }catch(error){if(!closed)fail()}\n finally{lane.polling=false;lane.controller=null}\n}\nfunction openWebSocket(){\n return new Promise((resolve,reject)=>{\n  const target=relayOrigin.replace(/^https:/,'wss:')+'/api/v1/ws',socket=new WebSocket(target,'tproxy-v1.'+sessionToken);\n  webSocket=socket;socket.binaryType='arraybuffer';\n  socket.onopen=()=>resolve();\n  socket.onmessage=event=>{\n   if(!(event.data instanceof ArrayBuffer)||!event.data.byteLength){fail();return}\n   port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');\n  };\n  socket.onerror=()=>reject(new Error('websocket failed'));\n  socket.onclose=()=>{if(!closed)fail()};\n });\n}\nfunction queueWebSocket(data){\n if(!reserve(data,null)){fail();return}\n upPending.push(data);runWebSocketUp();\n}\nfunction runWebSocketUp(){\n if(closed||!webSocket||webSocket.readyState!==WebSocket.OPEN||!upPending.length)return;\n if(webSocket.bufferedAmount+queuedBytes>queueLimit||webSocket.bufferedAmount>=batchLimit){\n  if(!webSocketTimer)webSocketTimer=setTimeout(()=>{webSocketTimer=0;runWebSocketUp()},10);\n  return;\n }\n try{\n  const batch=joinPending(upPending,null);webSocket.send(batch.body);release(batch.total,batch.count,null);\n  port.postMessage({t:'traffic',up:batch.total,down:0});\n  if(upPending.length)queueMicrotask(runWebSocketUp);\n }catch(error){fail()}\n}\nfunction closeFrame(id){\n const data=new ArrayBuffer(8),view=new DataView(data);\n view.setUint8(0,3);view.setUint8(1,id>>>16);view.setUint8(2,id>>>8);view.setUint8(3,id);view.setUint32(4,0);\n return data;\n}\nfunction finishWebSocketLane(lane,notify){\n if(lane.finished||lanes.get(lane.id)!==lane)return;\n lane.finished=true;if(lane.timer)clearTimeout(lane.timer);\n if(lane.bytes||lane.items)release(lane.bytes,lane.items,lane);\n lane.pending.length=0;lanes.delete(lane.id);rememberLaneClosed(lane.id);\n if(lane.socket&&(lane.socket.readyState===WebSocket.OPEN||lane.socket.readyState===WebSocket.CONNECTING))try{lane.socket.close()}catch(error){}\n if(notify&&port&&!closed){const frame=closeFrame(lane.id);port.postMessage(frame,[frame])}\n}\nfunction openWebSocketLane(lane){\n const target=relayOrigin.replace(/^https:/,'wss:')+'/api/v1/ws';\n const socket=new WebSocket(target,'tproxy-lane-v1.'+sessionToken+'.'+lane.id);\n lane.socket=socket;socket.binaryType='arraybuffer';\n socket.onopen=()=>{if(closed||lane.finished){socket.close();return}lane.opened=true;status('connected');runWebSocketLaneUp(lane)};\n socket.onmessage=event=>{\n  if(!(event.data instanceof ArrayBuffer)||!event.data.byteLength){fail();return}\n  let values;try{values=splitFrames(event.data)}catch(error){fail();return}\n  if(values.some(value=>value.id!==lane.id)){fail();return}\n  if(values.some(value=>value.type===3))lane.remoteClosed=true;\n  port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');\n };\n socket.onerror=()=>{};\n socket.onclose=()=>{\n  if(closed||lane.finished)return;\n  if(!lane.opened){fail();return}\n  finishWebSocketLane(lane,!lane.localClosed&&!lane.remoteClosed);\n };\n}\nfunction queueWebSocketLane(value){\n let lane=lanes.get(value.id);\n if(!lane&&(value.type===2||value.type===3||value.type===4))return;\n if(!value.id||(!lane&&closedLanes.has(value.id)))throw new Error('closed lane was reused');\n if(!lane&&value.type!==1)throw new Error('lane did not begin with OPEN');\n lane=lane||ensureLane(value.id);\n if(!reserve(value.data,lane)){fail();return}\n lane.pending.push(value.data);if(value.type===3)lane.localClosed=true;\n if(!lane.socket)openWebSocketLane(lane);else runWebSocketLaneUp(lane);\n}\nfunction runWebSocketLaneUp(lane){\n const socket=lane.socket;\n if(closed||lane.finished||!socket||socket.readyState!==WebSocket.OPEN||!lane.pending.length)return;\n if(socket.bufferedAmount>=batchLimit){\n  if(!lane.timer)lane.timer=setTimeout(()=>{lane.timer=0;runWebSocketLaneUp(lane)},10);\n  return;\n }\n try{\n  const batch=joinPending(lane.pending,lane);socket.send(batch.body);release(batch.total,batch.count,lane);\n  port.postMessage({t:'traffic',up:batch.total,down:0});\n  if(lane.pending.length)queueMicrotask(()=>runWebSocketLaneUp(lane));\n }catch(error){fail()}\n}\nfunction close(notifyServer){\n if(closed)return;\n closed=true;\n if(pollController)pollController.abort();\n for(const lane of lanes.values()){\n  if(lane.controller)lane.controller.abort();\n  if(lane.timer)clearTimeout(lane.timer);\n  if(lane.socket)try{lane.socket.close()}catch(error){}\n }\n if(webSocketTimer)clearTimeout(webSocketTimer);\n if(webSocket)webSocket.close();\n if(notifyServer&&sessionToken)fetch(relayOrigin+'/api/v1/session',options('DELETE',sessionToken,null,null,undefined,true)).catch(()=>{});\n if(port)port.close();\n}\nfunction activatePort(nextPort){\n initialized=true;port=nextPort;\n port.onmessage=message=>{\n  if(message.data instanceof ArrayBuffer){\n   if(!createStarted){createStarted=true;createSession(message.data)}\n   else if(!sessionToken){if(!reserve(message.data,null)){fail();return}pending.push(message.data)}\n   else queueCarrier(message.data);\n  }else if(message.data&&message.data.t==='close')close(true);\n };\n port.start();status('connecting');\n}\naddEventListener('message',event=>{\n if(initialized||event.source!==parent||event.data===null||typeof event.data!=='object')return;\n const keys=Object.keys(event.data).sort();\n if(keys.length!==2||keys[0]!=='t'||keys[1]!=='v'||event.data.t!=='tproxy-init'||event.data.v!==1||event.ports.length!==1)return;\n let source;try{source=new URL(event.origin)}catch(error){return}\n if(source.protocol!=='http:'||source.hostname!=='127.0.0.1'||!source.port||source.origin!==event.origin)return;\n activatePort(event.ports[0]);\n},{once:false});\nconst androidBridge=globalThis.TelegramWebProxy;\nif(!initialized&&androidNonce&&androidBridge&&typeof androidBridge.postMessage==='function'){\n const androidPort={onmessage:null,start(){},close(){androidBridge.onmessage=null},postMessage(value){\n  if(value instanceof ArrayBuffer){\n   let frames;try{frames=splitFrames(value)}catch(error){fail();return}\n   for(const frame of frames)androidBridge.postMessage(frame.data);\n  }else androidBridge.postMessage(JSON.stringify(value));\n }};\n androidBridge.onmessage=event=>{\n  let data=event.data;if(typeof data==='string'){try{data=JSON.parse(data)}catch(error){return}}\n  if(androidPort.onmessage)androidPort.onmessage({data});\n };\n activatePort(androidPort);androidBridge.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce:androidNonce}));\n}\naddEventListener('pagehide',()=>close(true),{once:true});\n})();\n</script>\n</body>\n</html>\n";
    html.replace("__NONCE__", &nonce)
        .replace("__ORIGIN__", &format!("\"{}\"", origin))
        .replace("__BOOTSTRAP__", &format!("\"{}\"", bootstrap))
        .replace("__CARRIER_MODE__", &format!("\"{}\"", st.cfg.carrier_mode))
        .replace("__BATCH_LIMIT__", "2097152")
}
