//! The server binding (transport.md, "The server binding"): discovery, the
//! WebSocket `frasil.p1`, objects over HTTP, mailboxes, `/healthz`, and
//! the answer to cross-origin requests.
//!
//! A reverse proxy terminates TLS in front of the peer; the peer serves
//! plain HTTP. Its channel binding is `SHA-256("frasil/server-channel/v1"
//! || field(origin))` over the origin clients connect to.

use crate::config::Extensions;
use crate::session::{PieceOutcome, Session, store_piece};
use crate::state::Outgoing;
use crate::util::{hex, log, unhex};
use crate::{Shared, Stop};
use axum::Router;
use axum::body::Bytes;
use axum::extract::ws::{CloseFrame, Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use frasil_base::cbor;
use frasil_events::EventId;
use frasil_peers::entries::Rights;
use frasil_transport::frame::{
    ConnectionKind, MAX_FRAME_BYTES, Message, MessageType, StreamClass, read_message,
};
use frasil_transport::labels::WEBSOCKET_SUBPROTOCOL;
use frasil_transport::mailbox::Kind;
use frasil_transport::peer::{
    CONNECT_PATH, DISCOVERY_PATH, Limits, read_transfer_authorization, server_channel,
};
use frasil_transport::{Closed, Code, TransportClass};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

/// The routes.
pub(crate) fn router(shared: Arc<Shared>) -> Router {
    let mut router = Router::new();
    if shared.settings.extensions.libraries {
        // ext-libraries.md, 3.6 Usage and refusals: the operator's
        // interface.
        router = router.route(LIBRARY_USAGE_PATH, get(library_usage));
        // ext-libraries.md, 2.4 Settings: the operator's interface.
        router = router.route(
            LIBRARY_SETTINGS_PATH,
            get(library_settings)
                .put(library_settings)
                .layer(DefaultBodyLimit::max(LIBRARY_SETTINGS_BYTES)),
        );
        // peers.md, 3.1 Hosting a space, "Hand-over": the operator's
        // interface.
        router = router.route(
            LIBRARY_HANDOVER_PATH,
            axum::routing::post(library_handover).layer(DefaultBodyLimit::disable()),
        );
    }
    router
        .route(DISCOVERY_PATH, get(discovery))
        .route("/healthz", get(health))
        .route(CONNECT_PATH, get(connect))
        .route(
            "/frasil/p1/spaces/{space}/objects/{locator}/chunks/{index}",
            get(get_piece).put(put_piece),
        )
        .route(
            "/frasil/p1/mailbox/{kind}/{address}",
            get(get_mailbox)
                .post(post_mailbox)
                .layer(DefaultBodyLimit::max(
                    frasil_transport::frame::MAILBOX_ITEM_BYTES + 1,
                )),
        )
        .fallback(|| async { reason(StatusCode::NOT_FOUND, "not_found") })
        .layer(axum::middleware::from_fn(cross_origin))
        .with_state(shared)
}

/// `ok` while the peer can write: 503 otherwise, with why, so that a health
/// check sees a peer that serves but keeps nothing.
async fn health(State(shared): State<Arc<Shared>>) -> Response {
    match shared.not_writing() {
        None => "ok".into_response(),
        Some(why) => (StatusCode::SERVICE_UNAVAILABLE, why).into_response(),
    }
}

/// The usage route: the operator's, behind its bearer token.
pub(crate) const LIBRARY_USAGE_PATH: &str = "/frasil/p1/libraries/{library}/usage";

/// `GET /frasil/p1/libraries/{library}/usage`, with
/// `Authorization: Bearer <operator token>`: `{"library", "used_bytes",
/// "quota_bytes", "spaces"}`. Refused `not_authorized` (403) while the
/// peer has no operator token, `unauthorized` (401) without the token,
/// and `not_found` (404) for a library the peer does not know. Per-author
/// usage never leaves through it.
async fn library_usage(
    State(shared): State<Arc<Shared>>,
    Path(library): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(token) = &shared.settings.libraries.operator_token else {
        return reason(StatusCode::FORBIDDEN, "not_authorized");
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if !presented.is_some_and(|presented| token.matches(presented)) {
        return reason(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let Ok(id) = frasil_libraries::LibraryId::new(&library) else {
        return reason(StatusCode::BAD_REQUEST, "malformed");
    };
    // In a cluster, the owner of the library's shard keeps its ledger.
    if let Some(cluster) = shared.cluster.get().cloned() {
        let (status, body) = cluster.usage(&id).await;
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
        return (status, [(header::CONTENT_TYPE, "application/json")], body).into_response();
    }
    match crate::libraries::library_usage(&shared, &id).await {
        Some(usage) => axum::Json(json!({
            "library": id.as_str(),
            "used_bytes": usage.used_bytes,
            "quota_bytes": usage.quota_bytes,
            "spaces": usage.spaces,
        }))
        .into_response(),
        None => reason(StatusCode::NOT_FOUND, "not_found"),
    }
}

/// The settings route: the operator's, behind its bearer token.
pub(crate) const LIBRARY_SETTINGS_PATH: &str = "/frasil/p1/libraries/{library}/settings";

/// The most bytes the settings route reads of a change.
const LIBRARY_SETTINGS_BYTES: usize = 1024;

/// `GET` and `PUT /frasil/p1/libraries/{library}/settings`, with
/// `Authorization: Bearer <operator token>` (ext-libraries.md, 2.4
/// Settings): `GET` reads the library's settings, and `PUT` changes those
/// its JSON body names, creating a library the peer does not know with the
/// defaults first. Both answer `{"library", "quota_bytes",
/// "erasure_timeout", "state", "open_until", "open"}`. Refused as the usage
/// route is without the token; then as crate `libraries`'
/// `library_settings` refuses.
async fn library_settings(
    State(shared): State<Arc<Shared>>,
    Path(library): Path<String>,
    method: axum::http::Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(token) = &shared.settings.libraries.operator_token else {
        return reason(StatusCode::FORBIDDEN, "not_authorized");
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if !presented.is_some_and(|presented| token.matches(presented)) {
        return reason(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let Ok(id) = frasil_libraries::LibraryId::new(&library) else {
        return reason(StatusCode::BAD_REQUEST, "malformed");
    };
    let change = (method == axum::http::Method::PUT).then(|| body.to_vec());
    if change.as_deref().is_some_and(|change| {
        crate::libraries::read_update(change, shared.settings.extensions.deposit_tokens).is_none()
    }) {
        return reason(StatusCode::BAD_REQUEST, "malformed");
    }
    // In a cluster, the owner of the library's shard keeps its settings.
    let (status, body) = match shared.cluster.get().cloned() {
        Some(cluster) => cluster.settings(&id, change).await,
        None => crate::libraries::library_settings(&shared, &id, change.as_deref()),
    };
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// The hand-over routes: the operator's, behind its bearer token.
pub(crate) const LIBRARY_HANDOVER_PATH: &str = "/frasil/p1/libraries/{library}/handover/{step}";

/// `POST /frasil/p1/libraries/{library}/handover/{step}`, with
/// `Authorization: Bearer <operator token>` (crate `libraries`, module
/// `handover`): `export` stops storing into the library and answers its
/// bundle (`application/cbor`); `import` takes a bundle in; `depart` keeps
/// the departure records and forgets the library; `resume` calls the
/// hand-over off. Refused as the usage route is without the token,
/// `not_found` (404) for a library the peer does not know or a step it
/// does not take, `malformed` (400) for a bundle that does not read, holds
/// what is not the library's or stops before its end, and with 409
/// `exists`, `library_spread`, `library_changed`, `moving`,
/// `not_handing_over` or `not_sharded`.
///
/// The bundle streams both ways: the export answers it as it is made, and
/// the import writes it as it arrives. The body is read only once the
/// token checks, and only for `import`.
async fn library_handover(
    State(shared): State<Arc<Shared>>,
    Path((library, step)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    use crate::libraries::handover;
    let Some(token) = &shared.settings.libraries.operator_token else {
        return reason(StatusCode::FORBIDDEN, "not_authorized");
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if !presented.is_some_and(|presented| token.matches(presented)) {
        return reason(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let Ok(id) = frasil_libraries::LibraryId::new(&library) else {
        return reason(StatusCode::BAD_REQUEST, "malformed");
    };
    let (status, json, body) = match step.as_str() {
        "export" => match handover::export(&shared, &id).await {
            handover::Export::Refused(answer) => answer,
            handover::Export::Bundle(parts) => {
                let stream = futures_util::stream::unfold(parts, |mut parts| async move {
                    let part = parts.recv().await?;
                    Some((part.map_err(std::io::Error::other), parts))
                });
                return (
                    [(header::CONTENT_TYPE, "application/cbor")],
                    axum::body::Body::from_stream(stream),
                )
                    .into_response();
            }
        },
        "import" => handover::import(&shared, &id, body).await,
        "depart" => handover::depart(&shared, &id).await,
        "resume" => handover::resume(&shared, &id).await,
        _ => return reason(StatusCode::NOT_FOUND, "not_found"),
    };
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    let kind = if json {
        "application/json"
    } else {
        "application/cbor"
    };
    (status, [(header::CONTENT_TYPE, kind)], body).into_response()
}

/// Cross-origin requests (transport.md, "The server binding"): every
/// answer allows any origin, and a preflight of any path is 204 with the
/// methods and headers the binding uses. No credentials are allowed:
/// every right travels in `Authorization`.
async fn cross_origin(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    use axum::http::{HeaderValue, Method};
    let mut response = if request.method() == Method::OPTIONS {
        let mut preflight = StatusCode::NO_CONTENT.into_response();
        let headers = preflight.headers_mut();
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, PUT, POST, DELETE"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Authorization, Content-Type"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("86400"),
        );
        preflight
    } else {
        next.run(request).await
    };
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

/// An HTTP error: `{"code": "<reason>"}` with its status.
fn reason(status: StatusCode, code: &str) -> Response {
    (status, axum::Json(json!({ "code": code }))).into_response()
}

fn refusal((code, status): (String, u16)) -> Response {
    reason(
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
        &code,
    )
}

/// `GET /.well-known/frasil`.
async fn discovery(State(shared): State<Arc<Shared>>) -> Response {
    let limits = Limits {
        max_streams_per_space: shared.settings.max_streams_per_space,
        ..Limits::PROTOCOL
    };
    let mut document = json!({
        "frasil": frasil_transport::peer::PROTOCOL,
        "revision": frasil_transport::peer::REVISION,
        "services": crate::session::services(&shared.settings.extensions).iter().map(|s| s.name()).collect::<Vec<_>>(),
        "limits": {
            "max_frame_bytes": limits.max_frame_bytes,
            "max_streams_per_space": limits.max_streams_per_space,
            "max_mailbox_item_bytes": limits.max_mailbox_item_bytes,
            "max_chunk_bytes": limits.max_chunk_bytes,
        },
    });
    let iroh = shared
        .iroh
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if let Some(iroh) = iroh {
        // Every machine's key, this one's first; one machine lists its own
        // alone (transport.md, 3.15 The server binding, discovery).
        let own = hex(&iroh.endpoint);
        let mut endpoints = vec![own.clone()];
        if let Some(cluster) = shared.cluster.get() {
            for key in cluster.iroh_endpoints() {
                if !endpoints.contains(&key) && endpoints.len() < 256 {
                    endpoints.push(key);
                }
            }
        }
        document["iroh"] = json!({
            "endpoint": own,
            "endpoints": endpoints,
        });
    }
    if !shared.settings.relays.is_empty() {
        document["relays"] = json!(shared.settings.relays);
    }
    if let Some(url) = &shared.settings.account_url {
        document["account_url"] = json!(url);
    }
    // ext-deposit-tokens.md, 2.5 Messages, "The server binding".
    if shared.settings.extensions.deposit_tokens {
        let keys: Vec<serde_json::Value> = shared
            .core
            .deposit_key_entries(shared.clock.now())
            .iter()
            .map(|entry| {
                json!({
                    "id": hex(&entry.key_id),
                    "key": hex(&entry.public),
                    "issuing": entry.role == frasil_deposit_tokens::Role::Issuing,
                })
            })
            .collect();
        document["deposit_keys"] = json!(keys);
    }
    axum::Json(document).into_response()
}

/// The origin the client connected to (transport.md, "The server
/// binding"), which its channel binds: a configured one, never one the
/// request names. A browser always sends `Origin` on a WebSocket request
/// and connects at the configured origin; a native client sends none and
/// connects at the native origin, when one is configured. Without a
/// configured origin, in development, `http://` and the request's `Host`.
fn origin(shared: &Shared, headers: &HeaderMap) -> Option<String> {
    if !headers.contains_key(header::ORIGIN)
        && let Some(native) = &shared.settings.native_origin
    {
        return Some(native.clone());
    }
    if let Some(origin) = &shared.settings.origin {
        return Some(origin.clone());
    }
    let host = headers.get(header::HOST)?.to_str().ok()?;
    Some(format!("http://{host}"))
}

/// `GET /frasil/p1/connect`, upgraded to a WebSocket with subprotocol
/// `frasil.p1`.
async fn connect(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>,
) -> Response {
    let Ok(upgrade) = upgrade else {
        return StatusCode::UPGRADE_REQUIRED.into_response();
    };
    let offered = headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|protocol| protocol.trim() == WEBSOCKET_SUBPROTOCOL);
    if !offered {
        return reason(StatusCode::BAD_REQUEST, "malformed");
    }
    let Some(origin) = origin(&shared, &headers) else {
        return reason(StatusCode::BAD_REQUEST, "malformed");
    };
    let channel = server_channel(&origin);
    let credentialed =
        headers.contains_key(header::COOKIE) || headers.contains_key(header::AUTHORIZATION);
    let source = crate::source::of_request(&shared.settings.trusted_proxies, remote, &headers);
    // Through a trusted proxy, the WebSocket counts toward its client's cap
    // on connections from one source, for as long as it lasts: the proxy's
    // TCP connection counted toward the overall cap alone (crate `limits`).
    let forwarded = if shared.settings.trusted_proxies.contains(remote.ip()) {
        match shared.connections.admit_forwarded(&source) {
            Some(permit) => Some(permit),
            None => return reason(StatusCode::SERVICE_UNAVAILABLE, "busy"),
        }
    } else {
        None
    };
    upgrade
        .protocols([WEBSOCKET_SUBPROTOCOL])
        .max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            let _forwarded = forwarded;
            run(shared, socket, channel, source, credentialed).await;
        })
}

/// Reads one WebSocket message: one transport.md message, with no prefix,
/// read in the class that carries its type, with the message types of the
/// extensions that are on.
pub(crate) fn read(
    payload: &[u8],
    extensions: Extensions,
) -> Result<Option<Message>, TransportClass> {
    let class = cbor::decode(payload)
        .ok()
        .and_then(|value| value.as_map().ok()?.get(&0)?.as_unsigned().ok())
        .and_then(MessageType::from_code)
        .map_or(StreamClass::Control, |kind| match kind {
            MessageType::Sync | MessageType::AdapterSync | MessageType::Open => StreamClass::Sync,
            MessageType::Ephemeral => StreamClass::Ephemeral,
            _ => StreamClass::Control,
        });
    if payload.len() > class.cap() {
        return Err(frasil_base::ErrorClass::TooLarge.into());
    }
    read_message(
        payload,
        class,
        ConnectionKind::DeviceToPeer,
        extensions.frames(),
    )
}

/// How long a connection waits for the device's own `Close` once it
/// sent one.
const CLOSE_WAIT: Duration = Duration::from_secs(1);

async fn close(socket: &mut WebSocket, code: u16) {
    let _ = socket
        .send(WsMessage::Close(Some(CloseFrame {
            code,
            reason: "".into(),
        })))
        .await;
}

/// Reads and drops what the device still sends, until its `Close` or the
/// connection's end, at most [`CLOSE_WAIT`] (RFC 6455, 7.1.1). A socket
/// dropped with the device's messages unread is reset on Windows, and the
/// reset can discard the close code before the device reads it: a
/// `reconnect` would arrive as a lost connection.
async fn finish(socket: &mut WebSocket) {
    let _ = tokio::time::timeout(CLOSE_WAIT, async {
        while let Some(Ok(message)) = socket.recv().await {
            if matches!(message, WsMessage::Close(_)) {
                break;
            }
        }
    })
    .await;
}

/// Sends messages, each within `limit`: false if the socket failed, or a
/// device read too slowly to take one in time.
async fn send_all(socket: &mut WebSocket, outgoing: Vec<Outgoing>, limit: Duration) -> bool {
    for out in outgoing {
        if !send_one(socket, out, limit).await {
            return false;
        }
    }
    true
}

async fn send_one(socket: &mut WebSocket, out: Outgoing, limit: Duration) -> bool {
    let messages = match out {
        Outgoing::Control(bytes) | Outgoing::Sync(_, bytes) => vec![bytes],
        Outgoing::Object(_, messages) => messages,
        Outgoing::Ephemeral(bytes) => vec![bytes],
        Outgoing::Reconnect => Vec::new(),
    };
    for bytes in messages {
        let sent = tokio::time::timeout(limit, socket.send(WsMessage::Binary(bytes.into()))).await;
        if !matches!(sent, Ok(Ok(()))) {
            return false;
        }
    }
    true
}

/// What a message is answered: at once, then every batch of the answers
/// the session serves in batches, before the connection's next message is
/// read. One batch is held at a time, and each write waits at most `limit`
/// (units.md, "Sync"; transport.md, 3.9).
async fn answer(
    socket: &mut WebSocket,
    session: &mut Session,
    outgoing: Vec<Outgoing>,
    limit: Duration,
) -> bool {
    if !send_all(socket, outgoing, limit).await {
        return false;
    }
    while let Some(next) = session.next_answer().await {
        if !send_one(socket, next, limit).await {
            return false;
        }
    }
    true
}

/// One WebSocket connection: the device-to-peer handshake, then its
/// messages; once its session is gone, the end of the closing handshake.
async fn run(
    shared: Arc<Shared>,
    mut socket: WebSocket,
    channel: [u8; 32],
    source: String,
    credentialed: bool,
) {
    serve(shared, &mut socket, channel, source, credentialed).await;
    // The session is gone: the node counts the connection no more while
    // the device's `Close` comes back.
    finish(&mut socket).await;
}

async fn serve(
    shared: Arc<Shared>,
    socket: &mut WebSocket,
    channel: [u8; 32],
    source: String,
    credentialed: bool,
) {
    let mut stop = shared.stop.subscribe();
    let extensions = shared.settings.extensions;
    let limits = shared.settings.connections;
    let write = Duration::from_secs(limits.write_timeout);
    let (mut session, hello, mut outbox) = match Session::start(shared, channel, true, source) {
        Ok(started) => started,
        Err(closed) => {
            close(socket, closed.code.websocket()).await;
            return;
        }
    };
    if credentialed {
        session.credentialed();
    }
    if !send_all(socket, vec![Outgoing::Control(hello)], write).await {
        return;
    }
    let deadline = tokio::time::sleep(frasil_iroh::HANDSHAKE_DEADLINE);
    tokio::pin!(deadline);
    let mut stopping = *stop.borrow_and_update();
    let mut watching = true;
    // The keep-alive: a ping every interval (RFC 6455, 5.5.2 Ping), which a
    // device's WebSocket answers as it reads.
    let every = Duration::from_secs(limits.keepalive_interval);
    let idle = Duration::from_secs(limits.idle_timeout);
    let mut keepalive = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut heard = tokio::time::Instant::now();
    let mut spoke = heard;
    loop {
        // The peer stops: `reconnect` once nothing holds the connection;
        // one still held after the drain is dropped as a lost one, with no
        // close code (transport.md, 3.10, "Reconnecting elsewhere").
        match stopping {
            Stop::Reconnect | Stop::Drop if session.may_reconnect() => {
                close(socket, Code::Reconnect.websocket()).await;
                return;
            }
            Stop::Drop => return,
            _ => {}
        }
        tokio::select! {
            changed = stop.changed(), if watching => {
                match changed {
                    Ok(()) => stopping = *stop.borrow_and_update(),
                    Err(_) => watching = false,
                }
            }
            incoming = socket.recv() => {
                heard = tokio::time::Instant::now();
                let bytes = match incoming {
                    Some(Ok(WsMessage::Binary(bytes))) => {
                        spoke = heard;
                        bytes
                    }
                    Some(Ok(WsMessage::Text(_))) => {
                        close(socket, 1003).await;
                        return;
                    }
                    Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
                    Some(Ok(WsMessage::Close(_))) | Some(Err(_)) | None => return,
                };
                let answer = match read(&bytes, extensions) {
                    Ok(Some(message)) => session.on_message(&message).await,
                    Ok(None) => Ok(Vec::new()),
                    Err(class) => Err(Closed::of(class)),
                };
                match answer {
                    Ok(outgoing) => {
                        if !self::answer(socket, &mut session, outgoing, write).await {
                            return;
                        }
                    }
                    Err(closed) => {
                        log(format_args!("closing a connection: {closed}"));
                        close(socket, closed.code.websocket()).await;
                        return;
                    }
                }
            }
            Some(out) = outbox.recv() => {
                session.dequeued(&out);
                // The cluster moves load, or a live delivery ended with its
                // entry: `reconnect`, once nothing holds the connection
                // (transport.md, 3.10; peers.md, 3.6 Retirement and the
                // cap, "Connections").
                if out == Outgoing::Reconnect {
                    if session.may_reconnect() {
                        close(socket, Code::Reconnect.websocket()).await;
                        return;
                    }
                    session.declined_reconnect();
                    continue;
                }
                if !send_one(socket, out, write).await {
                    return;
                }
            }
            () = &mut deadline, if !session.opened() => {
                close(socket, Code::Timeout.websocket()).await;
                return;
            }
            _ = keepalive.tick() => {
                // Nothing for three intervals, not even a pong: the device
                // is gone, or reads no more.
                if heard.elapsed() >= every * 3 {
                    log("closing a connection that answers no keep-alive");
                    return;
                }
                // A connection that holds no grant and sent nothing for
                // `idle_timeout` after its `Hello` is closed `done`; one
                // that holds a grant, such as one subscribed to live
                // delivery, stays while it answers the keep-alive.
                if session.opened() && !session.holds_grant() && spoke.elapsed() >= idle {
                    close(socket, Code::Done.websocket()).await;
                    return;
                }
                let ping = socket.send(WsMessage::Ping(Bytes::new()));
                if !matches!(tokio::time::timeout(write, ping).await, Ok(Ok(()))) {
                    return;
                }
            }
        }
    }
}

// -- Objects over HTTP

/// The transfer token a request carries.
fn token_of(headers: &HeaderMap) -> Option<[u8; 32]> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    read_transfer_authorization(value).ok()
}

/// The rights a transfer token grants in a space, at the node that keeps
/// the space's connections.
fn transfer(shared: &Shared, token: &[u8; 32], space: &EventId) -> Option<Rights> {
    crate::state::lock(&shared.core.transfers)
        .get(token)
        .filter(|transfer| transfer.space == *space)
        .map(|transfer| transfer.rights)
}

/// The path's space, locator and index.
fn object_path(space: &str, locator: &str, index: &str) -> Option<(EventId, [u8; 64], u64)> {
    let space = unhex::<32>(space)?;
    let locator = unhex::<64>(locator)?;
    if index.is_empty()
        || !index.bytes().all(|b| b.is_ascii_digit())
        || (index.len() > 1 && index.starts_with('0'))
    {
        return None;
    }
    Some((EventId(space), locator, index.parse().ok()?))
}

fn json_body(code: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({ "code": code })).unwrap_or_default()
}

/// An object piece at this node, which keeps the space's transfer tokens:
/// the HTTP status, whether the body is JSON, and the body.
pub(crate) async fn piece_here(
    shared: &Arc<Shared>,
    piece: &crate::cluster::wire::Piece,
) -> (u16, bool, Vec<u8>) {
    let space = EventId(piece.space);
    let locator = piece.locator;
    let rights = transfer(shared, &piece.token, &space);
    // A store's token checked before its body is read, at the gateway's
    // ask: nothing is stored.
    if piece.check {
        return if piece.put && rights.is_some_and(|rights| rights.store) {
            (200, true, json_body("ok"))
        } else {
            (403, true, json_body("credential_refused"))
        };
    }
    if !piece.put {
        if !rights.is_some_and(|rights| rights.fetch) {
            return (403, true, json_body("credential_refused"));
        }
        let home = match shared.core.object_fetchable(&space, &locator).await {
            Ok((home, _)) => home,
            Err((code, status)) => return (status, true, json_body(&code)),
        };
        let key = crate::objects::piece_key(home.as_bytes(), &locator, piece.index);
        return match shared.blobs.get(&key).await {
            Ok(Some(bytes)) => (200, false, bytes),
            Ok(None) => (404, true, json_body("not_found")),
            Err(error) => {
                log(format_args!("{error}"));
                (503, true, json_body("busy"))
            }
        };
    }
    if !rights.is_some_and(|rights| rights.store) {
        return (403, true, json_body("credential_refused"));
    }
    if piece.body.len() > crate::objects::PIECE_BYTES {
        return (413, true, json_body("too_large"));
    }
    let held = |held: u64| serde_json::to_vec(&json!({ "held": held })).unwrap_or_default();
    match store_piece(
        shared,
        space,
        locator,
        piece.index,
        piece.body.clone(),
        None,
    )
    .await
    {
        Ok(PieceOutcome::Stored(count)) => (201, true, held(count)),
        Ok(PieceOutcome::Identical(count)) => (200, true, held(count)),
        Err((code, status)) => (status, true, json_body(&code)),
    }
}

/// An object piece: here, or at the owner of its space in a cluster.
async fn piece(
    shared: &Arc<Shared>,
    put: bool,
    (space, locator, index): (EventId, [u8; 64], u64),
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Response {
    let Some(token) = token_of(headers) else {
        return reason(StatusCode::FORBIDDEN, "credential_refused");
    };
    let piece = crate::cluster::wire::Piece {
        put,
        epoch: 0,
        space: *space.as_bytes(),
        locator,
        index,
        token,
        body,
        check: false,
    };
    let (status, json, body) = match shared.cluster.get().cloned() {
        Some(cluster) => {
            let piece = crate::cluster::wire::Piece {
                epoch: cluster.epoch(),
                ..piece
            };
            cluster.piece(piece).await
        }
        None => piece_here(shared, &piece).await,
    };
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    let kind = if json {
        "application/json"
    } else {
        "application/octet-stream"
    };
    (status, [(header::CONTENT_TYPE, kind)], body).into_response()
}

/// `GET /frasil/p1/spaces/{space}/objects/{locator}/chunks/{index}`: the
/// fetch right.
async fn get_piece(
    State(shared): State<Arc<Shared>>,
    Path((space, locator, index)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(path) = object_path(&space, &locator, &index) else {
        return reason(StatusCode::BAD_REQUEST, "malformed");
    };
    piece(&shared, false, path, &headers, Vec::new()).await
}

/// `PUT /frasil/p1/spaces/{space}/objects/{locator}/chunks/{index}`: the
/// store right. The transfer token is checked before any of the body is
/// read: a request without one, or, at the node that keeps the space's
/// transfer tokens, with one that grants no store right in the space, is
/// refused `credential_refused` with its body unread (transport.md, 3.15
/// The server binding, "Objects over HTTP"). In a cluster the gateway
/// checks the token's form, and asks the space's owner, which keeps the
/// transfer tokens, to check its grant before the body is read; the owner
/// checks it again when the piece comes.
async fn put_piece(
    State(shared): State<Arc<Shared>>,
    Path((space, locator, index)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    let Some(path) = object_path(&space, &locator, &index) else {
        return reason(StatusCode::BAD_REQUEST, "malformed");
    };
    let Some(token) = token_of(&headers) else {
        return reason(StatusCode::FORBIDDEN, "credential_refused");
    };
    match shared.cluster.get().cloned() {
        None => {
            if !transfer(&shared, &token, &path.0).is_some_and(|rights| rights.store) {
                return reason(StatusCode::FORBIDDEN, "credential_refused");
            }
        }
        Some(cluster) => {
            let check = crate::cluster::wire::Piece {
                put: true,
                epoch: cluster.epoch(),
                space: *path.0.as_bytes(),
                locator: path.1,
                index: path.2,
                token,
                body: Vec::new(),
                check: true,
            };
            let (status, json, body) = cluster.piece(check).await;
            if status != 200 {
                let status =
                    StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
                let kind = if json {
                    "application/json"
                } else {
                    "application/octet-stream"
                };
                return (status, [(header::CONTENT_TYPE, kind)], body).into_response();
            }
        }
    }
    let Ok(body) = axum::body::to_bytes(body, crate::objects::PIECE_BYTES).await else {
        return reason(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
    };
    piece(&shared, true, path, &headers, body.to_vec()).await
}

// -- Mailboxes

fn mailbox_path(kind: &str, address: &str) -> Option<(Kind, [u8; 32])> {
    let kind = match kind {
        "1" => Kind::Exchange,
        "2" => Kind::Person,
        "3" => Kind::Device,
        "4" => Kind::Drop,
        _ => return None,
    };
    Some((kind, unhex::<32>(address)?))
}

/// `POST /frasil/p1/mailbox/{kind}/{address}`: anyone deposits one item.
/// With ext-deposit-tokens on, a deposit in a device mailbox that carries
/// `Authorization` pays with the token it names (ext-deposit-tokens.md,
/// 3.7 Redeeming); off, `Authorization` is not read.
async fn post_mailbox(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path((kind, address)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some((kind, address)) = mailbox_path(&kind, &address) else {
        return reason(StatusCode::NOT_FOUND, "not_found");
    };
    let now = shared.clock.now();
    let source = crate::source::of_request(&shared.settings.trusted_proxies, remote, &headers);
    if kind == Kind::Device
        && let Some(watch) = shared.watch.get()
    {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .filter(|_| shared.settings.extensions.deposit_tokens)
            .and_then(crate::testing::Watch::header_nonce);
        watch.posted(
            &source,
            address,
            token,
            headers.contains_key(header::COOKIE),
        );
    }
    if kind == Kind::Device
        && shared.settings.extensions.deposit_tokens
        && let Some(value) = headers.get(header::AUTHORIZATION)
    {
        let deposit = value
            .to_str()
            .map_err(|_| {
                frasil_deposit_tokens::TokenClass::from(frasil_base::ErrorClass::Malformed)
            })
            .and_then(|value| {
                frasil_deposit_tokens::TokenDeposit::read_post(address, body.to_vec(), value)
            });
        let answer = match deposit {
            Ok(deposit) => crate::cluster::route::token_put(&shared, deposit, &source, now).await,
            Err(class) => Err(crate::deposit::reason(class)),
        };
        return match answer {
            Ok(id) => (StatusCode::CREATED, axum::Json(json!({ "id": hex(&id) }))).into_response(),
            Err(refused) => refusal(refused),
        };
    }
    let answer =
        crate::cluster::route::mailbox_put(&shared, kind, &address, &body, &source, now).await;
    match answer {
        Ok(id) => (StatusCode::CREATED, axum::Json(json!({ "id": hex(&id) }))).into_response(),
        Err(refused) => refusal(refused),
    }
}

/// `GET /frasil/p1/mailbox/{kind}/{address}?after={id}`: an exchange
/// mailbox, by anyone who knows its address. A device mailbox is collected
/// only over the WebSocket.
async fn get_mailbox(
    State(shared): State<Arc<Shared>>,
    Path((kind, address)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some((kind, address)) = mailbox_path(&kind, &address) else {
        return reason(StatusCode::NOT_FOUND, "not_found");
    };
    if kind == Kind::Device {
        return reason(StatusCode::FORBIDDEN, "credential_refused");
    }
    let after = match query.get("after") {
        Some(after) => match unhex::<16>(after) {
            Some(after) => Some(after),
            None => return reason(StatusCode::BAD_REQUEST, "malformed"),
        },
        None => None,
    };
    let now = shared.clock.now();
    let answer =
        crate::cluster::route::mailbox_get(&shared, kind, &address, after, None, now).await;
    match answer {
        Ok(items) => {
            let items: Vec<serde_json::Value> = items
                .into_iter()
                .take(64)
                .map(|(id, item)| json!({ "id": hex(&id), "item": hex(&item) }))
                .collect();
            axum::Json(json!({ "items": items })).into_response()
        }
        Err(refused) => refusal(refused),
    }
}

#[cfg(test)]
mod connection_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_paths_are_lowercase_hex_and_decimal() {
        let space = "ab".repeat(32);
        let locator = "cd".repeat(64);
        assert!(object_path(&space, &locator, "3").is_some());
        assert!(object_path(&space, &locator, "03").is_none());
        assert!(object_path(&space, &locator, "x").is_none());
        assert!(object_path(&space.to_uppercase(), &locator, "3").is_none());
        assert!(object_path(&space, &locator[2..], "3").is_none());
    }

    /// Sends a request's head over a fresh TCP connection and nothing of
    /// its body; returns the status line the peer answers within five
    /// seconds, or `None`.
    pub(crate) async fn status_without_body(http: SocketAddr, head: &str) -> Option<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(http).await.ok()?;
        stream.write_all(head.as_bytes()).await.ok()?;
        let mut read = Vec::new();
        let answered = tokio::time::timeout(Duration::from_secs(5), async {
            let mut buffer = [0u8; 1024];
            while !read.windows(2).any(|w| w == b"\r\n") {
                let n = stream.read(&mut buffer).await.ok()?;
                if n == 0 {
                    return None;
                }
                read.extend_from_slice(&buffer[..n]);
            }
            Some(())
        })
        .await;
        answered.ok()??;
        let line = read.split(|&b| b == b'\r').next()?;
        Some(String::from_utf8_lossy(line).into_owned())
    }

    /// A chunk upload without a transfer token that grants the store right
    /// is refused before its body is read: the peer answers 403 to a
    /// request head whose body never comes.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_piece_is_refused_before_its_body_is_read() {
        let peer = crate::testing::spawn_with(crate::testing::Options {
            iroh: false,
            ..crate::testing::Options::default()
        })
        .await
        .unwrap();
        let path = format!(
            "/frasil/p1/spaces/{}/objects/{}/chunks/0",
            "ab".repeat(32),
            "cd".repeat(64)
        );
        let length = crate::objects::PIECE_BYTES;
        let without =
            format!("PUT {path} HTTP/1.1\r\nHost: peer\r\nContent-Length: {length}\r\n\r\n");
        let status = status_without_body(peer.http, &without).await;
        assert!(
            status.as_deref().is_some_and(|line| line.contains(" 403")),
            "{status:?}"
        );
        // A token the peer never granted.
        let forged = format!(
            "PUT {path} HTTP/1.1\r\nHost: peer\r\nAuthorization: Frasil-Transfer {}\r\n\
             Content-Length: {length}\r\n\r\n",
            "ee".repeat(32)
        );
        let status = status_without_body(peer.http, &forged).await;
        assert!(
            status.as_deref().is_some_and(|line| line.contains(" 403")),
            "{status:?}"
        );
        peer.shutdown().await;
    }

    /// In a cluster, a chunk upload whose transfer token no owner granted
    /// is refused by the space's owner before the gateway reads its body:
    /// at either node, whichever owns the space.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_piece_is_refused_in_a_cluster_before_its_body_is_read() {
        use crate::testing::cluster::{TIMING, TestCluster};
        let cluster = TestCluster::start(2, TIMING, 0x71)
            .await
            .expect("two nodes form a cluster");
        let path = format!(
            "/frasil/p1/spaces/{}/objects/{}/chunks/0",
            "ab".repeat(32),
            "cd".repeat(64)
        );
        let length = crate::objects::PIECE_BYTES;
        let forged = format!(
            "PUT {path} HTTP/1.1\r\nHost: peer\r\nAuthorization: Frasil-Transfer {}\r\n\
             Content-Length: {length}\r\n\r\n",
            "ee".repeat(32)
        );
        for n in 0..2 {
            let status = status_without_body(cluster.node(n).peer.http, &forged).await;
            assert!(
                status.as_deref().is_some_and(|line| line.contains(" 403")),
                "node {n}: {status:?}"
            );
        }
        cluster.shutdown().await;
    }

    #[test]
    fn a_websocket_message_is_read_in_its_class() {
        let hello = frasil_transport::peer::Hello::encode(
            &[7; 32],
            frasil_transport::peer::Purpose::SpaceTraffic,
        );
        assert_eq!(
            read(&hello, Extensions::NONE).unwrap().unwrap().kind,
            MessageType::Hello
        );
        let pairing = frasil_transport::messages::Pairing {
            message: vec![1],
            ticket: None,
        }
        .encode();
        assert!(read(&pairing, Extensions::NONE).is_err());
    }
}
