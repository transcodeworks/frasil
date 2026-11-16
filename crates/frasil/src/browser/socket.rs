//! The server binding over the browser's `WebSocket` and `fetch`
//! (transport.md, section 3.15, "The connection", "Objects over HTTP" and
//! "A client's HTTP transport").
//!
//! [`open`] opens the connect route with subprotocol `frasil.p1` and closes
//! a WebSocket whose peer does not echo it. The [`BrowserSocket`] it gives
//! is `frasil`'s [`ServerSocket`]:
//!
//! - binary messages in and out, one message each; a text message closes
//!   the connection with 1003; a message larger than the transport's frame
//!   limit, or one that would take the messages waiting to be read past
//!   [`INBOX_MESSAGES`] or [`INBOX_BYTES`], closes it with 4000 plus
//!   `too_large`'s code;
//! - a frame is written only while `bufferedAmount` holds less than 64 KiB;
//! - the device closes with 4000 plus `done`'s code; when the peer closes
//!   with 4017, `reconnect`, the connection opens the same route again
//!   (transport.md, "Reconnecting elsewhere");
//! - object requests through `fetch` with `redirect: "manual"`, so no
//!   redirect is followed: one arrives as a status the client refuses;
//!   no request is retried;
//! - tasks on the browser's microtask queue, timers on `setTimeout`.
//!
//! [`BrowserTasks`] and [`BrowserConnect`] hand the same tasks, timers and
//! sockets to a [`Device`](crate::Device), which a device in a browser
//! takes by default: its upkeep runs on the browser's event loop, and
//! [`Device::connect`](crate::Device::connect) opens a socket here.

use super::message_of;
use crate::client::peers::Connect;
use crate::device::Engine;
use crate::peer::PeerHandle;
use crate::peer::socket::{ServerSocket, administer_socket, connect_socket};
use crate::tasks::Tasks;
use frasil_events::EventId;
use frasil_store::BoxFuture;
use js_sys::{ArrayBuffer, Function, Promise, Uint8Array};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Poll, Waker};
use std::time::Duration;
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{BinaryType, CloseEvent, MessageEvent, WebSocket};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = setTimeout)]
    fn set_timeout(handler: &Function, milliseconds: f64) -> JsValue;

    #[wasm_bindgen(js_name = fetch)]
    fn global_fetch(request: &web_sys::Request) -> Promise;
}

/// The subprotocol of the connect route.
const SUBPROTOCOL: &str = "frasil.p1";

/// A sync frame waits while the socket's buffer holds this much.
const BUFFERED_LIMIT: u32 = 64 * 1024;

/// How often a waiting frame looks at the buffer again.
const BUFFER_POLL: Duration = Duration::from_millis(5);

/// The most messages received and not yet read that a socket keeps: the
/// browser hands every message over as it arrives, so the bound is here.
pub const INBOX_MESSAGES: usize = 32_768;

/// The most bytes of messages received and not yet read that a socket
/// keeps: 128 of the transport's largest frames.
pub const INBOX_BYTES: usize = 128 * frasil_transport::frame::MAX_FRAME_BYTES;

/// A future ready after `duration`, on the browser's `setTimeout`.
pub fn sleep(duration: Duration) -> BoxFuture<'static, ()> {
    let milliseconds = duration.as_secs_f64() * 1000.0;
    let promise = Promise::new(&mut |resolve, _reject| {
        let _ = set_timeout(&resolve, milliseconds);
    });
    Box::pin(async move {
        let _ = JsFuture::from(promise).await;
    })
}

/// What the WebSocket's handlers leave for the connection.
#[derive(Default)]
struct Inbox {
    open: bool,
    messages: VecDeque<Vec<u8>>,
    /// The bytes of `messages`.
    bytes: usize,
    ended: Option<String>,
    /// The peer's close code, once it closed the socket.
    code: Option<u16>,
    waker: Option<Waker>,
}

impl Inbox {
    fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    fn end(&mut self, why: String) {
        if self.ended.is_none() {
            self.ended = Some(why);
        }
        self.wake();
    }

    /// Takes a binary message of `length` bytes, unless it is larger than
    /// a frame may be or would take the waiting messages past their
    /// bound: `false` then, and the socket is to be closed.
    fn admits(&self, length: usize) -> bool {
        length <= frasil_transport::frame::MAX_FRAME_BYTES
            && self.messages.len() < INBOX_MESSAGES
            && self.bytes.saturating_add(length) <= INBOX_BYTES
    }

    fn push(&mut self, message: Vec<u8>) {
        self.bytes = self.bytes.saturating_add(message.len());
        self.messages.push_back(message);
    }

    fn pop(&mut self) -> Option<Vec<u8>> {
        let message = self.messages.pop_front()?;
        self.bytes = self.bytes.saturating_sub(message.len());
        Some(message)
    }
}

/// The handlers the WebSocket calls, kept alive as long as the socket.
struct Handlers {
    _open: Closure<dyn FnMut()>,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _close: Closure<dyn FnMut(CloseEvent)>,
    _error: Closure<dyn FnMut()>,
}

/// One connection's WebSocket and `fetch`.
pub struct BrowserSocket {
    socket: WebSocket,
    /// The connect route it opened, to open again.
    url: String,
    inbox: Rc<RefCell<Inbox>>,
    _handlers: Handlers,
}

impl Drop for BrowserSocket {
    fn drop(&mut self) {
        self.socket.set_onopen(None);
        self.socket.set_onmessage(None);
        self.socket.set_onclose(None);
        self.socket.set_onerror(None);
        let _ = self.socket.close_with_code(close_code());
    }
}

/// The device's close: 4000 plus `done`'s code (transport.md, section
/// 2.5).
fn close_code() -> u16 {
    coded(frasil_transport::Code::Done)
}

/// 4000 plus a code of transport.md, section 2.5.
fn coded(code: frasil_transport::Code) -> u16 {
    let number = u16::try_from(code.number()).unwrap_or(0);
    4000_u16.saturating_add(number)
}

/// Opens the connect route `url` (from
/// [`connect_url`](crate::advanced::peer::connect_url)) and waits until it
/// is open.
///
/// # Errors
///
/// Why it did not open, or that the peer did not echo `frasil.p1`.
pub async fn open(url: &str) -> Result<BrowserSocket, String> {
    let socket = WebSocket::new_with_str(url, SUBPROTOCOL).map_err(|e| message_of(&e))?;
    socket.set_binary_type(BinaryType::Arraybuffer);
    let inbox = Rc::new(RefCell::new(Inbox::default()));

    let opened = inbox.clone();
    let on_open = Closure::<dyn FnMut()>::new(move || {
        if let Ok(mut inbox) = opened.try_borrow_mut() {
            inbox.open = true;
            inbox.wake();
        }
    });
    let received = inbox.clone();
    let texts = socket.clone();
    let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
        let Ok(mut inbox) = received.try_borrow_mut() else {
            return;
        };
        if inbox.ended.is_some() {
            return;
        }
        match event.data().dyn_into::<ArrayBuffer>() {
            Ok(buffer) => {
                // The length is checked before the message is copied.
                let length = usize::try_from(buffer.byte_length()).unwrap_or(usize::MAX);
                if !inbox.admits(length) {
                    let _ = texts.close_with_code(coded(frasil_transport::Code::TooLarge));
                    inbox.end("a message over the inbox's bound".into());
                    return;
                }
                inbox.push(Uint8Array::new(&buffer).to_vec());
                inbox.wake();
            }
            Err(_) => {
                let _ = texts.close_with_code(1003);
                inbox.end("a text message".into());
            }
        }
    });
    let closed = inbox.clone();
    let on_close = Closure::<dyn FnMut(CloseEvent)>::new(move |event: CloseEvent| {
        if let Ok(mut inbox) = closed.try_borrow_mut() {
            if inbox.ended.is_none() {
                inbox.code = Some(event.code());
            }
            inbox.end(format!("closed by the peer: {}", event.code()));
        }
    });
    let failed = inbox.clone();
    let on_error = Closure::<dyn FnMut()>::new(move || {
        if let Ok(mut inbox) = failed.try_borrow_mut() {
            inbox.end("the WebSocket failed".into());
        }
    });
    socket.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));
    socket.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    let opened = BrowserSocket {
        socket,
        url: url.to_owned(),
        inbox,
        _handlers: Handlers {
            _open: on_open,
            _message: on_message,
            _close: on_close,
            _error: on_error,
        },
    };

    let waiting = opened.inbox.clone();
    poll_fn(|context| {
        let Ok(mut inbox) = waiting.try_borrow_mut() else {
            return Poll::Ready(Err("the socket is busy".to_owned()));
        };
        if inbox.open {
            return Poll::Ready(Ok(()));
        }
        if let Some(why) = &inbox.ended {
            return Poll::Ready(Err(why.clone()));
        }
        inbox.waker = Some(context.waker().clone());
        Poll::Pending
    })
    .await?;
    if opened.socket.protocol() != SUBPROTOCOL {
        opened.close();
        return Err("the peer did not echo the subprotocol".into());
    }
    Ok(opened)
}

impl BrowserSocket {
    fn ended(&self) -> Option<String> {
        self.inbox
            .try_borrow()
            .ok()
            .and_then(|inbox| inbox.ended.clone())
    }
}

/// The body of a response, or nothing for a response that has none.
async fn body_of(response: &web_sys::Response) -> Result<Vec<u8>, String> {
    let promise = response.array_buffer().map_err(|e| message_of(&e))?;
    let buffer = JsFuture::from(promise).await.map_err(|e| message_of(&e))?;
    Ok(Uint8Array::new(&buffer).to_vec())
}

impl ServerSocket for BrowserSocket {
    fn send<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            while self.socket.buffered_amount() >= BUFFERED_LIMIT {
                if let Some(why) = self.ended() {
                    return Err(why);
                }
                sleep(BUFFER_POLL).await;
            }
            if let Some(why) = self.ended() {
                return Err(why);
            }
            self.socket
                .send_with_u8_array(message)
                .map_err(|e| message_of(&e))
        })
    }

    fn receive(&self) -> BoxFuture<'_, Result<Vec<u8>, String>> {
        Box::pin(poll_fn(move |context| {
            let Ok(mut inbox) = self.inbox.try_borrow_mut() else {
                return Poll::Ready(Err("the socket is busy".to_owned()));
            };
            if let Some(message) = inbox.pop() {
                return Poll::Ready(Ok(message));
            }
            if let Some(why) = &inbox.ended {
                return Poll::Ready(Err(why.clone()));
            }
            inbox.waker = Some(context.waker().clone());
            Poll::Pending
        }))
    }

    fn close(&self) {
        let _ = self.socket.close_with_code(close_code());
        if let Ok(mut inbox) = self.inbox.try_borrow_mut() {
            inbox.end("closed by the device".into());
        }
    }

    fn request<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        authorization: &'a str,
        body: Option<&'a [u8]>,
    ) -> BoxFuture<'a, Result<(u16, Vec<u8>), String>> {
        Box::pin(async move {
            let headers = web_sys::Headers::new().map_err(|e| message_of(&e))?;
            headers
                .set("Authorization", authorization)
                .map_err(|e| message_of(&e))?;
            let init = web_sys::RequestInit::new();
            init.set_method(method);
            init.set_redirect(web_sys::RequestRedirect::Manual);
            if let Some(body) = body {
                headers
                    .set("Content-Type", "application/octet-stream")
                    .map_err(|e| message_of(&e))?;
                init.set_body(&Uint8Array::from(body));
            }
            init.set_headers(&headers);
            let request =
                web_sys::Request::new_with_str_and_init(url, &init).map_err(|e| message_of(&e))?;
            let response = JsFuture::from(global_fetch(&request))
                .await
                .map_err(|e| message_of(&e))?
                .dyn_into::<web_sys::Response>()
                .map_err(|_| "fetch answered something other than a Response".to_owned())?;
            let body = body_of(&response).await?;
            Ok((response.status(), body))
        })
    }

    fn spawn(&self, task: BoxFuture<'static, ()>) {
        wasm_bindgen_futures::spawn_local(task);
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        sleep(duration)
    }

    fn close_code(&self) -> Option<u16> {
        self.inbox.try_borrow().ok().and_then(|inbox| inbox.code)
    }

    fn reopen(&self) -> Option<BoxFuture<'static, Result<Arc<dyn ServerSocket>, String>>> {
        let url = self.url.clone();
        Some(Box::pin(async move {
            let socket = open(&url).await?;
            #[allow(clippy::arc_with_non_send_sync)]
            let socket: Arc<dyn ServerSocket> = Arc::new(socket);
            Ok(socket)
        }))
    }
}

/// A device's background work on the browser's event loop.
#[derive(Debug, Clone, Copy, Default)]
pub struct BrowserTasks;

impl Tasks for BrowserTasks {
    fn spawn(&self, task: BoxFuture<'static, ()>) {
        wasm_bindgen_futures::spawn_local(task);
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        sleep(duration)
    }
}

/// A device's connections to peers, over the browser's `WebSocket` and
/// `fetch`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BrowserConnect;

impl Connect for BrowserConnect {
    fn connect(
        &self,
        engine: Engine,
        url: String,
        spaces: Vec<EventId>,
    ) -> BoxFuture<'static, crate::Result<PeerHandle>> {
        Box::pin(async move {
            let route = crate::peer::connect_url(&url)?;
            let socket = open(&route).await.map_err(crate::Error::Connection)?;
            // A browser runs this module on one thread: the Arc only
            // satisfies the connection's types.
            #[allow(clippy::arc_with_non_send_sync)]
            let socket: Arc<dyn ServerSocket> = Arc::new(socket);
            connect_socket(&engine, &url, socket, spaces).await
        })
    }

    fn administer(
        &self,
        engine: Engine,
        url: String,
        space: EventId,
    ) -> BoxFuture<'static, crate::Result<bool>> {
        Box::pin(async move {
            let route = crate::peer::connect_url(&url)?;
            let socket = open(&route).await.map_err(crate::Error::Connection)?;
            #[allow(clippy::arc_with_non_send_sync)]
            let socket: Arc<dyn ServerSocket> = Arc::new(socket);
            administer_socket(&engine, &url, socket, space).await
        })
    }

    fn bare(
        &self,
        engine: Engine,
        url: String,
    ) -> BoxFuture<'static, crate::Result<crate::peer::Bare>> {
        Box::pin(async move {
            let route = crate::peer::connect_url(&url)?;
            let socket = open(&route).await.map_err(crate::Error::Connection)?;
            #[allow(clippy::arc_with_non_send_sync)]
            let socket: Arc<dyn ServerSocket> = Arc::new(socket);
            crate::peer::socket::bare_socket(&engine, &url, socket).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{INBOX_BYTES, INBOX_MESSAGES, Inbox};
    use frasil_transport::frame::MAX_FRAME_BYTES;
    use wasm_bindgen_test::wasm_bindgen_test;

    /// A message larger than the transport's frame limit is refused before
    /// it is copied, as is one past the bound of messages waiting.
    #[wasm_bindgen_test]
    fn the_inbox_keeps_to_its_bounds() {
        let mut inbox = Inbox::default();
        assert!(inbox.admits(MAX_FRAME_BYTES));
        assert!(!inbox.admits(MAX_FRAME_BYTES + 1));
        assert!(!inbox.admits(usize::MAX));
        // Bytes: the waiting messages stay within INBOX_BYTES.
        while inbox.admits(MAX_FRAME_BYTES) {
            inbox.push(vec![0; MAX_FRAME_BYTES]);
        }
        assert!(inbox.bytes <= INBOX_BYTES);
        assert_eq!(inbox.messages.len(), INBOX_BYTES / MAX_FRAME_BYTES);
        // Reading one makes room again.
        assert!(inbox.pop().is_some());
        assert!(inbox.admits(MAX_FRAME_BYTES));
        // Count: as many empty messages as the bound, then no more.
        let mut inbox = Inbox::default();
        for _ in 0..INBOX_MESSAGES {
            assert!(inbox.admits(0));
            inbox.push(Vec::new());
        }
        assert!(!inbox.admits(0));
    }
}
