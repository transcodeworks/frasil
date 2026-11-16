//! What the peer's connections may hold together, and how long it waits on
//! one: the operator's [`ConnectionLimits`](crate::config::ConnectionLimits).
//!
//! [`Connections`] counts the connections open, overall and per source, and
//! admits a new one only below both caps: TCP connections to the HTTP
//! listener, WebSockets among them, and device-to-peer connections on the
//! iroh binding. [`Listener`] is the HTTP listener: past a cap it answers
//! 503 `busy` and closes, and each connection it accepts is a [`Guarded`]
//! stream, closed if its first request's head does not arrive within
//! `header_read_timeout`, or if nothing is read or written on it for
//! `idle_timeout`, or three keep-alive intervals if that is longer. A
//! WebSocket keeps itself busy with the keep-alive the server binding sends
//! (crate `server`).

use crate::util::log;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, Sleep};

/// The connections open, overall and per source.
#[derive(Debug)]
pub(crate) struct Connections {
    max: usize,
    per_source: usize,
    held: Mutex<Counts>,
}

#[derive(Debug, Default)]
struct Counts {
    total: usize,
    by_source: HashMap<String, usize>,
}

impl Connections {
    /// At most `max` connections, and `per_source` from one source; 0 sets
    /// no limit per source.
    pub(crate) fn new(max: usize, per_source: usize) -> Arc<Self> {
        Arc::new(Self {
            max,
            per_source,
            held: Mutex::new(Counts::default()),
        })
    }

    /// Counts a new connection from `source`, if both caps have room: it is
    /// counted until the permit drops. A connection with no source (crate
    /// `source`, [`crate::source::NONE`]) counts toward the overall cap
    /// alone.
    pub(crate) fn admit(self: &Arc<Self>, source: &str) -> Option<Permit> {
        self.count(source, true)
    }

    /// Counts a connection a trusted proxy forwards for the client
    /// `source`, if the cap per source has room: the proxy's own TCP
    /// connection counts toward the overall cap, with no source, and this
    /// permit toward the client's.
    pub(crate) fn admit_forwarded(self: &Arc<Self>, source: &str) -> Option<Permit> {
        self.count(source, false)
    }

    fn count(self: &Arc<Self>, source: &str, total: bool) -> Option<Permit> {
        let mut held = crate::state::lock(&self.held);
        let sourced = source != crate::source::NONE;
        let from = held.by_source.get(source).copied().unwrap_or(0);
        if (total && held.total >= self.max)
            || (sourced && self.per_source > 0 && from >= self.per_source)
        {
            return None;
        }
        if total {
            held.total += 1;
        }
        if sourced {
            held.by_source.insert(source.to_owned(), from + 1);
        }
        Some(Permit {
            connections: self.clone(),
            source: source.to_owned(),
            total,
        })
    }

    /// How many connections are open.
    #[cfg(test)]
    pub(crate) fn open(&self) -> usize {
        crate::state::lock(&self.held).total
    }
}

/// A connection counted open, until it drops.
#[derive(Debug)]
pub(crate) struct Permit {
    connections: Arc<Connections>,
    source: String,
    /// Whether it counts toward the overall cap.
    total: bool,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut held = crate::state::lock(&self.connections.held);
        if self.total {
            held.total = held.total.saturating_sub(1);
        }
        if self.source == crate::source::NONE {
            return;
        }
        if let Some(from) = held.by_source.get_mut(&self.source) {
            *from = from.saturating_sub(1);
            if *from == 0 {
                held.by_source.remove(&self.source);
            }
        }
    }
}

/// What ends a request's head.
const HEAD_END: &[u8; 4] = b"\r\n\r\n";

/// An accepted HTTP connection, counted open while it lasts. It fails with
/// `TimedOut` once its first request's head has not arrived by its
/// deadline, or once it has been read from and written to nothing for its
/// idle time while the server waits on it.
#[derive(Debug)]
pub(crate) struct Guarded {
    stream: TcpStream,
    /// Until the first request's head has been read: its deadline, and how
    /// many bytes of [`HEAD_END`] the bytes read so far end with.
    head: Option<(Pin<Box<Sleep>>, usize)>,
    idle: Duration,
    quiet: Pin<Box<Sleep>>,
    _permit: Permit,
}

impl Guarded {
    fn new(stream: TcpStream, permit: Permit, head: Duration, idle: Duration) -> Self {
        let now = Instant::now();
        Self {
            stream,
            head: Some((Box::pin(tokio::time::sleep_until(now + head)), 0)),
            idle,
            quiet: Box::pin(tokio::time::sleep_until(now + idle)),
            _permit: permit,
        }
    }

    /// Something was read or written: the idle time starts again.
    fn progress(&mut self) {
        let until = Instant::now() + self.idle;
        self.quiet.as_mut().reset(until);
    }

    /// Notes bytes read, until they end the first request's head.
    fn scan(&mut self, read: &[u8]) {
        let Some((_, matched)) = &mut self.head else {
            return;
        };
        for &byte in read {
            if byte == HEAD_END[*matched] {
                *matched += 1;
                if *matched == HEAD_END.len() {
                    self.head = None;
                    return;
                }
            } else {
                *matched = usize::from(byte == HEAD_END[0]);
            }
        }
    }

    /// Whether a deadline passed while the server waits on the connection.
    fn expired(&mut self, cx: &mut Context<'_>) -> Option<io::Error> {
        if let Some((deadline, _)) = &mut self.head
            && deadline.as_mut().poll(cx).is_ready()
        {
            return Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "no request head within header_read_timeout",
            ));
        }
        self.quiet.as_mut().poll(cx).is_ready().then(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "nothing read or written within idle_timeout",
            )
        })
    }
}

impl AsyncRead for Guarded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let before = buf.filled().len();
        match Pin::new(&mut this.stream).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    this.progress();
                    this.scan(&buf.filled()[before..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => match this.expired(cx) {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Pending,
            },
        }
    }
}

impl AsyncWrite for Guarded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.stream).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    this.progress();
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => match this.expired(cx) {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Pending,
            },
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// The HTTP listener: TCP connections, admitted under the caps.
#[derive(Debug)]
pub(crate) struct Listener {
    listener: TcpListener,
    connections: Arc<Connections>,
    /// A connection from one of them counts toward the overall cap alone:
    /// its WebSockets count toward their clients' caps (crate `server`).
    proxies: crate::source::TrustedProxies,
    head: Duration,
    idle: Duration,
}

impl Listener {
    pub(crate) fn new(
        listener: TcpListener,
        connections: Arc<Connections>,
        limits: &crate::config::ConnectionLimits,
        proxies: crate::source::TrustedProxies,
    ) -> Self {
        Self {
            listener,
            connections,
            proxies,
            head: Duration::from_secs(limits.header_read_timeout),
            // Never shorter than the keep-alive's three intervals, so that a
            // quiet WebSocket is judged by its keep-alive (crate `server`).
            idle: Duration::from_secs(
                limits
                    .idle_timeout
                    .max(limits.keepalive_interval.saturating_mul(3)),
            ),
        }
    }
}

/// What a connection past a cap is answered before it closes: 503 `busy`
/// (transport.md, 2.5 Codes).
const BUSY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
Content-Type: application/json\r\n\
Access-Control-Allow-Origin: *\r\n\
Content-Length: 15\r\n\
Connection: close\r\n\r\n\
{\"code\":\"busy\"}";

impl axum::serve::Listener for Listener {
    type Io = Guarded;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Guarded, SocketAddr) {
        loop {
            let (stream, remote) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    // Out of descriptors, or a connection reset before it
                    // was taken: wait a moment rather than spin.
                    log(format_args!("an HTTP connection was not accepted: {error}"));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            // A trusted proxy carries many clients: their sources are known
            // only from each request's head.
            let source = if self.proxies.contains(remote.ip()) {
                crate::source::NONE.to_owned()
            } else {
                remote.ip().to_canonical().to_string()
            };
            match self.connections.admit(&source) {
                Some(permit) => {
                    return (Guarded::new(stream, permit, self.head, self.idle), remote);
                }
                None => {
                    // Best effort, never waited on: the socket is new, so
                    // its buffer has room for so short an answer.
                    let _ = stream.try_write(BUSY);
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connections_are_capped_overall_and_per_source() {
        let connections = Connections::new(3, 2);
        let a1 = connections.admit("a").unwrap();
        let _a2 = connections.admit("a").unwrap();
        assert!(connections.admit("a").is_none(), "per source");
        let _b1 = connections.admit("b").unwrap();
        assert!(connections.admit("c").is_none(), "overall");
        drop(a1);
        assert_eq!(connections.open(), 2);
        assert!(connections.admit("c").is_some());
        let unlimited = Connections::new(4, 0);
        let held: Vec<Permit> = (0..4).filter_map(|_| unlimited.admit("a")).collect();
        assert_eq!(held.len(), 4);
    }

    /// A proxy's connections count overall only; each client it forwards
    /// counts toward its own cap; a connection with no source counts
    /// overall only.
    #[test]
    fn a_forwarded_client_counts_toward_its_own_cap() {
        let connections = Connections::new(4, 1);
        let proxy_a = connections.admit(crate::source::NONE).unwrap();
        let _proxy_b = connections.admit(crate::source::NONE).unwrap();
        let client = connections.admit_forwarded("198.51.100.4").unwrap();
        assert!(connections.admit_forwarded("198.51.100.4").is_none());
        assert!(connections.admit("198.51.100.4").is_none(), "one source");
        let _other = connections.admit_forwarded("198.51.100.5").unwrap();
        assert_eq!(
            connections.open(),
            2,
            "forwarded permits count no TCP connection"
        );
        drop(client);
        assert!(connections.admit_forwarded("198.51.100.4").is_some());
        drop(proxy_a);
        assert_eq!(connections.open(), 1);
    }
}
