//! A proxy on loopback in front of a peer, which answers the HTTP chunk
//! routes itself (transport.md, "Objects over HTTP") and can cut, corrupt
//! or hold back a slice, and says which slices were asked for.

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// What the proxy does to the chunk routes, and what it saw of them.
#[derive(Default)]
pub struct Faults {
    /// Each chunk request's locator, in hex, and slice index, in order.
    pub asked: Mutex<Vec<(String, u64)>>,
    /// Chunk requests for this slice or a later one end the connection
    /// with no answer.
    pub cut_from: Mutex<Option<u64>>,
    /// Chunk requests for these slices end the connection with no answer.
    pub cut_only: Mutex<Vec<u64>>,
    /// This slice is served with its first byte flipped.
    pub corrupt: Mutex<Option<u64>>,
    /// This slice is served without its last byte.
    pub shorten: Mutex<Option<u64>>,
    /// Requests for these slices wait, once counted, until they are no
    /// longer held back.
    pub hold: Mutex<Vec<u64>>,
    /// How many requests the proxy cut.
    pub cut: AtomicUsize,
}

impl Faults {
    /// The slices asked for of one object, in order.
    pub fn asked(&self, locator: &[u8; 64]) -> Vec<u64> {
        let hex: String = locator.iter().map(|byte| format!("{byte:02x}")).collect();
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|(of, _)| *of == hex)
            .map(|(_, index)| *index)
            .collect()
    }

    /// The slices asked for of any object, in order.
    pub fn asked_of_any(&self) -> Vec<u64> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .map(|(_, index)| *index)
            .collect()
    }

    pub fn clear(&self) {
        self.asked.lock().unwrap().clear();
    }

    /// Holds back the requests for these slices, and no others.
    pub fn hold(&self, slices: &[u64]) {
        *self.hold.lock().unwrap() = slices.to_vec();
    }
}

/// A proxy on loopback in front of `upstream`: it answers chunk requests
/// (`GET …/chunks/{index}`) itself, fetching each from the peer, and
/// passes everything else, the WebSocket among it, through untouched.
pub async fn spawn_proxy(upstream: &str) -> (String, Arc<Faults>) {
    // ring, the only provider linked, for the proxy's own client.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let faults = Arc::new(Faults::default());
    let upstream = upstream.to_owned();
    let shared = faults.clone();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(serve(
                socket,
                upstream.clone(),
                client.clone(),
                shared.clone(),
            ));
        }
    });
    (origin, faults)
}

/// One connection to the proxy, request by request until one is not a
/// chunk request: from there on, bytes pass both ways as they are.
async fn serve(
    mut socket: TcpStream,
    upstream: String,
    client: reqwest::Client,
    faults: Arc<Faults>,
) {
    let mut buffer = Vec::new();
    loop {
        let end = loop {
            if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let mut piece = [0u8; 8192];
            match socket.read(&mut piece).await {
                Ok(0) | Err(_) => return,
                Ok(read) => buffer.extend_from_slice(&piece[..read]),
            }
        };
        let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
        let mut lines = head.split("\r\n");
        let request = lines.next().unwrap_or_default().to_owned();
        let mut words = request.split(' ');
        let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
        let slice = path
            .split_once("/objects/")
            .and_then(|(_, rest)| rest.split_once("/chunks/"))
            .and_then(|(locator, index)| Some((locator.to_owned(), index.parse::<u64>().ok()?)))
            .filter(|_| method == "GET");
        let Some((locator, index)) = slice else {
            let Ok(mut onward) = TcpStream::connect(upstream.trim_start_matches("http://")).await
            else {
                return;
            };
            if onward.write_all(&buffer).await.is_err() {
                return;
            }
            let _ = tokio::io::copy_bidirectional(&mut socket, &mut onward).await;
            return;
        };
        buffer.drain(..end);
        faults.asked.lock().unwrap().push((locator, index));
        if faults
            .cut_from
            .lock()
            .unwrap()
            .is_some_and(|from| index >= from)
            || faults.cut_only.lock().unwrap().contains(&index)
        {
            faults.cut.fetch_add(1, Ordering::SeqCst);
            return;
        }
        while faults.hold.lock().unwrap().contains(&index) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let authorization = lines
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.trim().to_owned())
            .unwrap_or_default();
        let Ok(response) = client
            .get(format!("{upstream}{path}"))
            .header("Authorization", authorization)
            .send()
            .await
        else {
            return;
        };
        let status = response.status().as_u16();
        let Ok(body) = response.bytes().await else {
            return;
        };
        let mut body = body.to_vec();
        if *faults.corrupt.lock().unwrap() == Some(index)
            && let Some(first) = body.first_mut()
        {
            *first ^= 1;
        }
        if *faults.shorten.lock().unwrap() == Some(index) {
            body.pop();
        }
        let answer = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        if socket.write_all(answer.as_bytes()).await.is_err()
            || socket.write_all(&body).await.is_err()
        {
            return;
        }
    }
}
