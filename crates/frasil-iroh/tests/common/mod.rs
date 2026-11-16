//! What the binding's tests share: transport.json, hex helpers, and
//! endpoints on loopback with no relay and no address lookup. Every wait
//! has a deadline, so a test never hangs.

#![allow(dead_code)]

use frasil_iroh::{Alpn, Config, Connection, Endpoint, fresh_secret_key};
use frasil_testkit::hex;
use serde_json::Value as Json;
use std::future::Future;
use std::time::Duration;

pub const FILE: &str = "transport.json";

/// The longest any step of a test waits.
pub const DEADLINE: Duration = Duration::from_secs(10);

pub fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

pub fn bytes(value: &Json) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex")).expect("hex")
}

pub fn array<const N: usize>(value: &Json) -> [u8; N] {
    hex::decode_array(value.as_str().expect("hex")).expect("hex")
}

pub fn text(value: &Json) -> &str {
    value.as_str().expect("text")
}

pub fn number(value: &Json) -> u64 {
    value.as_u64().expect("a number")
}

/// Runs a future within the test deadline.
pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the test deadline")
}

/// An endpoint on IPv4 loopback with a fresh key, accepting these ALPNs.
pub async fn endpoint(alpns: &[Alpn]) -> Endpoint {
    Endpoint::bind(Config::new(fresh_secret_key().unwrap(), alpns).loopback())
        .await
        .expect("an endpoint on loopback")
}

/// Dials `listener` from `dialer` with an ALPN, and accepts it: the
/// dialer's connection, then the listener's.
pub async fn connect(
    dialer: &Endpoint,
    listener: &Endpoint,
    alpn: Alpn,
) -> (Connection, Connection) {
    let addresses = listener.local_addresses();
    let key = listener.key();
    let (dialed, accepted) = within(async {
        tokio::join!(dialer.connect(&key, &addresses, &[], alpn), async {
            listener.accept().await.expect("an incoming connection")
        },)
    })
    .await;
    (dialed.expect("dialed"), accepted.expect("accepted"))
}

/// A fresh pair of loopback endpoints and one connection between them.
pub async fn pair(alpn: Alpn) -> (Endpoint, Endpoint, Connection, Connection) {
    let dialer = endpoint(&[]).await;
    let listener = endpoint(&[alpn]).await;
    let (d, l) = connect(&dialer, &listener, alpn).await;
    (dialer, listener, d, l)
}
