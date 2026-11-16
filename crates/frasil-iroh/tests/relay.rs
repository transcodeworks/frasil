//! A connection through an iroh relay, run locally on loopback with a
//! self-signed certificate. iroh's relay forwards QUIC packets it cannot
//! read: the TLS session is end to end, so both ends still compute the
//! same exporter and complete the member handshake's binding. Contrast a
//! relay that splices two sessions (tests/member.rs).

mod common;

use common::*;
use frasil_iroh::{Alpn, Config, Endpoint, fresh_secret_key};
use iroh_relay::server::{CertConfig, Server, testing};

#[tokio::test]
async fn a_relayed_connection_keeps_one_tls_session_end_to_end() {
    // The test configuration's relay, on loopback, under a self-signed
    // certificate the endpoints take as their only root, and with no QUIC
    // address discovery.
    let (certs, server_config) = testing::self_signed_tls_certs_and_config();
    let mut config = testing::server_config();
    config.quic = None;
    let tls = config.relay.as_mut().unwrap().tls.as_mut().unwrap();
    tls.cert = CertConfig::Manual { server_config };
    let server = Server::spawn(config).await.unwrap();
    let url = server.https_url().unwrap().to_string();

    let bind = |alpns: &[Alpn]| {
        Endpoint::bind(
            Config::new(fresh_secret_key().unwrap(), alpns)
                .loopback()
                .relays([url.clone()])
                .relay_roots(certs.clone()),
        )
    };
    let dialer = bind(&[]).await.unwrap();
    let listener = bind(&[Alpn::Member]).await.unwrap();
    let key = listener.key();
    let relays = [url.clone()];
    // The dialer names the key and the relay alone, no direct address.
    let (dialed, accepted) = within(async {
        tokio::join!(dialer.connect(&key, &[], &relays, Alpn::Member), async {
            listener.accept().await.unwrap()
        },)
    })
    .await;
    let (dialed, accepted) = (dialed.unwrap(), accepted.unwrap());
    assert_eq!(dialed.peer(), listener.key());
    assert_eq!(accepted.peer(), dialer.key());
    assert_eq!(dialed.channel(), accepted.channel());

    // A ticket names the relay.
    let ticket = listener.ticket(frasil_transport::ticket::TicketKind::Member);
    assert_eq!(ticket.relays.len(), 1);
    assert_eq!(ticket.endpoint, listener.key());

    dialer.close().await;
    listener.close().await;
    server.shutdown().await.unwrap();
}
