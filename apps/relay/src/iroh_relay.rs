//! iroh's relay server, embedded: devices use it as their iroh relay
//! (transport.md, "The iroh binding"). It forwards the QUIC packets of two
//! endpoints that have no direct path; the TLS session between them is end
//! to end, so it reads none of them.
//!
//! The relay runs beside the peer's HTTP listener, on a listener of its
//! own: iroh's relay service upgrades hyper's connections itself, and does
//! not mount on the peer's router. It serves plain HTTP for a reverse proxy
//! that terminates TLS, or HTTPS with a certificate and key of its own,
//! and then QUIC address discovery too, if it has a socket.

use crate::PeerError;
use crate::config::{IrohRelayConfig, RelayTls};
use iroh_relay::server::{CertConfig, QuicConfig, RelayConfig, Server, ServerConfig, TlsConfig};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;

/// A running relay.
#[derive(Debug)]
pub struct IrohRelay {
    server: Server,
    tls: bool,
}

impl IrohRelay {
    /// Starts the relay.
    ///
    /// # Errors
    ///
    /// A certificate or key that does not read, or a listener that does
    /// not bind.
    pub async fn spawn(config: &IrohRelayConfig) -> Result<Self, PeerError> {
        let mut relay = RelayConfig::new(config.listen);
        let mut quic = None;
        if let Some(tls) = &config.tls {
            relay.http_bind_addr = tls.http_listen;
            relay.tls = Some(TlsConfig::new(
                config.listen,
                CertConfig::Manual {
                    server_config: server_config(tls)?,
                },
            ));
            quic = config.quic.map(QuicConfig::new);
        }
        let mut server_config = ServerConfig::default();
        server_config.relay = Some(relay);
        server_config.quic = quic;
        let server = Server::spawn(server_config)
            .await
            .map_err(|e| PeerError(format!("iroh relay: {e}")))?;
        Ok(Self {
            server,
            tls: config.tls.is_some(),
        })
    }

    /// The relay's listener: HTTPS with a certificate, HTTP without.
    pub fn addr(&self) -> SocketAddr {
        let addr = if self.tls {
            self.server.https_addr()
        } else {
            self.server.http_addr()
        };
        addr.expect("the relay listens")
    }

    /// The relay's URL at its own listener, such as `http://127.0.0.1:3340`.
    /// Behind a reverse proxy, devices name the proxy's URL instead.
    pub fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{}", self.addr())
    }

    /// QUIC address discovery's socket, if it runs.
    pub fn quic_addr(&self) -> Option<SocketAddr> {
        self.server.quic_addr()
    }

    /// Stops the relay.
    pub async fn shutdown(self) {
        if let Err(error) = self.server.shutdown().await {
            crate::util::log(format_args!("the iroh relay stopped: {error}"));
        }
    }
}

/// A TLS server configuration from PEM files, with ring, TLS 1.2 and 1.3.
fn server_config(tls: &RelayTls) -> Result<rustls::ServerConfig, PeerError> {
    let read = |what: &str, path: &std::path::Path, error: &dyn core::fmt::Display| {
        PeerError(format!("iroh relay {what} {}: {error}", path.display()))
    };
    let certs = CertificateDer::pem_file_iter(&tls.cert)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| read("certificate", &tls.cert, &e))?;
    if certs.is_empty() {
        return Err(read("certificate", &tls.cert, &"no certificate"));
    }
    let key = PrivateKeyDer::from_pem_file(&tls.key).map_err(|e| read("key", &tls.key, &e))?;
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .and_then(|builder| builder.with_no_client_auth().with_single_cert(certs, key))
        .map_err(|e| PeerError(format!("iroh relay TLS: {e}")))
}
