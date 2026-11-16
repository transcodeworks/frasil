//! An iroh endpoint for Frasil (transport.md, section 3.16): QUIC version 1
//! with TLS 1.3 and Ed25519 raw public keys, ring as the only TLS provider,
//! and no address lookup.
//!
//! | Endpoint | Key |
//! |---|---|
//! | a device's member endpoint | random; rotated at least every `endpoint_rotation` and whenever the device joins another network; never one of its own keys |
//! | a device's side of a device-to-peer connection | fresh per connection |
//! | a nearby endpoint | fresh per pairing session |
//! | an always-on peer | stable, published in its discovery document or tickets |
//!
//! A device MUST NOT publish an endpoint key under a public name, such as
//! iroh's DNS or pkarr discovery: an [`Endpoint`] never configures either.
//! It registers with the home relays its [`Config`] names, or that
//! [`Endpoint::add_relays`] adds later, and with none until one is named.
//! TLS session tickets are off, so every connection is a fresh TLS session.

use crate::connection::Connection;
use crate::{Alpn, Error, Role};
use frasil_transport::frame::Extensions;
use frasil_transport::ticket::{Address, Ticket, TicketKind};
use iroh::{EndpointAddr, RelayMode, RelayUrl, SecretKey, TransportAddr};
use rustls::pki_types::CertificateDer;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

/// The most relay URLs a ticket names.
pub const TICKET_RELAYS: usize = 4;
/// The most direct addresses a ticket names.
pub const TICKET_ADDRESSES: usize = 16;

/// 32 fresh random bytes for an endpoint's secret key: a member endpoint's
/// at each rotation, and a fresh one per device-to-peer connection and per
/// nearby pairing session.
///
/// # Errors
///
/// `Io` if the operating system has no randomness to give.
pub fn fresh_secret_key() -> Result<[u8; 32], Error> {
    frasil_crypto::random_bytes::<32>()
        .map(|bytes| *bytes)
        .map_err(Error::io)
}

/// What an endpoint binds with.
#[derive(Clone)]
pub struct Config {
    secret_key: [u8; 32],
    alpns: Vec<Alpn>,
    relays: Vec<String>,
    bind: Vec<SocketAddr>,
    relay_roots: Option<Vec<CertificateDer<'static>>>,
    relay_only: bool,
    extensions: Extensions,
}

impl core::fmt::Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("alpns", &self.alpns)
            .field("relays", &self.relays)
            .field("bind", &self.bind)
            .field("relay_only", &self.relay_only)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// An endpoint with this secret key, accepting these ALPNs; no relay,
    /// bound to every IPv4 and IPv6 interface on ports the system picks.
    /// An endpoint that only dials accepts no ALPN.
    pub fn new(secret_key: [u8; 32], alpns: &[Alpn]) -> Self {
        Self {
            secret_key,
            alpns: alpns.to_vec(),
            relays: Vec::new(),
            bind: Vec::new(),
            relay_roots: None,
            relay_only: false,
            extensions: Extensions::NONE,
        }
    }

    /// The only certificate authorities a relay's TLS certificate may
    /// chain to, in place of the WebPKI roots: for relays under a private
    /// authority.
    #[must_use]
    pub fn relay_roots(mut self, roots: impl IntoIterator<Item = CertificateDer<'static>>) -> Self {
        self.relay_roots = Some(roots.into_iter().collect());
        self
    }

    /// [`Config::relay_roots`], each certificate as its DER bytes.
    #[must_use]
    pub fn relay_root_ders(self, roots: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.relay_roots(roots.into_iter().map(CertificateDer::from))
    }

    /// The home relays to register with and dial through.
    #[must_use]
    pub fn relays(mut self, relays: impl IntoIterator<Item = String>) -> Self {
        self.relays = relays.into_iter().collect();
        self
    }

    /// The sockets to bind, in place of every interface: a persisted port,
    /// or loopback alone.
    #[must_use]
    pub fn bind(mut self, addresses: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.bind = addresses.into_iter().collect();
        self
    }

    /// No IP socket at all: every path goes through the relays, and the
    /// endpoint has no direct address. For tests of a relay.
    #[must_use]
    pub fn relay_only(mut self) -> Self {
        self.relay_only = true;
        self
    }

    /// Loopback alone, IPv4, on a port the system picks.
    #[must_use]
    pub fn loopback(self) -> Self {
        self.bind([SocketAddr::from((Ipv4Addr::LOCALHOST, 0))])
    }

    /// The same sockets, relays and relay roots under another key and
    /// ALPNs, each socket on a port the system picks: an endpoint beside
    /// this one, such as a pairing session's, that reaches what this one
    /// reaches.
    #[must_use]
    pub fn beside(&self, secret_key: [u8; 32], alpns: &[Alpn]) -> Self {
        let mut config = self.clone();
        config.secret_key = secret_key;
        config.alpns = alpns.to_vec();
        for address in &mut config.bind {
            address.set_port(0);
        }
        config
    }

    /// The extensions this end's receivers implement.
    #[must_use]
    pub fn extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = extensions;
        self
    }
}

/// A bound iroh endpoint.
#[derive(Debug, Clone)]
pub struct Endpoint {
    inner: iroh::Endpoint,
    key: [u8; 32],
    relays: Arc<Mutex<Vec<RelayUrl>>>,
    extensions: Extensions,
}

impl Endpoint {
    /// Binds an endpoint.
    ///
    /// # Errors
    ///
    /// `Io` for a relay URL that does not parse, or a socket that does not
    /// bind.
    pub async fn bind(config: Config) -> Result<Self, Error> {
        let secret = SecretKey::from_bytes(&config.secret_key);
        let key = *secret.public().as_bytes();
        let relays = config
            .relays
            .iter()
            .map(|url| url.parse::<RelayUrl>().map_err(Error::io))
            .collect::<Result<Vec<_>, _>>()?;
        let mut builder = iroh::endpoint::Builder::empty()
            .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .secret_key(secret)
            .alpns(config.alpns.iter().map(|a| a.bytes().to_vec()).collect())
            .max_tls_tickets(0);
        // A custom map even when empty, so that the relay transport exists
        // and relays added later take effect.
        builder = builder.relay_mode(RelayMode::custom(relays.iter().cloned()));
        if let Some(roots) = config.relay_roots {
            builder = builder.ca_tls_config(iroh::tls::CaTlsConfig::custom_roots(roots));
        }
        if config.relay_only {
            builder = builder.clear_ip_transports();
        } else if !config.bind.is_empty() {
            builder = builder.clear_ip_transports();
            for address in config.bind {
                builder = builder.bind_addr(address).map_err(Error::io)?;
            }
        }
        let inner = builder.bind().await.map_err(Error::io)?;
        Ok(Self {
            inner,
            key,
            relays: Arc::new(Mutex::new(relays)),
            extensions: config.extensions,
        })
    }

    /// Registers with further home relays, HTTPS URLs, up to the four a
    /// ticket holds in all; a relay already named is skipped. Tickets made
    /// afterwards name them.
    ///
    /// # Errors
    ///
    /// `Io` for a relay URL that does not parse; none is added then.
    pub async fn add_relays(&self, relays: &[String]) -> Result<(), Error> {
        let parsed = relays
            .iter()
            .map(|url| url.parse::<RelayUrl>().map_err(Error::io))
            .collect::<Result<Vec<_>, _>>()?;
        let added: Vec<RelayUrl> = {
            let mut own = self.relays.lock().unwrap_or_else(PoisonError::into_inner);
            let mut added = Vec::new();
            for url in parsed {
                if own.len() < TICKET_RELAYS && !own.contains(&url) {
                    own.push(url.clone());
                    added.push(url);
                }
            }
            added
        };
        for url in added {
            let config = Arc::new(iroh::RelayConfig::from(url.clone()));
            self.inner.insert_relay(url, config).await;
        }
        Ok(())
    }

    /// The home relays the endpoint registers with.
    pub fn relays(&self) -> Vec<String> {
        self.relays
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// The endpoint key.
    pub fn key(&self) -> [u8; 32] {
        self.key
    }

    /// The sockets the endpoint is bound to.
    pub fn local_addresses(&self) -> Vec<SocketAddr> {
        self.inner.bound_sockets()
    }

    /// The endpoint's direct addresses as others dial them: what iroh
    /// knows of its interfaces, or the bound sockets that name one.
    pub fn direct_addresses(&self) -> Vec<SocketAddr> {
        let mut addresses: Vec<SocketAddr> = self.inner.addr().ip_addrs().copied().collect();
        if addresses.is_empty() {
            addresses = self
                .local_addresses()
                .into_iter()
                .filter(|a| !a.ip().is_unspecified())
                .collect();
        }
        addresses
    }

    /// A ticket that dials this endpoint (transport.md, section 2.8): its
    /// key, its home relays and its direct addresses, as many as a ticket
    /// holds.
    pub fn ticket(&self, kind: TicketKind) -> Ticket {
        Ticket {
            kind,
            endpoint: self.key,
            relays: self.relays().into_iter().take(TICKET_RELAYS).collect(),
            addresses: self
                .direct_addresses()
                .into_iter()
                .take(TICKET_ADDRESSES)
                .map(|address| match address.ip() {
                    IpAddr::V4(ip) => Address::V4(ip.octets(), address.port()),
                    IpAddr::V6(ip) => Address::V6(ip.octets(), address.port()),
                })
                .collect(),
        }
    }

    /// Dials an endpoint key at these direct addresses and relays, with an
    /// ALPN. The connection fails unless the listener proves the key.
    ///
    /// # Errors
    ///
    /// `InvalidKey` for a key crypto.md refuses, before anything is sent;
    /// `Io` for a relay URL that does not parse or a dial that fails.
    pub async fn connect(
        &self,
        key: &[u8; 32],
        addresses: &[SocketAddr],
        relays: &[String],
        alpn: Alpn,
    ) -> Result<Connection, Error> {
        crate::check_endpoint_key(key)?;
        let id = iroh::PublicKey::from_bytes(key)
            .map_err(|_| Error::protocol(frasil_crypto::ErrorClass::InvalidKey))?;
        let mut paths: Vec<TransportAddr> =
            addresses.iter().copied().map(TransportAddr::Ip).collect();
        for relay in relays {
            paths.push(TransportAddr::Relay(relay.parse().map_err(Error::io)?));
        }
        let connection = self
            .inner
            .connect(EndpointAddr::from_parts(id, paths), alpn.bytes())
            .await
            .map_err(Error::io)?;
        Connection::establish(connection, Role::Dialer, self.key, self.extensions)
    }

    /// Dials a ticket with the ALPN of its kind.
    ///
    /// # Errors
    ///
    /// As [`Endpoint::connect`].
    pub async fn dial(&self, ticket: &Ticket) -> Result<Connection, Error> {
        let addresses: Vec<SocketAddr> = ticket
            .addresses
            .iter()
            .map(|address| match *address {
                Address::V4(ip, port) => SocketAddr::from((Ipv4Addr::from(ip), port)),
                Address::V6(ip, port) => SocketAddr::from((Ipv6Addr::from(ip), port)),
            })
            .collect();
        self.connect(
            &ticket.endpoint,
            &addresses,
            &ticket.relays,
            Alpn::of_ticket(ticket.kind),
        )
        .await
    }

    /// Accepts the next connection with one of the endpoint's ALPNs. `None`
    /// once the endpoint is closed.
    ///
    /// # Errors
    ///
    /// `InvalidKey` (closing the connection) for a dialer whose endpoint key
    /// crypto.md refuses; `Io` for a transport handshake that fails.
    pub async fn accept(&self) -> Option<Result<Connection, Error>> {
        let incoming = self.inner.accept().await?;
        Some(match incoming.await {
            Ok(connection) => {
                Connection::establish(connection, Role::Listener, self.key, self.extensions)
            }
            Err(error) => Err(Error::io(error)),
        })
    }

    /// Closes the endpoint and every connection on it.
    pub async fn close(&self) {
        self.inner.close().await;
    }
}
