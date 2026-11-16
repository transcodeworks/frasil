//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's iroh binding: QUIC with raw public keys, the `frasil/p1/*`
//! ALPNs, channel binding, stream classes, the lossy channel, and the local
//! network's sockets.
//!
//! Specified by `docs/spec/transport.md`, section 3.16 (The iroh binding),
//! which maps the iroh transport onto section 2.1's four requirements:
//!
//! - **T1.** Each end proves an endpoint key, an Ed25519 public key, in the
//!   TLS 1.3 handshake with raw public keys. A dialer names the key it
//!   dials; a listener learns the dialer's. [`Connection::peer`] is the other
//!   end's key, checked with crypto.md before it is kept.
//! - **T2.** [`Connection::channel`] is RFC 9266's `tls-exporter` channel
//!   binding: `TLS-Exporter("EXPORTER-Channel-Binding", "", 32)`.
//! - **T3.** Frames on QUIC streams: the control stream, sync streams,
//!   object streams and the ephemeral stream, each with its class's cap and
//!   priority ([`stream`]).
//! - **T4.** QUIC datagrams (RFC 9221), with the ephemeral stream when a
//!   message does not fit ([`Connection::send_lossy`]).
//!
//! [`Endpoint`] binds an iroh endpoint with no address lookup: a device
//! never publishes an endpoint key under a public name, so iroh's DNS and
//! pkarr services are never configured. It dials and accepts the three
//! ALPNs ([`Alpn`]). [`lan`] holds the sockets of section 2.9's packets.
//!
//! The protocol itself, the frames' checks, the handshakes and the packets'
//! formats, is `frasil-transport`'s, which holds no IO. This crate only
//! carries its bytes.

pub mod connection;
pub mod endpoint;
pub mod lan;
pub mod stream;

pub use connection::{Connection, Lossy, Stream};
pub use endpoint::{Config, Endpoint, fresh_secret_key};
pub use frasil_transport::member::Role;
pub use stream::{FrameReceiver, FrameSender};

use frasil_transport::frame::ConnectionKind;
use frasil_transport::ticket::TicketKind;
use frasil_transport::{Closed, Code, TransportClass, labels};
use std::time::Duration;

/// `handshake_deadline`: from the transport's connection to the first
/// `Admit` or refusal (transport.md, section 3.4).
pub const HANDSHAKE_DEADLINE: Duration =
    Duration::from_secs(frasil_transport::HANDSHAKE_DEADLINE_SECONDS);

/// `pairing_deadline`: one nearby pairing (section 3.16).
pub const PAIRING_DEADLINE: Duration =
    Duration::from_secs(frasil_transport::PAIRING_DEADLINE_SECONDS);

/// `endpoint_rotation`: the longest a device keeps one member endpoint key
/// (overview.md, section 6). A device also takes a fresh one whenever it
/// joins another network, and binds a new [`Endpoint`] with it.
pub const ENDPOINT_ROTATION: Duration = Duration::from_secs(24 * 60 * 60);

/// A connection's ALPN (section 3.16), which fixes its kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alpn {
    /// `frasil/p1/member`: a member connection between two devices.
    Member,
    /// `frasil/p1/peer`: a device and an always-on peer.
    Peer,
    /// `frasil/p1/nearby`: one admission exchange on a local network.
    Nearby,
}

impl Alpn {
    /// Every ALPN, in the table's order.
    pub const ALL: [Alpn; 3] = [Self::Member, Self::Peer, Self::Nearby];

    /// The ALPN's bytes, from crypto.md's registry.
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::Member => labels::P1_MEMBER,
            Self::Peer => labels::P1_PEER,
            Self::Nearby => labels::P1_NEARBY,
        }
    }

    /// The ALPN of these bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|alpn| alpn.bytes() == bytes)
    }

    /// The kind of connection the ALPN opens.
    pub const fn connection(self) -> ConnectionKind {
        match self {
            Self::Member => ConnectionKind::Member,
            Self::Peer => ConnectionKind::DeviceToPeer,
            Self::Nearby => ConnectionKind::Nearby,
        }
    }

    /// The ALPN a ticket of this kind is dialed with.
    pub const fn of_ticket(kind: TicketKind) -> Self {
        match kind {
            TicketKind::Member => Self::Member,
            TicketKind::Peer => Self::Peer,
            TicketKind::Nearby => Self::Nearby,
        }
    }
}

/// A failure of the binding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A frame, message or key failed a check of transport.md. The binding
    /// closed the connection with the code [`Closed`] carries, unless no
    /// connection was open yet.
    Protocol(Closed),
    /// The other end closed the connection with this application code:
    /// section 2.5's code of that number, if it has one.
    ClosedByPeer(u64),
    /// This end closed the connection.
    ClosedLocally,
    /// The stream ended in the middle of a frame.
    Truncated,
    /// A deadline passed.
    Timeout,
    /// The operating system or QUIC failed: binding, dialing, a reset
    /// stream, a lost connection.
    Io(String),
}

impl Error {
    /// The failure of a class of transport.md.
    pub fn protocol(class: impl Into<TransportClass>) -> Self {
        Self::Protocol(Closed::of(class))
    }

    /// The code of section 2.5 that closed the connection, by either end,
    /// for a failure that closed it with one.
    pub fn code(&self) -> Option<Code> {
        match self {
            Self::Protocol(closed) => Some(closed.code),
            Self::ClosedByPeer(number) => Code::from_number(*number),
            _ => None,
        }
    }

    /// The class of transport.md, for a failure this end found.
    pub fn class(&self) -> Option<TransportClass> {
        match self {
            Self::Protocol(closed) => Some(closed.class),
            _ => None,
        }
    }

    pub(crate) fn io(error: impl core::fmt::Display) -> Self {
        Self::Io(error.to_string())
    }

    pub(crate) fn of_connection(error: &iroh::endpoint::ConnectionError) -> Self {
        use iroh::endpoint::ConnectionError as E;
        match error {
            E::ApplicationClosed(close) => Self::ClosedByPeer(close.error_code.into_inner()),
            E::LocallyClosed => Self::ClosedLocally,
            E::TimedOut => Self::Timeout,
            other => Self::io(other),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(closed) => write!(f, "{closed}"),
            Self::ClosedByPeer(number) => match Code::from_number(*number) {
                Some(code) => write!(f, "closed by the other end with {}", code.name()),
                None => write!(f, "closed by the other end with code {number}"),
            },
            Self::ClosedLocally => f.write_str("closed by this end"),
            Self::Truncated => f.write_str("the stream ended in the middle of a frame"),
            Self::Timeout => f.write_str("a deadline passed"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<TransportClass> for Error {
    fn from(class: TransportClass) -> Self {
        Self::protocol(class)
    }
}

impl From<Closed> for Error {
    fn from(closed: Closed) -> Self {
        Self::Protocol(closed)
    }
}

/// Checks an endpoint key with crypto.md (section 3.16: each end checks the
/// other's before it stores it).
///
/// # Errors
///
/// `InvalidKey`.
pub fn check_endpoint_key(key: &[u8; 32]) -> Result<(), Error> {
    frasil_crypto::keys::check_ed25519(key)
        .map_err(|_| Error::protocol(frasil_crypto::ErrorClass::InvalidKey))
}
