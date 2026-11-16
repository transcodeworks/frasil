//! One connection of the iroh binding (transport.md, section 3.16): its
//! kind, both endpoint keys, the channel binding, its streams and its lossy
//! channel.
//!
//! | Stream | Opened by | Priority |
//! |---|---|---|
//! | control: the first bidirectional stream | the dialer; on `frasil/p1/peer`, the peer, the listener | 2 |
//! | sync: one bidirectional stream per attach, or per space on a device-to-peer connection | the attach's initiator, or the device | 1 |
//! | object: one unidirectional stream per transfer | the sender | 0 |
//! | ephemeral: one unidirectional stream per direction, and QUIC datagrams | each sender, on first use | 3 |
//!
//! Every stream after the control stream starts with `Open`; each datagram
//! carries one `Ephemeral` message. The end that opens the control stream
//! writes on it first. A receiver accepts a second ephemeral stream from the
//! same direction and reads it as the first.

use crate::stream::{FrameReceiver, FrameSender, close};
use crate::{Alpn, Error, Role};
use frasil_crypto::ErrorClass;
use frasil_crypto::device::KeysCommitment;
use frasil_transport::frame::{
    ConnectionKind, Extensions, Message, MessageType, StreamClass, read_message,
};
use frasil_transport::messages::{Open, Scope};
use frasil_transport::session::MemberSession;
use frasil_transport::ticket::{Address, Ticket, TicketKind};
use frasil_transport::{Channel, Code, labels};
use iroh::TransportAddr;
use tokio::sync::Mutex;

/// One connection, after the transport's handshake: the other end's
/// endpoint key is proved and checked, and the channel binding is fixed.
#[derive(Debug)]
pub struct Connection {
    inner: iroh::endpoint::Connection,
    alpn: Alpn,
    role: Role,
    local: [u8; 32],
    peer: [u8; 32],
    channel: Channel,
    extensions: Extensions,
    ephemeral: Mutex<Option<FrameSender>>,
}

/// How [`Connection::send_lossy`] sent a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lossy {
    /// As one QUIC datagram.
    Datagram,
    /// On this end's ephemeral stream.
    Stream,
    /// Not at all: the ephemeral stream was still busy.
    Dropped,
}

/// A stream the other end opened, after its `Open`.
#[derive(Debug)]
pub enum Stream {
    /// A sync stream: bidirectional, for an attach or a space.
    Sync {
        /// The attach on a member connection, the space otherwise.
        scope: Scope,
        /// The stream's sending half.
        sender: FrameSender,
        /// The stream's receiving half.
        receiver: FrameReceiver,
    },
    /// An object stream: one transfer, unidirectional.
    Object {
        /// The attach on a member connection, the space otherwise.
        scope: Scope,
        /// The stream.
        receiver: FrameReceiver,
    },
    /// The other end's ephemeral stream. The receiver takes it beside the
    /// connection's datagrams.
    Ephemeral {
        /// The stream.
        receiver: FrameReceiver,
    },
}

impl Connection {
    /// Takes a connection the transport's handshake completed: reads its
    /// ALPN, checks the other end's endpoint key with crypto.md, and
    /// computes the channel binding.
    pub(crate) fn establish(
        inner: iroh::endpoint::Connection,
        role: Role,
        local: [u8; 32],
        extensions: Extensions,
    ) -> Result<Self, Error> {
        let Some(alpn) = Alpn::from_bytes(inner.alpn()) else {
            close(&inner, Code::UnsupportedVersion);
            return Err(Error::protocol(ErrorClass::UnsupportedVersion));
        };
        let peer = *inner.remote_id().as_bytes();
        if let Err(error) = crate::check_endpoint_key(&peer) {
            close(&inner, Code::InvalidKey);
            return Err(error);
        }
        let channel = exporter(&inner)?;
        Ok(Self {
            inner,
            alpn,
            role,
            local,
            peer,
            channel,
            extensions,
            ephemeral: Mutex::new(None),
        })
    }

    /// The connection's ALPN.
    pub fn alpn(&self) -> Alpn {
        self.alpn
    }

    /// The kind of connection.
    pub fn kind(&self) -> ConnectionKind {
        self.alpn.connection()
    }

    /// This end's role: the dialer opened the connection, the listener
    /// accepted it.
    pub fn role(&self) -> Role {
        self.role
    }

    /// This end's endpoint key.
    pub fn local(&self) -> [u8; 32] {
        self.local
    }

    /// `peer()`: the other end's endpoint key, as the transport proved it
    /// (T1).
    pub fn peer(&self) -> [u8; 32] {
        self.peer
    }

    /// A ticket of the other end, as this connection reaches it: its
    /// endpoint key, the IP addresses of the connection's open paths and
    /// their `https` relays, as many as a ticket holds (transport.md,
    /// "Reconnecting"). `None` when no open path names an address or a
    /// relay.
    pub fn remote_ticket(&self, kind: TicketKind) -> Option<Ticket> {
        let mut addresses = Vec::new();
        let mut relays = Vec::new();
        for path in self.inner.paths().iter() {
            match path.remote_addr() {
                TransportAddr::Ip(address) => {
                    let address = match address.ip().to_canonical() {
                        std::net::IpAddr::V4(ip) => Address::V4(ip.octets(), address.port()),
                        std::net::IpAddr::V6(ip) => Address::V6(ip.octets(), address.port()),
                    };
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
                TransportAddr::Relay(url) => {
                    let url = url.to_string();
                    if url.starts_with("https://") && !relays.contains(&url) {
                        relays.push(url);
                    }
                }
                _ => {}
            }
        }
        addresses.truncate(crate::endpoint::TICKET_ADDRESSES);
        relays.truncate(crate::endpoint::TICKET_RELAYS);
        if addresses.is_empty() && relays.is_empty() {
            return None;
        }
        Some(Ticket {
            kind,
            endpoint: self.peer,
            relays,
            addresses,
        })
    }

    /// `channel()`: RFC 9266's `tls-exporter` value over this connection's
    /// TLS session (T2).
    pub fn channel(&self) -> Channel {
        self.channel
    }

    /// The extensions this end's receivers implement.
    pub fn extensions(&self) -> Extensions {
        self.extensions
    }

    /// A member session over this connection (transport.md, sections 3.2 to
    /// 3.7): this end's role, the channel binding, and both endpoint keys as
    /// the transport proved them. `identity_seed` signs this device's
    /// `Identify`, which carries `kc`, the commitment to the device's other
    /// keys, beside the Ed25519 key.
    ///
    /// # Errors
    ///
    /// `PurposeViolation` on a connection that is not a member connection.
    pub fn member_session<T>(
        &self,
        identity_seed: &[u8; 32],
        kc: KeysCommitment,
    ) -> Result<MemberSession<T>, Error> {
        if self.alpn != Alpn::Member {
            return Err(Error::protocol(
                frasil_transport::TransportClass::PurposeViolation,
            ));
        }
        Ok(MemberSession::new(
            self.role,
            self.channel,
            self.local,
            self.peer,
            identity_seed,
            kc,
        ))
    }

    fn control_class(&self) -> StreamClass {
        match self.alpn {
            Alpn::Nearby => StreamClass::Nearby,
            Alpn::Member | Alpn::Peer => StreamClass::Control,
        }
    }

    fn receiver(&self, stream: iroh::endpoint::RecvStream, class: StreamClass) -> FrameReceiver {
        FrameReceiver::new(
            stream,
            class,
            self.kind(),
            self.extensions,
            self.inner.clone(),
        )
    }

    /// Whether this end opens the control stream: the dialer, except on
    /// `frasil/p1/peer`, where the peer, the listener, opens it to send
    /// `PeerHello` first.
    ///
    /// On a nearby connection the end that writes first opens the stream,
    /// and the ALPN does not say which flow runs. This answers for pairing,
    /// where the newcomer, the dialer, writes first. In setup the device
    /// being set up, the listener, writes the Hello first: it calls
    /// [`Connection::open_control`], and the dialer
    /// [`Connection::accept_control`].
    pub fn opens_control(&self) -> bool {
        match self.alpn {
            Alpn::Peer => self.role == Role::Listener,
            Alpn::Member | Alpn::Nearby => self.role == Role::Dialer,
        }
    }

    /// The control stream, the connection's first bidirectional stream:
    /// opened by the end [`Connection::opens_control`] names and accepted
    /// by the other. On a nearby connection it is the one stream of the
    /// nearby class, in pairing's direction; setup's ends call
    /// [`Connection::open_control`] and [`Connection::accept_control`].
    ///
    /// The other end sees a stream only once its opener writes on it, so
    /// the opener sends first.
    ///
    /// # Errors
    ///
    /// The connection's failure.
    pub async fn control(&self) -> Result<(FrameSender, FrameReceiver), Error> {
        if self.opens_control() {
            self.open_control().await
        } else {
            self.accept_control().await
        }
    }

    /// Opens the control stream, whichever end this is. The caller writes
    /// on it first.
    ///
    /// # Errors
    ///
    /// The connection's failure.
    pub async fn open_control(&self) -> Result<(FrameSender, FrameReceiver), Error> {
        let (send, receive) = self
            .inner
            .open_bi()
            .await
            .map_err(|error| Error::of_connection(&error))?;
        let class = self.control_class();
        Ok((FrameSender::new(send, class), self.receiver(receive, class)))
    }

    /// Accepts the control stream the other end opened, once it writes.
    ///
    /// # Errors
    ///
    /// The connection's failure.
    pub async fn accept_control(&self) -> Result<(FrameSender, FrameReceiver), Error> {
        let (send, receive) = self
            .inner
            .accept_bi()
            .await
            .map_err(|error| Error::of_connection(&error))?;
        let class = self.control_class();
        Ok((FrameSender::new(send, class), self.receiver(receive, class)))
    }

    /// Opens a sync stream for an attach or a space, and sends its `Open`.
    ///
    /// # Errors
    ///
    /// The connection's failure.
    pub async fn open_sync(&self, scope: Scope) -> Result<(FrameSender, FrameReceiver), Error> {
        let (send, receive) = self
            .inner
            .open_bi()
            .await
            .map_err(|error| Error::of_connection(&error))?;
        let mut sender = FrameSender::new(send, StreamClass::Sync);
        sender
            .send(
                &Open {
                    class: StreamClass::Sync,
                    scope: Some(scope),
                }
                .encode(),
            )
            .await?;
        Ok((sender, self.receiver(receive, StreamClass::Sync)))
    }

    /// Opens an object stream for one transfer, and sends its `Open`.
    ///
    /// # Errors
    ///
    /// The connection's failure.
    pub async fn open_object(&self, scope: Scope) -> Result<FrameSender, Error> {
        let send = self
            .inner
            .open_uni()
            .await
            .map_err(|error| Error::of_connection(&error))?;
        let mut sender = FrameSender::new(send, StreamClass::Object);
        sender
            .send(
                &Open {
                    class: StreamClass::Object,
                    scope: Some(scope),
                }
                .encode(),
            )
            .await?;
        Ok(sender)
    }

    /// Accepts the next stream the other end opens after the control
    /// stream, and reads its `Open`. A second ephemeral stream from the
    /// other end is accepted as the first was.
    ///
    /// # Errors
    ///
    /// `Malformed` (closing the connection) for a stream whose first frame
    /// is not an `Open` of a class its direction carries: sync on a
    /// bidirectional stream, object or ephemeral on a unidirectional one;
    /// `read_frame`'s classes; the connection's failure.
    pub async fn accept_stream(&self) -> Result<Stream, Error> {
        tokio::select! {
            bi = self.inner.accept_bi() => {
                let (send, receive) = bi.map_err(|error| Error::of_connection(&error))?;
                let mut receiver = self.receiver(receive, StreamClass::Sync);
                let open = read_open(&mut receiver, self.kind()).await?;
                match open {
                    Open { class: StreamClass::Sync, scope: Some(scope) } => Ok(Stream::Sync {
                        scope,
                        sender: FrameSender::new(send, StreamClass::Sync),
                        receiver,
                    }),
                    _ => Err(receiver.fail(ErrorClass::Malformed.into())),
                }
            }
            uni = self.inner.accept_uni() => {
                let receive = uni.map_err(|error| Error::of_connection(&error))?;
                let mut receiver = self.receiver(receive, StreamClass::Object);
                let open = read_open(&mut receiver, self.kind()).await?;
                match open {
                    Open { class: StreamClass::Object, scope: Some(scope) } => {
                        Ok(Stream::Object { scope, receiver })
                    }
                    Open { class: StreamClass::Ephemeral, .. } => {
                        Ok(Stream::Ephemeral {
                            receiver: receiver.with_class(StreamClass::Ephemeral),
                        })
                    }
                    _ => Err(receiver.fail(ErrorClass::Malformed.into())),
                }
            }
        }
    }

    /// Opens this end's ephemeral stream and sends its `Open {1: 3}`.
    /// [`Connection::send_lossy`] opens it on first use; a caller that
    /// writes on the ephemeral stream itself opens it here instead, and does
    /// not also call `send_lossy`, since each end keeps one ephemeral
    /// stream; a receiver still accepts a second.
    ///
    /// # Errors
    ///
    /// The connection's failure.
    pub async fn open_ephemeral(&self) -> Result<FrameSender, Error> {
        let send = self
            .inner
            .open_uni()
            .await
            .map_err(|error| Error::of_connection(&error))?;
        let mut sender = FrameSender::new(send, StreamClass::Ephemeral);
        sender
            .send(
                &Open {
                    class: StreamClass::Ephemeral,
                    scope: None,
                }
                .encode(),
            )
            .await?;
        Ok(sender)
    }

    /// `send_lossy` (T4): one `Ephemeral` message, as a QUIC datagram when
    /// it fits the path's datagram size, otherwise on this end's ephemeral
    /// stream, opened on first use (section 3.8). It is never acknowledged
    /// and never retried, and never waits behind an earlier one: a message
    /// the ephemeral stream is still busy for is dropped.
    ///
    /// # Errors
    ///
    /// `read_frame`'s classes for a message that is not an `Ephemeral` this
    /// connection may carry, which is not sent; the connection's failure.
    pub async fn send_lossy(&self, message: &[u8]) -> Result<Lossy, Error> {
        let read = read_message(
            message,
            StreamClass::Ephemeral,
            self.kind(),
            self.extensions,
        )?;
        if !matches!(
            read,
            Some(Message {
                kind: MessageType::Ephemeral,
                ..
            })
        ) {
            return Err(Error::protocol(ErrorClass::Malformed));
        }
        if self
            .inner
            .max_datagram_size()
            .is_some_and(|size| message.len() <= size)
            && self.inner.send_datagram(message.to_vec().into()).is_ok()
        {
            return Ok(Lossy::Datagram);
        }
        let Ok(mut ephemeral) = self.ephemeral.try_lock() else {
            return Ok(Lossy::Dropped);
        };
        if ephemeral.is_none() {
            *ephemeral = Some(self.open_ephemeral().await?);
        }
        let sender = ephemeral.as_mut().expect("opened above");
        sender.send(message).await?;
        Ok(Lossy::Stream)
    }

    /// `receive_lossy`'s datagram half: the next QUIC datagram, read as
    /// one `Ephemeral` frame with no prefix. The ephemeral stream's half is
    /// [`Stream::Ephemeral`].
    ///
    /// # Errors
    ///
    /// `read_frame`'s classes on the datagram, after which the connection
    /// is closed with the class's code; `Malformed` for a datagram that is
    /// not an `Ephemeral`; the connection's failure.
    pub async fn receive_datagram(&self) -> Result<Message, Error> {
        loop {
            let datagram = self
                .inner
                .read_datagram()
                .await
                .map_err(|error| Error::of_connection(&error))?;
            if datagram.len() > StreamClass::Ephemeral.cap() {
                return Err(self.fail(ErrorClass::TooLarge.into()));
            }
            match read_message(
                &datagram,
                StreamClass::Ephemeral,
                self.kind(),
                self.extensions,
            ) {
                Ok(Some(message)) if message.kind == MessageType::Ephemeral => return Ok(message),
                Ok(Some(_)) => return Err(self.fail(ErrorClass::Malformed.into())),
                Ok(None) => continue,
                Err(class) => return Err(self.fail(class)),
            }
        }
    }

    /// The largest datagram the path carries now, if the other end takes
    /// datagrams.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    /// `close(code)`: closes the connection with a code of section 2.5.
    pub fn close(&self, code: Code) {
        close(&self.inner, code);
    }

    /// Waits until the connection is closed, by either end, and says how.
    pub async fn closed(&self) -> Error {
        Error::of_connection(&self.inner.closed().await)
    }

    fn fail(&self, class: frasil_transport::TransportClass) -> Error {
        let closed = frasil_transport::Closed::of(class);
        close(&self.inner, closed.code);
        Error::Protocol(closed)
    }
}

/// `channel = TLS-Exporter("EXPORTER-Channel-Binding", context = "", 32)`.
fn exporter(connection: &iroh::endpoint::Connection) -> Result<Channel, Error> {
    let mut channel = [0u8; labels::EXPORTER_BYTES];
    connection
        .export_keying_material(&mut channel, labels::EXPORTER, b"")
        .map_err(|_| Error::Io("the TLS session exports no keying material".to_owned()))?;
    Ok(channel)
}

/// Reads a new stream's first frame, which is an `Open` (its cap, 4,096
/// bytes, is below every class's that carries it).
async fn read_open(receiver: &mut FrameReceiver, kind: ConnectionKind) -> Result<Open, Error> {
    let Some(payload) = receiver.read_payload(MessageType::Open.cap()).await? else {
        return Err(receiver.fail(ErrorClass::Malformed.into()));
    };
    let message = match read_message(&payload, receiver.class(), kind, Extensions::NONE) {
        Ok(Some(message)) => message,
        Ok(None) => return Err(receiver.fail(ErrorClass::Malformed.into())),
        Err(class) => return Err(receiver.fail(class)),
    };
    Open::read(&message, kind).map_err(|class| receiver.fail(class))
}
