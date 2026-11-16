//! The device-to-peer handshake (transport.md, sections 3.10 "The
//! device-to-peer handshake", 3.11 "Presenting credentials" and 3.12), and
//! the server binding's values (section 3.15).
//!
//! ```text
//! PeerHello = {0: 16, 1: 1, 2: nonce_P (32), 3: services, 4: limits, 5: revision}
//! Hello     = {0: 17, 1: 1, 2: nonce_C (32), 3: purpose, 4: revision}
//! binding   = SHA-256("frasil/peer-binding/v1" || field(channel) || nonce_P || nonce_C
//!                     || u8(purpose))
//! presented = field(binding) || field(space) || u8(credential) || field(public)
//! ```
//!
//! [`PeerSide`] and [`DeviceSide`] run the handshake's two ends. The device
//! never proves who it is: it presents storage credentials, each proof bound
//! to the connection through `binding`. peers.md checks each credential
//! and its proof, and decides the rights.

use crate::codes::{Right, Service};
use crate::frame::{Message, MessageType, OBJECT_CHUNK_BYTES};
use crate::messages::{self, Present, Refused, exactly, malformed, uint};
use crate::{Channel, Closed, Code, TransportClass};
use frasil_base::ErrorClass;
use frasil_base::cbor::{Map, Value};
use frasil_base::notation::{hex, push_field};
use frasil_crypto::device::DeviceId;
use frasil_crypto::labels;
use frasil_crypto::primitives::{ed25519_public, sha256};

pub use frasil_peers::proof::{Credential, Purpose, presented};

/// The protocol `PeerHello` and `Hello` carry at key 1.
pub const PROTOCOL: u64 = frasil_base::version::PROTOCOL;
/// The revision the hellos carry.
pub const REVISION: u64 = frasil_base::version::REVISION;

/// The server binding's channel: `SHA-256("frasil/server-channel/v1" ||
/// field(origin))`, where `origin` is the ASCII serialisation (RFC 6454) of
/// the origin the client connected to, such as `https://peer.example.org`.
pub fn server_channel(origin: &str) -> Channel {
    let mut input = labels::SERVER_CHANNEL.to_vec();
    push_field(&mut input, origin.as_bytes());
    sha256(&[&input])
}

/// `binding`: fresh per connection, and fixed to the channel and the
/// purpose.
pub fn peer_binding(
    channel: &Channel,
    nonce_peer: &[u8; 32],
    nonce_client: &[u8; 32],
    purpose: Purpose,
) -> [u8; 32] {
    let mut input = labels::PEER_BINDING.to_vec();
    push_field(&mut input, channel);
    input.extend_from_slice(nonce_peer);
    input.extend_from_slice(nonce_client);
    input.push(purpose.code());
    sha256(&[&input])
}

/// The purpose of a code: 1 space traffic, 2 administration.
pub fn purpose_of(code: u64) -> Option<Purpose> {
    match code {
        1 => Some(Purpose::SpaceTraffic),
        2 => Some(Purpose::Administration),
        _ => None,
    }
}

/// `PeerHello`'s limits (section 3.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// 1: the largest frame.
    pub max_frame_bytes: u64,
    /// 2: `max_streams_per_space` (units.md).
    pub max_streams_per_space: u64,
    /// 3: the largest mailbox item.
    pub max_mailbox_item_bytes: u64,
    /// 4: the largest object chunk.
    pub max_chunk_bytes: u64,
}

impl Limits {
    /// The limits of a peer that allows what this document allows, with
    /// units.md's `max_streams_per_space` of 65,536.
    pub const PROTOCOL: Self = Self {
        max_frame_bytes: crate::frame::MAX_FRAME_BYTES as u64,
        max_streams_per_space: 65_536,
        max_mailbox_item_bytes: crate::frame::MAILBOX_ITEM_BYTES as u64,
        max_chunk_bytes: OBJECT_CHUNK_BYTES as u64,
    };

    fn value(&self) -> Value {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(self.max_frame_bytes));
        map.insert(2, Value::Unsigned(self.max_streams_per_space));
        map.insert(3, Value::Unsigned(self.max_mailbox_item_bytes));
        map.insert(4, Value::Unsigned(self.max_chunk_bytes));
        Value::Map(map)
    }
}

/// A `PeerHello`, as the device reads it. The device checks its keys,
/// protocol and revision, and nothing else: a peer is trusted for
/// availability only. Its services and limits are hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHello {
    /// `nonce_P`.
    pub nonce: [u8; 32],
    /// Key 3, as received.
    pub services: Value,
    /// Key 4, as received.
    pub limits: Value,
}

impl PeerHello {
    /// The `PeerHello` message.
    pub fn encode(nonce: &[u8; 32], services: &[Service], limits: &Limits) -> Vec<u8> {
        messages::encode(
            MessageType::PeerHello,
            [
                (1, Value::Unsigned(PROTOCOL)),
                (2, Value::from(*nonce)),
                (
                    3,
                    Value::Array(services.iter().map(|s| Value::Unsigned(s.code())).collect()),
                ),
                (4, limits.value()),
                (5, Value::Unsigned(REVISION)),
            ],
        )
    }

    /// Reads a `PeerHello` at the device: its keys, protocol and revision,
    /// and a 32-byte nonce.
    ///
    /// # Errors
    ///
    /// `Malformed`; `UnsupportedVersion` for another protocol;
    /// `RevisionMismatch` for another revision.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        let map = read_hello_head(message, MessageType::PeerHello, &[0, 1, 2, 3, 4, 5], 5)?;
        Ok(Self {
            nonce: messages::array(map, 2)?,
            services: map[&3].clone(),
            limits: map[&4].clone(),
        })
    }

    /// The services listed that the device knows; unknown ones are skipped.
    pub fn services(&self) -> Vec<Service> {
        let Ok(items) = self.services.as_array() else {
            return Vec::new();
        };
        items
            .iter()
            .filter_map(|v| v.as_unsigned().ok().and_then(Service::from_code))
            .collect()
    }

    /// A limit by its key, 1 to 4, if listed.
    pub fn limit(&self, key: u64) -> Option<u64> {
        self.limits.as_map().ok()?.get(&key)?.as_unsigned().ok()
    }
}

/// A `Hello`, as the peer reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    /// `nonce_C`.
    pub nonce: [u8; 32],
    /// The device's purpose.
    pub purpose: Purpose,
}

impl Hello {
    /// The `Hello` message.
    pub fn encode(nonce: &[u8; 32], purpose: Purpose) -> Vec<u8> {
        messages::encode(
            MessageType::Hello,
            [
                (1, Value::Unsigned(PROTOCOL)),
                (2, Value::from(*nonce)),
                (3, Value::Unsigned(purpose.code().into())),
                (4, Value::Unsigned(REVISION)),
            ],
        )
    }

    /// Reads a `Hello` at the peer, steps 2 to 5 (section 3.10).
    ///
    /// # Errors
    ///
    /// In the document's order: `Malformed` without exactly keys 0 to 4;
    /// `UnsupportedVersion` unless key 1 is 1; `RevisionMismatch` for
    /// another revision; `Malformed` without a 32-byte nonce and a purpose
    /// of 1 or 2.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        let map = read_hello_head(message, MessageType::Hello, &[0, 1, 2, 3, 4], 4)?;
        let nonce = messages::array(map, 2)?;
        let purpose = purpose_of(uint(map, 3)?).ok_or_else(malformed)?;
        Ok(Self { nonce, purpose })
    }
}

/// A hello's keys, protocol, and revision, in order.
fn read_hello_head<'m>(
    message: &'m Message,
    kind: MessageType,
    keys: &[u64],
    revision_key: u64,
) -> Result<&'m Map, TransportClass> {
    exactly(message, kind, keys)?;
    let map = &message.map;
    if uint(map, 1)? != PROTOCOL {
        return Err(ErrorClass::UnsupportedVersion.into());
    }
    if uint(map, revision_key)? != REVISION {
        return Err(ErrorClass::RevisionMismatch.into());
    }
    Ok(map)
}

/// A request a purpose allows or not (section 3.10, step 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Request {
    /// A `Present` of this credential code.
    Present(u64),
    /// A `Merge`.
    Merge,
    /// A `RegisterRecoveryEntry`.
    RegisterRecoveryEntry,
    /// A mailbox message.
    Mailbox,
    /// A reserved request of ext-libraries.md: type 21, `LibraryAttach`, or
    /// type 31, `HoldObject`.
    LibraryAttach,
    /// A reserved request of ext-deposit-tokens.md: types 40 to 43.
    DepositTokens,
}

impl Request {
    /// The request a message is, if it is one step 6 judges. A `Present`'s
    /// credential is read from its key 3; one that has none is judged by
    /// step 7.
    pub fn of(message: &Message) -> Option<Self> {
        Some(match message.kind {
            MessageType::Present => {
                Self::Present(message.get(3).and_then(|v| v.as_unsigned().ok())?)
            }
            MessageType::Merge => Self::Merge,
            MessageType::RegisterRecoveryEntry => Self::RegisterRecoveryEntry,
            MessageType::MailboxPut
            | MessageType::MailboxGet
            | MessageType::MailboxItems
            | MessageType::MailboxDelete => Self::Mailbox,
            MessageType::LibraryAttach | MessageType::HoldObject => Self::LibraryAttach,
            MessageType::TokenKeysGet
            | MessageType::TokenKeys
            | MessageType::TokenRequest
            | MessageType::TokenIssue => Self::DepositTokens,
            _ => return None,
        })
    }
}

/// The purpose rules over one connection (section 3.10's table).
///
/// - Space traffic carries read credentials, upload keys and fetch keys for
///   any number of spaces, `Merge`, `RegisterRecoveryEntry`, mailbox
///   messages and types 21, 31 and 40 to 43; never an administrator
///   pseudonym.
/// - Administration carries exactly one `Present`: one administrator
///   pseudonym for one space; never a bearer token, `Merge`,
///   `RegisterRecoveryEntry`, mailbox messages or types 21, 31 and 40 to
///   43.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurposeGuard {
    purpose: Purpose,
    presents: usize,
}

impl PurposeGuard {
    /// The rules of a purpose, before any request.
    pub fn new(purpose: Purpose) -> Self {
        Self {
            purpose,
            presents: 0,
        }
    }

    /// The purpose.
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// An account's bearer token on the connection.
    ///
    /// # Errors
    ///
    /// `PurposeViolation` on an administration connection.
    pub fn bearer(&self) -> Result<(), TransportClass> {
        match self.purpose {
            Purpose::SpaceTraffic => Ok(()),
            Purpose::Administration => Err(TransportClass::PurposeViolation),
        }
    }

    /// One request.
    ///
    /// # Errors
    ///
    /// `PurposeViolation` if the purpose does not allow it.
    pub fn request(&mut self, request: Request) -> Result<(), TransportClass> {
        let allowed = match (self.purpose, request) {
            (Purpose::SpaceTraffic, Request::Present(credential)) => {
                credential != u64::from(Credential::Pseudonym.code())
            }
            (Purpose::SpaceTraffic, _) => true,
            (Purpose::Administration, Request::Present(credential)) => {
                credential == u64::from(Credential::Pseudonym.code()) && self.presents == 0
            }
            (Purpose::Administration, _) => false,
        };
        if !allowed {
            return Err(TransportClass::PurposeViolation);
        }
        if let Request::Present(_) = request {
            self.presents += 1;
        }
        Ok(())
    }

    /// At the connection's end: an administration connection presented
    /// exactly one pseudonym.
    ///
    /// # Errors
    ///
    /// `PurposeViolation` for an administration connection without its one
    /// `Present`.
    pub fn finish(&self) -> Result<(), TransportClass> {
        match (self.purpose, self.presents) {
            (Purpose::Administration, 1) | (Purpose::SpaceTraffic, _) => Ok(()),
            (Purpose::Administration, _) => Err(TransportClass::PurposeViolation),
        }
    }
}

/// The purpose rules over a whole connection: the credentials it
/// presented, whether it carried a bearer token, and its other requests.
///
/// # Errors
///
/// `PurposeViolation` if the purpose does not allow them.
pub fn check_connection(
    purpose: Purpose,
    credentials: &[u64],
    bearer: bool,
    requests: &[Request],
) -> Result<(), TransportClass> {
    let mut guard = PurposeGuard::new(purpose);
    if bearer {
        guard.bearer()?;
    }
    for &credential in credentials {
        guard.request(Request::Present(credential))?;
    }
    for &request in requests {
        guard.request(request)?;
    }
    guard.finish()
}

/// What the peer made of a message after the handshake (section 3.10,
/// steps 6 and 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checked {
    /// A `Present` the purpose allows: peers.md checks the credential and
    /// its proof over [`PeerSide::presented`].
    Present(Present),
    /// A `Present` refused: send this `Refused` with `credential_refused`.
    Refuse(Vec<u8>),
    /// Any other message, which step 6 allows: step 8 checks that its space
    /// holds the right it needs.
    Pass,
}

/// The peer's end of a device-to-peer connection.
#[derive(Debug, Clone)]
pub struct PeerSide {
    channel: Channel,
    nonce: [u8; 32],
    opened: Option<(Purpose, [u8; 32])>,
    guard: Option<PurposeGuard>,
}

impl PeerSide {
    /// Step 1: the peer's end of a new connection, and its `PeerHello`.
    /// `nonce` is 32 fresh random bytes.
    pub fn start_with(
        channel: Channel,
        nonce: [u8; 32],
        services: &[Service],
        limits: &Limits,
    ) -> (Self, Vec<u8>) {
        let hello = PeerHello::encode(&nonce, services, limits);
        let side = Self {
            channel,
            nonce,
            opened: None,
            guard: None,
        };
        (side, hello)
    }

    /// The connection's purpose, once its `Hello` read.
    pub fn purpose(&self) -> Option<Purpose> {
        self.opened.map(|(purpose, _)| purpose)
    }

    /// The connection's `binding`, once its `Hello` read.
    pub fn binding(&self) -> Option<&[u8; 32]> {
        self.opened.as_ref().map(|(_, binding)| binding)
    }

    /// `presented` for a present on this connection, for peers.md's proof.
    ///
    /// # Panics
    ///
    /// Before the `Hello`.
    pub fn presented(&self, present: &Present) -> Vec<u8> {
        let binding = self.binding().expect("the Hello was read");
        let credential = u8::try_from(present.credential).unwrap_or(u8::MAX);
        presented(binding, &present.space, credential, &present.public)
    }

    /// Steps 2 to 5: the device's `Hello`. Returns the connection's
    /// `binding`.
    ///
    /// # Errors
    ///
    /// Closes with `malformed`, `unsupported_version` or
    /// `revision_mismatch`; a second `Hello` is `malformed`.
    pub fn on_hello(&mut self, message: &Message) -> Result<[u8; 32], Closed> {
        if self.opened.is_some() {
            return Err(Closed::of(ErrorClass::Malformed));
        }
        let hello = Hello::read(message)?;
        let binding = peer_binding(&self.channel, &self.nonce, &hello.nonce, hello.purpose);
        self.opened = Some((hello.purpose, binding));
        self.guard = Some(PurposeGuard::new(hello.purpose));
        Ok(binding)
    }

    /// An account's bearer token rides on the connection.
    ///
    /// # Errors
    ///
    /// Closes with `purpose_violation` on an administration connection.
    pub fn bearer(&self) -> Result<(), Closed> {
        match &self.guard {
            Some(guard) => Ok(guard.bearer()?),
            None => Err(Closed::of(ErrorClass::Malformed)),
        }
    }

    /// Steps 6 and 7 on a message after the `Hello`.
    ///
    /// # Errors
    ///
    /// Closes with `purpose_violation` for a request the purpose does not
    /// allow, and with `malformed` before the `Hello` or for a `Present`
    /// with no request number to refuse.
    pub fn on_message(&mut self, message: &Message) -> Result<Checked, Closed> {
        let Some(guard) = self.guard.as_mut() else {
            return Err(Closed::of(ErrorClass::Malformed));
        };
        // 6. The purpose allows it.
        if let Some(request) = Request::of(message) {
            guard.request(request)?;
        }
        if message.kind != MessageType::Present {
            return Ok(Checked::Pass);
        }
        // 7. Exactly keys 0 to 5; peers.md's checks follow.
        match Present::read(message) {
            Ok(present) => Ok(Checked::Present(present)),
            Err(_) => {
                let request = message
                    .get(1)
                    .and_then(|v| v.as_unsigned().ok())
                    .ok_or(Closed::of(ErrorClass::Malformed))?;
                Ok(Checked::Refuse(
                    Refused {
                        request,
                        code: Code::CredentialRefused.name().to_owned(),
                    }
                    .encode(),
                ))
            }
        }
    }
}

/// What the device has once it answered the `PeerHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSide {
    /// The peer's hello.
    pub peer_hello: PeerHello,
    /// The device's `Hello`, to send.
    pub hello: Vec<u8>,
    /// The connection's purpose.
    pub purpose: Purpose,
    /// The connection's `binding`.
    pub binding: [u8; 32],
}

impl DeviceSide {
    /// The device's end: reads the peer's `PeerHello` and answers with its
    /// `Hello`, under `nonce`, 32 fresh random bytes, and its purpose.
    ///
    /// # Errors
    ///
    /// Closes with `malformed`, `unsupported_version` or
    /// `revision_mismatch`.
    pub fn answer_with(
        channel: &Channel,
        peer_hello: &Message,
        nonce: [u8; 32],
        purpose: Purpose,
    ) -> Result<Self, Closed> {
        let peer_hello = PeerHello::read(peer_hello)?;
        let binding = peer_binding(channel, &peer_hello.nonce, &nonce, purpose);
        Ok(Self {
            peer_hello,
            hello: Hello::encode(&nonce, purpose),
            purpose,
            binding,
        })
    }

    /// A `Present` of a read credential, an upload key or a fetch key, whose
    /// public half is its seed's Ed25519 key, its proof made with that seed
    /// over this connection's `presented`. `request` numbers the device's
    /// requests on the connection, from 1. An administrator pseudonym is
    /// presented by [`present_pseudonym`](Self::present_pseudonym).
    pub fn present(
        &self,
        request: u64,
        space: &[u8; 32],
        credential: Credential,
        seed: &[u8; 32],
    ) -> Vec<u8> {
        debug_assert!(credential != Credential::Pseudonym);
        self.present_as(request, space, credential, seed, &ed25519_public(seed))
    }

    /// A `Present` of an administrator pseudonym (credential 3): its public
    /// half is the pseudonym's device ID, and its proof is made with the
    /// pseudonym's Ed25519 seed (peers.md, "Presenting credentials").
    pub fn present_pseudonym(
        &self,
        request: u64,
        space: &[u8; 32],
        seed: &[u8; 32],
        pseudonym: &DeviceId,
    ) -> Vec<u8> {
        self.present_as(request, space, Credential::Pseudonym, seed, &pseudonym.0)
    }

    fn present_as(
        &self,
        request: u64,
        space: &[u8; 32],
        credential: Credential,
        seed: &[u8; 32],
        public: &[u8; 32],
    ) -> Vec<u8> {
        let presented = presented(&self.binding, space, credential.code(), public);
        Present {
            request,
            space: *space,
            credential: credential.code().into(),
            public: public.to_vec(),
            proof: frasil_peers::proof::prove(seed, &presented).to_vec(),
        }
        .encode()
    }
}

/// The rights a `Granted` lists for peers.md's rights.
pub fn granted_rights(rights: frasil_peers::entries::Rights) -> Vec<Right> {
    Right::of(rights)
}

/// An object's locator (units.md): its object ID, then the SHA-256 of the
/// stored object.
pub fn object_locator(object_id: &[u8; 32], stored: &[u8]) -> [u8; 64] {
    let mut locator = [0; 64];
    locator[..32].copy_from_slice(object_id);
    locator[32..].copy_from_slice(&sha256(&[stored]));
    locator
}

/// An object chunk's route on the server binding (section 3.15):
/// `/frasil/p1/spaces/{space}/objects/{locator}/chunks/{index}`.
pub fn chunk_path(space: &[u8; 32], locator: &[u8; 64], index: u64) -> String {
    format!(
        "/frasil/p1/spaces/{}/objects/{}/chunks/{index}",
        hex::encode(space),
        hex::encode(locator)
    )
}

/// A mailbox's route on the server binding: `/frasil/p1/mailbox/{kind}/
/// {address}`.
pub fn mailbox_path(kind: u8, address: &[u8; 32]) -> String {
    format!("/frasil/p1/mailbox/{kind}/{}", hex::encode(address))
}

/// The discovery route.
pub const DISCOVERY_PATH: &str = "/.well-known/frasil";
/// The connect route, upgraded to a WebSocket with subprotocol `frasil.p1`.
pub const CONNECT_PATH: &str = "/frasil/p1/connect";
/// The scheme of a transfer token's `Authorization` header.
pub const TRANSFER_SCHEME: &str = "Frasil-Transfer";

/// A transfer token's `Authorization` header value: `Frasil-Transfer <64
/// lowercase hex>`.
pub fn transfer_authorization(token: &[u8; 32]) -> String {
    format!("{TRANSFER_SCHEME} {}", hex::encode(token))
}

/// Reads a transfer token's `Authorization` header value.
///
/// # Errors
///
/// `Malformed` for another scheme or anything but 64 lowercase hex digits.
pub fn read_transfer_authorization(value: &str) -> Result<[u8; 32], TransportClass> {
    let token = value
        .strip_prefix(TRANSFER_SCHEME)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or_else(malformed)?;
    Ok(hex::decode_array(token)?)
}
