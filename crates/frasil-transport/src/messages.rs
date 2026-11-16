//! The message types of transport.md, section 2.4, read and written.
//!
//! The member handshake's messages are [`crate::member`]'s, the hellos
//! [`crate::peer`]'s, the mailbox messages [`crate::mailbox`]'s and
//! `Addresses` [`crate::addresses`]'s; this module holds the rest. Types 1
//! to 6, 8, 16, 17 and 18 have exactly the keys listed; `Refuse`, `Detach`, `Granted`, `Refused` and
//! `EventRefused` and `ErasureLate` have nothing else; any other type ignores a key it does
//! not know.
//!
//! The **scope** names what a message is about: the attach number on a
//! member connection, the space ID on a device-to-peer connection.
//!
//! Every reader takes a [`Message`] that [`crate::frame::read_message`]
//! has read, of its own type.

use crate::codes::{Code, Right};
use crate::frame::{ConnectionKind, Message, MessageType, StreamClass, UNITS_MESSAGE_BYTES};
use crate::{TransportClass, exact_keys};
use frasil_base::ErrorClass;
use frasil_base::cbor::{Map, Value};

pub(crate) fn malformed() -> TransportClass {
    ErrorClass::Malformed.into()
}

/// The value at `key`, or `Malformed`.
pub(crate) fn field(map: &Map, key: u64) -> Result<&Value, TransportClass> {
    map.get(&key).ok_or_else(malformed)
}

pub(crate) fn uint(map: &Map, key: u64) -> Result<u64, TransportClass> {
    Ok(field(map, key)?.as_unsigned()?)
}

pub(crate) fn bytes(map: &Map, key: u64) -> Result<&[u8], TransportClass> {
    Ok(field(map, key)?.as_bytes()?)
}

pub(crate) fn array<const N: usize>(map: &Map, key: u64) -> Result<[u8; N], TransportClass> {
    Ok(field(map, key)?.as_byte_array()?)
}

pub(crate) fn text(map: &Map, key: u64) -> Result<&str, TransportClass> {
    Ok(field(map, key)?.as_text()?)
}

/// Checks the message's type, and that its map has exactly these keys.
pub(crate) fn exactly(
    message: &Message,
    kind: MessageType,
    keys: &[u64],
) -> Result<(), TransportClass> {
    if message.kind != kind || !exact_keys(&message.map, keys) {
        return Err(malformed());
    }
    Ok(())
}

/// Checks the message's type.
pub(crate) fn of_type(message: &Message, kind: MessageType) -> Result<(), TransportClass> {
    if message.kind != kind {
        return Err(malformed());
    }
    Ok(())
}

/// A map with key 0, the type, and the given entries, encoded.
pub(crate) fn encode(
    kind: MessageType,
    entries: impl IntoIterator<Item = (u64, Value)>,
) -> Vec<u8> {
    let mut map = Map::new();
    map.insert(0, Value::Unsigned(kind.code()));
    map.extend(entries);
    Value::Map(map).encode()
}

/// What a message is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// An attach number, on a member connection.
    Attach(u64),
    /// A space ID, on a device-to-peer or nearby connection.
    Space([u8; 32]),
}

impl Scope {
    /// Reads a scope as the connection names one.
    pub fn read(value: &Value, connection: ConnectionKind) -> Result<Self, TransportClass> {
        Ok(if connection.scopes_by_attach() {
            Self::Attach(value.as_unsigned()?)
        } else {
            Self::Space(value.as_byte_array()?)
        })
    }

    /// The scope's value.
    pub fn value(self) -> Value {
        match self {
            Self::Attach(attach) => Value::Unsigned(attach),
            Self::Space(space) => Value::from(space),
        }
    }
}

/// `Refuse = {0: 3, 1: attach, 2: code}`: an offer refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refuse {
    /// The attach.
    pub attach: u64,
    /// The code.
    pub code: Code,
}

impl Refuse {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            MessageType::Refuse,
            [
                (1, Value::Unsigned(self.attach)),
                (2, Value::Unsigned(self.code.number())),
            ],
        )
    }

    /// Reads a `Refuse`: exactly keys 0 to 2, and a code of section 2.5.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        exactly(message, MessageType::Refuse, &[0, 1, 2])?;
        Ok(Self {
            attach: uint(&message.map, 1)?,
            code: Code::from_number(uint(&message.map, 2)?).ok_or_else(malformed)?,
        })
    }
}

/// `Admit = {0: 5, 1: attach}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admit {
    /// The attach.
    pub attach: u64,
}

impl Admit {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(MessageType::Admit, [(1, Value::Unsigned(self.attach))])
    }

    /// Reads an `Admit`: exactly keys 0 and 1.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        exactly(message, MessageType::Admit, &[0, 1])?;
        Ok(Self {
            attach: uint(&message.map, 1)?,
        })
    }
}

/// `Detach = {0: 6, 1: attach, 2: code}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detach {
    /// The attach.
    pub attach: u64,
    /// The code.
    pub code: Code,
}

impl Detach {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            MessageType::Detach,
            [
                (1, Value::Unsigned(self.attach)),
                (2, Value::Unsigned(self.code.number())),
            ],
        )
    }

    /// Reads a `Detach`: exactly keys 0 to 2, and a code of section 2.5.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        exactly(message, MessageType::Detach, &[0, 1, 2])?;
        Ok(Self {
            attach: uint(&message.map, 1)?,
            code: Code::from_number(uint(&message.map, 2)?).ok_or_else(malformed)?,
        })
    }
}

/// `Open = {0: 7, 1: class, 2: scope}`: the first message of a stream after
/// the control stream. The scope is absent for the ephemeral class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Open {
    /// The class: sync, object or ephemeral.
    pub class: StreamClass,
    /// The scope; `None` for the ephemeral class.
    pub scope: Option<Scope>,
}

impl Open {
    /// The message.
    ///
    /// # Panics
    ///
    /// If the class is not sync, object or ephemeral.
    pub fn encode(&self) -> Vec<u8> {
        let code = self
            .class
            .open_code()
            .expect("Open names sync, object or ephemeral");
        let mut entries = vec![(1, Value::Unsigned(code))];
        if let Some(scope) = self.scope {
            entries.push((2, scope.value()));
        }
        encode(MessageType::Open, entries)
    }

    /// Reads an `Open`: a class of 1 to 3, with a scope exactly when the
    /// class is not ephemeral.
    pub fn read(message: &Message, connection: ConnectionKind) -> Result<Self, TransportClass> {
        of_type(message, MessageType::Open)?;
        let class = StreamClass::from_open_code(uint(&message.map, 1)?).ok_or_else(malformed)?;
        let scope = match (class, message.get(2)) {
            (StreamClass::Ephemeral, None) => None,
            (StreamClass::Ephemeral, Some(_)) | (_, None) => return Err(malformed()),
            (_, Some(value)) => Some(Scope::read(value, connection)?),
        };
        Ok(Self { class, scope })
    }
}

/// `Present = {0: 18, 1: request, 2: space (32), 3: credential, 4: public
/// (bytes), 5: proof (bytes)}` (section 3.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Present {
    /// The device's request number on the connection, from 1.
    pub request: u64,
    /// The space.
    pub space: [u8; 32],
    /// The credential: 1 read credential, 2 upload key, 3 administrator
    /// pseudonym, 4 fetch key.
    pub credential: u64,
    /// The credential's public half.
    pub public: Vec<u8>,
    /// peers.md's proof over `presented`.
    pub proof: Vec<u8>,
}

impl Present {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            MessageType::Present,
            [
                (1, Value::Unsigned(self.request)),
                (2, Value::from(self.space)),
                (3, Value::Unsigned(self.credential)),
                (4, Value::from(self.public.as_slice())),
                (5, Value::from(self.proof.as_slice())),
            ],
        )
    }

    /// Reads a `Present`: exactly keys 0 to 5, a 32-byte space, and byte
    /// strings for the public half and the proof. peers.md checks the
    /// credential and its proof.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        exactly(message, MessageType::Present, &[0, 1, 2, 3, 4, 5])?;
        let map = &message.map;
        Ok(Self {
            request: uint(map, 1)?,
            space: array(map, 2)?,
            credential: uint(map, 3)?,
            public: bytes(map, 4)?.to_vec(),
            proof: bytes(map, 5)?.to_vec(),
        })
    }
}

/// `Granted = {0: 19, 1: request, 2: rights (array), 3: transfer token (32;
/// server binding only)}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Granted {
    /// The request granted.
    pub request: u64,
    /// The rights, in code order.
    pub rights: Vec<Right>,
    /// The transfer token, on the server binding only.
    pub transfer_token: Option<[u8; 32]>,
}

impl Granted {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            (1, Value::Unsigned(self.request)),
            (
                2,
                Value::Array(
                    self.rights
                        .iter()
                        .map(|r| Value::Unsigned(r.code()))
                        .collect(),
                ),
            ),
        ];
        if let Some(token) = self.transfer_token {
            entries.push((3, Value::from(token)));
        }
        encode(MessageType::Granted, entries)
    }

    /// Reads a `Granted`: keys 0 to 2 and an optional 3, nothing else;
    /// rights of section 3.11's table, each once.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        of_type(message, MessageType::Granted)?;
        let map = &message.map;
        if !(exact_keys(map, &[0, 1, 2]) || exact_keys(map, &[0, 1, 2, 3])) {
            return Err(malformed());
        }
        let mut rights = Vec::new();
        for value in field(map, 2)?.as_array()? {
            let right = Right::from_code(value.as_unsigned()?).ok_or_else(malformed)?;
            if rights.contains(&right) {
                return Err(malformed());
            }
            rights.push(right);
        }
        Ok(Self {
            request: uint(map, 1)?,
            rights,
            transfer_token: map.contains_key(&3).then(|| array(map, 3)).transpose()?,
        })
    }
}

/// `Refused = {0: 20, 1: request, 2: code (text)}`: a request refused with
/// a reason code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// The request refused.
    pub request: u64,
    /// The reason code, such as `credential_refused`.
    pub code: String,
}

impl Refused {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            MessageType::Refused,
            [
                (1, Value::Unsigned(self.request)),
                (2, Value::from(self.code.as_str())),
            ],
        )
    }

    /// Reads a `Refused`: exactly keys 0 to 2.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        exactly(message, MessageType::Refused, &[0, 1, 2])?;
        Ok(Self {
            request: uint(&message.map, 1)?,
            code: text(&message.map, 2)?.to_owned(),
        })
    }
}

/// `EventRefused = {0: 30, 1: space (32), 2: event ID (32), 3: code (text)}`:
/// a peer's answer to an event it neither acknowledges nor holds pending
/// (section 3.10). Events carry no request number, so it names the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRefused {
    /// The space.
    pub space: [u8; 32],
    /// The event refused.
    pub event: [u8; 32],
    /// The reason code, such as `conflict` or `credential_refused`.
    pub code: String,
}

impl EventRefused {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            MessageType::EventRefused,
            [
                (1, Value::from(self.space)),
                (2, Value::from(self.event)),
                (3, Value::from(self.code.as_str())),
            ],
        )
    }

    /// Reads an `EventRefused`: exactly keys 0 to 3.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        exactly(message, MessageType::EventRefused, &[0, 1, 2, 3])?;
        Ok(Self {
            space: array(&message.map, 1)?,
            event: array(&message.map, 2)?,
            code: text(&message.map, 3)?.to_owned(),
        })
    }
}

/// `Accepted = {0: 22, 1: request}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    /// The request accepted.
    pub request: u64,
}

impl Accepted {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(MessageType::Accepted, [(1, Value::Unsigned(self.request))])
    }

    /// Reads an `Accepted`.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        of_type(message, MessageType::Accepted)?;
        Ok(Self {
            request: uint(&message.map, 1)?,
        })
    }
}

/// `Merge = {0: 23, 1: request, 2: a merge statement}`: peers.md's merge
/// statement, a map, at key 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merge {
    /// The request.
    pub request: u64,
    /// The merge statement's deterministic CBOR, which peers.md reads.
    pub statement: Vec<u8>,
}

impl Merge {
    /// The message.
    ///
    /// # Errors
    ///
    /// `Malformed` if the statement is not one deterministic CBOR map.
    pub fn encode(&self) -> Result<Vec<u8>, TransportClass> {
        let statement = frasil_base::cbor::decode(&self.statement)?;
        statement.as_map()?;
        Ok(encode(
            MessageType::Merge,
            [(1, Value::Unsigned(self.request)), (2, statement)],
        ))
    }

    /// Reads a `Merge`: a request number and a map at key 2.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        of_type(message, MessageType::Merge)?;
        let statement = field(&message.map, 2)?;
        statement.as_map()?;
        Ok(Self {
            request: uint(&message.map, 1)?,
            statement: statement.encode(),
        })
    }
}

/// The most event IDs one `Awaiting` lists: as many as fit its cap of
/// 266,240 bytes, 34 bytes an ID beside 43 bytes of the rest.
pub const MAX_AWAITING: usize = 7_829;

/// `Awaiting = {0: 27, 1: space, 2: event IDs}`: 0 to 7,829 IDs, strictly
/// ascending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Awaiting {
    /// The space.
    pub space: [u8; 32],
    /// The requests and snapshots not yet stable at the peer that the
    /// connection's administrator slot has not acknowledged.
    pub ids: Vec<[u8; 32]>,
}

impl Awaiting {
    /// The message. IDs are written ascending, each once.
    pub fn encode(&self) -> Vec<u8> {
        let mut ids = self.ids.clone();
        ids.sort_unstable();
        ids.dedup();
        encode(
            MessageType::Awaiting,
            [
                (1, Value::from(self.space)),
                (2, Value::Array(ids.into_iter().map(Value::from).collect())),
            ],
        )
    }

    /// Reads an `Awaiting`.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        of_type(message, MessageType::Awaiting)?;
        let items = field(&message.map, 2)?.as_array()?;
        if items.len() > MAX_AWAITING {
            return Err(malformed());
        }
        let mut ids: Vec<[u8; 32]> = Vec::with_capacity(items.len());
        for item in items {
            let id = item.as_byte_array()?;
            if ids.last().is_some_and(|last| *last >= id) {
                return Err(malformed());
            }
            ids.push(id);
        }
        Ok(Self {
            space: array(&message.map, 1)?,
            ids,
        })
    }
}

/// `RegisterRecoveryEntry = {0: 29, 1: request, 2: space (32), 3: fetch key
/// (32)}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterRecoveryEntry {
    /// The request.
    pub request: u64,
    /// The space.
    pub space: [u8; 32],
    /// The fetch key to register.
    pub fetch_key: [u8; 32],
}

impl RegisterRecoveryEntry {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            MessageType::RegisterRecoveryEntry,
            [
                (1, Value::Unsigned(self.request)),
                (2, Value::from(self.space)),
                (3, Value::from(self.fetch_key)),
            ],
        )
    }

    /// Reads a `RegisterRecoveryEntry`.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        of_type(message, MessageType::RegisterRecoveryEntry)?;
        Ok(Self {
            request: uint(&message.map, 1)?,
            space: array(&message.map, 2)?,
            fetch_key: array(&message.map, 3)?,
        })
    }
}

/// `Sync = {0: 32, 1: scope, 2: one message of units.md's baseline sync}`,
/// a byte string of at most 1,052,672 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sync {
    /// The scope.
    pub scope: Scope,
    /// units.md's message.
    pub message: Vec<u8>,
}

impl Sync {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            MessageType::Sync,
            [
                (1, self.scope.value()),
                (2, Value::from(self.message.as_slice())),
            ],
        )
    }

    /// Reads a `Sync`. units.md reads its message, whose key 1 must be the
    /// scope's space (section 3.9).
    pub fn read(message: &Message, connection: ConnectionKind) -> Result<Self, TransportClass> {
        of_type(message, MessageType::Sync)?;
        let inner = bytes(&message.map, 2)?;
        if inner.len() > UNITS_MESSAGE_BYTES {
            return Err(ErrorClass::TooLarge.into());
        }
        Ok(Self {
            scope: Scope::read(field(&message.map, 1)?, connection)?,
            message: inner.to_vec(),
        })
    }
}

/// `AdapterSync = {0: 34, 1: scope, 2: adapter ID (text), 3: bytes}`: an
/// adapter's own sync between two members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterSync {
    /// The scope.
    pub scope: Scope,
    /// The adapter's ID.
    pub adapter: String,
    /// The adapter's bytes.
    pub bytes: Vec<u8>,
}

impl AdapterSync {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            MessageType::AdapterSync,
            [
                (1, self.scope.value()),
                (2, Value::from(self.adapter.as_str())),
                (3, Value::from(self.bytes.as_slice())),
            ],
        )
    }

    /// Reads an `AdapterSync`.
    pub fn read(message: &Message, connection: ConnectionKind) -> Result<Self, TransportClass> {
        of_type(message, MessageType::AdapterSync)?;
        Ok(Self {
            scope: Scope::read(field(&message.map, 1)?, connection)?,
            adapter: text(&message.map, 2)?.to_owned(),
            bytes: bytes(&message.map, 3)?.to_vec(),
        })
    }
}

/// `Ephemeral = {0: 48, 1: scope, 2: an outer frame, 3: origin (8 bytes;
/// from a peer only)}`: ext-ephemeral.md's outer frame, which this document
/// only carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ephemeral {
    /// The scope.
    pub scope: Scope,
    /// The outer frame.
    pub frame: Vec<u8>,
    /// The origin a relaying peer adds.
    pub origin: Option<[u8; 8]>,
}

impl Ephemeral {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            (1, self.scope.value()),
            (2, Value::from(self.frame.as_slice())),
        ];
        if let Some(origin) = self.origin {
            entries.push((3, Value::from(origin)));
        }
        encode(MessageType::Ephemeral, entries)
    }

    /// Reads an `Ephemeral`.
    pub fn read(message: &Message, connection: ConnectionKind) -> Result<Self, TransportClass> {
        of_type(message, MessageType::Ephemeral)?;
        let map = &message.map;
        Ok(Self {
            scope: Scope::read(field(map, 1)?, connection)?,
            frame: bytes(map, 2)?.to_vec(),
            origin: map.contains_key(&3).then(|| array(map, 3)).transpose()?,
        })
    }
}

/// `Gone = {0: 49, 1: scope, 2: origin (8 bytes)}`, from a relaying peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gone {
    /// The scope.
    pub scope: Scope,
    /// The origin gone.
    pub origin: [u8; 8],
}

impl Gone {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            MessageType::Gone,
            [(1, self.scope.value()), (2, Value::from(self.origin))],
        )
    }

    /// Reads a `Gone`.
    pub fn read(message: &Message, connection: ConnectionKind) -> Result<Self, TransportClass> {
        of_type(message, MessageType::Gone)?;
        Ok(Self {
            scope: Scope::read(field(&message.map, 1)?, connection)?,
            origin: array(&message.map, 2)?,
        })
    }
}

/// `Pairing = {0: 64, 1: one message of admission.md's exchange, 2: a member
/// ticket, its text form}`. Key 2 travels beside the welcome only
/// (section 3.16); [`crate::ticket::Ticket::read`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    /// admission.md's message.
    pub message: Vec<u8>,
    /// The member ticket the host sends beside the welcome.
    pub ticket: Option<String>,
}

impl Pairing {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![(1, Value::from(self.message.as_slice()))];
        if let Some(ticket) = &self.ticket {
            entries.push((2, Value::from(ticket.as_str())));
        }
        encode(MessageType::Pairing, entries)
    }

    /// Reads a `Pairing`: the message's bytes, and the ticket's text if
    /// key 2 is present.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        of_type(message, MessageType::Pairing)?;
        let map = &message.map;
        Ok(Self {
            message: bytes(map, 1)?.to_vec(),
            ticket: map
                .contains_key(&2)
                .then(|| text(map, 2).map(str::to_owned))
                .transpose()?,
        })
    }
}

/// A peer's answer to an erasure held late (peers.md, "A device's own erasure").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureLate {
    /// The space ID.
    pub space: [u8; 32],
    /// The erasure event ID.
    pub erasure: [u8; 32],
    /// The signed envelope of the cut in effect.
    pub cut: Vec<u8>,
    /// The ID of that cut's checkpoint.
    pub checkpoint: [u8; 32],
    /// The slot's standing: enrolled to this pseudonym, listed otherwise, or absent.
    pub standing: u8,
}

impl ErasureLate {
    /// Encodes the message. Standing must be 0, 1 or 2.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            MessageType::ErasureLate,
            [
                (1, self.space.into()),
                (2, self.erasure.into()),
                (3, self.cut.clone().into()),
                (4, self.checkpoint.into()),
                (5, u64::from(self.standing).into()),
            ],
        )
    }

    /// Reads exactly keys 0 to 5 and a standing of 0, 1 or 2.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        exactly(message, MessageType::ErasureLate, &[0, 1, 2, 3, 4, 5])?;
        let standing = uint(&message.map, 5)?;
        if standing > 2 {
            return Err(malformed());
        }
        Ok(Self {
            space: array(&message.map, 1)?,
            erasure: array(&message.map, 2)?,
            cut: bytes(&message.map, 3)?.to_vec(),
            checkpoint: array(&message.map, 4)?,
            standing: standing as u8,
        })
    }
}
