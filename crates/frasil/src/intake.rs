//! The client's readers: every byte another party or the store hands the
//! device goes through one of these first, each in its document's order.
//! Each failure names the class its document gives, by name.
//!
//! - [`read_event`]: events.md, "Decoding an event". The device decodes
//!   every event it is sent with it ([`Engine::ingest`](crate::advanced::Engine)).
//! - [`verify_hybrid`]: events.md, "The ML-DSA-65 half", under keys from
//!   any source that hash to the event's `kc`.
//! - [`read_unit`]: units.md, "A unit, at a peer" and "A unit, at a member",
//!   steps 1 to 14, under one content key, as the replica opens a unit.
//! - [`read_sync`]: units.md, "Sync messages", for every sync message a
//!   session receives.
//! - [`read_message`]: transport.md, "Reading a frame", steps 2 to 6, for
//!   every message of a connection's stream or WebSocket.
//! - [`read_frame`]: transport.md, "Reading a frame", from a stream's
//!   bytes.
//! - [`open_device_keys`], [`open_record`], [`open_mark`] and
//!   [`continuity`]: at-rest.md, "Sealing and opening the device keys",
//!   "Opening a record", "The mark" and "Continuity", as the device opens
//!   its store.

use frasil_base::errors::Class;
use frasil_crypto::device::{DeviceId, KeySource};
use frasil_events::{Event, VerifiedEvent};
use frasil_store::{
    Continuity, DeviceKeys, Head, LogKeys, Opened, RestoreMode, StoreKeys, device_keys::KeyKind,
};
use frasil_transport::frame::{ConnectionKind, Extensions, Message, Read, StreamClass};
use frasil_units::Inner;
use frasil_units::messages::{Received, SyncMessage};
use frasil_units::stream::StreamId;
use frasil_units::unit::Unit;

/// A refusal, by the class's name in UpperCamelCase.
pub type Refused = &'static str;

/// events.md, "Decoding an event": every check, in order.
///
/// # Errors
///
/// The first check's class.
pub fn read_event(signed: &[u8]) -> Result<Event, Refused> {
    frasil_events::decode(signed).map_err(Class::name)
}

/// events.md, "The ML-DSA-65 half": under the keys `keys` holds for the
/// event's `kc`, from any source (crypto.md, "Keys by their hash").
///
/// # Errors
///
/// `NoHybridKey` when no keys hash to the event's `kc` (pending, not
/// final); `BadSignature` when the half does not verify under them.
pub fn verify_hybrid(
    event: &Event,
    keys: &(impl KeySource + ?Sized),
) -> Result<VerifiedEvent, Refused> {
    event.verify_hybrid_in(keys).map_err(Class::name)
}

/// units.md, sections 3.1 and 3.2, steps 1 to 14, under `content_key`:
/// the envelope, the visible body, the seal and the sealed part. A key
/// received whole is `provisional`, and a seal it fails to open is
/// `Sealed`, not `BadSeal`.
///
/// # Errors
///
/// The first step's class.
pub fn read_unit(
    signed: &[u8],
    content_key: &[u8; 32],
    provisional: bool,
    system: Option<&StreamId>,
) -> Result<Inner, Refused> {
    Unit::check_at_peer(signed)
        .and_then(|unit| unit.open_with(content_key, provisional, system))
        .map_err(Class::name)
}

/// units.md, "Sync messages": `None` for a message of an ignorable type,
/// which the receiver drops.
///
/// # Errors
///
/// `Malformed`, `TooLarge` or `UnknownMessage`.
pub fn read_sync(bytes: &[u8]) -> Result<Option<SyncMessage>, Refused> {
    match frasil_units::messages::SyncMessage::read(bytes).map_err(Class::name)? {
        Received::Message(message) => Ok(Some(message)),
        Received::Ignored { .. } => Ok(None),
    }
}

/// transport.md, "Reading a frame", steps 2 to 6, on one message: `None`
/// for an unknown type in 96 to 127, which the receiver drops.
///
/// # Errors
///
/// The first step's class.
pub fn read_message(
    payload: &[u8],
    class: StreamClass,
    connection: ConnectionKind,
) -> Result<Option<Message>, Refused> {
    frasil_transport::frame::read_message(payload, class, connection, Extensions::NONE)
        .map_err(Class::name)
}

/// What [`read_frame`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Framed {
    /// Not a whole frame yet: read on.
    ReadOn,
    /// A message.
    Message(Message),
    /// An unknown type in 96 to 127: dropped.
    Dropped,
}

/// transport.md, "Reading a frame", steps 1 to 6, on the front of a
/// stream's bytes.
///
/// # Errors
///
/// The first step's class.
pub fn read_frame(
    bytes: &[u8],
    class: StreamClass,
    connection: ConnectionKind,
) -> Result<Framed, Refused> {
    match frasil_transport::frame::read_frame(bytes, class, connection, Extensions::NONE)
        .map_err(Class::name)?
    {
        Read::Incomplete => Ok(Framed::ReadOn),
        Read::Message(message, _) => Ok(Framed::Message(message)),
        Read::Dropped(_) => Ok(Framed::Dropped),
    }
}

/// at-rest.md, "Sealing and opening the device keys": `open_device_keys`,
/// in order.
///
/// # Errors
///
/// The first step's class.
pub fn open_device_keys(
    blob: &[u8],
    kind: KeyKind,
    unlock_key: &[u8; 32],
    person: &[u8; 32],
    device: Option<&DeviceId>,
) -> Result<DeviceKeys, Refused> {
    frasil_store::open_device_keys(blob, kind, unlock_key, person, device).map_err(Class::name)
}

/// at-rest.md, "Opening a record": `open(address, record, log or none)`,
/// in order.
///
/// # Errors
///
/// The first step's class.
pub fn open_record(
    store: &StoreKeys,
    log: Option<&LogKeys>,
    address: &[u8],
    record: &[u8],
) -> Result<Opened, Refused> {
    frasil_store::open_record(store, log, address, record).map_err(Class::name)
}

/// at-rest.md, "The mark": its store ID and generation.
///
/// # Errors
///
/// The first step's class.
pub fn open_mark(
    store: &StoreKeys,
    device: &DeviceId,
    mark: &[u8],
) -> Result<([u8; 16], u64), Refused> {
    frasil_store::open_mark(store, device, mark).map_err(Class::name)
}

/// at-rest.md, "Continuity": `continuity(mode, head, mark)`.
pub fn continuity(
    store: &StoreKeys,
    device: &DeviceId,
    mode: RestoreMode,
    head: Option<&Head>,
    mark: Option<&[u8]>,
) -> Continuity {
    frasil_store::continuity(store, device, mode, head, mark)
}
