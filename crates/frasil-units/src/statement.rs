//! Head statements (units.md, section 2.13, and section 3.13, "Heads,
//! acknowledgements and durability").
//!
//! ```text
//! statement = deterministic CBOR map {
//!               1: version, 1,
//!               2: space ID, bytes(32),
//!               3: device, bytes(64): its ed || kc (crypto.md),
//!               4: heads, array of 1 to 256 event IDs, strictly ascending,
//!               5: streams, optional: array of 1 to 64 pairs
//!                  [stream (bytes(16)), array of 1 to 4,096 pairs [writer, unit ID],
//!                   strictly ascending by writer],
//!                  strictly ascending by stream }
//! signed    = CBOR array [statement, signature]
//! signature = Ed25519, by the device's ed, over
//!             "frasil/head-statement/v1" || statement                    (scheme 0)
//! ```
//!
//! Key 5 states, for streams the device holds whole, each writer's stream
//! frontier. A statement is not an event and decides no validity,
//! stability or policy. It names a device, so it never reaches a peer in
//! the clear.

use crate::body::{Cover, covers_value, read_covers};
use crate::limits::{MAX_HEADS, MAX_STATEMENT_BYTES, MAX_STATEMENT_STREAMS};
use crate::stream::{self, StreamId};
use crate::{UnitClass, UnitError};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Malformed, Map, Value};
use frasil_crypto::device::{DeviceId, Signatory};
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::labels::HEAD_STATEMENT;
use frasil_crypto::primitives::ed25519_sign;
use frasil_crypto::schemes::ed25519_verify_strict;
use frasil_crypto::sizes::ED25519_SIGNATURE;
use frasil_events::EventId;

/// The statement's version.
pub const VERSION: u64 = 1;

/// A head statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadStatement {
    /// Key 2: the space.
    pub space: EventId,
    /// Key 3: the device's `ed || kc` (crypto.md, "A device's keys"); the
    /// statement names the device ID they give.
    pub device: Signatory,
    /// Key 4: 1 to 256 heads, ascending.
    pub heads: Vec<EventId>,
    /// Key 5: for streams the device holds whole, each writer's stream
    /// frontier; empty for none.
    pub streams: Vec<(StreamId, Vec<Cover>)>,
}

impl HeadStatement {
    /// The statement's deterministic encoding. Heads and streams are written
    /// ascending; key 5 is left out when there is no stream.
    pub fn encode(&self) -> Vec<u8> {
        let mut heads = self.heads.clone();
        heads.sort_unstable();
        heads.dedup();
        let mut map = Map::from([
            (1, Value::from(VERSION)),
            (2, Value::from(self.space.0)),
            (3, Value::from(self.device.to_bytes())),
            (
                4,
                Value::Array(heads.into_iter().map(|id| Value::from(id.0)).collect()),
            ),
        ]);
        if !self.streams.is_empty() {
            let mut streams = self.streams.clone();
            streams.sort_unstable_by_key(|(stream, _)| *stream);
            map.insert(
                5,
                Value::Array(
                    streams
                        .iter()
                        .map(|(stream, covers)| {
                            Value::Array(vec![Value::from(*stream), covers_value(covers)])
                        })
                        .collect(),
                ),
            );
        }
        Value::Map(map).encode()
    }

    /// Signs the statement under scheme 0 with the device's identity seed:
    /// `[statement, Ed25519("frasil/head-statement/v1" || statement)]`.
    pub fn sign(&self, identity_seed: &[u8; 32]) -> Vec<u8> {
        sign_statement(identity_seed, &self.encode())
    }

    /// Reads a signed head statement, in order: at most 65,536 bytes
    /// (`TooLarge`); the array and the map, with their types, limits and
    /// orders (`Malformed`), version 1 (`UnsupportedVersion`); then, as a
    /// receiver checks it, the signature under `device`'s `ed`
    /// (`BadSignature`); the space (`WrongSpace`); `device`'s `ed` is a
    /// valid key (`InvalidKey`), and the device ID of `device` is a member
    /// in the receiver's merged roster (`NotAMember`). A statement that
    /// fails is ignored.
    ///
    /// # Errors
    ///
    /// The first check that fails, as above.
    pub fn read(
        signed: &[u8],
        space: &EventId,
        is_member: impl Fn(&DeviceId) -> bool,
    ) -> Result<Self, UnitError> {
        if signed.len() > MAX_STATEMENT_BYTES {
            return Err(ErrorClass::TooLarge.into());
        }
        let outer = cbor::decode(signed)?;
        let [statement, signature] = outer.as_array()? else {
            return Err(ErrorClass::Malformed.into());
        };
        let statement_bytes = statement.as_bytes()?;
        let signature = signature.as_bytes()?;
        if signature.len() != ED25519_SIGNATURE {
            return Err(ErrorClass::Malformed.into());
        }
        let statement = Self::decode(statement_bytes)?;
        let mut message = HEAD_STATEMENT.to_vec();
        message.extend_from_slice(statement_bytes);
        if !ed25519_verify_strict(&statement.device.ed.0, &message, signature) {
            return Err(ErrorClass::BadSignature.into());
        }
        if statement.space != *space {
            return Err(UnitClass::WrongSpace.into());
        }
        ed25519_valid(&statement.device.ed.0)?;
        if !is_member(&statement.device.device_id()) {
            return Err(ErrorClass::NotAMember.into());
        }
        Ok(statement)
    }

    /// Reads a statement's map, without its signature: only
    /// [`read`](Self::read) uses it, before it checks the signature.
    ///
    /// # Errors
    ///
    /// `Malformed` or `UnsupportedVersion`.
    fn decode(data: &[u8]) -> Result<Self, UnitError> {
        let value = cbor::decode(data)?;
        let map = value.as_map()?;
        let version = map.get(&1).ok_or(Malformed)?.as_unsigned()?;
        if version != VERSION {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        if map.keys().any(|key| !(1..=5).contains(key)) || !(2..=4).all(|k| map.contains_key(&k)) {
            return Err(ErrorClass::Malformed.into());
        }
        let space = EventId(map[&2].as_byte_array()?);
        let device = Signatory::from_bytes(map[&3].as_bytes()?)?;
        let items = map[&4].as_array()?;
        if items.is_empty() || items.len() > MAX_HEADS {
            return Err(ErrorClass::Malformed.into());
        }
        let heads = items
            .iter()
            .map(|item| item.as_byte_array().map(EventId))
            .collect::<Result<Vec<_>, _>>()?;
        if !heads.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ErrorClass::Malformed.into());
        }
        let streams = match map.get(&5) {
            Some(value) => read_streams(value)?,
            None => Vec::new(),
        };
        Ok(Self {
            space,
            device,
            heads,
            streams,
        })
    }
}

/// Key 5: 1 to 64 pairs `[stream, 1 to 4,096 covers]`, ascending by stream.
fn read_streams(value: &Value) -> Result<Vec<(StreamId, Vec<Cover>)>, Malformed> {
    let items = value.as_array()?;
    if items.is_empty() || items.len() > MAX_STATEMENT_STREAMS {
        return Err(Malformed);
    }
    let mut streams: Vec<(StreamId, Vec<Cover>)> = Vec::with_capacity(items.len());
    for item in items {
        let [stream, covers] = item.as_array()? else {
            return Err(Malformed);
        };
        let stream = stream.as_bytes()?;
        if !stream::is_valid(stream) {
            return Err(Malformed);
        }
        let stream: StreamId = stream.try_into().map_err(|_| Malformed)?;
        let covers = read_covers(covers)?;
        if covers.is_empty() || streams.last().is_some_and(|(last, _)| *last >= stream) {
            return Err(Malformed);
        }
        streams.push((stream, covers));
    }
    Ok(streams)
}

/// Signs a statement's bytes under scheme 0.
pub fn sign_statement(identity_seed: &[u8; 32], statement: &[u8]) -> Vec<u8> {
    let mut message = HEAD_STATEMENT.to_vec();
    message.extend_from_slice(statement);
    let signature = ed25519_sign(identity_seed, &message);
    Value::Array(vec![Value::from(statement), Value::from(signature)]).encode()
}
