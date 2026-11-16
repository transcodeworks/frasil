//! `LibraryAttach`, message type 21 (ext-libraries.md, 2.3 LibraryAttach).
//!
//! ```text
//! LibraryAttach = {0: 21, 1: request, 2: space (32), 3: purpose, 4: signed}
//! ```
//!
//! It travels on the control stream of a space-traffic connection, and only
//! to a peer whose `PeerHello` lists service 5. It has exactly these keys.
//! The peer answers `Accepted`, or `Refused` with a code. The signed ticket
//! travels as opaque bytes: the device never reads it, and the peer checks
//! it with [`check_ticket`](crate::check::check_ticket).

use frasil_base::cbor::{self, Malformed, Map};

use crate::LIBRARY_ATTACH;
use crate::errors::LibraryClass;
use crate::ticket::Purpose;

/// The bytes of a space ID.
pub const SPACE_BYTES: usize = 32;

/// A `LibraryAttach` message.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LibraryAttach {
    /// Key 1: numbers it among the device's requests on the connection.
    pub request: u64,
    /// Key 2: the space it attaches.
    pub space: [u8; SPACE_BYTES],
    /// Key 3: create, import or move.
    pub purpose: Purpose,
    /// Key 4: the signed ticket, as the issuer handed it over.
    pub signed: Vec<u8>,
}

impl LibraryAttach {
    /// The message's deterministic CBOR map.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.signed.len() + 64);
        cbor::map_head(&mut out, 5);
        cbor::unsigned(&mut out, 0);
        cbor::unsigned(&mut out, LIBRARY_ATTACH);
        cbor::unsigned(&mut out, 1);
        cbor::unsigned(&mut out, self.request);
        cbor::unsigned(&mut out, 2);
        cbor::bytes(&mut out, &self.space);
        cbor::unsigned(&mut out, 3);
        cbor::unsigned(&mut out, self.purpose.code());
        cbor::unsigned(&mut out, 4);
        cbor::bytes(&mut out, &self.signed);
        out
    }

    /// Reads the message's map, as transport's framing read it: exactly
    /// keys 0 to 4; key 0 is 21; `request` unsigned; `space` of 32 bytes;
    /// `purpose` 1, 2 or 3; `signed` a byte string. The ticket inside is
    /// not read here.
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else.
    pub fn read(map: &Map) -> Result<Self, LibraryClass> {
        read_map(map).map_err(LibraryClass::from)
    }

    /// Reads the message from its bytes: one deterministic CBOR map, by
    /// [`read`](Self::read).
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else.
    pub fn decode(bytes: &[u8]) -> Result<Self, LibraryClass> {
        let value = cbor::decode(bytes).map_err(LibraryClass::from)?;
        Self::read(value.as_map().map_err(LibraryClass::from)?)
    }
}

fn read_map(map: &Map) -> Result<LibraryAttach, Malformed> {
    if map.len() != 5 || !(0..=4).all(|key| map.contains_key(&key)) {
        return Err(Malformed);
    }
    if map[&0].as_unsigned()? != LIBRARY_ATTACH {
        return Err(Malformed);
    }
    Ok(LibraryAttach {
        request: map[&1].as_unsigned()?,
        space: map[&2].as_byte_array::<SPACE_BYTES>()?,
        purpose: Purpose::from_code(map[&3].as_unsigned()?)
            .filter(|purpose| purpose.attaches())
            .ok_or(Malformed)?,
        signed: map[&4].as_bytes()?.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::cbor::Value;

    fn attach() -> LibraryAttach {
        LibraryAttach {
            request: 7,
            space: [3; 32],
            purpose: Purpose::Import,
            signed: vec![0x82, 0x40, 0x40],
        }
    }

    #[test]
    fn a_message_reads_back() {
        let message = attach();
        let bytes = message.encode();
        assert_eq!(LibraryAttach::decode(&bytes), Ok(message));
        assert_eq!(cbor::decode(&bytes).unwrap().encode(), bytes);
    }

    #[test]
    fn other_keys_and_values_are_malformed() {
        let malformed = Err(LibraryClass::from(Malformed));
        let map = || {
            cbor::decode(&attach().encode())
                .unwrap()
                .as_map()
                .unwrap()
                .clone()
        };
        let mut extra = map();
        extra.insert(5, Value::Unsigned(0));
        assert_eq!(LibraryAttach::read(&extra), malformed);
        let mut missing = map();
        missing.remove(&4);
        assert_eq!(LibraryAttach::read(&missing), malformed);
        let mut kind = map();
        kind.insert(0, Value::Unsigned(22));
        assert_eq!(LibraryAttach::read(&kind), malformed);
        let mut purpose = map();
        purpose.insert(3, Value::Unsigned(4));
        assert_eq!(LibraryAttach::read(&purpose), malformed);
        let mut space = map();
        space.insert(2, Value::from(&[0u8; 31][..]));
        assert_eq!(LibraryAttach::read(&space), malformed);
        let mut signed = map();
        signed.insert(4, Value::from("text"));
        assert_eq!(LibraryAttach::read(&signed), malformed);
    }
}
