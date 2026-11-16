//! Tickets (transport.md, section 2.8 "Tickets").
//!
//! ```text
//! ticket = {1: 1, 2: kind (1 member, 2 peer, 3 nearby), 3: endpoint key (32),
//!           4: relay URLs (array of 1 to 4 https URLs; optional),
//!           5: direct addresses (array of 1 to 16: 4 bytes IPv4 or 16 bytes IPv6,
//!              then a 2-byte port; optional)}
//! text   = "frasil:" || base64url(ticket), without padding
//! ```
//!
//! A ticket is an address to dial. It holds no secret and grants nothing.

use crate::TransportClass;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_crypto::keys::ed25519_valid;

/// The text form's prefix.
pub const PREFIX: &str = "frasil:";
/// The most bytes of a ticket's CBOR.
pub const MAX_BYTES: usize = 1_024;
/// The most relay URLs.
pub const MAX_RELAYS: usize = 4;
/// The most direct addresses.
pub const MAX_ADDRESSES: usize = 16;
/// The ticket format's version, key 1.
pub const VERSION: u64 = 1;

/// What a ticket dials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TicketKind {
    /// 1: a member endpoint.
    Member,
    /// 2: an always-on peer.
    Peer,
    /// 3: a nearby endpoint.
    Nearby,
}

impl TicketKind {
    /// The kind's code.
    pub const fn code(self) -> u64 {
        match self {
            Self::Member => 1,
            Self::Peer => 2,
            Self::Nearby => 3,
        }
    }

    /// The kind of a code.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Member),
            2 => Some(Self::Peer),
            3 => Some(Self::Nearby),
            _ => None,
        }
    }
}

/// A direct address: an IPv4 or IPv6 address, then a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Address {
    /// 4 bytes of IPv4 and a port.
    V4([u8; 4], u16),
    /// 16 bytes of IPv6 and a port.
    V6([u8; 16], u16),
}

impl Address {
    /// The address's bytes: the IP address, then `u16be(port)`.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::V4(ip, port) => [&ip[..], &port.to_be_bytes()].concat(),
            Self::V6(ip, port) => [&ip[..], &port.to_be_bytes()].concat(),
        }
    }

    /// Reads 6 or 18 bytes.
    pub fn read(bytes: &[u8]) -> Option<Self> {
        let (ip, port) = bytes.split_last_chunk::<2>()?;
        let port = u16::from_be_bytes(*port);
        match ip.len() {
            4 => Some(Self::V4(ip.try_into().ok()?, port)),
            16 => Some(Self::V6(ip.try_into().ok()?, port)),
            _ => None,
        }
    }
}

/// A ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    /// What it dials.
    pub kind: TicketKind,
    /// The endpoint key the dialer names.
    pub endpoint: [u8; 32],
    /// Relay URLs, each `https`; empty when the ticket names none.
    pub relays: Vec<String>,
    /// Direct addresses; empty when the ticket names none.
    pub addresses: Vec<Address>,
}

impl Ticket {
    /// The ticket's CBOR.
    pub fn cbor(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION));
        map.insert(2, Value::Unsigned(self.kind.code()));
        map.insert(3, Value::from(self.endpoint));
        if !self.relays.is_empty() {
            map.insert(
                4,
                Value::Array(
                    self.relays
                        .iter()
                        .map(|r| Value::from(r.as_str()))
                        .collect(),
                ),
            );
        }
        if !self.addresses.is_empty() {
            map.insert(
                5,
                Value::Array(
                    self.addresses
                        .iter()
                        .map(|a| Value::Bytes(a.encode()))
                        .collect(),
                ),
            );
        }
        Value::Map(map).encode()
    }

    /// The ticket's text: `"frasil:" || base64url(ticket)`, without
    /// padding.
    ///
    /// # Errors
    ///
    /// `TooLarge` over 1,024 bytes of CBOR; `Malformed` for more than 4
    /// relays or 16 addresses, or a relay URL that is not `https`.
    pub fn encode(&self) -> Result<String, TransportClass> {
        if self.relays.len() > MAX_RELAYS
            || self.addresses.len() > MAX_ADDRESSES
            || !self.relays.iter().all(|r| r.starts_with("https://"))
        {
            return Err(ErrorClass::Malformed.into());
        }
        let raw = self.cbor();
        if raw.len() > MAX_BYTES {
            return Err(ErrorClass::TooLarge.into());
        }
        Ok(format!("{PREFIX}{}", base64url::encode(&raw)))
    }

    /// Reads a ticket's text.
    ///
    /// # Errors
    ///
    /// `Malformed` for another prefix, padding, a base64url or CBOR
    /// encoding that is not canonical, more than 1,024 bytes, an unknown
    /// key, a relay array that is empty, too long or not all `https`, or
    /// direct addresses of another shape; then `InvalidKey` for an endpoint
    /// key crypto.md refuses.
    pub fn read(text: &str) -> Result<Self, TransportClass> {
        let malformed = || TransportClass::from(ErrorClass::Malformed);
        let encoded = text.strip_prefix(PREFIX).ok_or_else(malformed)?;
        if encoded.contains('=') || encoded.len() > 4 * MAX_BYTES / 3 + 4 {
            return Err(malformed());
        }
        let raw = base64url::decode(encoded).ok_or_else(malformed)?;
        Self::read_cbor(&raw)
    }

    /// Reads a ticket's CBOR, by the checks of [`Ticket::read`] that follow
    /// the base64url decoding, as `Addresses` carries it (transport.md,
    /// "The iroh binding", member addresses) and at-rest.md's `endpoint`
    /// table keeps it.
    ///
    /// # Errors
    ///
    /// As [`Ticket::read`].
    pub fn read_cbor(raw: &[u8]) -> Result<Self, TransportClass> {
        let malformed = || TransportClass::from(ErrorClass::Malformed);
        if raw.len() > MAX_BYTES {
            return Err(malformed());
        }
        let value = cbor::decode(raw)?;
        let map = value.as_map()?;
        if map.get(&1) != Some(&Value::Unsigned(VERSION))
            || map.keys().any(|k| !(1..=5).contains(k))
        {
            return Err(malformed());
        }
        let kind = map
            .get(&2)
            .and_then(|v| v.as_unsigned().ok())
            .and_then(TicketKind::from_code)
            .ok_or_else(malformed)?;
        let endpoint: [u8; 32] = map.get(&3).ok_or_else(malformed)?.as_byte_array()?;
        let mut relays = Vec::new();
        if let Some(value) = map.get(&4) {
            let items = value.as_array()?;
            if !(1..=MAX_RELAYS).contains(&items.len()) {
                return Err(malformed());
            }
            for item in items {
                let url = item.as_text()?;
                if !url.starts_with("https://") {
                    return Err(malformed());
                }
                relays.push(url.to_owned());
            }
        }
        let mut addresses = Vec::new();
        if let Some(value) = map.get(&5) {
            let items = value.as_array()?;
            if !(1..=MAX_ADDRESSES).contains(&items.len()) {
                return Err(malformed());
            }
            for item in items {
                addresses.push(Address::read(item.as_bytes()?).ok_or_else(malformed)?);
            }
        }
        ed25519_valid(&endpoint)?;
        Ok(Self {
            kind,
            endpoint,
            relays,
            addresses,
        })
    }
}

/// base64url (RFC 4648, section 5) without padding, with one accepted
/// encoding per byte string.
pub mod base64url {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// Encodes bytes, without padding.
    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let mut block = [0u8; 3];
            block[..chunk.len()].copy_from_slice(chunk);
            let n = u32::from_be_bytes([0, block[0], block[1], block[2]]);
            for i in 0..=chunk.len() {
                let index = (n >> (18 - 6 * i)) & 0x3f;
                out.push(char::from(ALPHABET[index as usize]));
            }
        }
        out
    }

    fn digit(c: u8) -> Option<u32> {
        ALPHABET.iter().position(|&a| a == c).map(|p| p as u32)
    }

    /// Decodes text without padding. `None` for a character outside the
    /// alphabet, a length that no byte string has, or unused bits that are
    /// not zero: only [`encode`]'s output decodes.
    pub fn decode(text: &str) -> Option<Vec<u8>> {
        let text = text.as_bytes();
        if text.len() % 4 == 1 {
            return None;
        }
        let mut out = Vec::with_capacity(text.len() / 4 * 3 + 2);
        for chunk in text.chunks(4) {
            let mut n = 0u32;
            for (i, &c) in chunk.iter().enumerate() {
                n |= digit(c)? << (18 - 6 * i);
            }
            let bytes = n.to_be_bytes();
            let kept = chunk.len() - 1;
            out.extend_from_slice(&bytes[1..=kept]);
            // The bits after the last byte are zero.
            if bytes[kept + 1..].iter().any(|&b| b != 0) {
                return None;
            }
        }
        Some(out)
    }
}
