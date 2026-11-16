//! The messages (ext-deposit-tokens.md, 2.5 Messages).
//!
//! ```text
//! TokenKeysGet = {0: 40, 1: request}
//! TokenKeys    = {0: 41, 1: request, 2: keys}
//! keys         = array of 1 or 2 arrays [key ID (32), public key (32), role]
//!                role: 1 issuing, 2 accepting only; exactly one issuing
//! TokenRequest = {0: 42, 1: request, 2: grant (bytes, at most 512) or 5: space (32),
//!                 3: key ID (32), 4: blinded (array of 1 to 256 elements of 32 bytes)}
//! TokenIssue   = {0: 43, 1: request, 2: evaluated (array of 1 to 256 elements
//!                 of 32 bytes), 3: proof (64)}
//! MailboxPut, kind 3, with a token
//!              = {0: 24, 1: request, 2: address (32), 3: item, 6: 3, 7: token (129)}
//! ```
//!
//! Each travels on the control stream of a space-traffic connection, and
//! has exactly these keys; transport's framing has read its type and cap.
//! Each reader here takes the message's map and checks the form its
//! receiver's procedure checks first: [`TokenRequest::read`] is section
//! 3.4's step 1, [`TokenIssue::read`] section 3.5's, [`TokenPut::read`]
//! section 3.7's. A `TokenKeys` is read by
//! [`KeyList::read`](crate::device::KeyList::read), with section 3.2's
//! checks.

use frasil_base::cbor::{self, Map, Value};
use frasil_transport::frame::MAILBOX_ITEM_BYTES;
use frasil_transport::mailbox::{Kind, TOKEN_KEY};

use crate::errors::{TokenClass, malformed};
use crate::key::{KEY_ID_BYTES, KeyId, Role};
use crate::suite::{ELEMENT_BYTES, PROOF_BYTES};
use crate::token::{TOKEN_BYTES, Token};
use crate::{MAX_BATCH, MAX_GRANT_BYTES, TOKEN_ISSUE, TOKEN_KEYS, TOKEN_KEYS_GET, TOKEN_REQUEST};

/// `MailboxPut`'s message type.
const MAILBOX_PUT: u64 = 24;

/// Whether a map has exactly these keys.
fn exactly(map: &Map, keys: &[u64]) -> bool {
    map.len() == keys.len() && keys.iter().all(|key| map.contains_key(key))
}

fn field(map: &Map, key: u64) -> Result<&Value, TokenClass> {
    map.get(&key).ok_or_else(malformed)
}

fn of_type(map: &Map, kind: u64) -> Result<(), TokenClass> {
    if field(map, 0)?.as_unsigned()? != kind {
        return Err(malformed());
    }
    Ok(())
}

fn encode(kind: u64, entries: impl IntoIterator<Item = (u64, Value)>) -> Vec<u8> {
    let mut map = Map::new();
    map.insert(0, Value::Unsigned(kind));
    map.extend(entries);
    Value::Map(map).encode()
}

/// An array of 1 to `most` byte strings of 32 bytes.
fn elements(value: &Value, most: usize) -> Result<Vec<[u8; ELEMENT_BYTES]>, TokenClass> {
    let items = value.as_array()?;
    if items.is_empty() || items.len() > most {
        return Err(malformed());
    }
    Ok(items
        .iter()
        .map(Value::as_byte_array::<ELEMENT_BYTES>)
        .collect::<Result<_, _>>()?)
}

fn decode(bytes: &[u8]) -> Result<Map, TokenClass> {
    Ok(cbor::decode(bytes)?.as_map()?.clone())
}

/// `TokenKeysGet`: a device asks for the peer's live keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenKeysGet {
    /// Key 1.
    pub request: u64,
}

impl TokenKeysGet {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(TOKEN_KEYS_GET, [(1, Value::Unsigned(self.request))])
    }

    /// Reads the message: exactly keys 0 and 1, `request` unsigned.
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else.
    pub fn read(map: &Map) -> Result<Self, TokenClass> {
        of_type(map, TOKEN_KEYS_GET)?;
        if !exactly(map, &[0, 1]) {
            return Err(malformed());
        }
        Ok(Self {
            request: field(map, 1)?.as_unsigned()?,
        })
    }

    /// Reads the message from its bytes.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn decode(bytes: &[u8]) -> Result<Self, TokenClass> {
        Self::read(&decode(bytes)?)
    }
}

/// One entry of `TokenKeys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyEntry {
    /// The key ID.
    pub key_id: KeyId,
    /// The public key.
    pub public: [u8; ELEMENT_BYTES],
    /// Issuing or accepting only.
    pub role: Role,
}

/// `TokenKeys`: the peer's live keys, one or two, exactly one issuing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenKeys {
    /// Key 1: the `TokenKeysGet` it answers.
    pub request: u64,
    /// Key 2.
    pub keys: Vec<KeyEntry>,
}

impl TokenKeys {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        let keys = self
            .keys
            .iter()
            .map(|key| {
                Value::Array(vec![
                    Value::from(key.key_id),
                    Value::from(key.public),
                    Value::Unsigned(key.role.code()),
                ])
            })
            .collect();
        encode(
            TOKEN_KEYS,
            [(1, Value::Unsigned(self.request)), (2, Value::Array(keys))],
        )
    }
}

/// How a `TokenRequest` draws (ext-deposit-tokens.md, 3.1 Two ways in).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Draw {
    /// Key 2: a grant draw, with the grant as the issuer handed it over.
    Grant(Vec<u8>),
    /// Key 5: a space draw, as a writer of this space.
    Space([u8; 32]),
}

/// `TokenRequest`: a batch of blinded elements to evaluate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenRequest {
    /// Key 1.
    pub request: u64,
    /// Key 2 or key 5.
    pub draw: Draw,
    /// Key 3: the issuing key the device took from its key list.
    pub key_id: KeyId,
    /// Key 4: the blinded elements, as sent.
    pub blinded: Vec<[u8; ELEMENT_BYTES]>,
}

impl TokenRequest {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        let draw = match &self.draw {
            Draw::Grant(grant) => (2, Value::from(grant.as_slice())),
            Draw::Space(space) => (5, Value::from(*space)),
        };
        encode(
            TOKEN_REQUEST,
            [
                (1, Value::Unsigned(self.request)),
                draw,
                (3, Value::from(self.key_id)),
                (
                    4,
                    Value::Array(self.blinded.iter().map(|e| Value::from(*e)).collect()),
                ),
            ],
        )
    }

    /// Section 3.4, step 1: keys 0, 1, 3 and 4, and exactly one of 2 and
    /// 5, and no other; `request` unsigned; `grant` a byte string of at
    /// most 512 bytes, or `space` of 32 bytes; key ID of 32 bytes;
    /// `blinded` an array of 1 to 256 byte strings of 32 bytes. Whether
    /// each element deserializes is step 2, the peer's.
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else.
    pub fn read(map: &Map) -> Result<Self, TokenClass> {
        of_type(map, TOKEN_REQUEST)?;
        let draw = if map.contains_key(&2) {
            if !exactly(map, &[0, 1, 2, 3, 4]) {
                return Err(malformed());
            }
            let grant = field(map, 2)?.as_bytes()?;
            if grant.len() > MAX_GRANT_BYTES {
                return Err(malformed());
            }
            Draw::Grant(grant.to_vec())
        } else {
            if !exactly(map, &[0, 1, 3, 4, 5]) {
                return Err(malformed());
            }
            Draw::Space(field(map, 5)?.as_byte_array()?)
        };
        Ok(Self {
            request: field(map, 1)?.as_unsigned()?,
            draw,
            key_id: field(map, 3)?.as_byte_array::<KEY_ID_BYTES>()?,
            blinded: elements(field(map, 4)?, MAX_BATCH)?,
        })
    }

    /// Reads the message from its bytes, by [`read`](Self::read).
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn decode(bytes: &[u8]) -> Result<Self, TokenClass> {
        Self::read(&decode(bytes)?)
    }
}

/// `TokenIssue`: the evaluated elements and one proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenIssue {
    /// Key 1: the `TokenRequest` it answers.
    pub request: u64,
    /// Key 2: the evaluated elements, in order.
    pub evaluated: Vec<[u8; ELEMENT_BYTES]>,
    /// Key 3: RFC 9497's serialized proof.
    pub proof: [u8; PROOF_BYTES],
}

impl TokenIssue {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            TOKEN_ISSUE,
            [
                (1, Value::Unsigned(self.request)),
                (
                    2,
                    Value::Array(self.evaluated.iter().map(|e| Value::from(*e)).collect()),
                ),
                (3, Value::from(self.proof)),
            ],
        )
    }

    /// Section 3.5, step 1: exactly keys 0 to 3; `request` names the
    /// `TokenRequest` it answers; `evaluated` an array of m byte strings of
    /// 32 bytes, 1 <= m <= `sent`, the number of elements the device sent;
    /// `proof` of 64 bytes.
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else.
    pub fn read(map: &Map, request: u64, sent: usize) -> Result<Self, TokenClass> {
        of_type(map, TOKEN_ISSUE)?;
        if !exactly(map, &[0, 1, 2, 3]) || field(map, 1)?.as_unsigned()? != request {
            return Err(malformed());
        }
        Ok(Self {
            request,
            evaluated: elements(field(map, 2)?, sent.min(MAX_BATCH))?,
            proof: field(map, 3)?.as_byte_array()?,
        })
    }

    /// Reads the message from its bytes, by [`read`](Self::read).
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn decode(bytes: &[u8], request: u64, sent: usize) -> Result<Self, TokenClass> {
        Self::read(&decode(bytes)?, request, sent)
    }
}

/// `MailboxPut` of kind 3 with key 7: a deposit paid with a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenPut {
    /// Key 1.
    pub request: u64,
    /// Key 2: the device mailbox's address.
    pub address: [u8; 32],
    /// Key 3: the item.
    pub item: Vec<u8>,
    /// Key 7: the token.
    pub token: Token,
}

impl TokenPut {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        encode(
            MAILBOX_PUT,
            [
                (1, Value::Unsigned(self.request)),
                (2, Value::from(self.address)),
                (3, Value::from(self.item.as_slice())),
                (6, Value::Unsigned(Kind::Device.code().into())),
                (TOKEN_KEY, Value::from(*self.token.as_bytes())),
            ],
        )
    }

    /// Section 3.7, step 1, on the WebSocket and the iroh binding: exactly
    /// keys 0, 1, 2, 3, 6 and 7; kind 3; `address` of 32 bytes; `item` a
    /// byte string; `token` of 129 bytes. The token's version and the
    /// item's size are steps 2 and 3, the peer's.
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else.
    pub fn read(map: &Map) -> Result<Self, TokenClass> {
        of_type(map, MAILBOX_PUT)?;
        if !exactly(map, &[0, 1, 2, 3, 6, TOKEN_KEY])
            || field(map, 6)?.as_unsigned()? != u64::from(Kind::Device.code())
        {
            return Err(malformed());
        }
        let token = field(map, TOKEN_KEY)?.as_bytes()?;
        if token.len() != TOKEN_BYTES {
            return Err(malformed());
        }
        Ok(Self {
            request: field(map, 1)?.as_unsigned()?,
            address: field(map, 2)?.as_byte_array()?,
            item: field(map, 3)?.as_bytes()?.to_vec(),
            token: Token::from_bytes(token)?,
        })
    }

    /// Reads the message from its bytes, by [`read`](Self::read).
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn decode(bytes: &[u8]) -> Result<Self, TokenClass> {
        Self::read(&decode(bytes)?)
    }
}

/// The most bytes of an item a token pays for.
pub const MAX_ITEM_BYTES: usize = MAILBOX_ITEM_BYTES;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_read_back() {
        let get = TokenKeysGet { request: 3 };
        assert_eq!(TokenKeysGet::decode(&get.encode()), Ok(get));
        let request = TokenRequest {
            request: 1,
            draw: Draw::Space([5; 32]),
            key_id: [7; 32],
            blinded: vec![[1; 32], [2; 32]],
        };
        assert_eq!(TokenRequest::decode(&request.encode()), Ok(request.clone()));
        let grant = TokenRequest {
            draw: Draw::Grant(vec![0x80]),
            ..request
        };
        assert_eq!(TokenRequest::decode(&grant.encode()), Ok(grant));
        let issue = TokenIssue {
            request: 1,
            evaluated: vec![[1; 32]],
            proof: [2; 64],
        };
        assert_eq!(TokenIssue::decode(&issue.encode(), 1, 1), Ok(issue.clone()));
        assert_eq!(TokenIssue::decode(&issue.encode(), 2, 1), Err(malformed()));
        assert_eq!(TokenIssue::decode(&issue.encode(), 1, 0), Err(malformed()));
        let put = TokenPut {
            request: 4,
            address: [9; 32],
            item: vec![1, 2, 3],
            token: Token::new(&[1; 32], &[2; 32], &[3; 64]),
        };
        assert_eq!(TokenPut::decode(&put.encode()), Ok(put));
    }

    #[test]
    fn a_request_with_both_draws_or_neither_is_malformed() {
        let mut map = Map::new();
        map.insert(0, Value::Unsigned(TOKEN_REQUEST));
        map.insert(1, Value::Unsigned(1));
        map.insert(3, Value::from([0u8; 32]));
        map.insert(4, Value::Array(vec![Value::from([0u8; 32])]));
        assert_eq!(TokenRequest::read(&map), Err(malformed()));
        map.insert(2, Value::from(vec![0u8]));
        map.insert(5, Value::from([0u8; 32]));
        assert_eq!(TokenRequest::read(&map), Err(malformed()));
        map.remove(&5);
        map.insert(2, Value::from(vec![0u8; MAX_GRANT_BYTES + 1]));
        assert_eq!(TokenRequest::read(&map), Err(malformed()));
    }
}
