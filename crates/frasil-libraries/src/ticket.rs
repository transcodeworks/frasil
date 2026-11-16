//! The library ID and the signed library ticket (ext-libraries.md, 2.1 The
//! library ID, and 2.2 The library ticket).
//!
//! ```text
//! ticket    = deterministic CBOR map {
//!               1: version, 1,
//!               2: library, text: a library ID,
//!               3: id, bytes(16): random, drawn by the issuer,
//!               4: purpose, unsigned: 1 create, 2 import, 3 move,
//!                  4 deposit tokens (ext-deposit-tokens.md),
//!               5: not_after, unsigned: a wall-clock instant,
//!               6: issuer, bytes(32): the issuer's Ed25519 public key,
//!               7: tokens, unsigned: 1 to 256; exactly for purpose 4 }
//! signed    = CBOR array [ticket (bytes), signature (bytes)]   at most 512 bytes
//! signature = Ed25519-Sign(issuer's seed, "frasil/library-ticket/v1" || ticket)
//! ```
//!
//! Purpose 4 and key 7 make a **deposit grant** (ext-deposit-tokens.md, 2.3
//! The deposit grant). Only a build with the `ext-deposit-tokens` feature
//! reads one, and only where the caller says the peer implements that
//! extension; anywhere else both are `Malformed`, as at a core peer.

use core::fmt;

use frasil_base::cbor::{self, Malformed, Value};
use frasil_crypto::labels::LIBRARY_TICKET;
use frasil_crypto::sizes::{ED25519_PUBLIC, ED25519_SIGNATURE};

use crate::errors::LibraryClass;

/// The ticket format's version, key 1.
pub const VERSION: u64 = 1;

/// The most bytes a signed ticket may hold.
pub const MAX_TICKET_BYTES: usize = 512;

/// The most bytes of UTF-8 a library ID may hold.
pub const MAX_LIBRARY_ID_BYTES: usize = 128;

/// The bytes of a ticket ID.
pub const TICKET_ID_BYTES: usize = 16;

/// The most tokens a deposit grant names, key 7 (ext-deposit-tokens.md, 2.3
/// The deposit grant); the fewest is 1.
pub const MAX_GRANT_TOKENS: u64 = 256;

/// Whether this build reads deposit grants where the caller asks it to.
const fn reads_grants(grants: bool) -> bool {
    grants && cfg!(feature = "ext-deposit-tokens")
}

/// A ticket's ID: 16 random bytes the issuer draws. A peer keeps each ID
/// that attached a space until its `not_after` and `ticket_skew` have passed
/// (ext-libraries.md, 2.5 What a peer keeps).
pub type TicketId = [u8; TICKET_ID_BYTES];

/// The message an issuer signs: `"frasil/library-ticket/v1" || ticket`.
pub fn signed_message(ticket: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(LIBRARY_TICKET.len() + ticket.len());
    message.extend_from_slice(LIBRARY_TICKET);
    message.extend_from_slice(ticket);
    message
}

// ---------------------------------------------------------------------------
// The library ID.

/// A library ID (ext-libraries.md, 2.1 The library ID): 1 to 128 bytes of
/// UTF-8, with no control character (Unicode category Cc) and not only
/// white space. It is the operator's or the issuer's name for a billing
/// pool, opaque to the peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LibraryId(String);

impl LibraryId {
    /// Checks `text` as a library ID.
    ///
    /// # Errors
    ///
    /// `Malformed` for text that breaks a rule of section 2.1.
    pub fn new(text: &str) -> Result<Self, LibraryClass> {
        if Self::is_valid(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(Malformed.into())
        }
    }

    /// Whether `text` is a library ID.
    pub fn is_valid(text: &str) -> bool {
        frasil_base::notation::text_ok(text, MAX_LIBRARY_ID_BYTES)
    }

    /// The ID's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LibraryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for LibraryId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Purposes.

/// What a ticket is for, key 4: attaching a space (ext-libraries.md, 3.3
/// Attaching), or drawing deposit tokens (ext-deposit-tokens.md, 2.3 The
/// deposit grant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Purpose {
    /// 1: the space is new to the peer.
    Create,
    /// 2: the space comes to the peer with its history.
    Import,
    /// 3: the space is hosted at the peer, in another library or in none.
    Move,
    /// 4: a deposit grant, which draws deposit tokens against the library
    /// once (ext-deposit-tokens.md). It attaches nothing, and
    /// `LibraryAttach` never carries it.
    Deposit,
}

impl Purpose {
    /// Every purpose a space attaches for, in code order: those
    /// `LibraryAttach` carries.
    pub const ALL: [Purpose; 3] = [Purpose::Create, Purpose::Import, Purpose::Move];

    /// The purpose's code on the wire.
    pub const fn code(self) -> u64 {
        match self {
            Self::Create => 1,
            Self::Import => 2,
            Self::Move => 3,
            Self::Deposit => 4,
        }
    }

    /// The purpose of a code, or `None` for any other code. Whether a
    /// reader takes purpose 4 is its own rule.
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Create),
            2 => Some(Self::Import),
            3 => Some(Self::Move),
            4 => Some(Self::Deposit),
            _ => None,
        }
    }

    /// Whether a space attaches for this purpose: every purpose but 4.
    pub const fn attaches(self) -> bool {
        !matches!(self, Self::Deposit)
    }

    /// The purpose's name: `create`, `import`, `move` or `deposit`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Import => "import",
            Self::Move => "move",
            Self::Deposit => "deposit",
        }
    }

    /// The purpose of a name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .chain([Self::Deposit])
            .find(|purpose| purpose.name() == name)
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// The ticket.

/// A library ticket's fields (ext-libraries.md, 2.2 The library ticket). It
/// names a library and never an account, a person, a device or a space.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ticket {
    /// Key 2: the library the ticket attaches a space to.
    pub library: LibraryId,
    /// Key 3: random, drawn by the issuer.
    pub id: TicketId,
    /// Key 4: what the ticket attaches a space for.
    pub purpose: Purpose,
    /// Key 5: the wall-clock instant, in seconds since 1970, after which the
    /// ticket is expired.
    pub not_after: u64,
    /// Key 6: the issuer's Ed25519 public key.
    pub issuer: [u8; ED25519_PUBLIC],
    /// Key 7: the tokens a deposit grant names, 1 to 256; present exactly
    /// for purpose 4.
    pub tokens: Option<u64>,
}

impl Ticket {
    /// The ticket's deterministic CBOR map, the bytes the issuer signs
    /// after the label.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(100 + self.library.as_str().len());
        cbor::map_head(&mut out, if self.tokens.is_some() { 7 } else { 6 });
        cbor::unsigned(&mut out, 1);
        cbor::unsigned(&mut out, VERSION);
        cbor::unsigned(&mut out, 2);
        cbor::text(&mut out, self.library.as_str());
        cbor::unsigned(&mut out, 3);
        cbor::bytes(&mut out, &self.id);
        cbor::unsigned(&mut out, 4);
        cbor::unsigned(&mut out, self.purpose.code());
        cbor::unsigned(&mut out, 5);
        cbor::unsigned(&mut out, self.not_after);
        cbor::unsigned(&mut out, 6);
        cbor::bytes(&mut out, &self.issuer);
        if let Some(tokens) = self.tokens {
            cbor::unsigned(&mut out, 7);
            cbor::unsigned(&mut out, tokens);
        }
        out
    }

    /// Reads a ticket's map by the rules of `check_ticket`, step 1: a
    /// deterministic CBOR map of exactly keys 1 to 6; version 1; a library
    /// ID by section 2.1; `id` of 16 bytes; purpose 1, 2 or 3; `not_after`
    /// unsigned; `issuer` of 32 bytes.
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else, purpose 4 and key 7 included.
    pub fn decode(bytes: &[u8]) -> Result<Self, LibraryClass> {
        Self::decode_with_grants(bytes, false)
    }

    /// Reads a ticket's map as [`decode`](Self::decode) does, and, where
    /// `grants` says the peer implements ext-deposit-tokens.md and the
    /// build has its feature, a deposit grant: purpose 4 with key 7, 1 to
    /// 256 tokens.
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else.
    pub fn decode_with_grants(bytes: &[u8], grants: bool) -> Result<Self, LibraryClass> {
        decode_ticket(bytes, reads_grants(grants)).map_err(LibraryClass::from)
    }
}

fn decode_ticket(bytes: &[u8], grants: bool) -> Result<Ticket, Malformed> {
    let value = cbor::decode(bytes)?;
    let map = value.as_map()?;
    let grant = grants && map.get(&4).and_then(|v| v.as_unsigned().ok()) == Some(4);
    let keys = if grant { 7 } else { 6 };
    if map.len() != keys || !(1..=keys as u64).all(|key| map.contains_key(&key)) {
        return Err(Malformed);
    }
    if map[&1].as_unsigned()? != VERSION {
        return Err(Malformed);
    }
    let library = map[&2].as_text()?;
    if !LibraryId::is_valid(library) {
        return Err(Malformed);
    }
    let id = map[&3].as_byte_array::<TICKET_ID_BYTES>()?;
    let purpose = Purpose::from_code(map[&4].as_unsigned()?)
        .filter(|purpose| purpose.attaches() || grant)
        .ok_or(Malformed)?;
    let not_after = map[&5].as_unsigned()?;
    let issuer = map[&6].as_byte_array::<ED25519_PUBLIC>()?;
    let tokens = if grant {
        let tokens = map[&7].as_unsigned()?;
        if !(1..=MAX_GRANT_TOKENS).contains(&tokens) {
            return Err(Malformed);
        }
        Some(tokens)
    } else {
        None
    };
    Ok(Ticket {
        library: LibraryId(library.to_owned()),
        id,
        purpose,
        not_after,
        issuer,
        tokens,
    })
}

// ---------------------------------------------------------------------------
// The signed ticket.

/// A signed ticket as a peer reads it: the ticket's fields, the exact bytes
/// the issuer signed, and the signature. Reading it checks only the form
/// (`check_ticket`, step 1); [`check_ticket`](crate::check::check_ticket)
/// checks the rest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignedTicket {
    /// The ticket's fields.
    pub ticket: Ticket,
    /// The ticket's bytes, as signed.
    pub ticket_bytes: Vec<u8>,
    /// `Ed25519-Sign(issuer's seed, "frasil/library-ticket/v1" || ticket)`.
    pub signature: [u8; ED25519_SIGNATURE],
}

impl SignedTicket {
    /// `check_ticket`, step 1 (ext-libraries.md, 3.2 Checking a ticket):
    /// `len(signed) <= 512`; a CBOR array of two byte strings, the second
    /// of 64 bytes; the first a ticket by [`Ticket::decode`].
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else.
    pub fn decode(signed: &[u8]) -> Result<Self, LibraryClass> {
        Self::decode_with_grants(signed, false)
    }

    /// `check_ticket`, step 1, reading a deposit grant where `grants` says
    /// the peer implements ext-deposit-tokens.md
    /// ([`Ticket::decode_with_grants`]).
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else.
    pub fn decode_with_grants(signed: &[u8], grants: bool) -> Result<Self, LibraryClass> {
        decode_signed(signed, reads_grants(grants)).map_err(LibraryClass::from)
    }

    /// `CBOR array [ticket (bytes), signature (bytes)]`.
    pub fn encode(&self) -> Vec<u8> {
        encode_signed(&self.ticket_bytes, &self.signature)
    }

    /// The message the issuer signed.
    pub fn signed_message(&self) -> Vec<u8> {
        signed_message(&self.ticket_bytes)
    }
}

/// `CBOR array [ticket (bytes), signature (bytes)]`, from a ticket's bytes
/// and its signature.
pub fn encode_signed(ticket: &[u8], signature: &[u8; ED25519_SIGNATURE]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ticket.len() + ED25519_SIGNATURE + 6);
    cbor::array_head(&mut out, 2);
    cbor::bytes(&mut out, ticket);
    cbor::bytes(&mut out, signature);
    out
}

fn decode_signed(signed: &[u8], grants: bool) -> Result<SignedTicket, Malformed> {
    if signed.len() > MAX_TICKET_BYTES {
        return Err(Malformed);
    }
    let outer = cbor::decode(signed)?;
    let [ticket_bytes, signature] = outer.as_array()? else {
        return Err(Malformed);
    };
    let signature = signature.as_byte_array::<ED25519_SIGNATURE>()?;
    let ticket_bytes = match ticket_bytes {
        Value::Bytes(bytes) => bytes,
        _ => return Err(Malformed),
    };
    let ticket = decode_ticket(ticket_bytes, grants)?;
    Ok(SignedTicket {
        ticket,
        ticket_bytes: ticket_bytes.clone(),
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket() -> Ticket {
        Ticket {
            library: LibraryId::new("project:1").unwrap(),
            id: [7; 16],
            purpose: Purpose::Import,
            not_after: 1_792_000_000,
            issuer: [9; 32],
            tokens: None,
        }
    }

    #[test]
    fn a_ticket_round_trips() {
        let t = ticket();
        assert_eq!(Ticket::decode(&t.encode()).unwrap(), t);
        let signed = encode_signed(&t.encode(), &[3; 64]);
        let read = SignedTicket::decode(&signed).unwrap();
        assert_eq!(read.ticket, t);
        assert_eq!(read.encode(), signed);
    }

    #[test]
    fn a_grant_reads_only_where_the_peer_implements_deposit_tokens() {
        let malformed = LibraryClass::Shared(frasil_base::ErrorClass::Malformed);
        let grant = Ticket {
            purpose: Purpose::Deposit,
            tokens: Some(16),
            ..ticket()
        };
        let bytes = grant.encode();
        assert_eq!(Ticket::decode(&bytes).unwrap_err(), malformed);
        assert_eq!(
            Ticket::decode_with_grants(&bytes, true),
            if cfg!(feature = "ext-deposit-tokens") {
                Ok(grant.clone())
            } else {
                Err(malformed)
            }
        );
        // 0 and 257 tokens, no key 7, and key 7 on another purpose.
        for changed in [
            Ticket {
                tokens: Some(0),
                ..grant.clone()
            },
            Ticket {
                tokens: Some(MAX_GRANT_TOKENS + 1),
                ..grant.clone()
            },
            Ticket {
                tokens: None,
                ..grant.clone()
            },
            Ticket {
                purpose: Purpose::Import,
                ..grant.clone()
            },
        ] {
            assert_eq!(
                Ticket::decode_with_grants(&changed.encode(), true).unwrap_err(),
                malformed
            );
        }
        let most = Ticket {
            tokens: Some(MAX_GRANT_TOKENS),
            ..grant
        };
        assert_eq!(
            Ticket::decode_with_grants(&most.encode(), true).is_ok(),
            cfg!(feature = "ext-deposit-tokens")
        );
    }

    #[test]
    fn library_ids_follow_the_rules() {
        assert!(LibraryId::is_valid("personal:ab"));
        assert!(LibraryId::is_valid(" a "));
        assert!(LibraryId::is_valid(&"é".repeat(64)));
        assert!(!LibraryId::is_valid(&"é".repeat(65)));
        assert!(!LibraryId::is_valid(""));
        assert!(!LibraryId::is_valid(" \u{3000}\t"));
        assert!(!LibraryId::is_valid("a\u{7}"));
        assert!(!LibraryId::is_valid("a\u{85}"));
        assert!(LibraryId::is_valid(&"x".repeat(128)));
        assert!(!LibraryId::is_valid(&"x".repeat(129)));
    }

    #[test]
    fn step_one_refuses_each_rule() {
        let malformed = LibraryClass::Shared(frasil_base::ErrorClass::Malformed);
        let good = ticket().encode();
        // Another version, an extra key, a missing key, a short ID, another
        // purpose and a short issuer.
        let mut map = cbor::decode(&good).unwrap().as_map().unwrap().clone();
        for (key, value) in [
            (1, Value::Unsigned(2)),
            (3, Value::Bytes(vec![0; 15])),
            (4, Value::Unsigned(4)),
            (4, Value::Unsigned(0)),
            (5, Value::Text("1".into())),
            (6, Value::Bytes(vec![0; 31])),
            (2, Value::Bytes(b"project:1".to_vec())),
        ] {
            let mut changed = map.clone();
            changed.insert(key, value);
            assert_eq!(
                Ticket::decode(&Value::Map(changed).encode()).unwrap_err(),
                malformed
            );
        }
        map.insert(7, Value::Unsigned(0));
        assert_eq!(
            Ticket::decode(&Value::Map(map.clone()).encode()).unwrap_err(),
            malformed
        );
        map.remove(&7);
        map.remove(&5);
        assert_eq!(
            Ticket::decode(&Value::Map(map).encode()).unwrap_err(),
            malformed
        );
        // The outer array: three items, a short signature, a ticket as text,
        // trailing bytes and too many bytes.
        let sig = Value::Bytes(vec![0; 64]);
        let bytes = Value::Bytes(good.clone());
        for outer in [
            Value::Array(vec![bytes.clone(), sig.clone(), sig.clone()]),
            Value::Array(vec![bytes.clone(), Value::Bytes(vec![0; 63])]),
            Value::Array(vec![Value::Text("x".into()), sig.clone()]),
            Value::Array(vec![bytes.clone()]),
            Value::Map(Default::default()),
        ] {
            assert_eq!(
                SignedTicket::decode(&outer.encode()).unwrap_err(),
                malformed
            );
        }
        let mut trailing = encode_signed(&good, &[0; 64]);
        trailing.push(0);
        assert_eq!(SignedTicket::decode(&trailing).unwrap_err(), malformed);
        let long = Ticket {
            library: LibraryId::new(&"x".repeat(128)).unwrap(),
            ..ticket()
        };
        let mut signed = encode_signed(&long.encode(), &[0; 64]);
        assert!(signed.len() <= MAX_TICKET_BYTES);
        signed.resize(MAX_TICKET_BYTES + 1, 0);
        assert_eq!(SignedTicket::decode(&signed).unwrap_err(), malformed);
    }
}
