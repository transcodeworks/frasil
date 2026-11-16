//! The envelope, what is signed, and the event ID (events.md, "The
//! envelope", "Field rules" and "What is signed, and the event ID").
//!
//! An event is a deterministic CBOR map:
//!
//! | Key | Field | Type | Value |
//! |---|---|---|---|
//! | 0 | `version` | unsigned | `1` |
//! | 1 | `kind` | unsigned | the kind |
//! | 2 | `log` | bytes(32) | the log ID; absent in a genesis |
//! | 3 | `ed` | bytes(32) | the author's Ed25519 identity key |
//! | 4 | `seq` | unsigned | the author's sequence number in this log, from 1 |
//! | 5 | `prev` | bytes(32) | the ID of the author's event at `seq − 1`; absent when `seq` is 1 |
//! | 6 | `parents` | array of bytes(32) | IDs of events of this log, strictly ascending |
//! | 7 | `cuts` | array of bytes(32) | the checkpoints the event follows: 1 to 4 event IDs of this log, strictly ascending; absent when its past holds no checkpoint, and in a genesis |
//! | 8 | `body` | bytes | the kind's body |
//! | 9 | `scheme` | unsigned | absent for scheme 0; `2` for scheme 2 |
//! | 10 | `kc` | bytes(32) | the author's keys commitment |
//!
//! The event's **author** is the device ID of keys 3 and 10,
//! `SHA-256("frasil/device-id/v1" || ed || kc)` (crypto.md, "A device's
//! keys"): chains, fork evidence and every reference to an event's author
//! name it, never `ed`.
//!
//! ```text
//! signed event = CBOR array [event, signature]
//! tbs          = "frasil/event/v1" || event
//! event ID     = SHA-256("frasil/event-id/v1" || event)
//! ```
//!
//! The ID leaves out the signature: two signed copies of one map are one
//! event with one ID.

use core::fmt;
use frasil_base::cbor;
use frasil_crypto::device::{DeviceId, IdentityKey, KeysCommitment, device_id};
use frasil_crypto::labels::{EVENT, EVENT_ID};
use frasil_crypto::primitives::sha256;
use frasil_crypto::schemes::{Scheme, Signer};

/// The envelope's version.
pub const VERSION: u64 = 1;

/// Key 0, `version`.
pub const KEY_VERSION: u64 = 0;
/// Key 1, `kind`.
pub const KEY_KIND: u64 = 1;
/// Key 2, `log`.
pub const KEY_LOG: u64 = 2;
/// Key 3, `ed`.
pub const KEY_ED: u64 = 3;
/// Key 4, `seq`.
pub const KEY_SEQ: u64 = 4;
/// Key 5, `prev`.
pub const KEY_PREV: u64 = 5;
/// Key 6, `parents`.
pub const KEY_PARENTS: u64 = 6;
/// Key 7, `cuts`: the checkpoints the event follows (events.md, 3.11
/// Cuts). Refs to other logs travel sealed in the body, never here.
pub const KEY_CUTS: u64 = 7;
/// Key 8, `body`.
pub const KEY_BODY: u64 = 8;
/// Key 9, `scheme`.
pub const KEY_SCHEME: u64 = 9;
/// Key 10, `kc`.
pub const KEY_KC: u64 = 10;

/// An event ID: SHA-256 under `frasil/event-id/v1` of the event's map
/// bytes. A log ID, a space ID and a person ID are the IDs of a genesis.
///
/// Its order is the byte order, by which canonical order breaks ties.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId(pub [u8; 32]);

impl EventId {
    /// The ID's 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for EventId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for EventId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventId({self})")
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("…")
    }
}

/// `tbs = "frasil/event/v1" || event`: what an event's signature signs,
/// key 9 included.
pub fn tbs(event: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(EVENT.len() + event.len());
    out.extend_from_slice(EVENT);
    out.extend_from_slice(event);
    out
}

/// The event ID of an event's map bytes:
/// `SHA-256("frasil/event-id/v1" || event)`.
pub fn event_id(event: &[u8]) -> EventId {
    EventId(sha256(&[EVENT_ID, event]))
}

/// The signed event, `[event, signature]`, as a deterministic CBOR array of
/// two byte strings.
pub fn assemble(event: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(event.len() + signature.len() + 12);
    cbor::array_head(&mut out, 2);
    cbor::bytes(&mut out, event);
    cbor::bytes(&mut out, signature);
    out
}

/// An event's fields: everything in its map but the version, which is
/// always 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The kind (events.md, "Kinds").
    pub kind: u8,
    /// The log ID; `None` in a genesis.
    pub log: Option<EventId>,
    /// The author's Ed25519 identity key, `ed`.
    pub ed: IdentityKey,
    /// The author's keys commitment, `kc`.
    pub kc: KeysCommitment,
    /// The author's sequence number in this log, from 1.
    pub seq: u64,
    /// The ID of the author's event at `seq − 1`; `None` when `seq` is 1.
    pub prev: Option<EventId>,
    /// IDs of events of this log: the heads the author holds, with `prev`.
    /// [`encode`](Envelope::encode) writes them strictly ascending.
    pub parents: Vec<EventId>,
    /// `cuts`: the checkpoints the event follows, the maximal ones its
    /// parents give (events.md, 3.11 Cuts); empty when its past holds no
    /// checkpoint, and in a genesis. [`encode`](Envelope::encode) writes
    /// them strictly ascending, and leaves key 7 out when there is none.
    /// [`cuts::expected`](crate::cuts::expected) gives the ones to declare.
    pub cuts: Vec<EventId>,
    /// The kind's body.
    pub body: Vec<u8>,
    /// The signature scheme, which the map carries as key 9.
    pub scheme: Scheme,
}

impl Envelope {
    /// Whether this is a genesis: it has no `log`.
    pub fn is_genesis(&self) -> bool {
        self.log.is_none()
    }

    /// The author: the device ID of `ed` and `kc`.
    pub fn author(&self) -> DeviceId {
        device_id(&self.ed, &self.kc)
    }

    /// The map's bytes, the one deterministic encoding. Parents and cuts
    /// are written strictly ascending, each once, whatever their order
    /// here; key 7 is left out when there is no cut.
    pub fn encode(&self) -> Vec<u8> {
        let mut parents = self.parents.clone();
        parents.sort_unstable();
        parents.dedup();
        let mut cuts = self.cuts.clone();
        cuts.sort_unstable();
        cuts.dedup();
        let count = 7
            + usize::from(self.log.is_some())
            + usize::from(self.prev.is_some())
            + usize::from(!cuts.is_empty())
            + usize::from(self.scheme != Scheme::Ed25519);
        let mut out = Vec::with_capacity(self.body.len() + 33 * (parents.len() + cuts.len()) + 160);
        cbor::map_head(&mut out, count);
        cbor::unsigned(&mut out, KEY_VERSION);
        cbor::unsigned(&mut out, VERSION);
        cbor::unsigned(&mut out, KEY_KIND);
        cbor::unsigned(&mut out, u64::from(self.kind));
        if let Some(log) = &self.log {
            cbor::unsigned(&mut out, KEY_LOG);
            cbor::bytes(&mut out, &log.0);
        }
        cbor::unsigned(&mut out, KEY_ED);
        cbor::bytes(&mut out, &self.ed.0);
        cbor::unsigned(&mut out, KEY_SEQ);
        cbor::unsigned(&mut out, self.seq);
        if let Some(prev) = &self.prev {
            cbor::unsigned(&mut out, KEY_PREV);
            cbor::bytes(&mut out, &prev.0);
        }
        cbor::unsigned(&mut out, KEY_PARENTS);
        cbor::array_head(&mut out, parents.len());
        for parent in &parents {
            cbor::bytes(&mut out, &parent.0);
        }
        if !cuts.is_empty() {
            cbor::unsigned(&mut out, KEY_CUTS);
            cbor::array_head(&mut out, cuts.len());
            for cut in &cuts {
                cbor::bytes(&mut out, &cut.0);
            }
        }
        cbor::unsigned(&mut out, KEY_BODY);
        cbor::bytes(&mut out, &self.body);
        if self.scheme != Scheme::Ed25519 {
            cbor::unsigned(&mut out, KEY_SCHEME);
            cbor::unsigned(&mut out, u64::from(self.scheme.code()));
        }
        cbor::unsigned(&mut out, KEY_KC);
        cbor::bytes(&mut out, &self.kc.0);
        out
    }

    /// The event's ID.
    pub fn id(&self) -> EventId {
        event_id(&self.encode())
    }

    /// The signed event: the map signed by `signer` under the envelope's
    /// scheme, scheme 2 deterministically. The signer's Ed25519 key must be
    /// the envelope's `ed`, or the event fails decoding, and its keys must
    /// hash to `kc`, or its ML-DSA-65 half fails.
    pub fn sign(&self, signer: &Signer) -> Vec<u8> {
        let event = self.encode();
        let signature = signer.sign(self.scheme, &tbs(&event));
        assemble(&event, &signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parents_are_written_ascending_once() {
        let a = EventId([1; 32]);
        let b = EventId([2; 32]);
        let mut envelope = Envelope {
            kind: 4,
            log: Some(EventId([9; 32])),
            ed: IdentityKey([3; 32]),
            kc: KeysCommitment([4; 32]),
            seq: 1,
            prev: None,
            parents: vec![b, a, b],
            cuts: Vec::new(),
            body: vec![],
            scheme: Scheme::Ed25519,
        };
        let shuffled = envelope.encode();
        envelope.parents = vec![a, b];
        assert_eq!(shuffled, envelope.encode());
        let value = cbor::decode(&shuffled).unwrap();
        assert_eq!(value.as_map().unwrap().len(), 8);
    }

    #[test]
    fn cuts_are_written_ascending_once_and_only_when_present() {
        let a = EventId([1; 32]);
        let b = EventId([2; 32]);
        let mut envelope = Envelope {
            kind: 4,
            log: Some(EventId([9; 32])),
            ed: IdentityKey([3; 32]),
            kc: KeysCommitment([4; 32]),
            seq: 1,
            prev: None,
            parents: vec![a],
            cuts: Vec::new(),
            body: vec![],
            scheme: Scheme::Ed25519,
        };
        let without = envelope.encode();
        assert!(
            cbor::decode(&without)
                .unwrap()
                .as_map()
                .unwrap()
                .get(&KEY_CUTS)
                .is_none()
        );
        envelope.cuts = vec![b, a, b];
        let shuffled = envelope.encode();
        envelope.cuts = vec![a, b];
        assert_eq!(shuffled, envelope.encode());
        assert_ne!(shuffled, without);
        let value = cbor::decode(&shuffled).unwrap();
        let map = value.as_map().unwrap();
        assert_eq!(map.len(), 9);
        let cuts = map.get(&KEY_CUTS).unwrap().as_array().unwrap();
        assert_eq!(cuts.len(), 2);
        assert_eq!(cuts[0].as_byte_array::<32>().unwrap(), a.0);
        assert_eq!(cuts[1].as_byte_array::<32>().unwrap(), b.0);
        // The ID hashes the map, cuts included.
        assert_ne!(event_id(&shuffled), event_id(&without));
    }

    #[test]
    fn ids_display_briefly() {
        let id = EventId([0xab; 32]);
        assert_eq!(id.to_string(), "abababababababab…");
        assert_eq!(format!("{id:?}"), "EventId(abababababababab…)");
    }
}
