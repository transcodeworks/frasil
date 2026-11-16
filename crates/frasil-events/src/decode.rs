//! Decoding an event (events.md, "Decoding an event") and its ML-DSA-65
//! half (events.md, "The ML-DSA-65 half").
//!
//! [`decode`] runs every check of the document on a signed event, in order,
//! before anything else:
//!
//! ```text
//!  1. len(signed) <= 16,777,216.                                    else TooLarge
//!  2. signed is a deterministic CBOR array of two byte strings,
//!     with nothing after it.                                        else Malformed
//!  3. event is a deterministic CBOR map whose key 0 is unsigned.    else Malformed
//!  4. version = 1.                                                  else UnsupportedVersion
//!  5. Its keys are among 0 to 10; keys 1, 3, 4, 6, 8 and 10 are
//!     present.                                                      else Malformed
//!  6. Key 9, if present, is unsigned and not 0.                     else Malformed
//!  7. kind is 1 to 127, and not 3.                                  else Malformed
//!  8. scheme is 0 or 2.                                             else UnsupportedVersion
//!  9. scheme is one the kind may carry.                             else SchemeNotAllowed
//! 10. len(signature) = 64 for scheme 0, 3,373 for scheme 2.         else Malformed
//! 11. seq >= 1; ed and kc are 32 bytes each; body is bytes; log
//!     and prev, if present, are 32 bytes; parents is an array of
//!     32-byte strings, strictly ascending; cuts, if present, an
//!     array of 1 to 4 32-byte strings, strictly ascending.          else Malformed
//! 12. A genesis's shape, of kind 1 or 2; parents outside a
//!     genesis; prev present exactly when seq > 1, and among the
//!     parents; an anchor's body empty; no cuts in a genesis.        else Malformed
//! 13. A kind from 1 to 63 is one this replica knows.                else UnknownKind
//! 14. The kind's size and parent limits.                            else TooLarge
//! 15. ed passes ed25519_valid.                                      else InvalidKey
//! 16. Scheme 0: the signature verifies strictly over tbs under ed.
//!     Scheme 2: its Ed25519 half verifies strictly over m_ed
//!     under ed, with no other key.                                  else BadSignature
//! ```
//!
//! Whether an event's cuts are the ones its parents give is no question for
//! decoding: it needs the parents (events.md, 3.11 Cuts), and
//! [`cuts::check`](crate::cuts::check) answers it.
//!
//! No value of `kc` fails here: any 32 bytes may be a commitment. Whether
//! `kc` commits to keys the author holds is [`Event::verify_hybrid`]'s
//! question; it yields a [`VerifiedEvent`].
//!
//! These include crypto.md's `verify`, steps 1 to 4. A kind from 7 to 63
//! passes steps 8 and 9 under scheme 0 or 2 (crypto.md's `KindPolicy`), so
//! that step 13 refuses it as `UnknownKind`.

use crate::EventClass;
use crate::envelope::{
    self, Envelope, EventId, KEY_BODY, KEY_CUTS, KEY_ED, KEY_KC, KEY_KIND, KEY_LOG, KEY_PARENTS,
    KEY_PREV, KEY_SCHEME, KEY_SEQ, KEY_VERSION, VERSION,
};
use crate::kind;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, KeyRules, Malformed, Reader, UnknownKeys, Value};
use frasil_crypto::device::{
    DeviceId, HybridKeys, IdentityKey, KeySource, KeysCommitment, device_id,
};
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::schemes::{self, KindPolicy, Scheme, Signed};
use std::sync::Arc;

/// The keys an envelope may hold: 0 to 10.
const ENVELOPE_KEYS: KeyRules<'static> = KeyRules {
    required: &[KEY_KIND, KEY_ED, KEY_SEQ, KEY_PARENTS, KEY_BODY, KEY_KC],
    optional: &[KEY_VERSION, KEY_LOG, KEY_PREV, KEY_CUTS, KEY_SCHEME],
    unknown: UnknownKeys::Malformed,
};

/// A decoded event whose Ed25519 signature, or Ed25519 half, is checked:
/// its envelope's fields, its map's bytes, its signature and its ID.
///
/// An `Event` passed every check of [`decode`]: for scheme 0 its signature
/// verified, for scheme 2 its Ed25519 half did, and nothing else. It is what
/// a peer stores and serves (peers.md, 3.2 Storing an event), and what a
/// replica places and keeps pending while a scheme-2 event is `NoHybridKey`
/// (events.md, 3.3 The ML-DSA-65 half): it gives the envelope's fields, the
/// ID and the bytes, and its body only through
/// [`unverified_body`](Event::unverified_body), whose name says what it is.
///
/// [`Event::verify_hybrid`] yields a [`VerifiedEvent`], whose signature
/// verified in full: at once for scheme 0, and for scheme 2 once keys that
/// hash to its `kc` are held, from any source. Code that applies, judges or
/// acts on an event's meaning takes a [`VerifiedEvent`].
///
/// Its bytes are shared: a clone, as logs and caches keep, costs a count.
#[derive(Clone, PartialEq, Eq)]
pub struct Event(Arc<EventData>);

#[derive(PartialEq, Eq)]
struct EventData {
    envelope: Envelope,
    event: Vec<u8>,
    signature: Vec<u8>,
    id: EventId,
    author: DeviceId,
}

impl core::fmt::Debug for Event {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Event")
            .field("envelope", &self.0.envelope)
            .field("event", &self.0.event)
            .field("signature", &self.0.signature)
            .field("id", &self.0.id)
            .finish()
    }
}

impl Event {
    /// The envelope, body included, for this crate's records at rest.
    pub(crate) fn fields(&self) -> &Envelope {
        &self.0.envelope
    }

    /// The event ID, which leaves out the signature.
    pub fn id(&self) -> EventId {
        self.0.id
    }

    /// The kind.
    pub fn kind(&self) -> u8 {
        self.0.envelope.kind
    }

    /// The author: the device ID of `ed` and `kc`. Chains, fork evidence
    /// and every reference to an event's author name it.
    pub fn author(&self) -> &DeviceId {
        &self.0.author
    }

    /// The author's Ed25519 key, `ed`, which signs.
    pub fn ed(&self) -> &IdentityKey {
        &self.0.envelope.ed
    }

    /// The author's keys commitment, `kc`.
    pub fn kc(&self) -> &KeysCommitment {
        &self.0.envelope.kc
    }

    /// The author's sequence number in this log.
    pub fn seq(&self) -> u64 {
        self.0.envelope.seq
    }

    /// The author's previous event, when `seq` is above 1.
    pub fn prev(&self) -> Option<EventId> {
        self.0.envelope.prev
    }

    /// The parents, strictly ascending.
    pub fn parents(&self) -> &[EventId] {
        &self.0.envelope.parents
    }

    /// The cuts, strictly ascending: the checkpoints the event declares it
    /// follows (events.md, 3.11 Cuts), 1 to 4, or none. Decoding checked
    /// their shape only; [`cuts::check`](crate::cuts::check) checks them
    /// against the parents. A peer reads them as they are.
    pub fn cuts(&self) -> &[EventId] {
        &self.0.envelope.cuts
    }

    /// The body, whose signature may be checked only in part: for scheme 2,
    /// the ML-DSA-65 half may not have verified.
    ///
    /// It is for what reads a body before or without that half, as the
    /// specification allows: a peer, which checks only the Ed25519 half
    /// (peers.md, 3.2 Storing an event); a replica's checks of an event
    /// alone that come before its signature (roster.md, 3.2 The event
    /// alone, steps 2 to 10); and keys taken from any source (events.md,
    /// 3.3 The ML-DSA-65 half, "Any source"). Code that applies, judges or
    /// acts on an event reads [`VerifiedEvent::body`].
    pub fn unverified_body(&self) -> &[u8] {
        &self.0.envelope.body
    }

    /// The log the event names: `None` for a genesis.
    pub fn log(&self) -> Option<EventId> {
        self.0.envelope.log
    }

    /// The signature scheme.
    pub fn scheme(&self) -> Scheme {
        self.0.envelope.scheme
    }

    /// Whether this is a genesis, with no `log`.
    pub fn is_genesis(&self) -> bool {
        self.0.envelope.is_genesis()
    }

    /// The log the event belongs to: its `log`, or its own ID for a genesis.
    pub fn log_id(&self) -> EventId {
        self.0.envelope.log.unwrap_or(self.0.id)
    }

    /// The map's bytes, as signed.
    pub fn event_bytes(&self) -> &[u8] {
        &self.0.event
    }

    /// The signature.
    pub fn signature(&self) -> &[u8] {
        &self.0.signature
    }

    /// `tbs = "frasil/event/v1" || event`.
    pub fn tbs(&self) -> Vec<u8> {
        envelope::tbs(&self.0.event)
    }

    /// The signed event's bytes, `[event, signature]`, exactly as decoded.
    pub fn signed(&self) -> Vec<u8> {
        envelope::assemble(&self.0.event, &self.0.signature)
    }

    /// The length of the signed event, in bytes.
    pub fn signed_len(&self) -> usize {
        signed_len(self.0.event.len(), self.0.signature.len())
    }

    /// An event from fields a replica kept at rest after [`decode`] accepted
    /// them (crate `state`): the map is the envelope's one encoding, which
    /// is the map [`decode`] read, and the ID is computed from it. Nothing
    /// is verified again.
    pub(crate) fn from_parts(envelope: Envelope, signature: Vec<u8>) -> Self {
        let event = envelope.encode();
        let id = envelope::event_id(&event);
        let author = envelope.author();
        Self(Arc::new(EventData {
            envelope,
            event,
            signature,
            id,
            author,
        }))
    }

    /// The ML-DSA-65 half (events.md, "The ML-DSA-65 half"):
    ///
    /// ```text
    /// verify_hybrid(event), in order:
    ///   1. The replica holds an ML-DSA-65 key that, with an X-Wing key,
    ///      or with none for a holder that has none, hashes to the
    ///      event's kc.                                          else NoHybridKey
    ///   2. The ML-DSA-65 half verifies under that key, over m_ml
    ///      (crypto.md).                                         else BadSignature
    /// ```
    ///
    /// `keys` may come from any source: they are used only if their
    /// commitment is the event's `kc`, and then they are the author's only
    /// keys. A scheme-0 event has no such half and passes, whatever `keys`.
    ///
    /// Returns the event as a [`VerifiedEvent`]: its signature verified in
    /// full.
    ///
    /// # Errors
    ///
    /// `NoHybridKey` (pending) when `keys` is `None` or hashes to another
    /// `kc`; `BadSignature` (final) when the half does not verify.
    pub fn verify_hybrid(&self, keys: Option<&HybridKeys>) -> Result<VerifiedEvent, EventClass> {
        if self.scheme() == Scheme::Hybrid {
            let tbs = self.tbs();
            let signed = Signed {
                scheme: u64::from(Scheme::Hybrid.code()),
                ed: self.ed(),
                kc: self.kc(),
                tbs: &tbs,
                signature: &self.0.signature,
            };
            schemes::verify_mldsa_steps(&signed, keys).map_err(EventClass::from)?;
        }
        Ok(VerifiedEvent(self.clone()))
    }

    /// [`verify_hybrid`](Self::verify_hybrid) with the keys `source` holds
    /// for the event's `kc`.
    ///
    /// # Errors
    ///
    /// As [`verify_hybrid`](Self::verify_hybrid).
    pub fn verify_hybrid_in(
        &self,
        source: &(impl KeySource + ?Sized),
    ) -> Result<VerifiedEvent, EventClass> {
        if self.scheme() != Scheme::Hybrid {
            return Ok(VerifiedEvent(self.clone()));
        }
        self.verify_hybrid(source.hybrid_keys(self.kc()).as_ref())
    }

    /// The event as a [`VerifiedEvent`] if it is scheme 0, whose signature
    /// [`decode`] verified in full; `None` for scheme 2, whose ML-DSA-65 half
    /// [`verify_hybrid`](Self::verify_hybrid) checks.
    pub fn verified_scheme_0(&self) -> Option<VerifiedEvent> {
        (self.scheme() == Scheme::Ed25519).then(|| VerifiedEvent(self.clone()))
    }
}

/// An event whose signature verified in full: scheme 0 strictly, or both
/// halves of scheme 2 (events.md, 3.1 Decoding an event, and 3.3 The
/// ML-DSA-65 half).
///
/// Only [`Event::verify_hybrid`], [`Event::verify_hybrid_in`] and
/// [`Event::verified_scheme_0`] make one, and a [`Log`](crate::Log) hands
/// out the ones it holds verified ([`Log::verified`](crate::Log::verified)).
/// It gives everything an [`Event`] gives, through `Deref`, and the body
/// and the whole envelope: what applies, judges or acts on an event takes
/// this type.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedEvent(Event);

impl core::fmt::Debug for VerifiedEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("VerifiedEvent").field(&self.0).finish()
    }
}

impl core::ops::Deref for VerifiedEvent {
    type Target = Event;

    fn deref(&self) -> &Event {
        &self.0
    }
}

impl VerifiedEvent {
    /// An event a replica verified before and kept at rest (crate
    /// `state`): nothing is verified again.
    pub(crate) fn from_rest(event: Event) -> Self {
        Self(event)
    }

    /// The body.
    pub fn body(&self) -> &[u8] {
        &self.0.0.envelope.body
    }

    /// The event's fields, the body among them.
    pub fn envelope(&self) -> &Envelope {
        &self.0.0.envelope
    }

    /// The event, as an [`Event`].
    pub fn event(&self) -> &Event {
        &self.0
    }

    /// The event, as an [`Event`].
    pub fn into_event(self) -> Event {
        self.0
    }
}

/// The length of `[event, signature]` as deterministic CBOR.
fn signed_len(event: usize, signature: usize) -> usize {
    fn head(length: usize) -> usize {
        match length {
            0..=23 => 1,
            24..=0xff => 2,
            0x100..=0xffff => 3,
            0x1_0000..=0xffff_ffff => 5,
            _ => 9,
        }
    }
    1 + head(event) + event + head(signature) + signature
}

/// A byte string of exactly 32 bytes, as an event ID.
fn id_of(value: &Value) -> Result<EventId, Malformed> {
    value.as_byte_array::<32>().map(EventId)
}

/// `decode(signed)`: every check of events.md, "Decoding an event", in
/// order. See the module's documentation for the steps.
///
/// # Errors
///
/// The class of the first check that fails: `TooLarge`, `Malformed`,
/// `UnsupportedVersion`, `SchemeNotAllowed`, `UnknownKind`, `InvalidKey` or
/// `BadSignature`.
pub fn decode(signed: &[u8]) -> Result<Event, EventClass> {
    use ErrorClass::{
        BadSignature, Malformed as M, SchemeNotAllowed, TooLarge, UnsupportedVersion,
    };

    // 1. The overall limit.
    if signed.len() > kind::MAX_SIGNED_EVENT_BYTES {
        return Err(TooLarge.into());
    }
    // 2. [event, signature], two byte strings, nothing after. The reader
    // takes only shortest, definite heads, so what it accepts is the one
    // encoding of what it read.
    let mut reader = Reader::new(signed);
    if reader.array_len()? != 2 {
        return Err(M.into());
    }
    let event = reader.bytes()?;
    let signature = reader.bytes()?;
    reader.finish()?;
    // 3. A deterministic CBOR map whose key 0 is unsigned.
    let value = cbor::decode(event)?;
    let map = value.as_map()?;
    let version = map.get(&KEY_VERSION).ok_or(M)?.as_unsigned()?;
    // 4. Version 1.
    if version != VERSION {
        return Err(UnsupportedVersion.into());
    }
    // 5. Keys among 0 to 10; keys 1, 3, 4, 6, 8 and 10 present.
    ENVELOPE_KEYS.check(map)?;
    let field = |key: u64| map.get(&key).ok_or(M);
    // 6. Key 9, if present, unsigned and not 0.
    let scheme_code = match map.get(&KEY_SCHEME) {
        Some(value) => match value.as_unsigned()? {
            0 => return Err(M.into()),
            code => code,
        },
        None => u64::from(Scheme::Ed25519.code()),
    };
    // 7. Kind 1 to 127, and not 3.
    let kind_code = field(KEY_KIND)?.as_unsigned()?;
    if !kind::is_valid(kind_code) {
        return Err(M.into());
    }
    let kind = u8::try_from(kind_code).map_err(|_| M)?;
    let policy = KindPolicy::for_kind(kind_code)?;
    // 8. Scheme 0 or 2.
    let scheme = Scheme::from_code(scheme_code).map_err(|_| UnsupportedVersion)?;
    // 9. A scheme the kind may carry.
    if !policy.accepted().contains(&scheme) {
        return Err(SchemeNotAllowed.into());
    }
    // 10. The signature's length.
    if signature.len() != scheme.signature_bytes() {
        return Err(M.into());
    }
    // 11. The fields' types.
    let seq = field(KEY_SEQ)?.as_unsigned()?;
    if seq < 1 {
        return Err(M.into());
    }
    let ed = IdentityKey(field(KEY_ED)?.as_byte_array::<32>()?);
    let kc = KeysCommitment(field(KEY_KC)?.as_byte_array::<32>()?);
    let body = field(KEY_BODY)?.as_bytes()?;
    let log = map.get(&KEY_LOG).map(id_of).transpose()?;
    let prev = map.get(&KEY_PREV).map(id_of).transpose()?;
    let parents = field(KEY_PARENTS)?
        .as_array()?
        .iter()
        .map(id_of)
        .collect::<Result<Vec<_>, _>>()?;
    if parents.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(M.into());
    }
    let cuts = match map.get(&KEY_CUTS) {
        Some(value) => {
            let cuts = value
                .as_array()?
                .iter()
                .map(id_of)
                .collect::<Result<Vec<_>, _>>()?;
            if cuts.is_empty()
                || cuts.len() > crate::cuts::MAX_CUTS
                || cuts.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(M.into());
            }
            cuts
        }
        None => Vec::new(),
    };
    // 12. The field rules.
    match log {
        None if seq != 1
            || !parents.is_empty()
            || !cuts.is_empty()
            || !kind::may_start_log(kind) =>
        {
            return Err(M.into());
        }
        Some(_) if parents.is_empty() => return Err(M.into()),
        _ => {}
    }
    if prev.is_some() != (seq > 1) {
        return Err(M.into());
    }
    if prev.is_some_and(|prev| parents.binary_search(&prev).is_err()) {
        return Err(M.into());
    }
    if kind == kind::ANCHOR && !body.is_empty() {
        return Err(M.into());
    }
    // 13. A kind that must be understood is one this replica knows.
    if kind::must_understand(kind) && !kind::is_known(kind) {
        return Err(EventClass::UnknownKind);
    }
    // 14. The kind's limits.
    let limits = kind::limits(kind);
    if signed.len() > limits.bytes || parents.len() > limits.parents {
        return Err(TooLarge.into());
    }
    // 15. The author's Ed25519 key.
    ed25519_valid(&ed.0)?;
    // 16. Scheme 0 strictly over tbs; scheme 2's Ed25519 half over m_ed.
    // crypto.md's steps 1 to 3 pass again; step 4 is this one.
    let tbs = envelope::tbs(event);
    let checked = schemes::verify_ed25519_steps(
        policy,
        &Signed {
            scheme: scheme_code,
            ed: &ed,
            kc: &kc,
            tbs: &tbs,
            signature,
        },
    );
    if checked != Ok(scheme) {
        return Err(BadSignature.into());
    }
    Ok(Event(Arc::new(EventData {
        author: device_id(&ed, &kc),
        envelope: Envelope {
            kind,
            log,
            ed,
            kc,
            seq,
            prev,
            parents,
            cuts,
            body: body.to_vec(),
            scheme,
        },
        id: envelope::event_id(event),
        event: event.to_vec(),
        signature: signature.to_vec(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cuts::MAX_CUTS;
    use frasil_crypto::primitives::ed25519_public;
    use frasil_crypto::schemes::Signer;

    fn signer(seed: u8) -> Signer {
        Signer::from_seeds(&[seed; 32], &[seed.wrapping_add(100); 32], None)
    }

    fn genesis(signer: &Signer) -> Envelope {
        Envelope {
            kind: kind::SPACE,
            log: None,
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq: 1,
            prev: None,
            parents: vec![],
            cuts: Vec::new(),
            body: b"genesis".to_vec(),
            scheme: Scheme::Hybrid,
        }
    }

    #[test]
    fn signed_events_round_trip() {
        let founder = signer(1);
        let envelope = genesis(&founder);
        let signed = envelope.sign(&founder);
        let event = decode(&signed).unwrap();
        assert_eq!(event.fields(), &envelope);
        assert_eq!(event.signed(), signed);
        assert_eq!(event.signed_len(), signed.len());
        assert_eq!(event.id(), envelope.id());
        assert_eq!(event.log_id(), event.id());
        assert!(event.is_genesis());
        assert_eq!(event.author(), founder.device_id());
        let verified = event.verify_hybrid(Some(founder.keys())).unwrap();
        assert_eq!(verified.envelope(), &envelope);
        assert_eq!(verified.body(), b"genesis");
        assert_eq!(verified.event(), &event);
        assert_eq!(event.verified_scheme_0(), None);
        // Another holder's keys hash to another kc: never tried.
        let other = signer(2);
        assert_eq!(
            event.verify_hybrid(Some(other.keys())),
            Err(ErrorClass::NoHybridKey.into())
        );
        assert_eq!(
            event.verify_hybrid(None),
            Err(ErrorClass::NoHybridKey.into())
        );
        let mut ring = frasil_crypto::device::KeyRing::new();
        assert_eq!(
            event.verify_hybrid_in(&ring),
            Err(ErrorClass::NoHybridKey.into())
        );
        ring.add_keys(other.keys().clone());
        ring.add_keys(founder.keys().clone());
        assert_eq!(
            event.verify_hybrid_in(&ring).map(VerifiedEvent::into_event),
            Ok(event)
        );
    }

    /// An event of the founder's after the genesis, with these cuts.
    fn with_cuts(founder: &Signer, cuts: Vec<EventId>) -> Envelope {
        let log = EventId([7; 32]);
        Envelope {
            kind: kind::UNIT,
            log: Some(log),
            ed: *founder.identity_key(),
            kc: *founder.kc(),
            seq: 1,
            prev: None,
            parents: vec![log],
            cuts,
            body: b"unit".to_vec(),
            scheme: Scheme::Ed25519,
        }
    }

    /// The envelope's map with key 7 set to `cuts`, or left out for
    /// `None`, signed by `signer` under the envelope's scheme.
    fn signed_with_key_7(signer: &Signer, envelope: &Envelope, cuts: Option<Value>) -> Vec<u8> {
        let mut map = cbor::decode(&envelope.encode())
            .unwrap()
            .as_map()
            .unwrap()
            .clone();
        match cuts {
            Some(cuts) => map.insert(KEY_CUTS, cuts),
            None => map.remove(&KEY_CUTS),
        };
        let event = Value::Map(map).encode();
        let signature = signer.sign(envelope.scheme, &envelope::tbs(&event));
        envelope::assemble(&event, &signature)
    }

    fn ids(ids: &[EventId]) -> Value {
        Value::Array(ids.iter().map(|id| Value::Bytes(id.0.to_vec())).collect())
    }

    #[test]
    fn cuts_round_trip() {
        let founder = signer(1);
        for count in 0..=MAX_CUTS {
            let cuts: Vec<EventId> = (0..count)
                .map(|i| EventId([u8::try_from(i).unwrap() * 17 + 3; 32]))
                .collect();
            let envelope = with_cuts(&founder, cuts.clone());
            let signed = envelope.sign(&founder);
            let event = decode(&signed).unwrap();
            assert_eq!(event.cuts(), cuts.as_slice());
            assert_eq!(event.fields(), &envelope);
            assert_eq!(event.signed(), signed);
            assert_eq!(event.id(), envelope.id());
            assert_eq!(event.verified_scheme_0().unwrap().envelope(), &envelope);
            // Key 7 is in the map exactly when there is a cut.
            let map = cbor::decode(event.event_bytes()).unwrap();
            assert_eq!(map.as_map().unwrap().contains_key(&KEY_CUTS), count > 0);
        }
        // The order given does not matter: the map is the one encoding.
        let a = EventId([1; 32]);
        let b = EventId([2; 32]);
        assert_eq!(
            with_cuts(&founder, vec![b, a, b]).encode(),
            with_cuts(&founder, vec![a, b]).encode()
        );
        // Cuts change the ID: they are in the map.
        assert_ne!(
            with_cuts(&founder, vec![a]).id(),
            with_cuts(&founder, vec![]).id()
        );
    }

    #[test]
    fn cuts_of_the_wrong_shape_are_malformed() {
        let founder = signer(1);
        let envelope = with_cuts(&founder, vec![]);
        let a = EventId([1; 32]);
        let b = EventId([2; 32]);
        let five: Vec<EventId> = (1..=5).map(|i| EventId([i; 32])).collect();
        let malformed = [
            ids(&[]),
            ids(&five),
            ids(&[b, a]),
            ids(&[a, a]),
            Value::Array(vec![Value::Bytes(vec![1; 31])]),
            Value::Array(vec![Value::Bytes(vec![1; 33])]),
            Value::Array(vec![ids(&[a, b])]),
            Value::Bytes(a.0.to_vec()),
            Value::Unsigned(1),
        ];
        for cuts in malformed {
            assert_eq!(
                decode(&signed_with_key_7(&founder, &envelope, Some(cuts.clone()))),
                Err(ErrorClass::Malformed.into()),
                "{cuts:?}"
            );
        }
        for cuts in [ids(&[a]), ids(&[a, b]), ids(&five[..4])] {
            let event = decode(&signed_with_key_7(&founder, &envelope, Some(cuts))).unwrap();
            assert!(!event.cuts().is_empty());
        }
        assert!(decode(&signed_with_key_7(&founder, &envelope, None)).is_ok());
    }

    #[test]
    fn a_genesis_declares_no_cuts() {
        let founder = signer(1);
        let envelope = genesis(&founder);
        assert!(decode(&signed_with_key_7(&founder, &envelope, None)).is_ok());
        assert_eq!(
            decode(&signed_with_key_7(
                &founder,
                &envelope,
                Some(ids(&[EventId([1; 32])]))
            )),
            Err(ErrorClass::Malformed.into())
        );
    }

    #[test]
    fn signed_lengths() {
        for (event, signature) in [(0, 64), (23, 64), (24, 3373), (300, 64), (70_000, 3373)] {
            let signed = envelope::assemble(&vec![0; event], &vec![0; signature]);
            assert_eq!(signed_len(event, signature), signed.len());
        }
    }

    #[test]
    fn kind_limits_count_the_signed_bytes() {
        let founder = signer(1);
        let log = EventId([7; 32]);
        let mut envelope = Envelope {
            kind: kind::ANCHOR,
            log: Some(log),
            ed: *founder.identity_key(),
            kc: *founder.kc(),
            seq: 1,
            prev: None,
            parents: vec![log],
            cuts: Vec::new(),
            body: vec![],
            scheme: Scheme::Hybrid,
        };
        assert!(decode(&envelope.sign(&founder)).is_ok());
        // An ignorable kind: 16,384 bytes in all.
        envelope.kind = 64;
        envelope.scheme = Scheme::Ed25519;
        envelope.body = vec![0; 16_384 - 240];
        let signed = envelope.sign(&founder);
        assert!(signed.len() <= 16_384);
        assert!(decode(&signed).is_ok());
        envelope.body = vec![0; 16_384];
        assert_eq!(
            decode(&envelope.sign(&founder)),
            Err(ErrorClass::TooLarge.into())
        );
        // A device-list event: 16 parents at most.
        envelope.kind = kind::DEVICE_LIST;
        envelope.scheme = Scheme::Hybrid;
        envelope.body = vec![];
        envelope.parents = (0..17).map(|i| EventId([i; 32])).collect();
        assert_eq!(
            decode(&envelope.sign(&founder)),
            Err(ErrorClass::TooLarge.into())
        );
        envelope.parents.pop();
        assert!(decode(&envelope.sign(&founder)).is_ok());
    }

    #[test]
    fn overall_limit_comes_first() {
        let huge = vec![0xff; kind::MAX_SIGNED_EVENT_BYTES + 1];
        assert_eq!(decode(&huge), Err(ErrorClass::TooLarge.into()));
        assert_eq!(decode(&[]), Err(ErrorClass::Malformed.into()));
    }

    #[test]
    fn a_kind_from_7_to_63_is_unknown_under_either_scheme() {
        let founder = signer(1);
        let log = EventId([7; 32]);
        for scheme in [Scheme::Ed25519, Scheme::Hybrid] {
            let envelope = Envelope {
                kind: 7,
                log: Some(log),
                ed: IdentityKey(ed25519_public(&[1; 32])),
                kc: *founder.kc(),
                seq: 1,
                prev: None,
                parents: vec![log],
                cuts: Vec::new(),
                body: vec![],
                scheme,
            };
            assert_eq!(
                decode(&envelope.sign(&founder)),
                Err(EventClass::UnknownKind)
            );
        }
    }
}
