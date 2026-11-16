//! Units as a peer and as a member check them (units.md, sections 3.1 and
//! 3.2), and writing one (sections 2.2 to 2.5).
//!
//! A unit is an event of kind 4 in its space's log (events.md), never a
//! genesis. Its author, the **writer**, is the signing device, named by
//! the device ID its envelope's `ed` and `kc` give (events.md, "The
//! envelope");
//! `seq` is the writer's place in its chain in that log, shared with every
//! other event it signs there, so it is per space, never per stream;
//! `scheme` is 0 or 2.
//!
//! **At a peer**, on the envelope and the visible body, without any key, in
//! order ([`Unit::check_at_peer`]):
//!
//! ```text
//!  1. events.md's checks of the event alone (kind 4, scheme 0 or 2).    else that class
//!  2. The signed unit is at most 1,048,576 bytes.                       else TooLarge
//!  3. events.md's placement, counting stubbed parents.                  else that class
//!  4.–10. The visible body (body.rs).                                   else Malformed / ...
//! ```
//!
//! Placement, step 3, is the log's (`frasil_events::Log`).
//!
//! **At a member**, after those, in order ([`Unit::open_at_member`]):
//!
//! ```text
//!     After a checkpoint in effect, for a unit after it: the key
//!     reference's visible state names only the checkpoint and events
//!     after it in the unit's past ([`UnitKeys::world_seal`]).          else StaleSeal
//! 11. The key reference names rotations the replica holds, as keys.md
//!     says; a missing rotation is Pending.                              else that class
//! 12. The replica holds k(S), or a body key handed over for the unit
//!     that matches the seal's commitment.                               else Sealed
//! 13. The body key matches the commitment and the seal opens under it.
//!     Under a key derived from rotation keys that each matched their
//!     commitments, a failure is BadSeal. Under a provisional key, or a
//!     body key handed over, it is Sealed.                               else BadSeal / Sealed
//! 14. inner (inner.rs).                                                 else Malformed / TooLarge
//! 15. roster.md's write rule.                                           else its class
//! 16. The unit is valid; its content goes to its adapter.
//! ```
//!
//! The text numbers the first check and step 11 together as its step 12
//! (units.md, 3.2 A unit, at a member); the steps here keep their earlier
//! numbers. `StaleSeal` is final and decided before any key, from the
//! visible part alone, so a replica that forgot the checkpoint's past and
//! one that kept it agree ([`world_seal`], [`InWorld`]).
//!
//! A unit that fails a step from 4 to 10 is dropped. One that fails step 13
//! with `BadSeal`, or step 14, is void. One held at step 12 or 13 still
//! counts as fork evidence. Step 15 is `frasil-space`'s, which reads the
//! unit's seal and sealed refs through [`UnitReader`], its [`UnitBodies`]
//! hook.

use crate::UnitError;
use crate::body::{Body, Compacts, KeyReference, encode_body};
use crate::inner::Inner;
use crate::limits::{MAX_UNIT_BYTES, NONCE_BYTES};
use crate::seal::{self, unit_aad};
use crate::stream::StreamId;
use frasil_adapter::Locator;
use frasil_base::ErrorClass;
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::{Envelope, Event, EventId, Log, kind};
use frasil_keys::KeyClass;
use frasil_keys::derive::{SecretKind, state_secret};
use frasil_keys::reference::{RotationLog, check_key_reference};
use frasil_space::{Keyring, UnitBodies, UnitBody};
use zeroize::Zeroizing;

/// A unit that passed a peer's checks, steps 1, 2 and 4 to 10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    /// The event.
    pub event: Event,
    /// Its visible body.
    pub body: Body,
}

impl Unit {
    /// Section 3.1, steps 1, 2 and 4 to 10, on a signed unit.
    ///
    /// # Errors
    ///
    /// events.md's classes for the event alone; `Malformed` for an event of
    /// another kind; `TooLarge` for more than 1,048,576 bytes; then the
    /// visible body's classes ([`Body::read`]).
    pub fn check_at_peer(signed: &[u8]) -> Result<Self, UnitError> {
        let event = frasil_events::decode(signed)?;
        Self::from_event(event)
    }

    /// Section 3.1, steps 1, 2 and 4 to 10, on a decoded event.
    ///
    /// # Errors
    ///
    /// As [`check_at_peer`](Self::check_at_peer), after decoding.
    pub fn from_event(event: Event) -> Result<Self, UnitError> {
        // 1. Kind 4; events.md's checks ran in decoding, scheme 0 or 2
        // among them.
        if event.kind() != kind::UNIT || event.is_genesis() {
            return Err(ErrorClass::Malformed.into());
        }
        // 2. At most 1,048,576 bytes.
        if event.signed_len() > MAX_UNIT_BYTES {
            return Err(ErrorClass::TooLarge.into());
        }
        // 4. to 10. A peer's checks read the visible body of an event whose
        // Ed25519 signature, or half, decoding checked, and nothing more.
        let body = Body::read(event.unverified_body())?;
        Ok(Self { event, body })
    }

    /// The unit's event ID.
    pub fn id(&self) -> EventId {
        self.event.id()
    }

    /// The space the unit belongs to.
    pub fn space(&self) -> EventId {
        self.event.log_id()
    }

    /// Whether the unit is a snapshot unit.
    pub fn is_snapshot(&self) -> bool {
        self.body.is_snapshot()
    }

    /// The seal's associated data.
    pub fn aad(&self) -> Vec<u8> {
        unit_aad(
            &self.space(),
            self.event.author(),
            self.event.seq(),
            &self.body.stream,
            &self.body.key,
        )
    }

    /// Steps 13 and 14 under the content key of the state the key reference
    /// names. `provisional` says whether the key could not be checked
    /// against single rotations' commitments (roster.md, "Space events a
    /// replica cannot open"). When `system` is given, step 14 checks that
    /// sealed key 6 is present exactly outside the system stream.
    ///
    /// # Errors
    ///
    /// `BadSeal`, or `Sealed` under a provisional key; then `Malformed` or
    /// `TooLarge` ([`Inner::read`]).
    pub fn open_with(
        &self,
        content_key: &[u8; 32],
        provisional: bool,
        system: Option<&StreamId>,
    ) -> Result<Inner, UnitError> {
        // 13. The seal opens.
        let inner = seal::open(content_key, &self.body.sealed, &self.aad()).map_err(|_| {
            if provisional {
                ErrorClass::Sealed
            } else {
                ErrorClass::BadSeal
            }
        })?;
        // 14. The sealed part.
        Inner::read(&inner, self.is_snapshot(), &self.body.stream, system)
    }

    /// The check against the checkpoint in effect, then steps 11 to 14,
    /// with the keys this replica holds.
    ///
    /// # Errors
    ///
    /// As [`UnitKeys::world_seal`] (`StaleSeal`, final, before any key),
    /// then as [`UnitKeys::key`], then as [`open_with`](Self::open_with).
    pub fn open_at_member(
        &self,
        keys: &impl UnitKeys,
        system: Option<&StreamId>,
    ) -> Result<Inner, UnitError> {
        keys.world_seal(&self.event, &self.body.reference)?;
        let opened = keys
            .key(&self.space(), &self.body.reference)
            .and_then(|state| self.open_with(&state.key, state.provisional, system));
        match opened {
            Err(class) if class.shared() == Some(ErrorClass::Sealed) => {
                self.open_handed(keys.handed(&self.id()), system)
            }
            opened => opened,
        }
    }

    /// Steps 13 and 14 under a body key handed over for this unit
    /// (units.md, "Frasil's own units", body keys): the first that matches
    /// the seal's commitment. Such a key is provisional, so a seal it fails
    /// to open holds the unit.
    ///
    /// # Errors
    ///
    /// `Sealed` when no key matches or the seal does not open; then
    /// `Malformed` or `TooLarge` ([`Inner::read`]).
    pub fn open_handed(
        &self,
        handed: &[Zeroizing<[u8; 32]>],
        system: Option<&StreamId>,
    ) -> Result<Inner, UnitError> {
        let key = handed
            .iter()
            .find(|key| seal::commits_to(key, &self.body.sealed))
            .ok_or(ErrorClass::Sealed)?;
        let inner = seal::open_with_body_key(key, &self.body.sealed, &self.aad())
            .map_err(|_| ErrorClass::Sealed)?;
        Inner::read(&inner, self.is_snapshot(), &self.body.stream, system)
    }

    /// The unit's body key, as this replica holds it: derived from `k(S)`,
    /// or handed over; either matches the seal's commitment. `None` when it
    /// holds neither.
    pub fn body_key_at_member(&self, keys: &impl UnitKeys) -> Option<Zeroizing<[u8; 32]>> {
        if let Ok(state) = keys.key(&self.space(), &self.body.reference) {
            let key = seal::body_key(&state.key, &self.aad());
            if seal::commits_to(&key, &self.body.sealed) {
                return Some(key);
            }
        }
        keys.handed(&self.id())
            .iter()
            .find(|key| seal::commits_to(key, &self.body.sealed))
            .cloned()
    }
}

/// The content key of a state, as a member holds it (section 3.2, step 12).
#[derive(Clone, PartialEq, Eq)]
pub struct StateKey {
    /// `k(S)`.
    pub key: Zeroizing<[u8; 32]>,
    /// Whether it could not be checked against single rotations'
    /// commitments: a merged state's key received whole. A seal that does
    /// not open under it holds the unit `Sealed`, not `BadSeal`.
    pub provisional: bool,
}

impl core::fmt::Debug for StateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StateKey")
            .field("provisional", &self.provisional)
            .finish_non_exhaustive()
    }
}

/// What a member holds to read a unit's key reference and open its seal:
/// section 3.2, steps 11 and 12.
pub trait UnitKeys {
    /// Step 11, keys.md's "Reading a unit's key reference", steps 2 to 4,
    /// against the space's log; then step 12, the content key of the state
    /// it names.
    ///
    /// # Errors
    ///
    /// `NotARotation`; `Pending` while the reader lacks a rotation's event;
    /// `Malformed` when one ID is in the past of another; `Sealed` when the
    /// replica does not hold `k(S)`; `ExtensionRequired` for a restricted
    /// key reference a core implementation does not read.
    fn key(&self, space: &EventId, reference: &KeyReference) -> Result<StateKey, UnitError>;

    /// The body keys handed over for one unit, as `frasil:body-keys` units
    /// carry them: provisional, each checked against the unit's commitment
    /// before use.
    fn handed(&self, _unit: &EventId) -> &[Zeroizing<[u8; 32]>] {
        &[]
    }

    /// Section 3.2, step 12, its first check: after a checkpoint in
    /// effect, a unit after it whose key reference names a rotation that is
    /// neither the checkpoint nor an event after it in the unit's past is
    /// `StaleSeal` (roster.md, "The world after a checkpoint"). Nothing by
    /// default: no checkpoint is in effect. [`InWorld`] checks it against
    /// a log.
    ///
    /// # Errors
    ///
    /// `StaleSeal`, final; `Pending` while the answer waits for checkpoint
    /// envelopes.
    fn world_seal(&self, _unit: &Event, _reference: &KeyReference) -> Result<(), UnitError> {
        Ok(())
    }
}

/// The rotations a key reference names in its visible part: a rotation
/// set, or a restricted reference's own state (the parent's is sealed).
fn visible_rotations(reference: &KeyReference) -> &[EventId] {
    match reference {
        KeyReference::Set(state) => state.ids(),
        KeyReference::Restricted { own, .. } => own.ids(),
    }
}

/// Section 3.2, step 12, its first check, against a log: when `unit`
/// follows `checkpoint`, the checkpoint in effect (its cuts reach it,
/// events.md, 3.11 Cuts), every rotation the key reference's visible part
/// names is the checkpoint, or an event after it in the unit's past. A
/// unit that does not follow the checkpoint passes: it is in its past, or
/// late, which roster.md decides.
///
/// It reads envelopes and the visible part alone: a replica that forgot
/// the checkpoint's past, which never holds a rotation before it, and one
/// that kept it decide alike.
///
/// # Errors
///
/// `StaleSeal`, final; the shared `Pending` while whether the unit, or a
/// rotation it names, follows the checkpoint waits for checkpoint
/// envelopes.
pub fn world_seal(
    log: &Log,
    checkpoint: EventId,
    unit: &Event,
    reference: &KeyReference,
) -> Result<(), UnitError> {
    let follows = |event: &Event| {
        frasil_events::cuts::follows(log, event, checkpoint)
            .map_err(|_| UnitError::from(ErrorClass::Pending))
    };
    if !follows(unit)? {
        return Ok(());
    }
    for rotation in visible_rotations(reference) {
        if *rotation == checkpoint {
            continue;
        }
        let Some(event) = log.event(*rotation) else {
            // Not placed: outside the unit's held past, which placement
            // holds whole for a placed unit.
            return Err(KeyClass::StaleSeal.into());
        };
        if !log.precedes(*rotation, unit.id()) || !follows(event)? {
            return Err(KeyClass::StaleSeal.into());
        }
    }
    Ok(())
}

/// A member's keys in the world of a checkpoint in effect: `keys` for
/// steps 11 to 14, and [`world_seal`] against `log` first.
#[derive(Debug, Clone, Copy)]
pub struct InWorld<'a, K> {
    /// The keys.
    pub keys: &'a K,
    /// The space's log, as the reader holds it.
    pub log: &'a Log,
    /// The checkpoint in effect, the last of its chain.
    pub checkpoint: EventId,
}

impl<K: UnitKeys> UnitKeys for InWorld<'_, K> {
    fn key(&self, space: &EventId, reference: &KeyReference) -> Result<StateKey, UnitError> {
        self.keys.key(space, reference)
    }

    fn handed(&self, unit: &EventId) -> &[Zeroizing<[u8; 32]>] {
        self.keys.handed(unit)
    }

    fn world_seal(&self, unit: &Event, reference: &KeyReference) -> Result<(), UnitError> {
        self.keys.world_seal(unit, reference)?;
        world_seal(self.log, self.checkpoint, unit, reference)
    }
}

/// A [`Keyring`] over the space's log, as a core implementation reads a
/// unit's key reference: a rotation set, whose content key derives from
/// the rotation keys held, or is a merged state's key received whole
/// (provisional).
#[derive(Debug, Clone, Copy)]
pub struct KeyringKeys<'a, L> {
    /// The keys held.
    pub keyring: &'a Keyring,
    /// The space's log, as the reader holds it.
    pub log: &'a L,
}

impl<L: RotationLog> UnitKeys for KeyringKeys<'_, L> {
    fn key(&self, space: &EventId, reference: &KeyReference) -> Result<StateKey, UnitError> {
        let KeyReference::Set(state) = reference else {
            return Err(ErrorClass::ExtensionRequired.into());
        };
        // 11. keys.md's steps 2 to 4.
        check_key_reference(state, self.log)?;
        // 12. k(S): derived from the rotation keys held, or received whole.
        let inputs: Option<Zeroizing<Vec<[u8; 32]>>> = state
            .ids()
            .iter()
            .map(|id| self.keyring.rotations.get(id).map(|key| **key))
            .collect::<Option<Vec<_>>>()
            .map(Zeroizing::new);
        if let Some(inputs) = inputs {
            let key = state_secret(SecretKind::Content, space, state, &inputs)?;
            return Ok(StateKey {
                key,
                provisional: false,
            });
        }
        match self.keyring.states.get(state) {
            Some(key) => Ok(StateKey {
                key: key.clone(),
                provisional: true,
            }),
            None => Err(ErrorClass::Sealed.into()),
        }
    }

    fn handed(&self, unit: &EventId) -> &[Zeroizing<[u8; 32]>] {
        self.keyring.bodies.get(unit).map_or(&[], Vec::as_slice)
    }
}

/// units.md's reading of a unit for the roster: [`UnitBodies`], steps 11 to
/// 14 of section 3.2 over the keys a replica holds.
#[derive(Debug, Clone, Copy)]
pub struct UnitReader<'a, K> {
    /// The keys.
    pub keys: &'a K,
    /// The space's system stream, if the replica knows it, so that step 14
    /// checks where sealed key 6 appears.
    pub system: Option<StreamId>,
}

impl<K: UnitKeys> UnitBodies for UnitReader<'_, K> {
    fn list_copy(&self, event: &Event) -> Vec<Event> {
        let Ok(unit) = Unit::from_event(event.clone()) else {
            return Vec::new();
        };
        if Some(unit.body.stream) != self.system {
            return Vec::new();
        }
        let Ok(inner) = unit.open_at_member(self.keys, self.system.as_ref()) else {
            return Vec::new();
        };
        if inner.type_ != crate::types::LIST {
            return Vec::new();
        }
        crate::own::read_list_copy(&inner.content).unwrap_or_default()
    }

    /// A unit whose key reference waits for a rotation (`Pending`), whose
    /// state this replica does not hold or holds only provisionally under a
    /// failed seal (`Sealed`), or whose reference needs an extension
    /// (`ExtensionRequired`), is held. One whose seal fails under checked
    /// keys (`BadSeal`), whose sealed part breaks step 14, or whose key
    /// reference names a non-rotation or concurrent-only IDs, is void. A
    /// unit that fails steps 4 to 10 should never reach the log, which a
    /// peer drops; it is void here.
    fn open(&self, unit: &Event) -> UnitBody {
        let opened = Unit::from_event(unit.clone())
            .and_then(|unit| unit.open_at_member(self.keys, self.system.as_ref()));
        match opened {
            Ok(inner) => UnitBody::Opened(inner.refs),
            Err(class) => match class.shared() {
                Some(ErrorClass::Pending | ErrorClass::Sealed | ErrorClass::ExtensionRequired) => {
                    UnitBody::Held(class.into())
                }
                _ => UnitBody::Void(class.into()),
            },
        }
    }
}

/// A unit to write: everything but the signer, the key and the sealed part
/// (sections 2.2 and 2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    /// The space ID.
    pub log: EventId,
    /// The writer's `seq` in the space's log.
    pub seq: u64,
    /// The writer's event at `seq − 1`.
    pub prev: Option<EventId>,
    /// The unit's parents, `prev` among them.
    pub parents: Vec<EventId>,
    /// Scheme 0 until the classical sunset (crypto.md).
    pub scheme: Scheme,
    /// The stream.
    pub stream: StreamId,
    /// The key reference of the state the unit is sealed under.
    pub key_reference: Vec<u8>,
    /// The writer's previous unit in this stream.
    pub stream_prev: Option<EventId>,
    /// The locators the unit names.
    pub objects: Vec<Locator>,
    /// The compaction declaration of a snapshot unit.
    pub compacts: Option<Compacts>,
    /// The supersessions the unit carries (ext-file-versions.md).
    pub supersedes: Vec<frasil_adapter::Supersession>,
}

/// A written unit and every intermediate value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    /// The seal's associated data.
    pub aad: Vec<u8>,
    /// The seal.
    pub sealed: Vec<u8>,
    /// The visible body.
    pub body: Vec<u8>,
    /// The event's map, as signed.
    pub event: Vec<u8>,
    /// The signed event.
    pub signed: Vec<u8>,
    /// The event ID.
    pub id: EventId,
}

impl Draft {
    /// Seals `inner` under `content_key` with a nonce the caller drew, and
    /// signs the unit. It declares no cuts: for a unit whose parents reach a
    /// checkpoint, use [`write_with_cuts`](Self::write_with_cuts).
    pub fn write_with(
        &self,
        signer: &Signer,
        content_key: &[u8; 32],
        inner: &[u8],
        nonce: &[u8; NONCE_BYTES],
    ) -> Written {
        self.write_with_cuts(signer, content_key, inner, nonce, &[])
    }

    /// [`write_with`](Self::write_with), the envelope declaring `cuts`
    /// (events.md, 3.11 Cuts): the checkpoints the unit's parents reach,
    /// as [`frasil_events::cuts::expected`] gives them, strictly ascending.
    /// With no cuts it is the unit [`write_with`](Self::write_with) writes.
    pub fn write_with_cuts(
        &self,
        signer: &Signer,
        content_key: &[u8; 32],
        inner: &[u8],
        nonce: &[u8; NONCE_BYTES],
        cuts: &[EventId],
    ) -> Written {
        let aad = unit_aad(
            &self.log,
            signer.device_id(),
            self.seq,
            &self.stream,
            &self.key_reference,
        );
        let sealed = seal::seal_with(content_key, nonce, inner, &aad);
        let body = encode_body(
            &self.stream,
            &self.key_reference,
            &sealed,
            self.stream_prev.as_ref(),
            &self.objects,
            self.compacts.as_ref(),
            &self.supersedes,
        );
        let envelope = Envelope {
            kind: kind::UNIT,
            log: Some(self.log),
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq: self.seq,
            prev: self.prev,
            parents: self.parents.clone(),
            cuts: cuts.to_vec(),
            body: body.clone(),
            scheme: self.scheme,
        };
        Written {
            aad,
            sealed,
            event: envelope.encode(),
            signed: envelope.sign(signer),
            id: envelope.id(),
            body,
        }
    }
}
