//! Checking a space event alone (roster.md, "The event alone", steps 2 to
//! 11, and "An author's keys").
//!
//! ```text
//!  2. The visible part passes keys.md's checks. Key 13 is present
//!     exactly in a genesis, which rotates; key 15 is absent from a
//!     genesis.                                                       else that class / Malformed
//!  3. An event that does not rotate: every rotation its
//!     sealed_under names is in its past.                             else Malformed
//!  4. The body key: a key derived from rotation keys that each
//!     matched their rotation's commitments, whose commitment
//!     equals key 14;                                                 else BadSeal (held)
//!     otherwise a provisional key whose commitment equals key 14.    else Sealed (held)
//!  5. The sealed part opens under it, and passes keys.md's checks
//!     on the sealed part.                                            else BadSeal (held) / that class
//!  6. Inner key 16, if present, is a map whose key 0 is 0, 1 or 2,
//!     0 exactly in a genesis; a genesis has key 16; key 15 only on
//!     a roster event. A key 0 from 3 is held (roster.md, 3.16).      else Malformed / ExtensionRequired (held)
//!     A checkpoint: its keys, its size at most the bound; it
//!     rotates and carries no inner key 18.                          else Malformed / TooLarge
//!  7. to 10. The roster part (crate::part); a genesis cites nothing.  else that class
//! 11. The signature's ML-DSA-65 half, under keys that hash to the
//!     event's kc.                                                    else NoHybridKey (pending) / BadSignature
//! ```
//!
//! Steps 2 and 3 read nothing sealed; an event that fails them gives no
//! evidence. Step 11 runs on every space event that passes step 3, opened
//! or not, so that its signature counts as chain evidence. Step 12, the
//! author's fork point, belongs to the resolution, with the chains.
//!
//! A core implementation that has read a restricted space's descriptor
//! holds the space's other events as `ExtensionRequired`, after step 3
//! ([`crate::ext`]).
//!
//! [`ScreenedLog`] runs these over every space event of a log, and is what
//! the rest of the roster reads: the opened bodies, the keys its grants
//! carry, indexed by their hashes, and the events held.
//!
//! Step 11 takes an author's keys by their hash (crypto.md, "Keys by their
//! hash"; roster.md, "An author's keys"): from the grants of every roster
//! event this view opened, valid or void, the genesis's founder among them,
//! then from [`Records`], which gives the keys of every other source a
//! replica holds: the lists it reads, the spaces it grants, the skeleton's
//! roots and enrolments, admission exchanges and caches. No source is
//! trusted; keys that do not hash to the event's `kc` are never tried. An
//! event left `NoHybridKey` is checked again when either source grows: the
//! caller screens again when [`ScreenedLog::keys`] or its records gain keys.

use crate::change::Change;
use crate::part::{Genesis, PartContext, RosterPart};
use crate::{Limits, RosterClass, SpaceClass, ext};
use frasil_base::ErrorClass;
use frasil_crypto::device::{DeviceId, DeviceKeys, HybridKeys, KeyRing, KeySource, KeysCommitment};
use frasil_events::{Event, EventClass, EventId, ForkPoints, Log, VerifiedEvent};
use frasil_keys::RotationSet;
use frasil_keys::body::{Inner, VisiblePart};
use frasil_keys::context::{Context, EventKind, Facts, check_context};
use frasil_keys::derive::{
    Secret, SecretKind, body_commitment, body_key, read_credential, state_secret,
};
use frasil_peers::body::{StorageBody, StorageType};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

fn malformed() -> RosterClass {
    ErrorClass::Malformed.into()
}

/// What a replica holds to open space events (roster.md, "Space events a
/// replica cannot open").
#[derive(Clone, Default)]
pub struct Keyring {
    /// The content key `k_R` of each rotation held, by the rotation's event
    /// ID. A key whose read credential does not match the rotation's
    /// visible `read` is not that rotation's key, and counts as not held.
    pub rotations: BTreeMap<EventId, Secret>,
    /// A merged state's content key received whole, which cannot be checked
    /// against single rotations' commitments: **provisional**.
    pub states: BTreeMap<RotationSet, Secret>,
    /// Body keys handed over for single events, each as the senders handed
    /// them: **provisional**. Two different keys for one event hold it.
    pub bodies: BTreeMap<EventId, Vec<Secret>>,
}

impl core::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keyring")
            .field("rotations", &self.rotations.keys().collect::<Vec<_>>())
            .field("states", &self.states.keys().collect::<Vec<_>>())
            .field("bodies", &self.bodies.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Keyring {
    /// The content key of a state, derived from the rotation keys held, or
    /// `None` if one is missing.
    fn state_key(&self, space: &EventId, state: &RotationSet) -> Option<Secret> {
        let inputs: Zeroizing<Vec<[u8; 32]>> = Zeroizing::new(
            state
                .ids()
                .iter()
                .map(|id| self.rotations.get(id).map(|key| **key))
                .collect::<Option<_>>()?,
        );
        state_secret(SecretKind::Content, space, state, &inputs).ok()
    }
}

/// A space event whose sealed part opened and passed steps 5 to 10.
#[derive(Clone)]
pub struct Opened {
    /// The visible part.
    pub visible: VisiblePart,
    /// The sealed part.
    pub inner: Inner,
    /// The body key it opened under.
    pub body_key: Secret,
    /// Whether the body key was provisional: a merged state's key received
    /// whole, or a body key handed over. Verdicts reached under it are
    /// provisional, and judged again once the replica holds the state.
    pub provisional: bool,
    /// The roster part: `None` in a key event.
    pub part: Option<RosterPart>,
}

impl core::fmt::Debug for Opened {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Opened")
            .field("visible", &self.visible)
            .field("inner", &self.inner)
            .field("provisional", &self.provisional)
            .field("part", &self.part)
            .finish_non_exhaustive()
    }
}

impl Opened {
    /// The changes the event makes: none in a key event, the founder's
    /// grant in the genesis.
    pub fn changes(&self) -> &[Change] {
        self.part.as_ref().map_or(&[], RosterPart::changes)
    }

    /// Whether it is a roster event (the genesis included).
    pub fn is_roster(&self) -> bool {
        self.part.is_some()
    }

    /// The checkpoint's roster part, if this is a checkpoint (roster.md,
    /// "Checkpoints").
    pub fn checkpoint(&self) -> Option<&crate::part::CheckpointPart> {
        self.part.as_ref().and_then(RosterPart::checkpoint)
    }

    /// The genesis's roster part, if this is the genesis.
    pub fn genesis(&self) -> Option<&Genesis> {
        match &self.part {
            Some(RosterPart::Genesis(genesis)) => Some(genesis),
            _ => None,
        }
    }

    /// What keys.md's checks against the event and its place read of the
    /// body.
    pub fn facts(&self) -> Facts {
        Facts::of(&self.visible, &self.inner)
    }
}

/// What steps 2 to 10 make of a space event.
#[derive(Debug, Clone)]
pub enum Body {
    /// Steps 2 or 3 refused it: void, and no evidence.
    Refused(RosterClass),
    /// Held: `Sealed`, `BadSeal` or `ExtensionRequired`. It and every event
    /// after it are judged as if not received; its signature is still
    /// checked, as evidence.
    Held(RosterClass),
    /// Void at steps 5 to 10, with that class. Its signature is still
    /// checked, as evidence.
    Void(RosterClass),
    /// Opened and checked.
    Opened(Box<Opened>),
}

impl Body {
    /// The opened body, if any.
    pub fn opened(&self) -> Option<&Opened> {
        match self {
            Self::Opened(opened) => Some(opened),
            _ => None,
        }
    }
}

/// Step 11's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signature {
    /// The signature verified in full.
    Verified,
    /// No keys held yet hash to the event's `kc`: pending.
    NoHybridKey,
    /// The ML-DSA-65 half does not verify under the author's keys.
    BadSignature,
}

/// What a space event's checks read of its log beyond the event.
#[derive(Clone, Copy)]
pub struct ScreenContext<'a> {
    /// The space's ID, its genesis's event ID.
    pub space: EventId,
    /// The limits.
    pub limits: &'a Limits,
    /// Whether an event of the log is in this event's past (step 3).
    pub in_past: &'a dyn Fn(EventId) -> bool,
}

/// Steps 2 to 10 for one space event: the genesis when `event` is one.
pub fn screen_body(event: &Event, context: &ScreenContext<'_>, keys: &Keyring) -> Body {
    screen_body_keyed(event, context, keys).0
}

/// [`screen_body`], with the body key of an event void at steps 5 to 10
/// under a key derived from checked rotation keys: the replica opened that
/// event, and a newcomer's snapshot carries its key (roster.md, "Space
/// events a replica cannot open", "Body keys for newcomers").
fn screen_body_keyed(
    event: &Event,
    context: &ScreenContext<'_>,
    keys: &Keyring,
) -> (Body, Option<Secret>) {
    match steps_2_and_3(event, context) {
        Ok(visible) => open_body(event, visible, context, keys),
        Err(class) => (Body::Refused(class), None),
    }
}

/// Steps 2 and 3, which read nothing sealed.
fn steps_2_and_3(event: &Event, context: &ScreenContext<'_>) -> Result<VisiblePart, RosterClass> {
    // 2. Steps 2 to 10 come before step 11, the signature: they read the
    // body of an event whose Ed25519 signature, or half, decoding checked,
    // and step 11 takes keys from what they open.
    let visible = VisiblePart::read(event.unverified_body(), event.author(), event.seq())?;
    if event.is_genesis() != visible.nonce.is_some() || (event.is_genesis() && !visible.rotates()) {
        return Err(malformed());
    }
    // 3.
    if let Some(state) = visible.sealed_under()
        && !state.ids().iter().all(|&id| (context.in_past)(id))
    {
        return Err(malformed());
    }
    Ok(visible)
}

/// Steps 4 to 10.
fn open_body(
    event: &Event,
    visible: VisiblePart,
    context: &ScreenContext<'_>,
    keys: &Keyring,
) -> (Body, Option<Secret>) {
    let author = event.author();
    let seq = event.seq();
    let log: Vec<u8> = match visible.nonce {
        Some(nonce) => nonce.to_vec(),
        None => context.space.as_bytes().to_vec(),
    };
    // 4.
    let derived = match &visible.seal {
        frasil_keys::body::Seal::Rotation(rotation) => keys
            .rotations
            .get(&event.id())
            .filter(|secret| read_credential(secret).public == rotation.read)
            .cloned(),
        frasil_keys::body::Seal::Under(state) => keys.state_key(&context.space, state),
    };
    let (key, provisional) = if let Some(secret) = derived {
        let key = body_key(&secret, &log, author, seq);
        if body_commitment(&key) != visible.commitment {
            return (Body::Held(ErrorClass::BadSeal.into()), None);
        }
        (key, false)
    } else {
        let whole = visible
            .sealed_under()
            .and_then(|state| keys.states.get(state))
            .map(|secret| body_key(secret, &log, author, seq));
        let key = whole.or_else(|| {
            let mut handed: Zeroizing<Vec<[u8; 32]>> = Zeroizing::new(
                keys.bodies
                    .get(&event.id())
                    .map(|list| list.iter().map(|key| **key).collect())
                    .unwrap_or_default(),
            );
            handed.sort_unstable();
            handed.dedup();
            match handed.as_slice() {
                [only] => Some(Secret::new(*only)),
                _ => None,
            }
        });
        match key {
            Some(key) if body_commitment(&key) == visible.commitment => (key, true),
            _ => return (Body::Held(ErrorClass::Sealed.into()), None),
        }
    };
    let void_key = |key: &Secret| (!provisional).then(|| key.clone());
    // 5.
    let inner = match visible.open(&key, &log, author, seq) {
        Ok(inner) => inner,
        Err(class) => {
            let class = RosterClass::from(class);
            return if class == ErrorClass::BadSeal.into() {
                (Body::Held(class), None)
            } else {
                (Body::Void(class), void_key(&key))
            };
        }
    };
    // 6. to 10.
    let part = match read_part(event, &visible, &inner, context) {
        Ok(part) => part,
        Err(class) if class == ErrorClass::ExtensionRequired.into() => {
            return (Body::Held(class.into()), None);
        }
        Err(class) => return (Body::Void(class.into()), void_key(&key)),
    };
    (
        Body::Opened(Box::new(Opened {
            visible,
            inner,
            body_key: key,
            provisional,
            part,
        })),
        None,
    )
}

/// Whether a space event held as `ExtensionRequired` is held for a roster
/// part of a type from 3 (roster.md, 3.16 Rules this replica lacks): its
/// sealed part opens, under a key derived or handed as step 4 finds it,
/// and its roster part's key 0 is 3 or more.
fn later_rules(event: &Event, context: &ScreenContext<'_>, keys: &Keyring) -> bool {
    if event.is_genesis() {
        return false;
    }
    let Ok(visible) = steps_2_and_3(event, context) else {
        return false;
    };
    let log = context.space.as_bytes().to_vec();
    let derived = match &visible.seal {
        frasil_keys::body::Seal::Rotation(rotation) => keys
            .rotations
            .get(&event.id())
            .filter(|secret| read_credential(secret).public == rotation.read)
            .cloned(),
        frasil_keys::body::Seal::Under(state) => keys.state_key(&context.space, state),
    };
    let key = derived
        .map(|secret| body_key(&secret, &log, event.author(), event.seq()))
        .or_else(|| {
            let handed = keys.bodies.get(&event.id())?;
            match handed.as_slice() {
                [only] => Some(only.clone()),
                _ => None,
            }
        });
    let Some(key) = key.filter(|key| body_commitment(key) == visible.commitment) else {
        return false;
    };
    visible
        .open(&key, &log, event.author(), event.seq())
        .ok()
        .and_then(|inner| inner.roster)
        .is_some_and(|roster| crate::part::is_later_rules(&roster, false))
}

/// Steps 6 to 10.
fn read_part(
    event: &Event,
    visible: &VisiblePart,
    inner: &Inner,
    context: &ScreenContext<'_>,
) -> Result<Option<RosterPart>, SpaceClass> {
    let genesis = event.is_genesis();
    let Some(bytes) = &inner.roster else {
        if genesis || visible.twin.is_some() {
            return Err(ErrorClass::Malformed.into());
        }
        return Ok(None);
    };
    let space = context.space.as_bytes();
    let part_context = PartContext {
        author: event.author(),
        space: (!genesis).then_some(space),
        rotates: visible.rotates(),
        limits: context.limits,
    };
    let part = RosterPart::read(bytes, &part_context)?;
    // A genesis cites nothing; nor does a checkpoint (roster.md, "The
    // roster part").
    if (genesis || matches!(part, RosterPart::Checkpoint(_))) && !inner.refs.is_empty() {
        return Err(ErrorClass::Malformed.into());
    }
    Ok(Some(part))
}

/// What a space's checks read of every source of keys beyond its own log
/// (roster.md, "An author's keys"; "Strangers' events").
///
/// The [`KeySource`] half gives keys by their hash from any source: the
/// `add`s of the lists the space reads, the grants of the spaces it grants,
/// the skeleton's roots and enrolments, admission exchanges, caches. The
/// replica that implements it re-screens a view whose events are
/// `NoHybridKey` when either of its lookups grows.
pub trait Records: KeySource {
    /// Whether a record of another log names `device`: an `add` of it in a
    /// list the space reads, or a grant of it in a space it grants, valid or
    /// not. An event whose author no record names is a stranger's.
    fn names(&self, device: &DeviceId) -> bool;

    /// Whether the skeleton vouches for a pseudonym: a root that passes
    /// peers.md's checks, or an enrolment that verifies against an
    /// administrator slot a held root or change made (roster.md, "The
    /// skeleton's resolution"). None by default: a replica that models no
    /// skeleton vouches for no pseudonym.
    fn vouches_for(&self, pseudonym: &DeviceId) -> bool {
        let _ = pseudonym;
        false
    }
}

/// No other log, and no other source of keys.
impl Records for () {
    fn names(&self, _device: &DeviceId) -> bool {
        false
    }
}

/// Whether a change names a device's keys: a grant of it as a device; with
/// ext-invite-links.md, also a grant of it as an invite key, and a
/// successor that grants it as a device.
fn names_device(change: &Change, device: &crate::MemberRef) -> bool {
    (change.op == crate::Op::Grant && change.member == Some(*device))
        || ext::names_invite_device(change, device)
}

/// Step 11 for one event, under keys from any source, used only if they
/// hash to the event's `kc`.
pub fn check_signature(event: &Event, keys: Option<&HybridKeys>) -> Signature {
    signature_of(&event.verify_hybrid(keys))
}

fn signature_of(outcome: &Result<VerifiedEvent, EventClass>) -> Signature {
    match outcome {
        Ok(_) => Signature::Verified,
        Err(class) if class.shared() == Some(ErrorClass::NoHybridKey) => Signature::NoHybridKey,
        Err(_) => Signature::BadSignature,
    }
}

/// The events of one log a view holds, each checked alone: steps 2 to 11
/// of roster.md's "The event alone" for its space events, and the
/// signature of every other event (step 11's sources, "Where an author's
/// ML-DSA-65 key comes from").
#[derive(Debug, Clone)]
pub struct ScreenedLog {
    space: EventId,
    view: BTreeSet<EventId>,
    /// Space events in canonical order, the genesis first.
    order: Vec<EventId>,
    bodies: BTreeMap<EventId, Body>,
    /// The body keys of space events void at steps 5 to 10, opened under
    /// keys derived from checked rotation keys.
    void_keys: BTreeMap<EventId, Secret>,
    /// Every event of the view whose signature was checked: all but space
    /// events refused at steps 2 and 3, and storage events whose body
    /// does not read.
    signatures: BTreeMap<EventId, Signature>,
    /// The events whose signature is [`Signature::Verified`].
    verified: BTreeMap<EventId, VerifiedEvent>,
    /// Storage events: their type, or the class their body fails with.
    storage: BTreeMap<EventId, Result<StorageType, RosterClass>>,
    /// The keys the grants of every roster event opened carry, valid or
    /// void, by their hashes.
    keys: KeyRing,
    /// The keys the genesis's grants carry, when they are not among
    /// [`Self::keys`]: in a checkpoint's world the genesis takes no part
    /// but the descriptor's, so its grants supply only its own signature.
    genesis_keys: KeyRing,
    /// Whether the genesis's grants name devices and supply keys: not in a
    /// checkpoint's world (roster.md, 3.15.5 The world after a checkpoint).
    genesis_counts: bool,
    /// The space events held for a roster part of a type from 3, which a
    /// later document defines (roster.md, 3.16 Rules this replica lacks).
    later_rules: BTreeSet<EventId>,
}

impl ScreenedLog {
    /// Checks every event of a log: [`ScreenedLog::screen_in`] over the
    /// whole log.
    ///
    /// # Errors
    ///
    /// As [`ScreenedLog::screen_in`].
    pub fn screen(
        log: &Log,
        keys: &Keyring,
        limits: &Limits,
        records: &dyn Records,
    ) -> Result<Self, RosterClass> {
        let all: BTreeSet<EventId> = log.canonical().into_iter().collect();
        Self::screen_in(log, &all, keys, limits, records)
    }

    /// Checks every event of a view (a set of placed events closed under
    /// parents), in canonical order: steps 2 to 10 for its space events,
    /// then step 11 for every event, under keys that hash to its `kc`: those
    /// this view's grants carry, then those `records` gives. A skeleton
    /// event's keys are its pseudonym's, which the skeleton's root or
    /// enrolment carries and `records` gives like any other.
    ///
    /// # Errors
    ///
    /// A replica that cannot use the genesis cannot use the space: the
    /// genesis's class when it fails steps 2 to 11 (`Sealed` or `BadSeal`
    /// when it cannot be opened), or keys.md's checks against the event and
    /// its place, with itself as its place. `Pending` for a view without
    /// the genesis.
    pub fn screen_in(
        log: &Log,
        view: &BTreeSet<EventId>,
        keys: &Keyring,
        limits: &Limits,
        records: &dyn Records,
    ) -> Result<Self, RosterClass> {
        Self::screen_with(log, view, keys, limits, records, true)
    }

    /// As [`ScreenedLog::screen_in`], for the log of a checkpoint's world
    /// ([`crate::checkpoint_world::WorldLog`]): the genesis stays the source
    /// of the descriptor and the system stream, but its grants name no
    /// device and supply no key but for its own signature, so that keys
    /// come only from the checkpoint's record, the world's events and other
    /// logs (roster.md, 3.15.5 The world after a checkpoint).
    ///
    /// # Errors
    ///
    /// As [`ScreenedLog::screen_in`].
    pub fn screen_world_in(
        log: &Log,
        view: &BTreeSet<EventId>,
        keys: &Keyring,
        limits: &Limits,
        records: &dyn Records,
    ) -> Result<Self, RosterClass> {
        Self::screen_with(log, view, keys, limits, records, false)
    }

    fn screen_with(
        log: &Log,
        view: &BTreeSet<EventId>,
        keys: &Keyring,
        limits: &Limits,
        records: &dyn Records,
        genesis_counts: bool,
    ) -> Result<Self, RosterClass> {
        let space = log.id();
        if !view.contains(&space) {
            return Err(ErrorClass::Pending.into());
        }
        let mut out = Self {
            space,
            view: view.clone(),
            order: Vec::new(),
            bodies: BTreeMap::new(),
            void_keys: BTreeMap::new(),
            signatures: BTreeMap::new(),
            verified: BTreeMap::new(),
            storage: BTreeMap::new(),
            keys: KeyRing::new(),
            genesis_keys: KeyRing::new(),
            genesis_counts,
            later_rules: BTreeSet::new(),
        };
        let canonical = log.canonical_in(view);
        let mut restricted = None;
        for &id in &canonical {
            let Some(event) = log.event(id) else {
                continue;
            };
            match event.kind() {
                frasil_events::kind::SPACE => {}
                frasil_events::kind::STORAGE => {
                    // Its type, read before step 11 as a space event's
                    // steps 2 to 10 are.
                    let read = StorageBody::read(event.unverified_body())
                        .map(|body| body.storage_type())
                        .map_err(RosterClass::from);
                    out.storage.insert(id, read);
                    continue;
                }
                _ => continue,
            }
            let in_past = |earlier: EventId| log.precedes(earlier, id);
            let context = ScreenContext {
                space,
                limits,
                in_past: &in_past,
            };
            let body = match (restricted, event.is_genesis()) {
                (Some(class), false) => match steps_2_and_3(event, &context) {
                    Ok(_) => Body::Held(class),
                    Err(refused) => Body::Refused(refused),
                },
                _ => {
                    let (body, void_key) = screen_body_keyed(event, &context, keys);
                    if let Some(key) = void_key {
                        out.void_keys.insert(id, key);
                    }
                    if later_rules(event, &context, keys) {
                        out.later_rules.insert(id);
                    }
                    body
                }
            };
            if let (true, Some(genesis)) =
                (event.is_genesis(), body.opened().and_then(Opened::genesis))
            {
                restricted = ext::check_descriptor(&genesis.descriptor)
                    .err()
                    .map(RosterClass::from);
            }
            out.order.push(id);
            out.bodies.insert(id, body);
        }
        // The keys every opened grant carries, by their hashes.
        for id in &out.order {
            let Some(opened) = out.bodies.get(id).and_then(Body::opened) else {
                continue;
            };
            let ring = if *id == space && !genesis_counts {
                &mut out.genesis_keys
            } else {
                &mut out.keys
            };
            for change in opened.changes() {
                if let Some(keys) = &change.keys {
                    ring.add_device(DeviceKeys::clone(keys));
                }
            }
        }
        // 11.
        for &id in &canonical {
            if matches!(out.bodies.get(&id), Some(Body::Refused(_)))
                || matches!(out.storage.get(&id), Some(Err(_)))
            {
                continue;
            }
            let event = log.event(id).expect("screened events are placed");
            // A signature the log already holds verified, or one checked
            // before under its author's keys, is not checked again.
            let found = match id == space {
                true => out
                    .genesis_keys
                    .get(event.kc())
                    .cloned()
                    .or_else(|| out.hybrid_keys_in(event.kc(), records)),
                false => out.hybrid_keys_in(event.kc(), records),
            };
            let outcome = log.verify_hybrid_remembered(event, found.as_ref());
            out.record_signature(id, outcome);
        }
        // The genesis: usable through step 11, and keys.md's checks
        // against itself as its place.
        out.verdict(space).unwrap_or_else(|| Err(malformed()))?;
        let genesis = out.opened(space).ok_or_else(malformed)?;
        let mut context = Context::new(EventKind::Genesis);
        context.author_propagates = true;
        context.restricted = genesis
            .genesis()
            .is_some_and(|g| g.descriptor.kind == crate::DescriptorKind::Restricted);
        check_context(Some(genesis.facts()), &context)?;
        Ok(out)
    }

    /// Step 11 on a content unit placed after this view was screened, under
    /// keys that hash to its `kc`, from this view's grants or `records`: the
    /// unit joins the view with its signature's outcome. What steps 2 to 10
    /// read, the space events, is unchanged by a unit.
    pub fn add_unit(&mut self, log: &Log, id: EventId, records: &dyn Records) -> Signature {
        let event = log.event(id).expect("an added unit is placed");
        let outcome =
            log.verify_hybrid_remembered(event, self.hybrid_keys_in(event.kc(), records).as_ref());
        self.view.insert(id);
        self.record_signature(id, outcome)
    }

    /// Keeps step 11's outcome for an event, and the event when it
    /// verified.
    fn record_signature(
        &mut self,
        id: EventId,
        outcome: Result<VerifiedEvent, EventClass>,
    ) -> Signature {
        let signature = signature_of(&outcome);
        self.signatures.insert(id, signature);
        match outcome {
            Ok(verified) => {
                self.verified.insert(id, verified);
            }
            Err(_) => {
                self.verified.remove(&id);
            }
        }
        signature
    }

    /// An event of the view whose signature step 11 verified in full,
    /// whatever its body's verdict: the type that what acts on an event's
    /// body takes.
    pub fn verified(&self, id: EventId) -> Option<&VerifiedEvent> {
        self.verified.get(&id)
    }

    /// The space's ID.
    pub fn space(&self) -> EventId {
        self.space
    }

    /// The view screened.
    pub fn view(&self) -> &BTreeSet<EventId> {
        &self.view
    }

    /// The space events screened, in canonical order, the genesis first.
    pub fn events(&self) -> &[EventId] {
        &self.order
    }

    /// What steps 2 to 10 made of a space event.
    pub fn body(&self, id: EventId) -> Option<&Body> {
        self.bodies.get(&id)
    }

    /// The body key of a space event void at steps 5 to 10, opened under
    /// a key derived from checked rotation keys: a newcomer's snapshot
    /// carries it, so that the event is judged void there too rather than
    /// held (roster.md, "Space events a replica cannot open").
    pub fn void_body_key(&self, id: EventId) -> Option<&Secret> {
        self.void_keys.get(&id)
    }

    /// An opened space event.
    pub fn opened(&self, id: EventId) -> Option<&Opened> {
        self.bodies.get(&id).and_then(Body::opened)
    }

    /// The genesis's roster part.
    pub fn genesis(&self) -> &Genesis {
        self.opened(self.space)
            .and_then(Opened::genesis)
            .expect("a screened log's genesis is opened")
    }

    /// Step 11's outcome for an event of the view whose signature was
    /// checked.
    pub fn signature(&self, id: EventId) -> Option<Signature> {
        self.signatures.get(&id).copied()
    }

    /// A storage event's type, or the class its body fails with.
    pub fn storage(&self, id: EventId) -> Option<Result<StorageType, RosterClass>> {
        self.storage.get(&id).copied()
    }

    /// The verdict of steps 2 to 11 on a space event: `Ok` when it opened
    /// and its signature verified. A void body's class comes before its
    /// signature's, a held body's after a bad signature's.
    pub fn verdict(&self, id: EventId) -> Option<Result<(), RosterClass>> {
        let body = self.bodies.get(&id)?;
        let signature = self.signatures.get(&id).copied();
        Some(match (body, signature) {
            (Body::Refused(class) | Body::Void(class), _) => Err(*class),
            (_, Some(Signature::BadSignature)) => Err(ErrorClass::BadSignature.into()),
            (Body::Held(class), _) => Err(*class),
            (Body::Opened(_), Some(Signature::Verified)) => Ok(()),
            (Body::Opened(_), _) => Err(ErrorClass::NoHybridKey.into()),
        })
    }

    /// The keys the grants of this view's opened roster events carry, valid
    /// or void, the genesis's founder among them, indexed by their hashes:
    /// a source of keys for any event, of this log or another.
    pub fn keys(&self) -> &KeyRing {
        &self.keys
    }

    /// The keys whose commitment is `kc`: this view's grants, then
    /// `records`.
    pub fn hybrid_keys_in(
        &self,
        kc: &KeysCommitment,
        records: &(impl Records + ?Sized),
    ) -> Option<HybridKeys> {
        self.keys
            .get(kc)
            .cloned()
            .or_else(|| records.hybrid_keys(kc))
    }

    /// Whether a grant of an opened roster event of this view names a
    /// device, valid or void, the genesis's founder among them; with
    /// ext-invite-links.md, also a grant of it as an invite key and a
    /// successor that grants it as a device.
    pub fn names(&self, device: &DeviceId) -> bool {
        let member = crate::MemberRef::device(*device);
        self.order.iter().any(|id| {
            (self.genesis_counts || *id != self.space)
                && self
                    .opened(*id)
                    .is_some_and(|opened| opened.changes().iter().any(|c| names_device(c, &member)))
        })
    }

    /// Whether an event of the view counts as evidence of a fork
    /// (events.md, "Chains and evidence of a fork"): its signature
    /// verified, and it is not a space event refused at steps 2 and 3 or a
    /// storage event whose body does not read. Whether the replica can
    /// open it does not matter.
    pub fn counts_as_evidence(&self, id: EventId) -> bool {
        self.signatures.get(&id) == Some(&Signature::Verified)
    }

    /// Each author's fork point among some of the view's events of `log`,
    /// those that count as evidence.
    pub fn fork_points_among(&self, log: &Log, events: &BTreeSet<EventId>) -> ForkPoints {
        log.fork_points_counting(events, |id| self.counts_as_evidence(id))
    }

    /// Each author's fork point among the view's events of `log` that count
    /// as evidence.
    pub fn fork_points(&self, log: &Log) -> ForkPoints {
        log.fork_points_counting(&self.view, |id| self.counts_as_evidence(id))
    }

    /// The space events held for a roster part of a type from 3 (roster.md,
    /// 3.16 Rules this replica lacks), in ascending order: the space holds
    /// each one whose author has standing in its past, and every event
    /// outside that past.
    pub fn later_rules(&self) -> &BTreeSet<EventId> {
        &self.later_rules
    }

    /// The space events held (`Sealed`, `BadSeal`, `ExtensionRequired`),
    /// in canonical order. They and every event after them are judged as
    /// if not received.
    pub fn held(&self) -> Vec<EventId> {
        self.order
            .iter()
            .copied()
            .filter(|id| matches!(self.bodies[id], Body::Held(_)))
            .collect()
    }

    /// The events of a log, of every kind, that are held or have a held
    /// event in their past (roster.md, "Space events a replica cannot
    /// open").
    pub fn held_closure(&self, log: &Log) -> BTreeSet<EventId> {
        let held = self.held();
        log.canonical()
            .into_iter()
            .filter(|&id| held.iter().any(|&h| h == id || log.precedes(h, id)))
            .collect()
    }
}
