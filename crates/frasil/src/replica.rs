//! The replica engine: one space's log as this device holds it, judged in
//! roster.md's order of verification, with the keys it takes and the
//! streams its adapters build.
//!
//! A [`Replica`] holds the space's placed events (`frasil-events`' [`Log`]),
//! the secrets of every rotation it has taken, and the verdicts of its last
//! resolution. [`Replica::refresh`] runs, after every batch of events:
//!
//! 1. **The order of verification** (roster.md, "The order of
//!    verification"), by `frasil-space`'s [`Space::resolve`]: envelopes and
//!    placement, each space event's body opened or held, the ML-DSA-65
//!    halves, the roster events by the resolution procedure with the twins
//!    the skeleton gives, each key event by the write rule, then each unit,
//!    anchor and storage event. Units are read through units.md's
//!    [`UnitReader`] over the keys held.
//! 2. **Taking keys** (keys.md, "Reading key names, bundles, wraps and
//!    links", "Taking a key"): every delivery of an opened space event that
//!    names a state this device lacks is tried with its X-Wing seed, and
//!    each secret of a single rotation is checked slot by slot against the
//!    rotation's commitments. Links under held states give the states they
//!    reach. A new key can open more events, so 1 and 2 repeat until no key
//!    is taken.
//! 3. **What replicas derive**: the merged roster, the current content and
//!    grant states, the valid set.
//! 4. **Units to their adapters** (units.md, "A unit, at a member", step
//!    16, and "Rebuilds"): each unit that opened goes to its stream's
//!    adapter after the content check, valid or not, so that adapters that
//!    count count it; a unit whose verdict changed marks its stream for one
//!    rebuild per batch.
//!
//! Nothing here reads a clock or draws randomness; the device gives the
//! reading at which a verdict is first reached (its first sight).

use crate::adapters::{AdapterRegistry, ContentOutcome, StreamRuntime};
use frasil_adapter::Locator;
use frasil_adapter::{Capabilities, Capability, Mode, StreamUnit};
use frasil_base::ErrorClass;
use frasil_base::collect::CollectMap;
use frasil_base::errors::{Class, Sort};
use frasil_base::time::Reading;
use frasil_crypto::device::{DeviceId, KeyRing, KeySource};
use frasil_events::{Event, EventId, Log, Placement, VerifiedEvent, kind};
use frasil_keys::KeyName;
use frasil_keys::RotationSet;
use frasil_keys::body::{RotationKeys, VisiblePart};
use frasil_keys::derive::{GrantKey, Secret, SecretKind, read_credential, state_secret};
use frasil_keys::links::LinkKind;
use frasil_keys::reference::{Lookup, RotationLog};
use frasil_keys::wraps::find_own_wrap;
use frasil_space::across::AuthorReach;
use frasil_space::graph::Reach;
use frasil_space::keygraph::{GrantedNotices, Kind, SpaceHistory, take_slots};
use frasil_space::{
    KeyEventChecks, Keyring, Level, Limits, MemberRef, MemberType, Options, OtherLogs, PathsFor,
    Policy, Roster, RosterClass, Space, Status, Twins,
};
use frasil_store::tables::EventState;
use frasil_units::Stub as UnitStub;
use frasil_units::body::KeyReference;
use frasil_units::snapshot::StreamEntry;
use frasil_units::stream::{StreamId, content_check};
use frasil_units::unit::{KeyringKeys, StateKey, UnitKeys};
use frasil_units::{Unit, UnitError};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use zeroize::Zeroizing;

/// The most events of one author a replica keeps that it cannot place
/// (events.md, "Placement and order").
pub const MAX_PENDING_PER_AUTHOR: usize = 1_024;

/// The most events in all a replica keeps that it cannot place (events.md,
/// "Placement and order").
pub const MAX_PENDING_EVENTS: usize = 8_192;

/// The most bytes of signed events in all a replica keeps that it cannot
/// place (events.md, "Placement and order").
pub const MAX_PENDING_BYTES: usize = 64 << 20;

/// This device, as the replica engine needs it: its device ID and the
/// X-Wing seed it opens wraps with.
pub(crate) struct Me {
    /// The device ID.
    pub device: DeviceId,
    /// The X-Wing seed.
    pub xwing_seed: Secret,
    /// The invite keys this device claims with, whose wraps it opens too
    /// (ext-invite-links.md, "Claiming").
    #[cfg(feature = "ext-invite-links")]
    pub invites: Vec<InviteMe>,
    /// The list member a device recovers with, a recovery key or a passkey
    /// member: its device ID and X-Wing seed, whose wraps it opens too
    /// (identity.md, "Recovery", step 2).
    pub recovering: Option<(DeviceId, Secret)>,
}

/// An invite key a claimant holds while it claims: its device ID, the
/// X-Wing seed its wraps open with, and the invite entry.
#[cfg(feature = "ext-invite-links")]
#[derive(Clone)]
pub(crate) struct InviteMe {
    /// `K`, a device ID.
    pub device: DeviceId,
    /// `K`'s X-Wing seed.
    pub xwing_seed: Secret,
    /// The invite entry.
    pub entry: EventId,
}

impl Me {
    /// This device's own wrap among a delivery's, then an invite key's
    /// (keys.md, "Trial decryption").
    ///
    /// `at` names the delivery, by its event and index. A delivery is a
    /// fixed part of its event, and whether a wrap opens is a function of
    /// the wrap, the info the delivery and the identity give, and the
    /// identity's seed: an identity whose trial of a delivery found nothing
    /// is kept in `tried`, and never tries that delivery again.
    fn find_wrap(
        &self,
        wraps: &[Vec<u8>],
        log: &[u8],
        key_name: Option<&KeyName>,
        grant_name: Option<&KeyName>,
        at: (EventId, usize),
        tried: &mut WrapsTried,
    ) -> Option<(usize, frasil_keys::bundle::Bundle)> {
        let mut identities: Vec<(&DeviceId, &Secret)> = vec![(&self.device, &self.xwing_seed)];
        if let Some((device, xwing_seed)) = &self.recovering {
            identities.push((device, xwing_seed));
        }
        #[cfg(feature = "ext-invite-links")]
        for invite in &self.invites {
            identities.push((&invite.device, &invite.xwing_seed));
        }
        for (device, xwing_seed) in identities {
            let trial = (at.0, at.1, device.0);
            if tried.contains(&trial) {
                continue;
            }
            if let Some(found) = find_own_wrap(wraps, log, key_name, grant_name, device, xwing_seed)
            {
                return Some(found);
            }
            tried.insert(trial);
        }
        None
    }
}

/// The deliveries an identity of this device tried and found no wrap for,
/// as (event, the delivery's index, the identity's device ID).
pub(crate) type WrapsTried = BTreeSet<(EventId, usize, [u8; 32])>;

/// The space wraps of deliveries tried with a granted space's rotation's
/// grant key and found to open none, as (event, the delivery's index, the
/// granted space, its rotation, the SHA-256 of the grant key's public key).
pub(crate) type SpaceWrapsTried = BTreeSet<(EventId, usize, EventId, EventId, [u8; 32])>;

/// The secrets of one rotation this device holds, each checked against the
/// rotation's commitments or drawn by this device.
#[derive(Clone, Default)]
pub(crate) struct RotationSecrets {
    /// `k_R`.
    pub content: Option<Secret>,
    /// `w_R`.
    pub upload: Option<Secret>,
    /// `g_R`.
    pub grant: Option<Secret>,
}

impl RotationSecrets {
    fn merge(&mut self, other: &RotationSecrets) -> bool {
        let mut changed = false;
        for (mine, theirs) in [
            (&mut self.content, &other.content),
            (&mut self.upload, &other.upload),
            (&mut self.grant, &other.grant),
        ] {
            if mine.is_none() && theirs.is_some() {
                *mine = theirs.clone();
                changed = true;
            }
        }
        changed
    }
}

/// The visible parts of a log's space events, each read and checked once
/// (keys.md, "The visible part"): an event's bytes never change under its
/// ID, so neither does what its visible part reads as.
#[derive(Default)]
pub(crate) struct VisibleParts(std::sync::Mutex<BTreeMap<EventId, Option<Arc<VisiblePart>>>>);

impl VisibleParts {
    /// A space event's visible part, as [`visible`] reads it.
    pub(crate) fn of(&self, event: &Event) -> Option<Arc<VisiblePart>> {
        if event.kind() != kind::SPACE {
            return None;
        }
        let id = event.id();
        let mut parts = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        parts
            .entry(id)
            .or_insert_with(|| visible(event).map(Arc::new))
            .clone()
    }

    /// Whether a space event's visible part rotates.
    pub(crate) fn rotates(&self, event: &Event) -> bool {
        self.of(event).is_some_and(|v| v.rotates())
    }
}

/// What a replica read of each unit, by event ID (units.md, "A unit, at a
/// member"): steps 1 to 10 once, and, once its seal opened, its sealed part.
/// An event's bytes never change under its ID, so a unit reads the same each
/// time; a seal that opened under a key the replica holds opens to the same
/// sealed part under any key it holds later, and every check passed on the
/// way (the key reference against the log, the seal, step 14) passes again.
/// A unit whose reading failed, or waits on a key or an event, is read again
/// at each refresh. Nothing is kept until the system stream is known, since
/// step 14 reads it.
#[derive(Default)]
pub(crate) struct UnitReads {
    read: std::sync::Mutex<BTreeMap<EventId, Result<Arc<Unit>, UnitError>>>,
    opened: std::sync::Mutex<BTreeMap<EventId, Arc<frasil_units::Inner>>>,
    /// Units whose kept sealed part no longer holds the content: their
    /// stream took it.
    released: std::sync::Mutex<BTreeSet<EventId>>,
}

impl UnitReads {
    /// A unit, read from its event (units.md, "A unit, at a member", steps
    /// 1, 2 and 4 to 10).
    pub(crate) fn unit(&self, event: &Event) -> Result<Arc<Unit>, UnitError> {
        let id = event.id();
        if let Some(read) = lock(&self.read).get(&id) {
            return read.clone();
        }
        let read = Unit::from_event(event.clone()).map(Arc::new);
        lock(&self.read).insert(id, read.clone());
        read
    }

    /// A unit's sealed part, opened at a member (steps 11 to 14).
    pub(crate) fn open(
        &self,
        unit: &Unit,
        keys: &impl UnitKeys,
        system: Option<&StreamId>,
    ) -> Result<Arc<frasil_units::Inner>, UnitError> {
        let id = unit.id();
        if system.is_some()
            && let Some(inner) = lock(&self.opened).get(&id)
        {
            return Ok(Arc::clone(inner));
        }
        let inner = Arc::new(unit.open_at_member(keys, system)?);
        if system.is_some() {
            lock(&self.opened).insert(id, Arc::clone(&inner));
        }
        Ok(inner)
    }

    /// [`open`](Self::open), with the content even where the kept sealed
    /// part let it go: opened again for it.
    pub(crate) fn open_whole(
        &self,
        unit: &Unit,
        keys: &impl UnitKeys,
        system: Option<&StreamId>,
    ) -> Result<Arc<frasil_units::Inner>, UnitError> {
        if lock(&self.released).contains(&unit.id()) {
            // Read again from its event: the kept reading let its sealed
            // bytes go too.
            return Unit::from_event(unit.event.clone())?
                .open_at_member(keys, system)
                .map(Arc::new);
        }
        self.open(unit, keys, system)
    }

    /// Keeps a unit's sealed part without its content, once its stream
    /// took it: what later refreshes read of it is the rest.
    pub(crate) fn release_content(&self, id: EventId) {
        let mut opened = lock(&self.opened);
        if let Some(inner) = opened.get_mut(&id)
            && !inner.content.is_empty()
        {
            let mut kept = (**inner).clone();
            kept.content = Vec::new();
            *inner = Arc::new(kept);
            lock(&self.released).insert(id);
            // Nor the sealed bytes it opened from, which the event holds.
            if let Some(Ok(unit)) = lock(&self.read).get_mut(&id) {
                let mut kept = (**unit).clone();
                kept.body.sealed = Vec::new();
                *unit = Arc::new(kept);
            }
        }
    }

    /// Whether a unit's kept sealed part let its content go.
    #[cfg(debug_assertions)]
    fn is_released(&self, id: &EventId) -> bool {
        lock(&self.released).contains(id)
    }

    /// A unit's event read and opened: [`unit`](Self::unit), then
    /// [`open`](Self::open).
    pub(crate) fn read_open(
        &self,
        event: &Event,
        keys: &impl UnitKeys,
        system: Option<&StreamId>,
    ) -> Result<(Arc<Unit>, Arc<frasil_units::Inner>), UnitError> {
        let unit = self.unit(event)?;
        let inner = self.open(&unit, keys, system)?;
        Ok((unit, inner))
    }

    /// The sealed parts kept, by unit ID.
    #[cfg(debug_assertions)]
    fn opened(&self) -> Vec<(EventId, Arc<frasil_units::Inner>)> {
        lock(&self.opened)
            .iter()
            .map(|(id, inner)| (*id, Arc::clone(inner)))
            .collect()
    }
}

/// What the checkpoint half of a refresh's check from scratch gives: every
/// event's verdict, and who wrote each unit of a forgotten past.
#[cfg(debug_assertions)]
type CheckedFromScratch = (BTreeMap<EventId, Status>, BTreeMap<EventId, Authorship>);

/// Whether each refresh is checked against a resolution from scratch
/// ([`Replica::check_from_scratch`]), in debug builds: when a test sets it;
/// with `FRASIL_CHECK_REFRESH` set in the environment (`0` turns it off);
/// and in every test of this workspace that cargo-nextest runs, which is
/// how its tests run, at about a tenth more of their time. A test of
/// another workspace that builds Frasil runs without it.
#[cfg(debug_assertions)]
pub(crate) fn check_refreshes() -> bool {
    static DEFAULT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    CHECK_REFRESHES.load(std::sync::atomic::Ordering::Relaxed)
        || *DEFAULT.get_or_init(|| match std::env::var("FRASIL_CHECK_REFRESH") {
            Ok(value) => value != "0",
            Err(_) => {
                let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .and_then(std::path::Path::parent);
                std::env::var_os("NEXTEST").is_some()
                    && std::env::var_os("CARGO_MANIFEST_DIR").is_some_and(|dir| {
                        workspace.is_some_and(|root| std::path::Path::new(&dir).starts_with(root))
                    })
            }
        })
}

/// Set by a test to check every refresh.
#[cfg(debug_assertions)]
pub(crate) static CHECK_REFRESHES: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// units.md's reading of a unit for the roster, as [`UnitReader`] reads
/// it, through what the replica read of each unit before.
struct CachedReader<'a, K> {
    log: &'a Log,
    base: Option<&'a Base>,
    forgotten: Option<EventId>,
    frozen: &'a BTreeMap<EventId, frasil_units::frozen::Frozen>,
    reads: &'a UnitReads,
    keys: &'a K,
    system: Option<StreamId>,
}

impl<K: UnitKeys> frasil_space::UnitBodies for CachedReader<'_, K> {
    fn held_list_copies(&self, _log: &Log) -> Vec<Event> {
        self.log
            .events()
            .flat_map(|event| self.list_copy(event))
            .collect()
    }

    fn list_copy(&self, unit: &Event) -> Vec<Event> {
        let Ok((unit, inner)) = self.reads.read_open(unit, self.keys, self.system.as_ref()) else {
            return Vec::new();
        };
        if Some(unit.body.stream) != self.system || inner.type_ != frasil_units::types::LIST {
            return Vec::new();
        }
        frasil_units::own::read_list_copy(&inner.content).unwrap_or_default()
    }

    fn list_events_at(&self, _log: &Log, event: EventId) -> Option<Vec<EventId>> {
        let mut events: Vec<_> = self
            .log
            .events()
            .filter(|copy| {
                copy.id() == event
                    || self.log.precedes(copy.id(), event)
                    || (self.frozen.contains_key(&copy.id())
                        && self
                            .forgotten
                            .is_some_and(|root| root == event || self.log.precedes(root, event)))
            })
            .flat_map(|copy| self.list_copy(copy).into_iter().map(|e| e.id()))
            .collect();
        if let Some(base) = self.base
            && base
                .heads
                .iter()
                .any(|head| *head == event || self.log.precedes(*head, event))
        {
            events.extend(base.lists.iter().copied());
        }
        Some(events)
    }

    fn open(&self, unit: &Event) -> frasil_space::UnitBody {
        match self.reads.read_open(unit, self.keys, self.system.as_ref()) {
            Ok((_, inner)) => frasil_space::UnitBody::Opened(inner.refs.clone()),
            Err(class) => match class.shared() {
                Some(
                    frasil_base::ErrorClass::Pending
                    | frasil_base::ErrorClass::Sealed
                    | frasil_base::ErrorClass::ExtensionRequired,
                ) => frasil_space::UnitBody::Held(class.into()),
                _ => frasil_space::UnitBody::Void(class.into()),
            },
        }
    }
}

/// The log's rotations, as a key reference reads them (keys.md, "Reading a
/// unit's key reference"): a space event whose visible part rotates is a
/// rotation, valid or void; any other event is not.
pub(crate) struct Rotations<'a> {
    /// The log.
    pub log: &'a Log,
    /// Its visible parts, read once each.
    pub parts: &'a VisibleParts,
    /// The rotations whose secrets the device holds, when it reads its own
    /// log: a dropped one reads as a rotation only if it kept them.
    pub kept: Option<&'a BTreeMap<EventId, RotationSecrets>>,
}

impl RotationLog for Rotations<'_> {
    fn lookup(&self, id: &EventId) -> Lookup {
        match self.log.event(*id) {
            // A rotation of the past a replica forgot whose `key` record it
            // kept, its secrets checked when it held the event, for the
            // states that seal what it kept (at-rest.md, "Forgetting before
            // a checkpoint"; `frasil_store::checkpoint_state`).
            None if self.log.is_dropped(*id)
                && self.kept.is_none_or(|kept| kept.contains_key(id)) =>
            {
                Lookup::Rotation
            }
            None => Lookup::Missing,
            Some(event) if self.parts.rotates(event) => Lookup::Rotation,
            Some(_) => Lookup::NotARotation,
        }
    }

    fn precedes(&self, earlier: &EventId, later: &EventId) -> bool {
        self.log.precedes(*earlier, *later)
    }
}

/// The keys a replica reads its units with: keys.md's key reference over
/// its own keyring, or in a restricted space ext-restricted-spaces.md's,
/// over its own keyring and its parent's.
pub(crate) enum ReplicaKeys<'k, 'l> {
    /// A rotation set, over the space's own keys.
    Plain(KeyringKeys<'k, Rotations<'l>>),
    /// The restricted key reference, over the space's and its parent's.
    #[cfg(feature = "ext-restricted-spaces")]
    Restricted(
        frasil_units::ext_restricted_spaces::RestrictedKeys<'k, Rotations<'l>, Rotations<'l>>,
    ),
}

impl UnitKeys for ReplicaKeys<'_, '_> {
    fn key(&self, space: &EventId, reference: &KeyReference) -> Result<StateKey, UnitError> {
        match self {
            Self::Plain(keys) => keys.key(space, reference),
            #[cfg(feature = "ext-restricted-spaces")]
            Self::Restricted(keys) => keys.key(space, reference),
        }
    }

    fn handed(&self, unit: &EventId) -> &[Secret] {
        match self {
            Self::Plain(keys) => keys.handed(unit),
            #[cfg(feature = "ext-restricted-spaces")]
            Self::Restricted(keys) => keys.handed(unit),
        }
    }
}

/// A space event's visible part, read without a key, as a peer reads it:
/// whether the event's signature verified in full is the caller's question.
pub(crate) fn visible(event: &Event) -> Option<VisiblePart> {
    if event.kind() != kind::SPACE {
        return None;
    }
    VisiblePart::read(event.unverified_body(), event.author(), event.seq()).ok()
}

/// Whether an event is a rotation: a space event whose visible part
/// rotates.
#[cfg_attr(
    not(any(feature = "server", feature = "iroh", feature = "server-socket")),
    allow(dead_code)
)]
pub(crate) fn rotates(event: &Event) -> bool {
    visible(event).is_some_and(|v| v.rotates())
}

/// What one refresh changed.
#[derive(Debug, Default)]
pub(crate) struct Refreshed {
    /// List events found in `frasil:list` units, not yet in the device's
    /// lists.
    pub list_events: Vec<Vec<u8>>,
    /// Events whose body key a unit handed over, for the store.
    pub bodies: Vec<EventId>,
    /// Rotations whose secrets this device took, for the store.
    pub taken: Vec<EventId>,
    /// Merged states received whole, for the store.
    pub states: Vec<RotationSet>,
    /// Events whose verdict changed, or that are new.
    pub changed: Vec<EventId>,
}

impl Refreshed {
    /// Adds what a later refresh changed to what this one did.
    pub(crate) fn absorb(&mut self, later: Refreshed) {
        if self.list_events.is_empty() {
            self.list_events = later.list_events;
        }
        self.bodies.extend(later.bodies);
        self.taken.extend(later.taken);
        self.states.extend(later.states);
        self.changed.extend(later.changed);
    }
}

/// A unit handed to a stream.
#[derive(Debug, Clone)]
struct Handed {
    stream: StreamId,
    /// Whether it is valid by the write rule.
    valid: bool,
    /// Whether its stream applies its content if the adapter accepts it:
    /// it is valid, and its author's capabilities were found (units.md,
    /// 3.17 "Capability checks"). A unit whose verdict moves to pending
    /// stops applying, as one whose capabilities are no longer found does.
    applies: bool,
    /// Its author's capabilities at its place, as last handed.
    capabilities: Capabilities,
}

/// One space's replica at this device.
pub struct Replica {
    space: EventId,
    log: Option<Log>,
    staged: BTreeMap<EventId, Event>,
    secrets: BTreeMap<EventId, RotationSecrets>,
    states: BTreeMap<RotationSet, Secret>,
    statuses: BTreeMap<EventId, Status>,
    unresolved: Option<RosterClass>,
    roster: Roster,
    policy: Policy,
    current: Option<RotationSet>,
    grant_current: Option<RotationSet>,
    valid: BTreeSet<EventId>,
    system_stream: Option<StreamId>,
    streams: BTreeMap<StreamId, Box<dyn StreamRuntime>>,
    handed: BTreeMap<EventId, Handed>,
    refused_content: BTreeMap<EventId, &'static str>,
    /// Valid units whose author's capabilities the replica did not find at
    /// their place (units.md, 3.17 "Capability checks"): content that waits
    /// (`Pending`) or is refused (`CapabilityRefused`), judged again at
    /// each resolution. Units handed before whose verdict is now undecided
    /// wait here too, with their class (units.md, 3.15 "Pending, never
    /// applied").
    unreached: BTreeMap<EventId, ContentOutcome>,
    /// Base stubs contradicted since: see [`Replica::contradicted_base`].
    contradicted_base: BTreeSet<EventId>,
    first_sight: BTreeMap<EventId, Reading>,
    /// The events whose every signature half verified, in the log or in
    /// the screening of the view.
    verified: BTreeMap<EventId, VerifiedEvent>,
    forks: frasil_events::ForkPoints,
    /// Body keys handed over, as each sender handed them: provisional.
    bodies: BTreeMap<EventId, Vec<Secret>>,
    /// Body keys this device opened or derived, which it hands newcomers.
    opened_bodies: BTreeMap<EventId, Secret>,
    /// The rotations held `Sealed` whose own deliveries this device has
    /// tried for a removal wrap (keys.md, "Trial decryption").
    removal_tried: BTreeSet<EventId>,
    /// The deliveries whose wraps an identity of this device tried and
    /// none opened (keys.md, "Trial decryption"): never tried again.
    wraps_tried: WrapsTried,
    /// Likewise for space wraps, by the grant key tried.
    space_wraps_tried: SpaceWrapsTried,
    /// Whether this device has been a member of the space since the
    /// replica was loaded: its view gave it a level.
    was_member: bool,
    /// The application kind the genesis's descriptor names, once read
    /// (roster.md, "The space descriptor").
    application: Option<String>,
    /// The base a replica that started from a snapshot holds.
    base: Option<Base>,
    /// Objects held, by locator: the header and each chunk received.
    objects: BTreeMap<Locator, HeldObject>,
    /// Objects the store holds whose locator is not yet known, by object
    /// ID: the locator hashes the whole object, which is read only once it
    /// is needed (units.md, "Objects").
    unlocated: BTreeMap<[u8; 32], HeldObject>,
    /// Objects forgotten because their bytes did not hash to their
    /// locators, whose records the device deletes.
    forgotten_objects: Vec<(Locator, BTreeSet<u64>)>,
    /// Events dropped to keep within the limits on what the replica holds
    /// of events it cannot place, whose records the device deletes.
    dropped_pending: Vec<EventId>,
    /// Whether chunks stay in the store once kept, rather than in memory:
    /// unless the log is kept in memory only.
    chunks_at_rest: bool,
    /// Objects a refresh needed whose chunks are in the store: the device
    /// reads them back and refreshes again.
    wanted_at_rest: BTreeSet<Locator>,
    /// Stream entries of a space snapshot not yet loaded.
    pending_streams: Vec<StreamEntry>,
    /// A space snapshot adopted from a message, not stored yet: kept as an
    /// object once the device can seal it under a state it holds.
    snapshot_to_keep: Option<Vec<u8>>,
    /// The newcomer's snapshot a welcome or an invite's drop names, until
    /// it is fetched and used (admission.md, "The newcomer's snapshot").
    awaited_snapshot: Option<Locator>,
    /// A newcomer's snapshot was never used, and its locator is lost: the
    /// replica places nothing new until a member hands it one.
    wants_snapshot: bool,
    /// The administrator slots of the merged view.
    slots: crate::skeleton::Slots,
    /// The keys every opened record of the log names, valid or void, by
    /// their hash: a source for every other log (crypto.md, "Keys by their
    /// hash").
    found_keys: KeyRing,
    /// Whether the view holds an event whose ML-DSA-65 half waits for keys
    /// that hash to its `kc` (`NoHybridKey`, pending): it is judged again
    /// when the device's keys grow.
    awaits_keys: bool,
    /// The signed space snapshot this replica adopted while it held no
    /// keys that hash to its sender's `kc`: provisional, its ML-DSA-65 half
    /// checked again when the device's keys grow (units.md, "The space
    /// snapshot", "Using it", step 3).
    provisional_snapshot: Option<Vec<u8>>,
    /// The sender of the space snapshot this replica adopted, until the
    /// view grants this device and shows whether the sender reaches the
    /// space (units.md, "The space snapshot", "Using it").
    snapshot_sender: Option<DeviceId>,
    /// The streams whose state was loaded from the space snapshot's stream
    /// entries.
    snapshot_streams: BTreeSet<StreamId>,
    /// The base was discarded since the device last stored the log's state.
    base_discarded: bool,
    /// How many times a refresh resolved the view in full, rather than
    /// from a kept resolution, for tests.
    #[cfg(test)]
    full_resolutions: usize,
    /// Effective membership of the merged view: each device that reaches
    /// the space, with its highest level over every path and its highest
    /// over the paths that propagate, if any does.
    effective: BTreeMap<[u8; 32], (Level, Option<Level>)>,
    /// What a space that grants this one reads of it.
    facts: Option<crate::granted::GrantedFacts>,
    /// The list events the space's `frasil:list` units carry.
    list_copies: BTreeSet<EventId>,
    /// Who wrote each valid unit, as the roster and the lists held at its
    /// place: for history's attribution.
    authorship: BTreeMap<EventId, Authorship>,
    /// The events that void each unit of the view the write rule voids.
    voiders: BTreeMap<EventId, Vec<EventId>>,
    /// The space principals in force, with the grant key a notice names.
    principals: Vec<(
        EventId,
        EventId,
        Box<[u8; frasil_crypto::sizes::XWING_PUBLIC]>,
        Level,
    )>,
    /// The heals the view calls for (keys.md, "Healing").
    heals: Vec<crate::healing::HealDue>,
    /// The space events and units whose body keys members admitted "from
    /// now on" are owed (admission.md, "Top-ups").
    top_ups: Vec<EventId>,
    /// The body keys of the units among `top_ups` this device holds.
    top_up_keys: BTreeMap<EventId, Secret>,
    /// The events known to follow every break of the view, when it holds
    /// one: units appended past them need no full resolution.
    break_frontier: Option<crate::top_ups::Frontier>,
    /// Inside devices that derive no current state (keys.md, "Deliveries").
    lacking: Option<crate::healing::Lacking>,
    /// Other content states inside devices are entitled to and lack, at
    /// the last resolution (keys.md, "Deliveries", item 2).
    entitled: Vec<crate::healing::Lacking>,
    /// The valid roster events of the merged view.
    roster_events: BTreeSet<EventId>,
    /// Events whose author administered at their place, for welcome checks.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    administrator_authors: BTreeSet<EventId>,
    /// Each stream's opening, from its units.
    openings: BTreeMap<StreamId, frasil_units::stream::Opening>,
    /// Snapshot units whose check failed (`BadCompaction`): never used.
    bad_compactions: BTreeSet<EventId>,
    /// State objects whose header names a plaintext larger than their
    /// adapter loads: never fetched further, and the snapshot units and
    /// stream entries that name them are never used.
    oversized_states: BTreeSet<Locator>,
    /// Units that carried supersessions, with their stream and the
    /// objects they superseded (ext-file-versions.md, 3.10 A superseding
    /// unit refused).
    #[cfg(feature = "ext-file-versions")]
    superseding: BTreeMap<EventId, (StreamId, BTreeSet<frasil_adapter::Locator>)>,
    /// Snapshot units whose state a stream loaded in place of its cover.
    used_snapshots: BTreeSet<EventId>,
    /// The snapshot unit whose state each stream uses as its base, while
    /// it does.
    bases: BTreeMap<StreamId, EventId>,
    /// Snapshot units whose cover this replica holds and whose check
    /// passed, with their declaration, `excluded` and parents: each may be
    /// used once settled, so that its cover can be collected.
    checked_snapshots: BTreeMap<EventId, SnapshotCandidate>,
    /// Checked or used snapshot units that are stable in the merged view.
    stable_snapshots: BTreeSet<EventId>,
    /// Valid snapshot units not yet used or refused: their declaration,
    /// `excluded` and parents.
    snapshot_candidates: BTreeMap<EventId, SnapshotCandidate>,
    /// The head statements of each member device that are not shown older
    /// than another kept (units.md, 3.13 "Head statements").
    statements: BTreeMap<DeviceId, Vec<frasil_units::statement::HeadStatement>>,
    /// Heads of statements asked of their authors and not yet held.
    stated_asked: BTreeSet<EventId>,
    /// The events of other logs that opened events of the view name in
    /// their sealed refs.
    refs_named: BTreeSet<(EventId, EventId)>,
    /// The invite keys the roster names, with what the administering
    /// devices act on (ext-invite-links.md, "Administering devices").
    #[cfg(feature = "ext-invite-links")]
    invites: BTreeMap<[u8; 32], crate::invite_links::InviteFacts>,
    /// The claimant's checks of each invite key it claims with
    /// ("Claiming", steps 6, 7 and 9).
    #[cfg(feature = "ext-invite-links")]
    claim_checks: BTreeMap<DeviceId, Result<(), frasil_space::ext_invite_links::InviteClass>>,
    /// The state a welcome or an invite's drop hands a newcomer before it
    /// holds the log: what it presents to fetch the space from a peer.
    bootstrap: Option<(RotationSet, Secret)>,
    /// The waiting list members this replica vouches for in the space, by
    /// person (ext-recovery-agent.md, "The waiting period").
    #[cfg(feature = "ext-recovery-agent")]
    vouched: BTreeMap<[u8; 32], BTreeSet<DeviceId>>,
    /// A restricted space's parent and its keys, and the space's moved
    /// streams (ext-restricted-spaces.md).
    #[cfg(feature = "ext-restricted-spaces")]
    pub(crate) restricted: crate::restricted::RestrictedPart,
    /// What the last resolution says of guests (ext-guests.md).
    #[cfg(feature = "ext-guests")]
    pub(crate) guests: crate::guests::GuestFacts,
    /// A partial replica's streams besides its frame; `None` for a full
    /// replica (units.md, "Partial replicas").
    partial: Option<BTreeSet<StreamId>>,
    /// Units that arrived at a partial replica before it knew the system
    /// stream: placed or witnessed once it does.
    undecided: Vec<Event>,
    /// What a partial replica's last resolution fetches by ID to learn the
    /// heights of contested roster events ("Heights").
    heights_wanted: Vec<EventId>,
    /// The `Path`s a partial replica's last resolution asks for, as
    /// `(from, to)`: the orders that pending units wait on.
    paths_wanted: BTreeSet<(EventId, EventId)>,
    /// Units a `Missing` named as carrying the stubs of events the replica
    /// asked for (units.md, "Sync", step 4): each carrier, with the events
    /// it stubs.
    carried: BTreeMap<EventId, BTreeSet<EventId>>,
    /// The carried stubs the last refresh read, with their signers.
    carried_stubs: Vec<(DeviceId, frasil_units::Stub)>,
    /// Snapshot units pending on a parent, with their own stubs, which may
    /// place them provisionally (units.md, "Where stubs come from").
    awaiting_stubs: BTreeMap<EventId, Vec<frasil_events::Stub>>,
    /// The last resolution's verdicts on the units placed on their own
    /// stubs: valid, or refused. A unit not yet decided either way is not
    /// listed.
    provisional_verdicts: BTreeMap<EventId, bool>,
    /// The visible parts of the log's space events, read once each.
    visible_parts: VisibleParts,
    /// What the replica read of each unit.
    unit_reads: UnitReads,
    /// What other replicas read of this one changed since the device last
    /// asked: its granted facts, keys or grant seeds, or a space event.
    changed_for_others: bool,
    /// Anything of this log changed since the device last asked: an event
    /// placed or a verdict changed.
    changed_log: bool,
    /// Whether an event of the view is held or pending at the last
    /// refresh: it may wait on another log.
    holds_back: bool,
    /// The last resolution, for a refresh after which only content units
    /// were placed.
    appendable: Option<Appendable>,
    /// Whether the administrators the skeleton resolves and those of the
    /// roster differ at the last refresh.
    skeleton_differs: bool,
    /// What this replica, having forgotten the past before its kept
    /// checkpoint, froze of each unit of that past (`crate::frozen`).
    pub(crate) frozen_content: BTreeMap<EventId, frasil_units::frozen::Frozen>,
    /// The events a device may cite, and their heads, as of the last
    /// refresh: what [`parents`](Replica::parents) reads.
    citable: Option<(BTreeSet<EventId>, BTreeSet<EventId>)>,
    /// The log's placed count and revision the citable events are of.
    citable_at: (usize, u64),
    /// What the replica keeps of the space's checkpoints, and what its last
    /// judgement said of them (roster.md, 3.15 Checkpoints).
    pub(crate) checkpoints: crate::checkpoints::Held,
}

/// What [`Replica::forget_past`] dropped.
#[derive(Debug, Clone)]
pub(crate) struct Forgotten {
    /// The kept checkpoint.
    pub checkpoint: EventId,
    /// The events dropped.
    pub dropped: Vec<EventId>,
    /// What was frozen of each unit kept of the past, to keep at rest
    /// (`crate::frozen`).
    pub frozen: Vec<(EventId, frasil_units::frozen::Frozen)>,
}

/// A late unit of this device, and what re-submits it (units.md, 3.11,
/// "Re-submission").
#[derive(Debug, Clone)]
pub(crate) struct LateUnitAgain {
    /// Its stream.
    pub stream: StreamId,
    /// The sealed part of the unit that re-submits it.
    pub inner: frasil_units::Inner,
    /// The objects it names.
    pub objects: Vec<Locator>,
}

/// The other logs a replica reads, as the device holds them: persons'
/// lists, and the spaces it holds, which a space may grant.
pub(crate) struct Others<'a> {
    /// Persons' lists, by person ID.
    pub lists: &'a BTreeMap<[u8; 32], crate::lists::PersonList>,
    /// Spaces this device holds, as granting spaces read them.
    pub spaces: &'a BTreeMap<EventId, &'a crate::granted::GrantedView<'a>>,
    /// The grant seeds this device holds of other spaces' rotations, by
    /// space then rotation: what opens a space wrap.
    pub grant_seeds: &'a BTreeMap<EventId, BTreeMap<EventId, [u8; 32]>>,
    /// The keys the device found in every source, by their hash (crypto.md,
    /// "Keys by their hash").
    pub keys: &'a KeyRing,
    /// What the recovery agent's waiting decisions read
    /// (ext-recovery-agent.md, "The waiting period").
    #[cfg(feature = "ext-recovery-agent")]
    pub agents: Option<crate::recovery_agent::Agents<'a>>,
    /// The other replicas the device holds: a restricted space's parent
    /// among them (ext-restricted-spaces.md, "Reading a restricted key
    /// reference").
    #[cfg(feature = "ext-restricted-spaces")]
    pub replicas: &'a BTreeMap<EventId, Replica>,
}

/// How many refreshes resolved from a kept resolution, for tests.
#[cfg(test)]
pub(crate) static APPENDED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many refreshes resumed the world of the checkpoint in effect, for
/// tests.
#[cfg(test)]
pub(crate) static WORLD_RESUMED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Whether an event is accepted in full: valid, or void with a final class.
fn accepts(statuses: &BTreeMap<EventId, Status>, id: &EventId) -> bool {
    match statuses.get(id) {
        Some(Status::Valid(_)) => true,
        Some(Status::Void { class, .. }) => class.sort() == Sort::Final,
        None => false,
    }
}

/// A replica's last resolution, kept for a refresh after which only
/// content units were placed (see `Replica::appended_units`).
struct Appendable {
    resolved: frasil_space::Resolved,
    /// [`Log::placed_count`] and [`Log::revision`] when it was made.
    placed: usize,
    revision: u64,
    /// What it read besides the log.
    inputs: Vec<u8>,
    /// Where the system stream carries each list event copy.
    copies: BTreeMap<EventId, EventId>,
    /// With a checkpoint in effect, the world's resolutions beside the
    /// plain one, resumed as units after the checkpoint arrive.
    world: Option<Box<WorldParts>>,
}

/// What a replica keeps of the world of the checkpoint in effect, so that
/// a refresh after which only content units after it were placed resumes
/// the world's resolutions instead of judging the view again (roster.md,
/// 3.15.5). The world is a pure function of the checkpoint, its record
/// and the events after it, so its log grows by appending them.
struct WorldParts {
    /// The checkpoint.
    checkpoint: EventId,
    /// The world's log.
    log: frasil_space::WorldLog,
    /// The world as the judgement with checkpoints resolves it, with the
    /// skeleton after the checkpoint's cut: the events' verdicts.
    judged: frasil_space::Resolved,
    /// The world as the replica's key graph reads it
    /// ([`frasil_space::KeyWorld::resolve`]): roster, keys and units.
    keys: frasil_space::Resolved,
    /// The world's checkpoints whose record the replica cannot read.
    unreadable: Vec<EventId>,
    /// Each author's tip in the checkpoint's record: a unit at or below it
    /// is evidence of a fork, which reaches every event of its author.
    tips: BTreeMap<DeviceId, (u64, EventId)>,
    /// What the judgement with checkpoints read besides the log's events
    /// ([`Replica::checkpoint_inputs`]) when it was made.
    inputs: Vec<u8>,
}

/// The base of a replica that started from a space snapshot (units.md,
/// "Placing against stubs", "A base"): the heads the snapshot was taken at
/// and the stubs it came with. Every event in its past is decided.
#[derive(Debug, Clone, Default)]
pub(crate) struct Base {
    /// List events supplied at the base.
    pub lists: BTreeSet<EventId>,
    /// The heads.
    pub heads: Vec<EventId>,
    /// The stubs, by event ID.
    pub stubs: BTreeMap<EventId, UnitStub>,
}

/// A checkpoint record read prepared independently of judgement.
pub(crate) struct RecordRequest {
    pub id: EventId,
    pub part: frasil_space::CheckpointPart,
    pub binding: frasil_units::record::RecordBinding,
    key: Option<zeroize::Zeroizing<[u8; 32]>>,
    pub handed: bool,
    pub mode: frasil_space::RecordMode,
    pub store_only: bool,
}
impl RecordRequest {
    pub fn key(&self) -> Option<frasil_units::record::RecordKey<'_>> {
        self.key.as_ref().map(|key| {
            if self.handed {
                frasil_units::record::RecordKey::Object(key)
            } else {
                frasil_units::record::RecordKey::Checkpoint(key)
            }
        })
    }
}

/// An object as received: its header and chunks, by index; or, for an
/// object the application holds (at-rest.md, "Held objects"), its header
/// alone, with the chunks sealed again from the plaintext when served.
///
/// The chunks of a log the store keeps stay in the store: the replica
/// notes which it holds, and the device reads them back when it serves or
/// opens the object. A log kept in memory only keeps its chunks here.
#[derive(Debug, Clone, Default)]
pub(crate) struct HeldObject {
    /// The header bytes.
    pub header: Option<Vec<u8>>,
    /// The sealed chunks held in memory, by index.
    pub chunks: BTreeMap<u64, Vec<u8>>,
    /// The indices of the chunks the store holds.
    pub stored: BTreeSet<u64>,
    /// Whether the application holds the plaintext, so that the object
    /// counts as whole with no chunk here.
    pub held: bool,
    /// Whether the object's stored bytes were found to hash to its locator
    /// (units.md, "Reading an object", step 0), or were sealed here, since
    /// a part was last kept: its chunks may then be served a range at a
    /// time.
    pub checked: bool,
}

impl HeldObject {
    /// The object's chunk count, once its header is held.
    fn chunk_count(&self) -> Option<u64> {
        let size = frasil_units::objects::Header::read(self.header.as_ref()?)
            .ok()?
            .size;
        Some(frasil_units::objects::chunk_count(
            size,
            frasil_units::limits::CHUNK_BYTES as u64,
        ))
    }

    /// Whether a chunk is held, in memory or in the store.
    fn has_chunk(&self, index: u64) -> bool {
        self.chunks.contains_key(&index) || self.stored.contains(&index)
    }

    /// How many chunks are held, in memory or in the store.
    fn chunks_held(&self) -> u64 {
        let in_memory = self.chunks.keys().filter(|i| !self.stored.contains(i));
        (self.stored.len() + in_memory.count()) as u64
    }

    /// Whether the header and every chunk are held, or the application
    /// holds the plaintext.
    pub fn is_whole(&self) -> bool {
        (self.held && self.header.is_some())
            || self
                .chunk_count()
                .is_some_and(|count| (0..count).all(|i| self.has_chunk(i)))
    }

    /// The object's stored bytes, once the header and every chunk are held
    /// in memory; `None` for an object the application holds, or whose
    /// chunks are in the store.
    pub fn bytes(&self) -> Option<Vec<u8>> {
        let header = self.header.as_ref()?;
        let size = frasil_units::objects::Header::read(header).ok()?.size;
        let count =
            frasil_units::objects::chunk_count(size, frasil_units::limits::CHUNK_BYTES as u64);
        if (0..count).any(|i| !self.chunks.contains_key(&i)) {
            return None;
        }
        let mut out = u32::try_from(header.len()).ok()?.to_be_bytes().to_vec();
        out.extend_from_slice(header);
        for i in 0..count {
            out.extend_from_slice(&self.chunks[&i]);
        }
        Some(out)
    }
}

impl core::fmt::Debug for Replica {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Replica")
            .field("space", &self.space)
            .field("events", &self.log.as_ref().map_or(0, Log::len))
            .field("streams", &self.streams.len())
            .finish_non_exhaustive()
    }
}

impl Replica {
    /// A replica of a space this device holds nothing of yet.
    pub fn new(space: EventId) -> Self {
        Self {
            space,
            log: None,
            staged: BTreeMap::new(),
            secrets: BTreeMap::new(),
            states: BTreeMap::new(),
            statuses: BTreeMap::new(),
            unresolved: None,
            #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
            administrator_authors: BTreeSet::new(),
            roster: Roster::default(),
            policy: Policy::default(),
            current: None,
            grant_current: None,
            valid: BTreeSet::new(),
            system_stream: None,
            streams: BTreeMap::new(),
            handed: BTreeMap::new(),
            refused_content: BTreeMap::new(),
            unreached: BTreeMap::new(),
            contradicted_base: BTreeSet::new(),
            first_sight: BTreeMap::new(),
            verified: BTreeMap::new(),
            forks: frasil_events::ForkPoints::default(),
            bodies: BTreeMap::new(),
            opened_bodies: BTreeMap::new(),
            removal_tried: BTreeSet::new(),
            wraps_tried: WrapsTried::new(),
            space_wraps_tried: SpaceWrapsTried::new(),
            was_member: false,
            application: None,
            base: None,
            objects: BTreeMap::new(),
            unlocated: BTreeMap::new(),
            forgotten_objects: Vec::new(),
            dropped_pending: Vec::new(),
            chunks_at_rest: true,
            wanted_at_rest: BTreeSet::new(),
            pending_streams: Vec::new(),
            snapshot_to_keep: None,
            awaited_snapshot: None,
            wants_snapshot: false,
            slots: crate::skeleton::Slots::default(),
            found_keys: KeyRing::new(),
            awaits_keys: false,
            provisional_snapshot: None,
            snapshot_sender: None,
            snapshot_streams: BTreeSet::new(),
            base_discarded: false,
            #[cfg(test)]
            full_resolutions: 0,
            effective: BTreeMap::new(),
            facts: None,
            list_copies: BTreeSet::new(),
            authorship: BTreeMap::new(),
            voiders: BTreeMap::new(),
            principals: Vec::new(),
            heals: Vec::new(),
            top_ups: Vec::new(),
            top_up_keys: BTreeMap::new(),
            break_frontier: None,
            lacking: None,
            entitled: Vec::new(),
            roster_events: BTreeSet::new(),
            openings: BTreeMap::new(),
            bad_compactions: BTreeSet::new(),
            oversized_states: BTreeSet::new(),
            #[cfg(feature = "ext-file-versions")]
            superseding: BTreeMap::new(),
            used_snapshots: BTreeSet::new(),
            bases: BTreeMap::new(),
            checked_snapshots: BTreeMap::new(),
            stable_snapshots: BTreeSet::new(),
            snapshot_candidates: BTreeMap::new(),
            statements: BTreeMap::new(),
            stated_asked: BTreeSet::new(),
            refs_named: BTreeSet::new(),
            #[cfg(feature = "ext-invite-links")]
            invites: BTreeMap::new(),
            #[cfg(feature = "ext-invite-links")]
            claim_checks: BTreeMap::new(),
            bootstrap: None,
            #[cfg(feature = "ext-recovery-agent")]
            vouched: BTreeMap::new(),
            #[cfg(feature = "ext-restricted-spaces")]
            restricted: crate::restricted::RestrictedPart::default(),
            #[cfg(feature = "ext-guests")]
            guests: crate::guests::GuestFacts::default(),
            partial: None,
            undecided: Vec::new(),
            heights_wanted: Vec::new(),
            paths_wanted: BTreeSet::new(),
            carried: BTreeMap::new(),
            carried_stubs: Vec::new(),
            awaiting_stubs: BTreeMap::new(),
            provisional_verdicts: BTreeMap::new(),
            visible_parts: VisibleParts::default(),
            unit_reads: UnitReads::default(),
            changed_for_others: false,
            changed_log: false,
            holds_back: false,
            appendable: None,
            frozen_content: BTreeMap::new(),
            skeleton_differs: false,
            citable: None,
            citable_at: (0, 0),
            checkpoints: crate::checkpoints::Held::default(),
        }
    }

    /// What changed for other replicas since the last call: whether what
    /// they read of this one changed, and whether anything of its log did.
    pub(crate) fn take_changes(&mut self) -> (bool, bool) {
        (
            std::mem::take(&mut self.changed_for_others),
            std::mem::take(&mut self.changed_log),
        )
    }

    /// Whether this replica may read what changed in another space's log:
    /// its view names that log's events in sealed refs, an event of its
    /// view is held or pending, or one of the two is the other's parent.
    pub(crate) fn may_read_log_of(&self, other: &Replica) -> bool {
        #[cfg(feature = "ext-restricted-spaces")]
        {
            let related = |a: &Replica, b: &Replica| {
                a.restricted.parent == Some(b.space) || a.restricted.carve_out_of == Some(b.space)
            };
            if related(self, other) || related(other, self) {
                return true;
            }
        }
        self.holds_back || self.refs_named.iter().any(|(log, _)| *log == other.space)
    }

    /// Takes a `Missing`'s pairs `[ID, unit ID]` (units.md, "Sync", step
    /// 4): the replica asks for each carrier it does not hold, and places
    /// against the stubs it carries once it does.
    pub(crate) fn take_carried(&mut self, pairs: &[(EventId, EventId)]) {
        for (id, carrier) in pairs {
            self.carried.entry(*carrier).or_default().insert(*id);
        }
    }

    /// Adds the stubs the carriers hold (units.md, "Placing against
    /// stubs"): each carrier is placed and valid, so its signer is a
    /// writer. A stub counts for units at once; a space event rests on it,
    /// and a partial replica takes it for a height, only once confirmed, by
    /// two such carriers of two different writers ("Confirming heights").
    /// Returns the events placed.
    fn add_carried_stubs(&mut self) -> Vec<EventId> {
        let sources = std::mem::take(&mut self.carried_stubs);
        let Some(log) = self.log.as_mut() else {
            return Vec::new();
        };
        let mut by_id: BTreeMap<EventId, Vec<(DeviceId, frasil_units::Stub)>> = BTreeMap::new();
        for (signer, stub) in sources {
            by_id.entry(stub.id).or_default().push((signer, stub));
        }
        let mut placed = Vec::new();
        for (id, sources) in by_id {
            if log.contains(id) {
                continue;
            }
            // A base stub stands: the base is decided. Another signer's stub
            // that disagrees with it is reported against the snapshot's
            // sender, and changes nothing (units.md, "A base").
            if let Some(stub) = self.base.as_ref().and_then(|base| base.stubs.get(&id)) {
                if sources
                    .iter()
                    .any(|(_, other)| other.event_stub() != stub.event_stub())
                {
                    self.contradicted_base.insert(id);
                }
                continue;
            }
            let confirmed = frasil_units::decisions::confirm_stub(false, &sources).placed();
            if self.heights_wanted.contains(&id) && !confirmed {
                continue;
            }
            for (_, stub) in &sources {
                placed.extend(log.add_stub_unconfirmed(stub.event_stub()));
            }
            if confirmed {
                placed.extend(log.confirm_stub(id));
            }
        }
        // A carrier is done with once each event it stubs is placed or
        // stubbed, or once it is refused or stays pending: the replica then
        // asks for those events again.
        let statuses = &self.statuses;
        self.carried.retain(|carrier, ids| {
            let refused = statuses
                .get(carrier)
                .and_then(Status::class)
                .is_some_and(|class| class.sort() == Sort::Final);
            !refused
                && !log.is_pending(*carrier)
                && ids
                    .iter()
                    .any(|id| !log.contains(*id) && log.stub(*id).is_none())
        });
        placed
    }

    /// Places each snapshot unit pending on a parent against its own
    /// stubs, provisionally, once they cover what its pending past lacks
    /// (units.md, "Where stubs come from"). Returns the events placed.
    fn place_on_own_stubs(&mut self) -> Vec<EventId> {
        let Some(log) = self.log.as_mut() else {
            return Vec::new();
        };
        let mut placed = Vec::new();
        self.awaiting_stubs.retain(|id, stubs| {
            if !log.is_pending(*id) {
                return false;
            }
            match log.add_provisional_stubs(*id, stubs) {
                Some(more) => {
                    placed.extend(more);
                    false
                }
                None => true,
            }
        });
        placed
    }

    /// Takes the last resolution's verdicts on the units placed on their
    /// own stubs (units.md, "Where stubs come from"): a valid unit's stubs
    /// stay, and a refused one's are taken back with every event placed on
    /// them. Returns whether the log changed.
    fn judge_own_stubs(&mut self) -> bool {
        let verdicts = std::mem::take(&mut self.provisional_verdicts);
        let Some(log) = self.log.as_mut() else {
            return false;
        };
        let sources = log.provisional_sources();
        let mut changed = false;
        for (source, valid) in verdicts {
            if !sources.contains(&source) {
                continue;
            }
            if valid {
                log.accept_provisional(source);
            } else {
                log.retract_provisional(source);
            }
            changed = true;
        }
        changed
    }

    /// The waiting list members this replica vouches for in the space, by
    /// person.
    #[cfg(feature = "ext-recovery-agent")]
    pub(crate) fn vouched(&self) -> &BTreeMap<[u8; 32], BTreeSet<DeviceId>> {
        &self.vouched
    }

    /// The space ID.
    pub fn space(&self) -> EventId {
        self.space
    }

    /// The log, once the genesis is held.
    pub fn log(&self) -> Option<&Log> {
        self.log.as_ref()
    }

    /// Whether the replica holds an event, placed or pending, or a stub
    /// of it from its base.
    pub fn holds(&self, id: EventId) -> bool {
        self.base
            .as_ref()
            .is_some_and(|base| base.stubs.contains_key(&id))
            || self.staged.contains_key(&id)
            || self.undecided.iter().any(|e| e.id() == id)
            || self.log.as_ref().is_some_and(|log| {
                log.contains(id) || log.witnessed(id).is_some() || log.is_pending(id)
            })
    }

    /// Whether the replica holds an event it cannot place yet: pending on
    /// a parent, or waiting for the genesis.
    pub(crate) fn is_pending(&self, id: &EventId) -> bool {
        self.staged.contains_key(id) || self.log.as_ref().is_some_and(|log| log.is_pending(*id))
    }

    /// Whether some record of the view names a device as an author: a
    /// grant of it in this log, an `add` of it in a list the space reads,
    /// a grant of it in a granted space, or a skeleton record of its
    /// pseudonym (roster.md, "Strangers' events").
    pub(crate) fn names_author(&self, author: &DeviceId) -> bool {
        self.roster().state(&MemberRef::device(*author)).is_some()
            || self.level_of(author).is_some()
            || self.slot_of(author).is_some()
    }

    /// Keeps what the replica holds of events it cannot place within
    /// [`MAX_PENDING_PER_AUTHOR`], [`MAX_PENDING_EVENTS`] and
    /// [`MAX_PENDING_BYTES`] (events.md, "Placement and order"). Past a
    /// limit it drops events, of the author with the most first, and of
    /// authors no record names before others; of an author, its greatest
    /// `seq` first. A dropped event is fetched again when an event the
    /// replica holds names it.
    fn limit_pending(&mut self) {
        let mut by_author: BTreeMap<DeviceId, Vec<(u64, EventId, usize)>> = BTreeMap::new();
        let (mut count, mut bytes) = (0usize, 0usize);
        for event in self
            .log
            .iter()
            .flat_map(Log::pending)
            .chain(self.staged.values())
        {
            let size = event.signed_len();
            by_author
                .entry(*event.author())
                .or_default()
                .push((event.seq(), event.id(), size));
            count += 1;
            bytes = bytes.saturating_add(size);
        }
        let within = count <= MAX_PENDING_EVENTS
            && bytes <= MAX_PENDING_BYTES
            && by_author
                .values()
                .all(|events| events.len() <= MAX_PENDING_PER_AUTHOR);
        if within {
            return;
        }
        let named: BTreeSet<DeviceId> = by_author
            .keys()
            .filter(|author| self.names_author(author))
            .copied()
            .collect();
        let mut dropped = Vec::new();
        for events in by_author.values_mut() {
            // Ascending, so that the greatest `seq` goes first.
            events.sort_unstable();
            while events.len() > MAX_PENDING_PER_AUTHOR {
                let Some((_, id, size)) = events.pop() else {
                    break;
                };
                dropped.push(id);
                count -= 1;
                bytes = bytes.saturating_sub(size);
            }
        }
        while count > MAX_PENDING_EVENTS || bytes > MAX_PENDING_BYTES {
            let Some(author) = by_author
                .iter()
                .filter(|(_, events)| !events.is_empty())
                .max_by_key(|(author, events)| (!named.contains(*author), events.len(), **author))
                .map(|(author, _)| *author)
            else {
                break;
            };
            let Some((_, id, size)) = by_author.get_mut(&author).and_then(Vec::pop) else {
                break;
            };
            dropped.push(id);
            count -= 1;
            bytes = bytes.saturating_sub(size);
        }
        for id in dropped {
            if self.staged.remove(&id).is_none()
                && let Some(log) = &mut self.log
            {
                log.drop_pending(id);
            }
            self.awaiting_stubs.remove(&id);
            self.dropped_pending.push(id);
        }
    }

    /// The events dropped by [`limit_pending`](Self::limit_pending) since
    /// the last call, whose records the device deletes.
    pub(crate) fn take_dropped_pending(&mut self) -> Vec<EventId> {
        std::mem::take(&mut self.dropped_pending)
    }

    /// An event the replica holds, placed or pending.
    pub fn event(&self, id: EventId) -> Option<&Event> {
        if let Some(event) = self.staged.get(&id) {
            return Some(event);
        }
        let log = self.log.as_ref()?;
        log.event(id).or_else(|| log.pending_event(id))
    }

    /// Places events (events.md, "Placement and order"): a genesis of
    /// this space starts the log; events that arrive before it wait.
    /// Returns the IDs of the events this call placed, and the parents the
    /// replica now waits for.
    pub fn place(&mut self, events: Vec<Event>) -> (Vec<EventId>, Vec<EventId>) {
        let mut placed = Vec::new();
        for event in events {
            if event.is_genesis() {
                if event.id() != self.space || self.log.is_some() {
                    continue;
                }
                let id = event.id();
                match Log::new(event) {
                    Ok(mut log) => {
                        if let Some(base) = &self.base {
                            for stub in base.stubs.values() {
                                log.add_stub(stub.event_stub());
                            }
                        }
                        // The heights a forgetting replica kept of the
                        // dropped parents of its kept events, which they are
                        // placed on (events.md, "Placement and order"), and
                        // the envelopes a snapshot's cut chain handed over.
                        for (id, origin) in &self.checkpoints.dropped_origins {
                            if let frasil_store::tables::DroppedOrigin::Held {
                                height: Some(height),
                                ..
                            } = origin
                            {
                                log.mark_dropped_at(*id, *height);
                            }
                        }
                        for event in std::mem::take(&mut self.checkpoints.envelopes) {
                            let _ = log.keep_envelope(event);
                        }
                        // Units that came before the genesis, which the
                        // replica could not yet tell in or out of its
                        // frame: witnessed now, as they would have been
                        // had the genesis come first.
                        let mut released = Vec::new();
                        for event in &self.undecided {
                            released.extend(log.witness(event.clone()).unwrap_or_default());
                        }
                        self.log = Some(log);
                        placed.push(id);
                        placed.extend(released);
                    }
                    Err(_) => continue,
                }
                let staged = std::mem::take(&mut self.staged);
                let (more, _) = self.place(staged.into_values().collect());
                placed.extend(more);
                continue;
            }
            if event.log_id() != self.space {
                continue;
            }
            // A partial replica places its frame and its streams, and
            // witnesses any other event (units.md, "Partial replicas").
            let in_frame = match self.in_frame(&event) {
                Some(in_frame) => in_frame,
                None => {
                    // Witnessed meanwhile: a newcomer admitted "with history"
                    // opens the genesis, and learns the system stream, only
                    // from a grant that may rest on this unit.
                    if let Some(log) = &mut self.log {
                        placed.extend(log.witness(event.clone()).unwrap_or_default());
                    }
                    self.undecided.push(event);
                    continue;
                }
            };
            if !in_frame {
                if let Some(log) = &mut self.log {
                    placed.extend(log.witness(event).unwrap_or_default());
                } else {
                    self.staged.insert(event.id(), event);
                }
                continue;
            }
            // A unit in the past of the base is decided: the replica keeps
            // its stub, and checks the stub against the unit's author, `seq`,
            // kind and cuts; a mismatch is the snapshot sender's `BadStub`
            // (units.md, "A base"; "The space snapshot").
            if event.kind() == kind::UNIT
                && let Some(stub) = self
                    .base
                    .as_ref()
                    .and_then(|base| base.stubs.get(&event.id()))
            {
                if stub.author != *event.author()
                    || stub.seq != event.seq()
                    || stub.kind != event.kind()
                    || stub.cuts.as_slice() != event.cuts()
                {
                    self.contradicted_base.insert(event.id());
                }
                continue;
            }
            match &mut self.log {
                None => {
                    self.staged.insert(event.id(), event);
                }
                Some(log) => {
                    let snapshot_stubs: Vec<frasil_units::Stub> = (event.kind() == kind::UNIT)
                        .then(|| Unit::from_event(event.clone()).ok())
                        .flatten()
                        .and_then(|unit| unit.body.compacts)
                        .map(|compacts| compacts.stubs)
                        .unwrap_or_default();
                    let id = event.id();
                    match log.place(event) {
                        Ok(Placement::Placed(ids)) => placed.extend(ids),
                        // A snapshot unit whose cover a peer collected
                        // may place against its own signed stubs, until
                        // it is judged (units.md, "Where stubs come
                        // from").
                        Ok(Placement::Pending(_)) if !snapshot_stubs.is_empty() => {
                            self.awaiting_stubs.insert(
                                id,
                                snapshot_stubs
                                    .iter()
                                    .map(frasil_units::Stub::event_stub)
                                    .collect(),
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        if let Some(log) = &mut self.log {
            placed.extend(log.confirm_held());
        }
        placed.extend(self.place_on_own_stubs());
        self.limit_pending();
        (placed, self.wanted())
    }

    // -- Partial replicas (units.md, "Partial replicas")

    /// Whether an event is in a partial replica's frame or streams: a
    /// space event, anchor or storage event, a unit of the system stream or
    /// of a stream it holds. `None` for a unit while the system stream is
    /// unknown. Every event is, at a full replica.
    fn in_frame(&self, event: &Event) -> Option<bool> {
        let Some(held) = &self.partial else {
            return Some(true);
        };
        if event.kind() != kind::UNIT {
            return Some(true);
        }
        // A unit that does not read is placed, and judged.
        let Ok(unit) = Unit::from_event(event.clone()) else {
            return Some(true);
        };
        let system = self.system_stream?;
        Some(unit.body.stream == system || held.contains(&unit.body.stream))
    }

    /// Whether this replica is partial.
    pub fn is_partial(&self) -> bool {
        self.partial.is_some()
    }

    /// A partial replica's streams besides its frame; `None` for a full
    /// replica.
    pub fn held_streams(&self) -> Option<&BTreeSet<StreamId>> {
        self.partial.as_ref()
    }

    /// Makes this replica partial: it keeps the streams it holds units of,
    /// and from now on places only its frame and those streams.
    #[cfg(feature = "partial-replicas")]
    pub(crate) fn make_partial(&mut self) {
        if self.partial.is_some() {
            return;
        }
        let system = self.system_stream;
        let held: BTreeSet<StreamId> = self
            .log
            .as_ref()
            .map(|log| {
                log.canonical()
                    .into_iter()
                    .filter_map(|id| crate::compaction::stream_of(log, id))
                    .filter(|stream| Some(*stream) != system)
                    .collect()
            })
            .unwrap_or_default();
        self.partial = Some(held);
        // A kept resolution was a full replica's: the next one resolves
        // the view again, as a partial replica.
        self.appendable = None;
    }

    /// Opens a stream at a partial replica: its units are placed from now
    /// on, and those it witnessed are placed at once, by a log rebuilt
    /// from its genesis. Returns the events newly placed.
    #[cfg(feature = "partial-replicas")]
    pub(crate) fn hold_stream(&mut self, stream: StreamId) -> Vec<EventId> {
        let Some(held) = &mut self.partial else {
            return Vec::new();
        };
        if !held.insert(stream) {
            return Vec::new();
        }
        let Some(log) = &self.log else {
            return Vec::new();
        };
        let witnessed: Vec<Event> = log.witnesses().cloned().collect();
        let opened: Vec<EventId> = witnessed
            .iter()
            .filter(|event| {
                event.kind() == kind::UNIT
                    && Unit::from_event((*event).clone()).is_ok_and(|u| u.body.stream == stream)
            })
            .map(Event::id)
            .collect();
        if opened.is_empty() {
            return Vec::new();
        }
        self.rebuild_log(witnessed);
        opened
            .into_iter()
            .filter(|id| self.log.as_ref().is_some_and(|log| log.contains(*id)))
            .collect()
    }

    /// Builds the log again from its genesis, with every event it placed,
    /// every pending one and `witnessed`, each placed or witnessed as the
    /// replica's frame and streams now say.
    fn rebuild_log(&mut self, witnessed: Vec<Event>) {
        let Some(log) = self.log.take() else {
            return;
        };
        let genesis = log.genesis().clone();
        let mut events: Vec<Event> = log
            .canonical()
            .into_iter()
            .filter(|id| *id != genesis.id())
            .filter_map(|id| log.event(id).cloned())
            .collect();
        events.extend(log.pending().cloned());
        events.extend(witnessed);
        let Ok(mut rebuilt) = Log::new(genesis) else {
            self.log = Some(log);
            return;
        };
        if let Some(base) = &self.base {
            for stub in base.stubs.values() {
                rebuilt.add_stub(stub.event_stub());
            }
        }
        // A new log: nothing kept of the old one's resolution applies.
        self.appendable = None;
        self.citable = None;
        self.log = Some(rebuilt);
        self.place(events);
    }

    /// Takes a `Path` (units.md, "Sync messages") from `from` down to `to`:
    /// one that checks witnesses its events. Returns the events it placed.
    #[cfg(feature = "partial-replicas")]
    pub(crate) fn add_path(
        &mut self,
        from: EventId,
        to: EventId,
        path: Vec<Event>,
    ) -> Vec<EventId> {
        self.log
            .as_mut()
            .and_then(|log| log.add_path(from, to, path).ok().flatten())
            .unwrap_or_default()
    }

    /// The `Path`s a partial replica asks for: for each unit pending on an
    /// event of unproven order, both ways.
    pub fn paths_wanted(&self) -> &BTreeSet<(EventId, EventId)> {
        &self.paths_wanted
    }

    /// Places or witnesses the units that waited for the system stream.
    fn place_undecided(&mut self) -> Vec<EventId> {
        if self.system_stream.is_none() || self.undecided.is_empty() {
            return Vec::new();
        }
        let undecided = std::mem::take(&mut self.undecided);
        self.place(undecided).0
    }

    /// Takes a rotation's secrets this device drew or opened earlier.
    pub(crate) fn keep_secrets(&mut self, rotation: EventId, secrets: RotationSecrets) {
        self.secrets.entry(rotation).or_default().merge(&secrets);
    }

    /// Takes a merged state's key received whole: provisional.
    pub(crate) fn keep_state(&mut self, state: RotationSet, key: Secret) {
        self.states.entry(state).or_insert(key);
    }

    /// Takes the state a welcome or an invite's drop hands a newcomer,
    /// which it presents to a peer until the log arrives (admission.md,
    /// "Exchange mailboxes"; ext-invite-links.md, "Claiming", step 4). The
    /// rotation's secrets are taken from the delivery once it arrives,
    /// checked against its commitments.
    #[cfg_attr(
        not(any(
            feature = "server",
            feature = "iroh",
            feature = "server-socket",
            feature = "ext-invite-links"
        )),
        allow(dead_code)
    )]
    pub(crate) fn keep_bootstrap_state(&mut self, state: RotationSet, key: Secret) {
        self.bootstrap = Some((state, key));
    }

    /// The invite keys the roster names, with what the administering
    /// devices act on.
    #[cfg(feature = "ext-invite-links")]
    pub(crate) fn invites(&self) -> &BTreeMap<[u8; 32], crate::invite_links::InviteFacts> {
        &self.invites
    }

    /// The claimant's checks of an invite key it claims with, once the
    /// space has resolved.
    #[cfg(feature = "ext-invite-links")]
    pub(crate) fn claim_check(
        &self,
        key: &DeviceId,
    ) -> Option<&Result<(), frasil_space::ext_invite_links::InviteClass>> {
        self.claim_checks.get(key)
    }

    /// The secrets held for a rotation.
    pub(crate) fn secrets_of(&self, rotation: &EventId) -> Option<&RotationSecrets> {
        self.secrets.get(rotation)
    }

    /// Whether the device holds a rotation's content key.
    pub fn secrets_held(&self, rotation: &EventId) -> bool {
        self.secrets
            .get(rotation)
            .is_some_and(|secrets| secrets.content.is_some())
    }

    /// Records the reading at which the device first saw an event decided.
    pub(crate) fn set_first_sight(&mut self, id: EventId, reading: Reading) {
        self.first_sight.entry(id).or_insert(reading);
    }

    /// An event's first sight at this device.
    pub fn first_sight(&self, id: &EventId) -> Option<&Reading> {
        self.first_sight.get(id)
    }

    /// The newest first sight among the events this device holds.
    pub(crate) fn latest_sight(&self) -> Option<&Reading> {
        self.first_sight
            .values()
            .max_by_key(|reading| (reading.run, reading.timeline))
    }

    pub(crate) fn keyring(&self) -> Keyring {
        let mut keyring = Keyring::default();
        for (id, secrets) in &self.secrets {
            if let Some(content) = &secrets.content {
                keyring.rotations.insert(*id, content.clone());
            }
        }
        keyring.states = self.states.clone();
        keyring.bodies = self.bodies.clone();
        keyring
    }

    /// Takes body keys handed over for single events: provisional, each
    /// checked against its event's commitment where the event is held
    /// (keys.md, "Body keys"). Returns those that are new.
    pub(crate) fn keep_bodies(&mut self, keys: &[(EventId, [u8; 32])]) -> Vec<EventId> {
        let mut new = Vec::new();
        for (id, key) in keys {
            if let Some(event) = self.event(*id)
                && let Some(visible) = self.visible_parts.of(event)
                && frasil_keys::derive::body_commitment(key) != visible.commitment
            {
                continue;
            }
            let held = self.bodies.entry(*id).or_default();
            if !held.iter().any(|k| **k == *key) {
                held.push(Zeroizing::new(*key));
                new.push(*id);
            }
        }
        new
    }

    /// The body keys this device holds of events: those it opened or
    /// derived, and those handed over.
    pub(crate) fn body_key(&self, id: &EventId) -> Option<Secret> {
        self.opened_bodies
            .get(id)
            .cloned()
            .or_else(|| self.top_up_keys.get(id).cloned())
            .or_else(|| self.bodies.get(id).and_then(|keys| keys.first().cloned()))
    }

    /// The stubs of this replica's base that an event it later held, or
    /// another signer's stub, contradicted (units.md, "A base"): each a
    /// `BadStub` against the space snapshot's sender. The base stands; the
    /// report is what the newcomer acts on.
    pub fn contradicted_base(&self) -> &BTreeSet<EventId> {
        &self.contradicted_base
    }

    /// Starts from a base: its heads and stubs (units.md, "A base").
    pub(crate) fn set_base(&mut self, heads: Vec<EventId>, stubs: Vec<UnitStub>) {
        self.wants_snapshot = false;
        let base = self.base.get_or_insert_with(Base::default);
        base.heads = heads;
        for stub in stubs {
            if let Some(log) = &mut self.log {
                log.add_stub(stub.event_stub());
            }
            base.stubs.insert(stub.id, stub);
        }
    }

    /// Counts the snapshot's list events at its base.
    pub(crate) fn set_base_lists(&mut self, placed: &[EventId]) {
        if let Some(base) = &mut self.base {
            base.lists = placed.iter().copied().collect();
        }
    }

    /// A device's administrator slot in the merged view.
    pub(crate) fn slot_of(&self, device: &DeviceId) -> Option<&crate::skeleton::SlotInfo> {
        self.slots.by_device.get(device)
    }

    /// The pseudonym enrolled in a slot, if any.
    pub(crate) fn enrolled(&self, slot: &frasil_peers::body::SlotId) -> Option<DeviceId> {
        self.slots.enrolled.get(slot).copied()
    }

    pub(crate) fn slot_holder(&self, pseudonym: &DeviceId) -> Option<(EventId, Option<DeviceId>)> {
        self.slots.holders.get(pseudonym).copied()
    }

    /// The skeleton heads of the view this device may cite.
    /// The skeleton's heads a pseudonym whose previous event is `prev`
    /// cites: among them, the checkpoint the device follows and the events
    /// after it, and `prev` whatever it is; the checkpoint itself when none
    /// reaches it (roster.md, 3.15.7, "Following"). Never a late event but
    /// through `prev`.
    pub(crate) fn skeleton_heads_after(&self, prev: Option<EventId>) -> Vec<EventId> {
        let heads = self.skeleton_heads();
        match &self.log {
            Some(log) => {
                crate::checkpoints::fence(log, self.checkpoints.facts.following, prev, heads)
            }
            None => heads,
        }
    }

    pub(crate) fn skeleton_heads(&self) -> Vec<EventId> {
        let Some(log) = &self.log else {
            return Vec::new();
        };
        let citable = log.citable(|event| self.accepted(&event.id()));
        crate::skeleton::skeleton_heads(log, &citable)
    }

    /// Sets the system stream from a signed source before the genesis
    /// opens: a space snapshot.
    pub(crate) fn set_system_stream(&mut self, stream: StreamId) {
        self.system_stream.get_or_insert(stream);
    }

    /// The object a locator names: located, or in the store by its ID with
    /// its locator not yet known.
    fn held_object(&self, locator: &Locator) -> Option<&HeldObject> {
        self.objects
            .get(locator)
            .or_else(|| self.unlocated.get(&object_id(locator)))
    }

    /// The object a locator names, for a change: one in the store by its
    /// ID moves under the locator.
    fn held_object_mut(&mut self, locator: Locator) -> &mut HeldObject {
        if !self.objects.contains_key(&locator)
            && let Some(object) = self.unlocated.remove(&object_id(&locator))
        {
            self.objects.insert(locator, object);
        }
        self.objects.entry(locator).or_default()
    }

    /// Keeps part of an object: its header, or a chunk. A chunk the store
    /// holds is noted, and its bytes stay there.
    pub(crate) fn keep_object(
        &mut self,
        locator: Locator,
        header: Option<Vec<u8>>,
        chunk: Option<(u64, Vec<u8>)>,
    ) {
        let at_rest = self.chunks_at_rest;
        let held = self.held_object_mut(locator);
        if header.is_some() {
            held.header = header;
        }
        if let Some((index, bytes)) = chunk {
            if at_rest {
                held.stored.insert(index);
            } else {
                held.chunks.insert(index, bytes);
            }
            held.checked = false;
        }
    }

    /// [`keep_object`](Self::keep_object) for a part as sync or a writer
    /// hands it over: a chunk the store holds is only noted, and not
    /// copied.
    pub(crate) fn keep_part(&mut self, part: &crate::snapshots::ObjectPart) {
        let at_rest = self.chunks_at_rest;
        let held = self.held_object_mut(part.locator);
        if let Some(header) = &part.header {
            held.header = Some(header.clone());
        }
        if at_rest {
            held.stored.insert(part.index);
        } else {
            held.chunks.insert(part.index, part.chunk.clone());
        }
        held.checked = false;
    }

    /// Whether bytes held as an object hash to its locator (units.md,
    /// "Reading an object", step 0). Bytes that do not were sent by a party
    /// that is not the object's writer: the replica forgets them, so that
    /// the object is missing and fetched again, and the device deletes
    /// their records ([`take_forgotten_objects`](Self::take_forgotten_objects)).
    fn is_object(&mut self, locator: &Locator, bytes: &[u8]) -> bool {
        if frasil_crypto::primitives::sha256(&[bytes]) == locator[32..] {
            return true;
        }
        if let Some(stored) = self.forget_object(locator) {
            self.forgotten_objects.push((*locator, stored));
        }
        false
    }

    /// The objects the replica forgot because their bytes did not hash to
    /// their locators, with the indices of the chunks the store held.
    pub(crate) fn take_forgotten_objects(&mut self) -> Vec<(Locator, BTreeSet<u64>)> {
        std::mem::take(&mut self.forgotten_objects)
    }

    /// The header bytes held of an object, by its locator or its ID.
    pub(crate) fn object_header(&self, locator: &Locator) -> Option<&[u8]> {
        self.held_object(locator)?.header.as_deref()
    }

    /// Forgets what the replica holds of an object, header and chunks, by
    /// its locator and its ID: the object is missing again. Returns the
    /// indices of its chunks the store held, whose records the device
    /// deletes, or `None` when it held nothing of it.
    pub(crate) fn forget_object(&mut self, locator: &Locator) -> Option<BTreeSet<u64>> {
        let located = self.objects.remove(locator);
        let unlocated = self.unlocated.remove(&object_id(locator));
        if located.is_none() && unlocated.is_none() {
            return None;
        }
        Some(
            located
                .into_iter()
                .chain(unlocated)
                .flat_map(|object| object.stored)
                .collect(),
        )
    }

    /// Notes that an object's stored bytes hash to its locator.
    pub(crate) fn mark_checked(&mut self, locator: &Locator) {
        if let Some(object) = self.objects.get_mut(locator) {
            object.checked = true;
        }
    }

    /// Whether an object's stored bytes were found to hash to its locator
    /// since a part was last kept.
    pub(crate) fn is_checked(&self, locator: &Locator) -> bool {
        self.objects
            .get(locator)
            .is_some_and(|object| object.checked)
    }

    /// Keeps an object the store holds, read at load: its header and the
    /// indices of its chunks there, under its ID until its locator is
    /// needed.
    pub(crate) fn keep_stored_object(
        &mut self,
        id: [u8; 32],
        header: Vec<u8>,
        stored: BTreeSet<u64>,
    ) {
        self.unlocated.insert(
            id,
            HeldObject {
                header: Some(header),
                stored,
                ..HeldObject::default()
            },
        );
    }

    /// Whether chunks stay in the store once kept: `false` for a log kept
    /// in memory only, whose chunks the device reads back first.
    pub(crate) fn set_chunks_at_rest(&mut self, at_rest: bool) {
        self.chunks_at_rest = at_rest;
    }

    /// An object's stored bytes, if every part is held here in memory. An
    /// object whose locator is not yet known answers only if its bytes hash
    /// to this one.
    pub(crate) fn object(&self, locator: &Locator) -> Option<Vec<u8>> {
        if let Some(object) = self.objects.get(locator) {
            return object.bytes();
        }
        let bytes = self.unlocated.get(&object_id(locator))?.bytes()?;
        (frasil_crypto::primitives::sha256(&[&bytes])[..] == locator[32..]).then_some(bytes)
    }

    /// [`object`](Self::object), for a refresh: an object whole in the
    /// store is noted, for the device to read back.
    fn object_or_want(&mut self, locator: &Locator) -> Option<Vec<u8>> {
        let bytes = self.object(locator);
        if bytes.is_none() && self.holds_object(locator) && !self.is_held(locator) {
            self.wanted_at_rest.insert(*locator);
        }
        bytes
    }

    /// Reads the record objects of the checkpoints the last judgement
    /// found, from what the replica holds; one whose chunks are in the store
    /// is noted for the device to read back. Returns whether one was read
    /// that was not before.
    fn gather_records(&mut self) -> bool {
        let wanted: Vec<_> = self
            .checkpoints
            .facts
            .parts
            .iter()
            .filter(|(id, part)| self.needs_record_read(**id, part))
            .map(|(id, part)| (*id, part.clone()))
            .collect();
        let mut read = false;
        for (id, part) in wanted {
            let Some(request) = self.record_request(id, &part) else {
                continue;
            };
            // A summary can be upgraded only from the stored object.
            if self
                .checkpoints
                .record_reads
                .get(&id)
                .is_some_and(|read| matches!(read.outcome, frasil_space::RecordObject::Summary(_)))
            {
                self.wanted_at_rest.insert(part.locator);
                continue;
            }
            let Some(object) = self.held_object(&part.locator) else {
                continue;
            };
            let Some(header) = object.header.as_deref() else {
                continue;
            };
            let mut reader = frasil_units::record_reader::RecordObjectReader::new(
                header,
                &self.space,
                request.key(),
                &request.binding,
            );
            let mut sink = frasil_space::RecordStream::new(request.mode);
            let count = reader.chunk_count().unwrap_or(0);
            if (0..count).any(|i| !object.chunks.contains_key(&i)) {
                if self.holds_object(&part.locator) {
                    self.wanted_at_rest.insert(part.locator);
                }
                continue;
            }
            for (&index, sealed) in &object.chunks {
                reader.feed(index, sealed, &mut sink);
            }
            let result =
                frasil_units::record::RecordRead::finish(reader, sink, &part, request.handed);
            let opened = !matches!(result.outcome, frasil_space::RecordObject::Missing);
            self.keep_record_read(id, result);
            read |= opened;
        }
        read
    }

    /// Prepares a record read without giving provisional plaintext to judgement.
    pub(crate) fn record_request(
        &self,
        id: EventId,
        part: &frasil_space::CheckpointPart,
    ) -> Option<RecordRequest> {
        let event = self
            .log
            .as_ref()?
            .event(id)
            .or_else(|| self.checkpoints.envelopes.iter().find(|e| e.id() == id))?;
        let key = self.secrets.get(&id).and_then(|s| s.content.clone());
        let handed = key.is_none() && self.checkpoints.object_keys.contains_key(&id);
        let key = key.or_else(|| self.checkpoints.object_keys.get(&id).cloned());
        let log = self.log.as_ref()?;
        let complete = log.past(id).iter().chain([&id]).all(|id| {
            log.event(*id)
                .is_some_and(|event| event.parents().iter().all(|p| log.contains(*p)))
        });
        let follows_kept = self.checkpoints.kept.as_ref().is_some_and(|kept| {
            if id == kept.checkpoint || log.follows(id, kept.checkpoint) != Ok(true) {
                return false;
            }
            let mut pending = vec![id];
            let mut seen = BTreeSet::new();
            while let Some(id) = pending.pop() {
                if id == kept.checkpoint || !seen.insert(id) {
                    continue;
                }
                let Some(event) = log.event(id) else {
                    return false;
                };
                pending.extend(event.parents());
            }
            true
        });
        let build = self.checkpoints.kept_id == Some(id) || !(complete || follows_kept);
        Some(RecordRequest {
            id,
            part: part.clone(),
            binding: frasil_units::record::RecordBinding {
                checkpoint: frasil_keys::SelfRef::new(*event.author(), event.seq()),
                locator: part.locator,
                size: part.size,
                digest: part.digest,
            },
            key,
            handed,
            store_only: self
                .checkpoints
                .record_reads
                .get(&id)
                .is_some_and(|read| matches!(read.outcome, frasil_space::RecordObject::Summary(_))),
            mode: if build {
                frasil_space::RecordMode::Build
            } else {
                frasil_space::RecordMode::Summary
            },
        })
    }

    /// Record reads needed from one stored object.
    pub(crate) fn stored_record_requests(&self, locator: &Locator) -> Vec<RecordRequest> {
        self.checkpoints
            .facts
            .parts
            .iter()
            .filter(|(id, part)| part.locator == *locator && self.needs_record_read(**id, part))
            .filter_map(|(id, part)| self.record_request(*id, part))
            .collect()
    }

    fn needs_record_read(&self, id: EventId, part: &frasil_space::CheckpointPart) -> bool {
        let Some(read) = self.checkpoints.record_reads.get(&id) else {
            return true;
        };
        read.part != *part
            || matches!(read.outcome, frasil_space::RecordObject::Missing)
            || (matches!(read.outcome, frasil_space::RecordObject::Summary(_))
                && !self.checkpoints.records.contains_key(&id)
                && self
                    .record_request(id, part)
                    .is_some_and(|request| matches!(request.mode, frasil_space::RecordMode::Build)))
    }

    /// Publishes only a finished read.
    pub(crate) fn keep_record_read(&mut self, id: EventId, read: frasil_units::record::RecordRead) {
        if read.object_outcome == frasil_units::RecordObjectOutcome::NotTheObject
            && let Some(stored) = self.forget_object(&read.part.locator)
        {
            self.forgotten_objects.push((read.part.locator, stored));
        }
        if matches!(
            read.outcome,
            frasil_space::RecordObject::Read(_) | frasil_space::RecordObject::Summary(_)
        ) {
            self.locate(read.part.locator);
            self.mark_checked(&read.part.locator);
        }
        if matches!(read.outcome, frasil_space::RecordObject::Missing) {
            self.checkpoints.record_reads.remove(&id);
        } else {
            self.checkpoints.record_reads.insert(id, read);
        }
    }

    /// Whether a record object the last judgement lacked is held now, so
    /// that the view is judged again with it.
    fn records_arrived(&mut self) -> bool {
        let arrived = self.checkpoints.facts.active && self.gather_records();
        if arrived {
            self.appendable = None;
        }
        arrived
    }

    /// The objects a refresh needed whose chunks are in the store.
    pub(crate) fn take_wanted_at_rest(&mut self) -> BTreeSet<Locator> {
        std::mem::take(&mut self.wanted_at_rest)
    }

    /// The header and the chunk indices the store holds of an object whole
    /// there, by its locator or its ID.
    pub(crate) fn stored_parts(&self, locator: &Locator) -> Option<(Vec<u8>, Vec<u64>)> {
        let object = self.held_object(locator)?;
        if object.held || !object.is_whole() {
            return None;
        }
        let header = object.header.clone()?;
        Some((header, object.stored.iter().copied().collect()))
    }

    /// Whether the replica holds an object's header, and not yet the key of
    /// the state the header names: the object opens once that key arrives.
    #[cfg(feature = "adapter-blobs")]
    pub(crate) fn object_awaits_key(&self, locator: &Locator) -> bool {
        self.held_object(locator)
            .and_then(|object| object.header.as_deref())
            .and_then(|header| frasil_units::objects::Header::read(header).ok())
            .is_some_and(|read| self.object_key(&read.key_reference).is_none())
    }

    /// Whether the replica holds a unit of the stream that it cannot open
    /// until a key arrives (`Sealed`).
    #[cfg(feature = "adapter-blobs")]
    pub(crate) fn stream_awaits_keys(&self, stream: &StreamId) -> bool {
        self.statuses.iter().any(|(id, status)| {
            matches!(status, Status::Void { class, .. } if class.name() == "Sealed")
                && self.unit_stream(id).as_ref() == Some(stream)
        })
    }

    /// Borrows a single sealed chunk without collecting the object.
    pub(crate) fn record_chunk(&self, locator: &Locator, index: u64) -> Option<&[u8]> {
        self.held_object(locator)?
            .chunks
            .get(&index)
            .map(Vec::as_slice)
    }

    /// The indices of parts to stream, including any extra stored parts.
    pub(crate) fn record_indices(&self, locator: &Locator, store_only: bool) -> Vec<u64> {
        let Some(object) = self.held_object(locator) else {
            return Vec::new();
        };
        let mut indices = object.stored.clone();
        if !store_only {
            indices.extend(object.chunks.keys());
        }
        indices.into_iter().collect()
    }

    /// The chunks held in memory of an object, by index.
    pub(crate) fn chunks_in_memory(&self, locator: &Locator) -> BTreeMap<u64, Vec<u8>> {
        self.held_object(locator)
            .map(|object| object.chunks.clone())
            .unwrap_or_default()
    }

    /// [`chunks_in_memory`](Self::chunks_in_memory) in a range of indices
    /// alone, copying no other.
    pub(crate) fn chunks_in_memory_in(
        &self,
        locator: &Locator,
        range: core::ops::Range<u64>,
    ) -> BTreeMap<u64, Vec<u8>> {
        self.held_object(locator)
            .map(|object| {
                object
                    .chunks
                    .range(range)
                    .map(|(index, chunk)| (*index, chunk.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Takes chunks read back from the store into memory, for a refresh
    /// that needs the object.
    pub(crate) fn fill_chunks(&mut self, locator: &Locator, chunks: BTreeMap<u64, Vec<u8>>) {
        let object = match self.objects.get_mut(locator) {
            Some(object) => Some(object),
            None => self.unlocated.get_mut(&object_id(locator)),
        };
        if let Some(object) = object {
            object.chunks.extend(chunks);
        }
    }

    /// Every object with chunks in the store: its locator, or its ID
    /// followed by zeros while the locator is not known, with the indices.
    #[cfg_attr(not(feature = "ext-guests"), allow(dead_code))]
    pub(crate) fn stored_chunks(&self) -> Vec<(Locator, Vec<u64>)> {
        let located = self
            .objects
            .iter()
            .map(|(locator, object)| (*locator, object));
        let unlocated = self.unlocated.iter().map(|(id, object)| {
            let mut locator = [0; 64];
            locator[..32].copy_from_slice(id);
            (locator, object)
        });
        located
            .chain(unlocated)
            .filter(|(_, object)| !object.stored.is_empty())
            .map(|(locator, object)| (locator, object.stored.iter().copied().collect()))
            .collect()
    }

    /// The chunks of one object the store holds: under its locator, and
    /// under its ID while its locator was not known (a locator whose tail
    /// is zero, as [`Replica::stored_chunks`] gives such an object).
    #[cfg(any(feature = "server", feature = "server-socket"))]
    pub(crate) fn stored_chunks_of(&self, locator: &Locator) -> BTreeSet<u64> {
        let mut id = [0; 32];
        id.copy_from_slice(&locator[..32]);
        let mut by_id = [0; 64];
        by_id[..32].copy_from_slice(&id);
        let located = self.objects.get(locator);
        let located_by_id = (by_id != *locator)
            .then(|| self.objects.get(&by_id))
            .flatten();
        located
            .into_iter()
            .chain(located_by_id)
            .chain(self.unlocated.get(&id))
            .flat_map(|object| object.stored.iter().copied())
            .collect()
    }

    /// Drops the chunks in memory that the store holds too.
    pub(crate) fn release_chunks(&mut self) {
        for object in self.objects.values_mut().chain(self.unlocated.values_mut()) {
            let stored = &object.stored;
            object.chunks.retain(|index, _| !stored.contains(index));
        }
    }

    /// Stops noting chunks as stored: the log is kept in memory only from
    /// now on, with the chunks read back.
    #[cfg_attr(not(feature = "ext-guests"), allow(dead_code))]
    pub(crate) fn unstore_chunks(&mut self) {
        for object in self.objects.values_mut().chain(self.unlocated.values_mut()) {
            object.stored.clear();
        }
        self.chunks_at_rest = false;
    }

    /// The objects the store holds whose locator is not yet known, by ID.
    pub(crate) fn unlocated(&self) -> Vec<[u8; 32]> {
        self.unlocated.keys().copied().collect()
    }

    /// Gives an object found in the store its locator, once its bytes were
    /// read and hashed.
    pub(crate) fn locate(&mut self, locator: Locator) {
        if let Some(object) = self.unlocated.remove(&object_id(&locator)) {
            self.objects.entry(locator).or_insert(object);
        }
    }

    /// Whether an object's locator is known.
    pub(crate) fn is_located(&self, locator: &Locator) -> bool {
        self.objects.contains_key(locator)
    }

    /// Marks an object as one the application holds, or no longer holds
    /// (at-rest.md, "Held objects").
    pub(crate) fn mark_held(&mut self, locator: Locator, held: bool) {
        self.held_object_mut(locator).held = held;
    }

    /// Whether the application holds an object's plaintext (at-rest.md,
    /// "Held objects").
    pub fn is_held(&self, locator: &Locator) -> bool {
        self.held_object(locator).is_some_and(|object| object.held)
    }

    /// Drops an object's chunks held here, keeping its header: the
    /// application holds the plaintext now.
    pub(crate) fn drop_chunks(&mut self, locator: &Locator) {
        if let Some(object) = self.objects.get_mut(locator) {
            object.chunks.clear();
            object.stored.clear();
        }
        if let Some(object) = self.unlocated.get_mut(&object_id(locator)) {
            object.chunks.clear();
            object.stored.clear();
        }
    }

    /// Whether the device holds an object whole: every chunk here, or the
    /// plaintext with the application (at-rest.md, "Held objects"). An
    /// object in the store whose locator is not yet known counts by its ID.
    pub fn holds_object(&self, locator: &Locator) -> bool {
        self.held_object(locator).is_some_and(HeldObject::is_whole)
    }

    /// The objects the device holds whole whose locators it knows, in
    /// ascending order; [`unlocated`](Self::unlocated) names the others.
    pub fn whole_objects(&self) -> Vec<Locator> {
        self.objects
            .iter()
            .filter(|(_, object)| object.is_whole())
            .map(|(locator, _)| *locator)
            .collect()
    }

    /// How much of an object the device holds: the chunks held, and their
    /// count once the header is held.
    #[cfg_attr(
        not(all(
            any(feature = "server", feature = "iroh", feature = "server-socket"),
            feature = "adapter-blobs"
        )),
        allow(dead_code)
    )]
    pub(crate) fn object_progress(&self, locator: &Locator) -> Option<(u64, Option<u64>)> {
        let object = self.held_object(locator)?;
        if object.held && object.header.is_some() {
            let count = object.chunk_count();
            return Some((count.unwrap_or(0), count));
        }
        Some((object.chunks_held(), object.chunk_count()))
    }

    /// Keeps a space snapshot's stream entries, loaded once their objects
    /// and keys are held.
    pub(crate) fn keep_stream_entries(&mut self, entries: Vec<StreamEntry>) {
        self.pending_streams.extend(entries);
    }

    /// Whether the replica started from a space snapshot's base.
    pub(crate) fn has_base(&self) -> bool {
        self.base.is_some()
    }

    /// Keeps an adopted space snapshot until the device stores it.
    pub(crate) fn keep_snapshot_until_sealed(&mut self, signed: Vec<u8>) {
        self.snapshot_to_keep = Some(signed);
    }

    /// The adopted space snapshot not stored yet, if any.
    pub(crate) fn snapshot_to_keep(&self) -> Option<&[u8]> {
        self.snapshot_to_keep.as_deref()
    }

    /// The adopted space snapshot is stored.
    pub(crate) fn snapshot_kept(&mut self) {
        self.snapshot_to_keep = None;
    }

    /// The objects the store holds whole whose locator the replica does
    /// not know yet, by ID, with each one's plaintext size, smallest first.
    pub(crate) fn unlocated_whole(&self) -> Vec<([u8; 32], u64)> {
        let mut out: Vec<([u8; 32], u64)> = self
            .unlocated
            .iter()
            .filter(|(_, object)| object.is_whole())
            .filter_map(|(id, object)| {
                let header = object.header.as_deref()?;
                let read = frasil_units::objects::Header::read(header).ok()?;
                Some((*id, read.size))
            })
            .collect();
        out.sort_unstable_by_key(|(id, size)| (*size, *id));
        out
    }

    /// The objects of the space snapshot's stream entries not yet loaded.
    pub(crate) fn pending_stream_objects(&self) -> impl Iterator<Item = &Locator> {
        self.pending_streams.iter().map(|entry| &entry.object)
    }

    /// The adapter type of the stream whose state an object holds, when it
    /// is a state object this replica may load: a pending stream entry's,
    /// or a snapshot unit's not yet used or refused.
    pub(crate) fn state_object_type(&self, locator: &Locator) -> Option<String> {
        if let Some(entry) = self.pending_streams.iter().find(|e| e.object == *locator) {
            return Some(entry.opening.type_.clone());
        }
        self.snapshot_candidates
            .iter()
            .chain(self.checked_snapshots.iter())
            .find(|(_, (_, compacts, _, _))| compacts.object == *locator)
            .and_then(|(_, (stream, _, _, _))| {
                self.streams
                    .get(stream)
                    .map(|runtime| runtime.adapter_type().to_owned())
                    .or_else(|| self.openings.get(stream).map(|o| o.type_.clone()))
            })
    }

    /// A state object whose header names a plaintext larger than its
    /// adapter loads: each snapshot unit that names it is `BadCompaction`
    /// (units.md, "Checking, using and settling a snapshot"), each stream
    /// entry that names it is dropped as one whose object does not read,
    /// and it is not fetched again.
    pub(crate) fn refuse_oversized_state(&mut self, locator: Locator) {
        self.oversized_states.insert(locator);
        let naming: Vec<EventId> = self
            .snapshot_candidates
            .iter()
            .chain(self.checked_snapshots.iter())
            .filter(|(_, (_, compacts, _, _))| compacts.object == locator)
            .map(|(id, _)| *id)
            .collect();
        for id in naming {
            self.snapshot_candidates.remove(&id);
            self.checked_snapshots.remove(&id);
            self.bad_compactions.insert(id);
        }
        self.pending_streams.retain(|entry| entry.object != locator);
    }

    /// Whether a state object was refused for its size.
    pub(crate) fn is_oversized_state(&self, locator: &Locator) -> bool {
        self.oversized_states.contains(locator)
    }

    /// Awaits the newcomer's snapshot at this locator: the device fetches
    /// it, and uses it before it places the space's events.
    #[cfg_attr(
        not(any(
            feature = "server",
            feature = "iroh",
            feature = "server-socket",
            feature = "ext-invite-links"
        )),
        allow(dead_code)
    )]
    pub(crate) fn await_snapshot(&mut self, locator: Locator) {
        if self.base.is_none() {
            self.awaited_snapshot = Some(locator);
        }
    }

    /// The newcomer's snapshot the device awaits, if any.
    pub(crate) fn awaited_snapshot(&self) -> Option<&Locator> {
        self.awaited_snapshot.as_ref()
    }

    /// Whether the replica waits for any member's snapshot (admission.md,
    /// "The newcomer's snapshot"): its newcomer's snapshot was never used.
    pub(crate) fn wants_snapshot(&self) -> bool {
        self.wants_snapshot
    }

    /// After a restart, whether this device was admitted "from now on" and
    /// never used its snapshot: no record keeps the wait at rest, so a
    /// replica that is not the founder's, has no base, holds events it
    /// cannot place, and whose view does not yet grant this device, waits
    /// for any member's snapshot. Its admitting event names units it holds
    /// no stub of, so it cannot place it without one.
    pub(crate) fn notice_unused_snapshot(&mut self, me: &DeviceId) {
        let Some(log) = &self.log else {
            return;
        };
        let granted = self.roster().state(&MemberRef::device(*me)).is_some();
        self.wants_snapshot = self.base.is_none()
            && log.genesis().author() != me
            && log.pending().next().is_some()
            && !granted;
    }

    /// The snapshot awaited is used, or given up.
    pub(crate) fn snapshot_taken(&mut self) {
        self.awaited_snapshot = None;
        self.wants_snapshot = false;
    }

    /// Loads each pending stream entry whose object and key are held
    /// (units.md, "The space snapshot", "Using it", step 6).
    fn load_streams(&mut self, registry: &AdapterRegistry) {
        let pending = std::mem::take(&mut self.pending_streams);
        for entry in pending {
            // A partial replica loads a stream once it opens it.
            if self
                .partial
                .as_ref()
                .is_some_and(|held| !held.contains(&entry.stream))
            {
                self.pending_streams.push(entry);
                continue;
            }
            let Some(bytes) = self.object_or_want(&entry.object) else {
                self.pending_streams.push(entry);
                continue;
            };
            // Bytes that are not the object the entry names: fetched again.
            if !self.is_object(&entry.object, &bytes) {
                self.pending_streams.push(entry);
                continue;
            }
            let Some((key, _)) = self.object_key(&entry.key) else {
                self.pending_streams.push(entry);
                continue;
            };
            let Ok(plaintext) =
                frasil_units::objects::read_object(&bytes, &self.space, Some(&key), &entry.object)
            else {
                continue;
            };
            let Ok(snapshot) = frasil_units::snapshot::StreamSnapshot::read(
                &plaintext,
                &entry.stream,
                &entry.opening.type_,
            ) else {
                continue;
            };
            if !snapshot.history_free {
                continue;
            }
            let Some(mut runtime) = registry.stream(&entry.opening.type_) else {
                continue;
            };
            self.openings
                .entry(entry.stream)
                .or_insert_with(|| entry.opening.clone());
            let cover: BTreeSet<[u8; 32]> = entry.covers.iter().map(|c| c.unit.0).collect();
            let excluded: BTreeSet<[u8; 32]> = entry.excluded.iter().map(|id| id.0).collect();
            // The newcomer holds no unit of the cover: the entry's key 7
            // is where the supersession set reaches it (ext-file-versions.md,
            // 3.3 The supersession set, Load).
            if runtime.use_snapshot(snapshot.state, cover, excluded, entry.supersedes.clone()) {
                // Units of the stream already held are handed over again
                // after the cover.
                if let Some(old) = self.streams.remove(&entry.stream) {
                    drop(old);
                    self.handed
                        .retain(|_, handed| handed.stream != entry.stream);
                }
                self.bases.remove(&entry.stream);
                self.streams.insert(entry.stream, runtime);
                self.snapshot_streams.insert(entry.stream);
            }
        }
    }

    /// Runs the order of verification and takes keys until none is new,
    /// then hands units to their adapters. At a partial replica that learns
    /// the system stream here, the units that waited for it are then placed
    /// or witnessed, and the replica refreshed again. A replica that first
    /// opens the genesis here is refreshed again too, so that the units of
    /// its system stream (list copies, body keys, stubs) are read now: a
    /// device that recovers holds no key before the wraps it opens here.
    pub(crate) fn refresh(
        &mut self,
        me: &Me,
        registry: &AdapterRegistry,
        held: &Others<'_>,
    ) -> Refreshed {
        let knew_system = self.system_stream.is_some();
        let mut refreshed = self.refresh_once(me, registry, held);
        self.was_member |= self.level_of(&me.device).is_some();
        let mut placed = self.place_undecided();
        placed.extend(self.add_carried_stubs());
        let learned_system = !knew_system && self.system_stream.is_some();
        let mut again = !placed.is_empty() || learned_system;
        // Units placed on their own stubs are judged, and the view resolved
        // again with what they placed or without it. Each pass judges at
        // least one unit, which no later pass places again.
        again |= self.judge_own_stubs();
        // A checkpoint's record object held now: the view is judged again
        // with it.
        again |= self.records_arrived();
        while again {
            let more = self.refresh_once(me, registry, held);
            if refreshed.list_events.is_empty() {
                refreshed.list_events = more.list_events;
            }
            refreshed.bodies.extend(more.bodies);
            refreshed.taken.extend(more.taken);
            refreshed.states.extend(more.states);
            refreshed.changed.extend(more.changed);
            again = self.judge_own_stubs();
            again |= self.records_arrived();
        }
        #[cfg(debug_assertions)]
        if check_refreshes()
            && let Err(difference) = self.check_from_scratch(&me.device, held)
        {
            panic!("a refresh differs from one from scratch: {difference}");
        }
        refreshed
    }

    /// Resolves the view again from scratch, reading every unit and visible
    /// part anew with the keys held now, and compares: every event's status
    /// (or why the space does not resolve), and every sealed part the
    /// replica kept against the unit opened again. A difference is an error
    /// of what the replica keeps between refreshes.
    #[cfg(debug_assertions)]
    pub(crate) fn check_from_scratch(
        &self,
        me: &DeviceId,
        held: &Others<'_>,
    ) -> Result<(), String> {
        let Some(log) = self.log.as_ref() else {
            return Ok(());
        };
        // A refresh that held a rival's past whole stops judging from its
        // kept checkpoint once it is done (roster.md, 3.15.6): the next one
        // judges as a replica that kept everything, which a judgement from
        // scratch already does.
        if !self.checkpoints.facts.rivals.is_empty() {
            return Ok(());
        }
        // Every signature verified again, as a replica that remembers none.
        let log = &log.forgetting_verdicts();
        let parts = VisibleParts::default();
        let keyring = self.keyring();
        let rotations = Rotations {
            log,
            parts: &parts,
            kept: Some(&self.secrets),
        };
        #[cfg(feature = "ext-restricted-spaces")]
        let parent_parts = VisibleParts::default();
        #[cfg(feature = "ext-restricted-spaces")]
        let parent = self
            .restricted
            .parent
            .and_then(|p| held.replicas.get(&p))
            .and_then(|p| {
                p.log().map(|log| {
                    (
                        p,
                        Rotations {
                            log,
                            parts: &parent_parts,
                            kept: None,
                        },
                    )
                })
            });
        #[cfg(feature = "ext-restricted-spaces")]
        let parent_keyring = parent
            .as_ref()
            .map(|(p, _)| p.keyring())
            .unwrap_or_default();
        let unit_keys = {
            #[cfg(feature = "ext-restricted-spaces")]
            match (&parent, self.restricted.parent) {
                (Some((_, parent_log)), Some(parent_id)) => {
                    ReplicaKeys::Restricted(frasil_units::ext_restricted_spaces::RestrictedKeys {
                        parent: parent_id,
                        own: &keyring,
                        own_log: &rotations,
                        parent_keys: &parent_keyring,
                        parent_log,
                    })
                }
                _ => ReplicaKeys::Plain(KeyringKeys {
                    keyring: &keyring,
                    log: &rotations,
                }),
            }
            #[cfg(not(feature = "ext-restricted-spaces"))]
            ReplicaKeys::Plain(KeyringKeys {
                keyring: &keyring,
                log: &rotations,
            })
        };
        let scratch = UnitReads::default();
        let reader = CachedReader {
            log,
            base: self.base.as_ref(),
            forgotten: self
                .checkpoints
                .kept
                .as_ref()
                .map(|kept| kept.checkpoint)
                .or(self.checkpoints.kept_id),
            frozen: &self.frozen_content,
            reads: &scratch,
            keys: &unit_keys,
            system: self.system_stream,
        };
        let mut others = OtherLogs::none().with_keys(held.keys);
        for list in held.lists.values() {
            #[cfg_attr(not(feature = "ext-recovery-agent"), allow(unused_mut))]
            let mut held_list = list.held();
            #[cfg(feature = "ext-recovery-agent")]
            if let Some(vouched) = self.vouched.get(&list.person_id()) {
                held_list.set_vouched(vouched.iter().map(|device| device.0).collect());
            }
            others = others.with_list(held_list);
        }
        for (id, facts) in held.spaces {
            if *id != self.space {
                others = others.with_space(*facts);
            }
        }
        let notices = GrantedNotices::new(&others);
        let options = Options {
            keys: &keyring,
            limits: Limits::PROTOCOL,
            others: &others,
            units: &reader,
            twins: Twins::Skeleton,
            key_checks: KeyEventChecks::Context,
            notices: Some(&notices),
        };
        let resolved = resolve_held_apart(log, options, self.partial.is_some()).0;
        match resolved {
            Err(class) if self.unresolved != Some(class) => {
                return Err(format!(
                    "from scratch the space does not resolve ({class:?}); kept: {:?}",
                    self.unresolved
                ));
            }
            Err(_) => {}
            Ok(space) => {
                // A view judged with its checkpoints: the verdicts, the
                // chain, the electorate and whom each pending checkpoint
                // waits for, and the key world, as a judgement from scratch
                // gives them, with none of what the last one found taken as
                // known.
                let judged = match self.checkpoints.facts.active {
                    true => Some(self.check_checkpointed(log, options, &space, me)?),
                    false => None,
                };
                let (judged, frozen_authorship) = match judged {
                    Some((statuses, frozen)) => (Some(statuses), frozen),
                    None => (None, BTreeMap::new()),
                };
                for id in space.view() {
                    let fresh = match &judged {
                        Some(statuses) => statuses.get(id),
                        None => space.status(*id),
                    };
                    let kept = self.statuses.get(id);
                    if fresh != kept {
                        return Err(format!(
                            "event {id:?}: from scratch {fresh:?}, kept {kept:?}"
                        ));
                    }
                }
                // What a refresh after placed units only derives anew for
                // them: the valid events, who wrote each unit, whether any
                // event is held back, and the facts other spaces read.
                let valid: BTreeSet<EventId> = match &judged {
                    Some(statuses) => statuses
                        .iter()
                        .filter(|(_, status)| status.is_valid())
                        .map(|(id, _)| *id)
                        .collect(),
                    None => space.valid().into_iter().collect(),
                };
                if valid != self.valid {
                    return Err(format!(
                        "valid events: from scratch {}, kept {}",
                        valid.len(),
                        self.valid.len()
                    ));
                }
                // A kept unit with what was frozen of it, as the refresh
                // attributes it when the view reads no world.
                let mut frozen_authorship = frozen_authorship;
                {
                    for &id in space.view() {
                        if frozen_authorship.contains_key(&id) {
                            continue;
                        }
                        if self.kept_frozen(log, &id)
                            && let Some(frozen) = self.frozen_content.get(&id)
                            && let Some(found) = crate::frozen::authorship(frozen)
                        {
                            frozen_authorship.insert(id, found);
                        }
                    }
                }
                let mut authorship = authorship(
                    &space,
                    space
                        .view()
                        .iter()
                        .copied()
                        .filter(|id| !frozen_authorship.contains_key(id))
                        // A kept unit with what was frozen of it is
                        // attributed by that alone, or not at all.
                        .filter(|id| {
                            !(self.frozen_content.contains_key(id) && self.kept_frozen(log, id))
                        }),
                );
                authorship.extend(frozen_authorship);
                if authorship != self.authorship {
                    return Err("who wrote each unit differs from scratch".into());
                }
                let holds_back = self.statuses.values().any(|status| {
                    status
                        .class()
                        .is_some_and(|class| class.sort() != Sort::Final)
                });
                if holds_back != self.holds_back {
                    return Err(format!(
                        "held back: from scratch {holds_back}, kept {}",
                        self.holds_back
                    ));
                }
                if let Some((citable, heads)) = &self.citable
                    && self.citable_at == (log.placed_count(), log.revision())
                {
                    let fresh = log.citable(|event| self.accepted(&event.id()));
                    let fresh_heads: BTreeSet<EventId> = log.heads_in(&fresh).into_iter().collect();
                    if fresh != *citable || fresh_heads != *heads {
                        return Err("the citable events differ from scratch".into());
                    }
                }
                if let Some(kept) = &self.facts
                    && judged.is_none()
                {
                    let fresh = crate::granted::GrantedFacts::of(&space, log);
                    if !fresh.reads_as(kept) || !fresh.holds_same(kept) {
                        return Err("the facts other spaces read differ from scratch".into());
                    }
                }
            }
        }
        for (id, inner) in self.unit_reads.opened() {
            let Some(event) = log.event(id) else {
                continue;
            };
            // A unit of the past a replica forgot opens under content keys
            // it kept of states whose rotations it dropped (roster.md,
            // 3.15.6, "What must be kept"), which a resolution from
            // scratch over what it holds cannot derive again.
            if self.kept_frozen(log, &id) {
                continue;
            }
            let mut fresh = Unit::from_event(event.clone())
                .and_then(|unit| unit.open_at_member(&unit_keys, self.system_stream.as_ref()));
            if self.unit_reads.is_released(&id)
                && let Ok(fresh) = &mut fresh
            {
                fresh.content = Vec::new();
            }
            if fresh.as_ref().ok() != Some(&*inner) {
                return Err(format!(
                    "unit {id:?}: from scratch {:?}, kept its sealed part",
                    fresh.err()
                ));
            }
        }
        Ok(())
    }

    /// The checkpoint half of [`Self::check_from_scratch`]: judges `plain`,
    /// the view resolved from scratch, with its checkpoints from scratch,
    /// compares the chain, every pending checkpoint's electorate and whom it
    /// waits for, the roster and the key world's current states with what
    /// the replica keeps, and gives every event's verdict from scratch.
    #[cfg(debug_assertions)]
    fn check_checkpointed(
        &self,
        log: &Log,
        options: Options<'_>,
        plain: &Space<'_>,
        me: &DeviceId,
    ) -> Result<CheckedFromScratch, String> {
        let mut fresh = self.checkpoints.clone();
        fresh.before = None;
        fresh.facts.stable_seed.clear();
        fresh.facts.validity_seed = (None, BTreeMap::new());
        fresh.records.clear();
        let Some(judgement) = crate::checkpoints::judge(log, options, plain, &fresh, me) else {
            return Err("from scratch the view is not judged with checkpoints".into());
        };
        let kept = &self.checkpoints.facts;
        if judgement.facts.chain != kept.chain {
            return Err(format!(
                "the chain: from scratch {:?}, kept {:?}",
                judgement.facts.chain, kept.chain
            ));
        }
        let waiting = |facts: &crate::checkpoints::Facts| -> Vec<(EventId, Vec<DeviceId>)> {
            facts
                .pending
                .iter()
                .map(|p| (p.checkpoint, p.waiting.iter().map(|w| w.device).collect()))
                .collect()
        };
        if waiting(&judgement.facts) != waiting(kept) {
            return Err(
                "the pending checkpoints, or whom they wait for, differ from scratch".into(),
            );
        }
        if judgement.roster != self.roster {
            return Err("the roster differs from scratch".into());
        }
        let world = crate::checkpoints::resolve_world(&judgement, log, options);
        let mut statuses = BTreeMap::new();
        let mut frozen_authorship = BTreeMap::new();
        if let Some(world) = &world {
            let frozen: Vec<EventId> = plain
                .view()
                .iter()
                .copied()
                .filter(|id| self.kept_frozen(log, id))
                .collect();
            // What forgetting froze is an input, as frozen verdicts are; a
            // unit of the forgotten past with nothing frozen of it has no
            // place left to read its attribution at.
            for id in frozen {
                if let Some(found) = self
                    .frozen_content
                    .get(&id)
                    .and_then(crate::frozen::authorship)
                {
                    frozen_authorship.insert(id, found);
                }
            }
            for id in world.view() {
                if let Some(status) = world.status(*id) {
                    statuses.insert(*id, *status);
                }
            }
            // The key world: the states its graph holds current.
            let reads = &self.unit_reads;
            let history = SpaceHistory::with_units(world, |event| {
                match &reads.unit(event).ok()?.body.reference {
                    KeyReference::Set(state) | KeyReference::Restricted { own: state, .. } => {
                        Some(state.clone())
                    }
                }
            });
            let graph = history.key_graph();
            if graph.current(Kind::Grant) != self.grant_current {
                return Err("the key world's current grant state differs from scratch".into());
            }
            let mut current = graph.current(Kind::Content);
            if let Some(c) = judgement.facts.following
                && judgement.facts.last() != Some(c)
                && let Some(state) = &current
                && !state
                    .ids()
                    .iter()
                    .all(|&id| id == c || log.follows(id, c) == Ok(true))
                && let Ok(own) = RotationSet::new([c])
                && self.state_key(&own).is_some()
            {
                current = Some(own);
            }
            if current != self.current {
                return Err("the key world's current content state differs from scratch".into());
            }
        }
        statuses.extend(judgement.statuses);
        Ok((statuses, frozen_authorship))
    }

    fn refresh_once(
        &mut self,
        me: &Me,
        registry: &AdapterRegistry,
        held: &Others<'_>,
    ) -> Refreshed {
        let mut refreshed = Refreshed::default();
        self.gather_records();
        let Some(log) = self.log.as_ref() else {
            return refreshed;
        };
        let mut units = Vec::new();
        // Whom this replica vouches for, under the policy of its view.
        #[cfg(feature = "ext-recovery-agent")]
        if let Some(agents) = &held.agents {
            self.vouched = agents.decide(held.lists, &self.policy);
        }
        // What the resolution reads besides the log; when only content
        // units were placed since the last one, under the same, the space
        // is resolved from it.
        let inputs = self.refresh_inputs(me, held);
        // A view judged with its checkpoints is resolved in full each time.
        // Placed units alone would be sound to take on their own only when
        // no checkpoint waits for votes (an administrator's unit after one
        // is a vote, which may put it in effect and change every verdict),
        // no rival is held, and each unit follows the last checkpoint in
        // effect (else it is late, which reads the chain). Even then its
        // verdict is the world's: the world's log (`WorldLog`) is built
        // afresh by each judgement and takes no event once built, and
        // `Space::resolve_appended` resumes a plain resolution without the
        // verdicts the world presets (a unit's `BadCuts`, the holds of a
        // record not read), which only `Checkpointed` derives. So the whole
        // view is judged again.
        // With a checkpoint in effect and nothing else to judge, the world
        // is resumed instead: no checkpoint waits for votes, no rival is
        // held and no proposal asks for a record, so each unit after the
        // checkpoint leaves the chain, the electorate and every other
        // verdict as they were, and is judged in the world as a resolution
        // from scratch judges it.
        let facts = &self.checkpoints.facts;
        let world_resumable = facts.active
            && self.checkpoints.propose.is_none()
            && facts.pending.is_empty()
            && facts.rivals.is_empty()
            && facts.rival_wanted.is_empty()
            && facts.last().is_some();
        if self
            .appendable
            .as_ref()
            .is_some_and(|kept| match &kept.world {
                Some(world) => !world_resumable || facts.last() != Some(world.checkpoint),
                None => facts.active || self.checkpoints.propose.is_some(),
            })
        {
            self.appendable = None;
        }
        let mut appended = self.appendable.take().and_then(|kept| {
            let (added, frontier) = self.appended_units(log, &kept, &inputs)?;
            if let Some(world) = &kept.world {
                if world.inputs != self.checkpoint_inputs() {
                    return None;
                }
                for id in &added {
                    let event = log.event(*id)?;
                    if world
                        .tips
                        .get(event.author())
                        .is_some_and(|&(tip, _)| event.seq() <= tip)
                    {
                        return None;
                    }
                }
            }
            Some((kept, added, frontier))
        });
        if let Some((_, _, frontier)) = &mut appended
            && let Some(frontier) = frontier.take()
        {
            self.break_frontier = Some(frontier);
        }
        let mut appended = appended.map(|(kept, added, _)| (kept, added));
        let mut fast: Option<Vec<EventId>> = appended.as_ref().map(|(_, added)| added.clone());
        let mut previous = if fast.is_some() {
            BTreeMap::new()
        } else {
            std::mem::take(&mut self.statuses)
        };
        let mut carried_on: Option<Appendable> = None;
        // A bound: each pass takes at least one key.
        for _ in 0..64 {
            let keyring = self.keyring();
            let rotations = Rotations {
                log,
                parts: &self.visible_parts,
                kept: Some(&self.secrets),
            };
            // A restricted space's units read through its parent's keys.
            #[cfg(feature = "ext-restricted-spaces")]
            let parent = self
                .restricted
                .parent
                .and_then(|p| held.replicas.get(&p))
                .and_then(|p| {
                    p.log().map(|log| {
                        (
                            p,
                            Rotations {
                                log,
                                parts: &p.visible_parts,
                                kept: None,
                            },
                        )
                    })
                });
            #[cfg(feature = "ext-restricted-spaces")]
            let parent_keyring = parent
                .as_ref()
                .map(|(p, _)| p.keyring())
                .unwrap_or_default();
            let unit_keys = {
                #[cfg(feature = "ext-restricted-spaces")]
                match (&parent, self.restricted.parent) {
                    (Some((_, parent_log)), Some(parent_id)) => ReplicaKeys::Restricted(
                        frasil_units::ext_restricted_spaces::RestrictedKeys {
                            parent: parent_id,
                            own: &keyring,
                            own_log: &rotations,
                            parent_keys: &parent_keyring,
                            parent_log,
                        },
                    ),
                    _ => ReplicaKeys::Plain(KeyringKeys {
                        keyring: &keyring,
                        log: &rotations,
                    }),
                }
                #[cfg(not(feature = "ext-restricted-spaces"))]
                ReplicaKeys::Plain(KeyringKeys {
                    keyring: &keyring,
                    log: &rotations,
                })
            };
            let reader = CachedReader {
                log,
                base: self.base.as_ref(),
                forgotten: self
                    .checkpoints
                    .kept
                    .as_ref()
                    .map(|kept| kept.checkpoint)
                    .or(self.checkpoints.kept_id),
                frozen: &self.frozen_content,
                reads: &self.unit_reads,
                keys: &unit_keys,
                system: self.system_stream,
            };
            let mut others = OtherLogs::none().with_keys(held.keys);
            for list in held.lists.values() {
                #[cfg_attr(not(feature = "ext-recovery-agent"), allow(unused_mut))]
                let mut held_list = list.held();
                #[cfg(feature = "ext-recovery-agent")]
                if let Some(vouched) = self.vouched.get(&list.person_id()) {
                    held_list.set_vouched(vouched.iter().map(|device| device.0).collect());
                }
                others = others.with_list(held_list);
            }
            for (id, facts) in held.spaces {
                if *id != self.space {
                    others = others.with_space(*facts);
                }
            }
            let notices = GrantedNotices::new(&others);
            let options = Options {
                keys: &keyring,
                limits: Limits::PROTOCOL,
                others: &others,
                units: &reader,
                twins: Twins::Skeleton,
                key_checks: KeyEventChecks::Context,
                notices: Some(&notices),
            };
            if appended
                .as_ref()
                .is_some_and(|(kept, _)| kept.world.is_some())
                && let Some((
                    Appendable {
                        resolved: prior_resolved,
                        copies: prior_copies,
                        world: Some(world),
                        ..
                    },
                    added,
                )) = appended.take()
            {
                let mut world = world;
                let c = world.checkpoint;
                let Some(presets) = crate::checkpoints::presets_after(
                    log,
                    options,
                    &self.checkpoints,
                    c,
                    &mut world.log,
                    &world.unreadable,
                    &added,
                ) else {
                    // Not to be resumed: the view is judged again whole.
                    fast = None;
                    previous = std::mem::take(&mut self.statuses);
                    continue;
                };
                #[cfg(test)]
                WORLD_RESUMED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let plain = Space::resolve_appended(log, options, prior_resolved, &added);
                let judged = Space::resolve_appended_world(
                    world.log.log(),
                    log,
                    options,
                    world.judged,
                    &added,
                    &presets,
                );
                let space = Space::resolve_appended_world(
                    world.log.log(),
                    log,
                    options,
                    world.keys,
                    &added,
                    &presets,
                );
                // The verdicts are the judgement's, in the world; the rest
                // reads the world as the key graph does, and the whole view
                // for who wrote each unit.
                for id in &added {
                    if let Some(status) = judged.status(*id) {
                        self.statuses.insert(*id, *status);
                        if status.is_valid() {
                            self.valid.insert(*id);
                        }
                    }
                    if let Some(verified) = space
                        .screened()
                        .verified(*id)
                        .or_else(|| plain.screened().verified(*id))
                        .or_else(|| log.verified(*id))
                    {
                        self.verified.insert(*id, verified.clone());
                    }
                }
                self.authorship
                    .extend(authorship(&plain, added.iter().copied()));
                self.voiders
                    .extend(unit_voiders(&plain, added.iter().copied()));
                if let Some(facts) = &mut self.facts {
                    facts.add_events(log, &added);
                }
                let pending: Vec<EventId> = self
                    .checked_snapshots
                    .keys()
                    .chain(self.used_snapshots.iter())
                    .copied()
                    .filter(|id| !self.stable_snapshots.contains(id))
                    .collect();
                for id in pending {
                    if space.stable(&[id]) {
                        self.stable_snapshots.insert(id);
                    }
                }
                let (checked, used) = (&self.checked_snapshots, &self.used_snapshots);
                self.stable_snapshots
                    .retain(|id| checked.contains_key(id) || used.contains(id));
                #[cfg(feature = "ext-guests")]
                if space.policy().bounded_window.is_some() {
                    self.guests = crate::guests::facts(&space, &me.device, &self.first_sight);
                }
                units = self.units_of(&space, log, &unit_keys, Some(&added), None, None);
                let kept = (
                    plain.into_resolved(),
                    judged.into_resolved_world(),
                    space.into_resolved_world(),
                );
                carried_on = match kept {
                    (Some(resolved), Some(judged), Some(keys)) => Some(Appendable {
                        resolved,
                        placed: log.placed_count(),
                        revision: log.revision(),
                        inputs: inputs.clone(),
                        copies: prior_copies,
                        world: Some(Box::new(WorldParts {
                            checkpoint: c,
                            log: world.log,
                            judged,
                            keys,
                            unreadable: world.unreadable,
                            tips: world.tips,
                            inputs: world.inputs,
                        })),
                    }),
                    _ => None,
                };
                break;
            }
            if let Some((prior, added)) = appended.take() {
                #[cfg(test)]
                APPENDED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let space = Space::resolve_appended(log, options, prior.resolved, &added);
                // What replicas derive, for the units added: the rest
                // reads space events, which are as they were.
                for id in &added {
                    if let Some(status) = space.status(*id) {
                        self.statuses.insert(*id, *status);
                        if status.is_valid() {
                            self.valid.insert(*id);
                        }
                    }
                    if let Some(verified) =
                        space.screened().verified(*id).or_else(|| log.verified(*id))
                    {
                        self.verified.insert(*id, verified.clone());
                    }
                }
                self.authorship
                    .extend(authorship(&space, added.iter().copied()));
                self.voiders
                    .extend(unit_voiders(&space, added.iter().copied()));
                if let Some(facts) = &mut self.facts {
                    facts.add_events(log, &added);
                }
                // A snapshot not yet stable may be now; one that is stays so.
                let pending: Vec<EventId> = self
                    .checked_snapshots
                    .keys()
                    .chain(self.used_snapshots.iter())
                    .copied()
                    .filter(|id| !self.stable_snapshots.contains(id))
                    .collect();
                for id in pending {
                    if space.stable(&[id]) {
                        self.stable_snapshots.insert(id);
                    }
                }
                let (checked, used) = (&self.checked_snapshots, &self.used_snapshots);
                self.stable_snapshots
                    .retain(|id| checked.contains_key(id) || used.contains(id));
                #[cfg(feature = "ext-guests")]
                if space.policy().bounded_window.is_some() {
                    self.guests = crate::guests::facts(&space, &me.device, &self.first_sight);
                }
                units = self.units_of(&space, log, &unit_keys, Some(&added), None, None);
                carried_on = space.into_resolved().map(|resolved| Appendable {
                    resolved,
                    placed: log.placed_count(),
                    revision: log.revision(),
                    inputs: inputs.clone(),
                    copies: prior.copies,
                    world: None,
                });
                break;
            }
            #[cfg(test)]
            {
                self.full_resolutions += 1;
            }
            let (resolved, verdicts) = resolve_held_apart(log, options, self.partial.is_some());
            self.provisional_verdicts = verdicts;
            // The view judged with its checkpoints (roster.md, 3.15.5): with
            // a chain in effect the replica reads the world of its last
            // checkpoint, for its roster, its keys and its units.
            // What the judgement reads besides the log's events, so that
            // what it judged before under the same is taken as known.
            let mut fingerprint = inputs.clone();
            fingerprint.extend(self.checkpoint_inputs());
            self.checkpoints.inputs = fingerprint;
            let judgement = resolved.as_ref().ok().and_then(|plain| {
                crate::checkpoints::judge(log, options, plain, &self.checkpoints, &me.device)
            });
            let world = judgement
                .as_ref()
                .and_then(|judgement| crate::checkpoints::resolve_world(judgement, log, options));
            // Stubs that carriers a `Missing` named hold, from carriers
            // placed and valid.
            let reads = &self.unit_reads;
            let valid = |id: EventId| {
                resolved
                    .as_ref()
                    .ok()
                    .and_then(|space| space.status(id))
                    .is_some_and(Status::is_valid)
            };
            self.carried_stubs = carried_stubs(log, reads, &self.carried, valid);
            // Body keys that units of the system stream hand over.
            let handed = take_body_keys(log, reads, &unit_keys, self.system_stream.as_ref());
            let new_bodies: Vec<(EventId, [u8; 32])> = handed
                .into_iter()
                .filter(|(id, key)| {
                    !self
                        .bodies
                        .get(id)
                        .is_some_and(|held| held.iter().any(|k| **k == *key))
                        && !self.opened_bodies.contains_key(id)
                })
                .collect();
            let mut kept = Vec::new();
            for (id, key) in new_bodies {
                // Each key is checked against its event's commitment
                // before use.
                if let Some(event) = log.event(id)
                    && self
                        .visible_parts
                        .of(event)
                        .is_some_and(|v| frasil_keys::derive::body_commitment(&key) != v.commitment)
                {
                    continue;
                }
                self.bodies.entry(id).or_default().push(Zeroizing::new(key));
                kept.push(id);
            }
            if !kept.is_empty() {
                refreshed.bodies.extend(kept);
                continue;
            }
            // List events that `frasil:list` units of the system stream
            // carry, for the persons' lists the device keeps.
            let copies = take_list_copies(
                log,
                &self.unit_reads,
                &unit_keys,
                self.system_stream.as_ref(),
            );
            self.list_copies = copies
                .iter()
                .filter_map(|signed| frasil_events::decode(signed).ok().map(|e| e.id()))
                .collect();
            let new_copies: Vec<Vec<u8>> = copies
                .into_iter()
                .filter(|signed| {
                    frasil_events::decode(signed).is_ok_and(|event| {
                        !held
                            .lists
                            .get(&event.log_id().0)
                            .is_some_and(|list| list.has_seen(event.id()))
                    })
                })
                .collect();
            if !new_copies.is_empty() && refreshed.list_events.is_empty() {
                refreshed.list_events = new_copies;
            }
            let parts = &self.visible_parts;
            let mut taken = take_keys(
                resolved.as_ref().ok(),
                log,
                parts,
                me,
                &self.secrets,
                &self.states,
                &mut self.wraps_tried,
            );
            // The world's deliveries and links, read with its roster.
            if taken.is_empty() && world.is_some() {
                taken = take_keys(
                    world.as_ref(),
                    log,
                    parts,
                    me,
                    &self.secrets,
                    &self.states,
                    &mut self.wraps_tried,
                );
            }
            take_space_wraps(
                world.as_ref().or(resolved.as_ref().ok()),
                log,
                parts,
                held.grant_seeds,
                &self.secrets,
                &mut taken,
                &mut self.space_wraps_tried,
            );
            if !taken.is_empty() {
                for (id, secrets) in taken.rotations {
                    if self.secrets.entry(id).or_default().merge(&secrets) {
                        refreshed.taken.push(id);
                    }
                }
                for (state, key) in taken.states {
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        self.states.entry(state.clone())
                    {
                        refreshed.states.push(state);
                        entry.insert(key);
                    }
                }
                continue;
            }
            // A rotation this device holds `Sealed`: the body key a
            // removal wrap hands it, provisional (keys.md, "Trial
            // decryption"; roster.md, "Space events a replica cannot
            // open").
            if let Ok(space) = &resolved {
                let removals = take_removal_wraps(
                    space,
                    log,
                    &self.visible_parts,
                    me,
                    &self.secrets,
                    &self.bodies,
                    &mut self.removal_tried,
                );
                if !removals.is_empty() {
                    for (id, key) in removals {
                        self.bodies.entry(id).or_default().push(key);
                        refreshed.bodies.push(id);
                    }
                    continue;
                }
            }
            let plain = match resolved {
                Ok(space) => space,
                Err(class) => {
                    self.unresolved = Some(class);
                    break;
                }
            };
            let (space, whole) = match world {
                Some(world) => (world, Some(plain)),
                None => (plain, None),
            };
            // The skeleton reads the whole view the replica holds.
            let skeleton_view = whole.as_ref().unwrap_or(&space);
            self.application
                .clone_from(&space.screened().genesis().descriptor.application);
            self.checkpoints.later_descriptor =
                space.screened().genesis().descriptor.kind.is_reserved();
            // The descriptor decides how units read: a restricted space
            // learned of here resolves again through its parent's keys.
            #[cfg(feature = "ext-restricted-spaces")]
            {
                let descriptor = &space.screened().genesis().descriptor;
                let parent = (descriptor.kind == frasil_space::DescriptorKind::Restricted)
                    .then_some(descriptor.parent)
                    .flatten()
                    .map(EventId);
                self.restricted.kind = Some(descriptor.kind);
                self.restricted.carve_out_of = (descriptor.kind
                    == frasil_space::DescriptorKind::CarveOut)
                    .then_some(descriptor.parent)
                    .flatten()
                    .map(EventId);
                if parent != self.restricted.parent {
                    self.restricted.parent = parent;
                    continue;
                }
                self.restricted.parent_keys = parent_keyring.clone();
                self.restricted.administered = crate::restricted::administered(&space);
            }
            self.unresolved = None;
            // Which snapshots are stable, for settling (units.md,
            // "Checking, using and settling a snapshot").
            self.stable_snapshots = self
                .checked_snapshots
                .keys()
                .chain(self.used_snapshots.iter())
                .copied()
                .filter(|id| space.stable(&[*id]))
                .collect();
            // What replicas derive: from the world, and from the whole view
            // for the events outside it, whose verdicts the judgement with
            // checkpoints gives below.
            for (index, view) in [Some(&space), whole.as_ref()]
                .into_iter()
                .flatten()
                .enumerate()
            {
                for id in view.view() {
                    if index == 0
                        && let Some(status) = view.status(*id)
                    {
                        self.statuses.insert(*id, *status);
                    }
                    if index > 0 && self.opened_bodies.contains_key(id) {
                        continue;
                    }
                    if let Some(opened) = view.opened(*id)
                        && !opened.provisional
                    {
                        self.opened_bodies.insert(*id, opened.body_key.clone());
                    } else if let Some(key) = view.screened().void_body_key(*id) {
                        // A void event this replica opened: a newcomer's
                        // snapshot carries its key too, else the newcomer
                        // holds it sealed, and every event after it with it.
                        self.opened_bodies.insert(*id, key.clone());
                    }
                    if let Some(verified) =
                        view.screened().verified(*id).or_else(|| log.verified(*id))
                    {
                        self.verified.insert(*id, verified.clone());
                    }
                }
            }
            #[cfg(feature = "ext-invite-links")]
            {
                self.invites = crate::invite_links::facts(&space, log);
                self.claim_checks = me
                    .invites
                    .iter()
                    .map(|invite| {
                        (
                            invite.device,
                            frasil_admission::ext_invite_links::check_claimable(
                                &space,
                                invite.entry,
                                &invite.device,
                            ),
                        )
                    })
                    .collect();
            }
            if self.partial.is_some() {
                self.heights_wanted = space.heights_wanted().to_vec();
                self.paths_wanted = paths_wanted(&space, log);
            }
            #[cfg(feature = "ext-guests")]
            {
                self.guests = crate::guests::facts(&space, &me.device, &self.first_sight);
            }
            self.roster = space.roster().clone();
            let copies = list_copy_places(
                log,
                &self.unit_reads,
                &unit_keys,
                self.system_stream.as_ref(),
            );
            let (frozen, read): (Vec<EventId>, Vec<EventId>) =
                skeleton_view.view().iter().copied().partition(|id| {
                    (whole.is_some() || self.frozen_content.contains_key(id))
                        && self.kept_frozen(log, id)
                });
            self.voiders = unit_voiders(skeleton_view, read.iter().copied());
            self.authorship = authorship(skeleton_view, read.into_iter());
            // What forgetting froze of who wrote a unit wins; a unit with
            // nothing frozen has no place left to read it at.
            let (kept_authors, frozen): (Vec<EventId>, Vec<EventId>) = frozen
                .into_iter()
                .partition(|id| self.frozen_content.contains_key(id));
            for id in kept_authors {
                match self
                    .frozen_content
                    .get(&id)
                    .and_then(crate::frozen::authorship)
                {
                    Some(found) => {
                        self.authorship.insert(id, found);
                    }
                    None => {
                        self.authorship.remove(&id);
                    }
                }
            }
            for id in frozen {
                self.authorship.remove(&id);
            }
            self.effective = space.effective_at(space.valid_roster(), 0, &[]);
            let facts = crate::granted::GrantedFacts::of(&space, log);
            if !self.facts.as_ref().is_some_and(|old| old.reads_as(&facts)) {
                self.changed_for_others = true;
            }
            self.facts = Some(facts);
            self.slots = crate::skeleton::derive_slots(&space, log, &self.slots);
            // Whether the skeleton and the roster differ in this view: an
            // administrator signs no acknowledgement or vote while they do
            // (peers.md, 3.12, "Where the peer and the roster differ";
            // 3.15).
            let in_roster: BTreeSet<DeviceId> = space
                .roster()
                .members_in()
                .filter(|(_, state)| state.level == Level::Administer)
                .filter_map(|(member, _)| member.device_id())
                .collect();
            let in_skeleton: BTreeSet<DeviceId> = space.administrator_slots().into_keys().collect();
            self.skeleton_differs = space.skeleton().is_some() && in_roster != in_skeleton;
            if *space.screened().keys() != self.found_keys {
                self.found_keys = space.screened().keys().clone();
            }
            self.awaits_keys = space.view().iter().any(|id| {
                matches!(
                    space.screened().signature(*id),
                    Some(frasil_space::Signature::NoHybridKey)
                )
            });
            self.forks = space.forks().clone();
            self.policy = *space.policy();
            self.valid = space.valid().into_iter().collect();
            self.roster_events = space.valid_roster().iter().copied().collect();
            #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
            {
                self.administrator_authors = space
                    .view()
                    .iter()
                    .copied()
                    .filter(|id| {
                        log.event(*id).is_some_and(|event| {
                            event.kind() == kind::SPACE
                                && !event.is_genesis()
                                && space
                                    .roster_at(&space.place_of(*id))
                                    .is_administrator(&event.author().0)
                        })
                    })
                    .collect();
            }
            self.refs_named = space
                .view()
                .iter()
                .filter_map(|id| space.opened(*id))
                .flat_map(|opened| opened.inner.refs.iter().map(|r| (r.log, r.id)))
                .collect();
            // Each unit's key reference, which the key graph reads as the
            // state it is sealed under (keys.md, "Deliveries").
            let reads = &self.unit_reads;
            let history = SpaceHistory::with_units(&space, |event| {
                match &reads.unit(event).ok()?.body.reference {
                    KeyReference::Set(state) | KeyReference::Restricted { own: state, .. } => {
                        Some(state.clone())
                    }
                }
            });
            let graph = history.key_graph();
            self.current = graph.current(Kind::Content);
            self.principals = principals_in_force(&space, log, &graph);
            self.grant_current = graph.current(Kind::Grant);
            let called = crate::healing::heals(&space, log, &graph);
            self.heals = called.heals;
            self.lacking = called.lacking;
            self.entitled = called.entitled;
            let carried = body_key_carriers(
                log,
                &self.unit_reads,
                &unit_keys,
                self.system_stream.as_ref(),
            );
            let reads = &self.unit_reads;
            let owed = crate::top_ups::owed(&space, log, &carried, |event| {
                let unit = reads.unit(event).ok()?;
                Some(match &unit.body.reference {
                    KeyReference::Set(state) | KeyReference::Restricted { own: state, .. } => {
                        state.ids().to_vec()
                    }
                })
            });
            // The units' body keys: derived from the state, or handed over,
            // each checked against the seal's commitment. Read from the
            // event, since a kept reading lets its sealed bytes go once its
            // stream took the content.
            self.top_up_keys = owed
                .ids
                .iter()
                .filter_map(|id| {
                    let event = log.event(*id).filter(|e| e.kind() == kind::UNIT)?;
                    let unit = Unit::from_event(event.clone()).ok()?;
                    unit.body_key_at_member(&unit_keys).map(|key| (*id, key))
                })
                .collect();
            self.top_ups = owed.ids;
            self.break_frontier = owed.frontier;
            if self.system_stream.is_none() {
                self.system_stream = space
                    .opened(log.id())
                    .and_then(|opened| opened.genesis())
                    .map(|genesis| genesis.system_stream);
            }
            if let Some(judgement) = &judgement {
                for (id, status) in &judgement.statuses {
                    self.statuses.insert(*id, *status);
                }
                self.valid = self
                    .statuses
                    .iter()
                    .filter(|(_, status)| status.is_valid())
                    .map(|(id, _)| *id)
                    .collect();
                self.roster = judgement.roster.clone();
                self.policy = judgement.policy;
                let valid = &self.valid;
                self.roster_events.retain(|id| valid.contains(id));
            }
            self.checkpoints.facts = judgement
                .as_ref()
                .map(|judgement| judgement.facts.clone())
                .unwrap_or_default();
            // Without a judgement the view holds no checkpoint: its growth
            // counts from the genesis, so that the first one is proposed.
            if judgement.is_none() {
                self.checkpoints.facts.growth = crate::checkpoints::plain_growth(log, &space);
            }
            // An event that follows a checkpoint is judged in its world and
            // sealed under a state of it (roster.md, 3.15.5, else
            // `StaleSeal`). While the device follows a checkpoint not yet in
            // effect, the view's current state may come from before it: the
            // device seals under the checkpoint's own rotation instead.
            if let Some(c) = self.checkpoints.facts.following
                && self.checkpoints.facts.last() != Some(c)
                && let Some(current) = &self.current
                && !current
                    .ids()
                    .iter()
                    .all(|&id| id == c || log.follows(id, c) == Ok(true))
                && let Ok(own) = RotationSet::new([c])
                && self.state_key(&own).is_some()
            {
                self.current = Some(own);
            }
            self.checkpoints.records = judgement
                .as_ref()
                .map(|judgement| judgement.records.clone())
                .unwrap_or_default();
            self.checkpoints.before = judgement
                .as_ref()
                .and_then(|judgement| judgement.before.clone());
            if self.checkpoints.kept.is_none() {
                self.checkpoints.kept = judgement
                    .as_ref()
                    .and_then(|judgement| judgement.kept.clone());
            }
            // A rival whose past the replica now holds whole: it no longer
            // judges from its kept checkpoint alone, and the next judgement
            // reads the rival's past as a replica that kept everything does
            // (roster.md, 3.15.6). The verdicts it froze stay.
            if !self.checkpoints.facts.rivals.is_empty()
                && self.checkpoints.facts.rival_wanted.is_empty()
            {
                self.checkpoints.kept = None;
                self.checkpoints.kept_id = None;
            }
            // Units in the world are read there; the others, in the first
            // checkpoint's past or late, with the verdicts the judgement
            // gave them.
            units = match (&judgement, &whole) {
                (Some(judgement), Some(whole)) => {
                    let mut units = self.units_of(&space, log, &unit_keys, None, None, None);
                    let in_world = space.view();
                    let rest: Vec<EventId> = log
                        .canonical_in(whole.view())
                        .into_iter()
                        .filter(|id| !in_world.contains(id))
                        .collect();
                    // A replica that forgot keeps the units of its kept
                    // checkpoint's past with their verdicts; their authors'
                    // capabilities are read at the root of the world, whose
                    // record carries them, not in the whole view, which
                    // lacks the grants it forgot.
                    let (frozen, rest): (Vec<EventId>, Vec<EventId>) =
                        rest.into_iter().partition(|id| self.kept_frozen(log, id));
                    units.extend(self.units_of(
                        whole,
                        log,
                        &unit_keys,
                        Some(&rest),
                        Some(&judgement.statuses),
                        None,
                    ));
                    if !frozen.is_empty() {
                        let root = space.world().map(|world| world.root);
                        units.extend(self.units_of(
                            &space,
                            log,
                            &unit_keys,
                            Some(&frozen),
                            Some(&judgement.statuses),
                            root,
                        ));
                    }
                    units.sort_unstable_by_key(|unit| (unit.height, unit.id));
                    units
                }
                (Some(judgement), None) => self.units_of(
                    &space,
                    log,
                    &unit_keys,
                    None,
                    Some(&judgement.statuses),
                    None,
                ),
                (None, _) => self.units_of(&space, log, &unit_keys, None, None, None),
            };
            // Kept for the next refresh, unless a list copy waits for the
            // device. A view judged with its checkpoints keeps its world's
            // resolutions beside the plain one, while nothing but units
            // after the checkpoint in effect would change them.
            let facts = &self.checkpoints.facts;
            let world_resumable = facts.pending.is_empty()
                && facts.rivals.is_empty()
                && facts.rival_wanted.is_empty()
                && self.checkpoints.propose.is_none();
            if refreshed.list_events.is_empty() && judgement.is_none() {
                carried_on = space.into_resolved().map(|resolved| Appendable {
                    resolved,
                    placed: log.placed_count(),
                    revision: log.revision(),
                    inputs: inputs.clone(),
                    copies,
                    world: None,
                });
            } else if refreshed.list_events.is_empty()
                && world_resumable
                && let Some(whole) = whole
            {
                let keys = space.into_resolved_world();
                let resolved = whole.into_resolved();
                if let Some(judgement) = judgement
                    && let (Some(world), Some(judged), Some(keys), Some(resolved)) =
                        (judgement.world, judgement.world_resolved, keys, resolved)
                {
                    let tips = world.record().tips.clone();
                    carried_on = Some(Appendable {
                        resolved,
                        placed: log.placed_count(),
                        revision: log.revision(),
                        inputs: inputs.clone(),
                        copies,
                        world: Some(Box::new(WorldParts {
                            checkpoint: world.checkpoint(),
                            log: world.into_log(),
                            judged,
                            keys,
                            unreadable: judgement.world_unreadable,
                            tips,
                            inputs: self.checkpoint_inputs(),
                        })),
                    });
                }
            }
            break;
        }
        if let Some(added) = &fast {
            // The units added join the citable events when their past is.
            if let Some((citable, heads)) = &mut self.citable {
                let mut ordered = added.clone();
                ordered.sort_unstable_by_key(|&id| (log.height(id).unwrap_or(0), id));
                for id in ordered {
                    let Some(event) = log.event(id) else {
                        continue;
                    };
                    let past = event.parents().iter().all(|parent| {
                        citable.contains(parent)
                            || (!log.contains(*parent)
                                && (log.stub(*parent).is_some()
                                    || log.witnessed(*parent).is_some()))
                    });
                    if past && accepts(&self.statuses, &id) {
                        citable.insert(id);
                        for parent in event.parents() {
                            heads.remove(parent);
                        }
                        // A unit placed after an event that cites it, as a
                        // cover unit fetched after the snapshot placed
                        // against its stub, is in a head's past: no head
                        // (events.md, 3.3, "Parents are the heads").
                        if !heads.iter().any(|&head| log.precedes(id, head)) {
                            heads.insert(id);
                        }
                    }
                }
            }
            self.citable_at = (log.placed_count(), log.revision());
            for id in added {
                refreshed.changed.push(*id);
                self.changed_log = true;
                self.holds_back |= self.statuses.get(id).is_some_and(|status| {
                    status
                        .class()
                        .is_some_and(|class| class.sort() != Sort::Final)
                });
            }
            self.appendable = carried_on;
            self.load_streams(registry);
            self.hand_units(units, registry, true);
            return refreshed;
        }
        for id in log.canonical() {
            if previous.get(&id) != self.statuses.get(&id) {
                refreshed.changed.push(id);
                self.changed_log = true;
                if log.event(id).is_some_and(|e| e.kind() != kind::UNIT) {
                    self.changed_for_others = true;
                }
            }
        }
        if !refreshed.taken.is_empty()
            || !refreshed.states.is_empty()
            || !refreshed.bodies.is_empty()
        {
            self.changed_for_others = true;
        }
        self.holds_back = self.statuses.values().any(|status| {
            status
                .class()
                .is_some_and(|class| class.sort() != Sort::Final)
        });
        self.appendable = carried_on;
        let citable = log.citable(|event| accepts(&self.statuses, &event.id()));
        let heads = log.heads_in(&citable).into_iter().collect();
        self.citable = Some((citable, heads));
        self.citable_at = (log.placed_count(), log.revision());
        self.load_streams(registry);
        self.hand_units(units, registry, false);
        refreshed
    }

    /// What a resolution reads besides the log: the keys, the other logs
    /// and spaces, the grant seeds, the device's own invite and recovery
    /// keys, the system stream and a restricted space's parent, written
    /// out so that two refreshes that read the same compare equal.
    /// Whether the administrators the skeleton resolves and those of the
    /// roster differ in this view: until the difference is repaired, an
    /// administrator signs no acknowledgement or vote (peers.md, 3.15).
    pub(crate) fn skeleton_differs(&self) -> bool {
        self.skeleton_differs
    }

    /// The rotations whose `key` records of kind 1 a forgetting that
    /// dropped `dropped` deletes (`frasil_store::checkpoint_state`): each
    /// dropped one whose states seal no unit the log keeps, nor its
    /// current state; their secrets go from memory too.
    pub(crate) fn drop_rotation_keys(&mut self, dropped: &[EventId]) -> BTreeSet<[u8; 32]> {
        let Some(log) = &self.log else {
            return BTreeSet::new();
        };
        let mut sealing: Vec<RotationSet> = log
            .events()
            .filter(|event| event.kind() == kind::UNIT)
            .filter_map(|event| self.unit_reads.unit(event).ok())
            .map(|unit| match &unit.body.reference {
                KeyReference::Set(state) | KeyReference::Restricted { own: state, .. } => {
                    state.clone()
                }
            })
            .collect();
        sealing.extend(self.current.iter().cloned());
        sealing.extend(self.grant_current.iter().cloned());
        let dropped: BTreeSet<[u8; 32]> = dropped.iter().map(|id| id.0).collect();
        let gone = frasil_store::checkpoint_state::rotation_keys_dropped(
            self.secrets.keys().map(|id| id.0),
            &dropped,
            &sealing,
        );
        self.secrets.retain(|id, _| !gone.contains(&id.0));
        gone
    }

    /// The events that void a unit the write rule voids (roster.md, 3.14,
    /// "The events that void an event"): read in the view that judged it, or
    /// for a unit of a forgotten past, from what was frozen of it.
    pub(crate) fn unit_voiders(&self, unit: &EventId) -> &[EventId] {
        match self.frozen_content.get(unit) {
            Some(frozen) => &frozen.voided_by,
            None => self.voiders.get(unit).map_or(&[], Vec::as_slice),
        }
    }

    /// The device whose administrator slot a pseudonym was enrolled in,
    /// as this replica's skeleton derives it.
    pub(crate) fn device_of_pseudonym(&self, pseudonym: &DeviceId) -> Option<DeviceId> {
        let slot = self
            .slots
            .enrolled
            .iter()
            .find(|(_, enrolled)| *enrolled == pseudonym)
            .map(|(slot, _)| *slot)?;
        self.slots
            .by_device
            .iter()
            .find(|(_, info)| info.slot == slot)
            .map(|(device, _)| *device)
    }

    /// Asks the next judgement to freeze the units of the past of the last
    /// checkpoint of the chain in effect, which the device is about to
    /// forget; `false` when there is none to forget.
    pub(crate) fn request_freeze(&mut self) -> bool {
        let Some(c) = self.checkpoints.facts.last() else {
            return false;
        };
        if self
            .checkpoints
            .kept
            .as_ref()
            .is_some_and(|kept| kept.checkpoint == c)
        {
            return false;
        }
        if matches!(&self.checkpoints.facts.frozen_units, Some((at, _)) if *at == c) {
            return false;
        }
        self.checkpoints.freeze = Some(c);
        self.appendable = None;
        true
    }

    /// Whether a unit is one of the kept checkpoint's past that this
    /// replica, having forgotten that past, keeps with its verdict: its
    /// place is gone with the past, so what reads its author's standing
    /// reads it at the root of the world, whose record carries it.
    fn kept_frozen(&self, log: &Log, id: &EventId) -> bool {
        let Some(c) = self
            .checkpoints
            .kept
            .as_ref()
            .map(|kept| kept.checkpoint)
            .or(self.checkpoints.kept_id)
        else {
            return false;
        };
        self.checkpoints.frozen.contains_key(id)
            || (self.checkpoints.recorded.contains_key(id) && log.follows(*id, c) != Ok(true))
    }

    /// What a judgement with checkpoints reads besides the log's placed
    /// events and [`Self::refresh_inputs`]: the kept checkpoint and the
    /// verdicts kept of its past, the record objects and their keys, the
    /// checkpoint envelopes and stubs kept, and the dropped events. A world
    /// is resumed only while these are as they were.
    fn checkpoint_inputs(&self) -> Vec<u8> {
        let held = &self.checkpoints;
        let mut out = Vec::new();
        let id = |out: &mut Vec<u8>, bytes: &[u8]| out.extend_from_slice(bytes);
        if let Some(kept) = &held.kept {
            id(&mut out, &kept.checkpoint.0);
        }
        out.push(0xff);
        if let Some(c) = held.kept_id {
            id(&mut out, &c.0);
        }
        out.push(0xff);
        for counted in [
            held.frozen.len(),
            held.recorded.len(),
            held.object_keys.len(),
            held.record_reads.len(),
            usize::from(held.later_descriptor),
            held.envelopes.len(),
            held.restored_dropped.len(),
            held.dropped_origins.len(),
        ] {
            out.extend_from_slice(&(counted as u64).to_be_bytes());
        }
        for c in held.object_keys.keys() {
            id(&mut out, &c.0);
        }
        out.push(0xff);
        if let Some(log) = &self.log {
            for envelope in log.kept_envelopes() {
                id(&mut out, &envelope.id().0);
            }
            out.push(0xff);
            out.extend_from_slice(&(log.stubs().count() as u64).to_be_bytes());
        }
        out
    }

    fn refresh_inputs(&self, me: &Me, held: &Others<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        let id = |out: &mut Vec<u8>, bytes: &[u8]| out.extend_from_slice(bytes);
        for (rotation, secrets) in &self.secrets {
            id(&mut out, &rotation.0);
            out.push(
                u8::from(secrets.content.is_some())
                    | u8::from(secrets.upload.is_some()) << 1
                    | u8::from(secrets.grant.is_some()) << 2,
            );
        }
        out.push(0xff);
        for state in self.states.keys() {
            id(&mut out, &state.encode());
        }
        out.push(0xff);
        for (event, keys) in &self.bodies {
            id(&mut out, &event.0);
            out.extend_from_slice(&(keys.len() as u64).to_be_bytes());
        }
        out.push(0xff);
        for (person, list) in held.lists {
            id(&mut out, person);
            let (placed, revision) = list.revision();
            out.extend_from_slice(&placed.to_be_bytes());
            out.extend_from_slice(&revision.to_be_bytes());
        }
        out.push(0xff);
        for (space, view) in held.spaces {
            id(&mut out, &space.0);
            out.extend_from_slice(&view.generation().to_be_bytes());
        }
        out.push(0xff);
        for (space, seeds) in held.grant_seeds {
            id(&mut out, &space.0);
            for rotation in seeds.keys() {
                id(&mut out, &rotation.0);
            }
        }
        out.push(0xff);
        #[cfg(feature = "ext-recovery-agent")]
        for (list, devices) in &self.vouched {
            id(&mut out, list);
            for device in devices {
                id(&mut out, &device.0);
            }
        }
        out.push(0xff);
        #[cfg(feature = "ext-invite-links")]
        for invite in &me.invites {
            id(&mut out, &invite.device.0);
            id(&mut out, &invite.entry.0);
        }
        if let Some((member, _)) = &me.recovering {
            id(&mut out, &member.0);
        }
        out.push(0xff);
        // Keys from other sources: an event pending on keys is judged again
        // when they grow (crypto.md, "Keys by their hash").
        out.extend_from_slice(&held.keys.revision().to_be_bytes());
        out.push(0xff);
        if let Some(stream) = &self.system_stream {
            id(&mut out, &stream[..]);
        }
        out.push(0xff);
        #[cfg(feature = "ext-restricted-spaces")]
        if let Some(parent) = self.restricted.parent.and_then(|p| held.replicas.get(&p)) {
            id(&mut out, &parent.space.0);
            out.extend(parent.refresh_inputs_own());
        }
        out
    }

    /// A restricted space's parent's part of [`refresh_inputs`]: its keys
    /// and its log.
    #[cfg(feature = "ext-restricted-spaces")]
    fn refresh_inputs_own(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (rotation, secrets) in &self.secrets {
            out.extend_from_slice(&rotation.0);
            out.push(u8::from(secrets.content.is_some()));
        }
        for state in self.states.keys() {
            out.extend_from_slice(&state.encode());
        }
        if let Some(log) = &self.log {
            out.extend_from_slice(&(log.placed_count() as u64).to_be_bytes());
            out.extend_from_slice(&log.revision().to_be_bytes());
        }
        out
    }

    /// The events placed since a kept resolution, when it may be resolved
    /// from: the same inputs, a log changed only by placing, at a full
    /// replica with no witness, no carrier waiting, and each new event a
    /// content unit outside the system stream that is no evidence of a
    /// fork (events.md, "Chains and evidence of a fork": no other event of
    /// its author at its `seq`, and its `prev` its author's event before
    /// it).
    fn appended_units(
        &self,
        log: &Log,
        kept: &Appendable,
        inputs: &[u8],
    ) -> Option<(Vec<EventId>, Option<crate::top_ups::Frontier>)> {
        if kept.inputs != inputs
            || kept.revision != log.revision()
            || log.has_witnesses()
            || self.partial.is_some()
            || self.unresolved.is_some()
            || !self.carried.is_empty()
            || !self.carried_stubs.is_empty()
            || log.has_provisional()
        {
            return None;
        }
        let system = self.system_stream?;
        let added = log.placed_since(kept.placed);
        for id in added {
            let event = log.event(*id)?;
            if event.kind() != kind::UNIT || kept.resolved.view().contains(id) {
                return None;
            }
            let unit = self.unit_reads.unit(event).ok()?;
            if unit.body.stream == system {
                return None;
            }
            // A merged state other than the current one may be a state a
            // member is entitled to and lacks, which only a full resolution
            // finds (keys.md, "Deliveries", item 2).
            if let KeyReference::Set(state) = &unit.body.reference
                && state.len() > 1
                && self.current.as_ref() != Some(state)
            {
                return None;
            }
            let author = event.author();
            if log.chain_at(author, event.seq()).any(|other| other != *id) {
                return None;
            }
            if let Some(prev) = event.prev()
                && let Some(previous) = log.event(prev)
                && (previous.author() != author
                    || previous.seq().checked_add(1) != Some(event.seq()))
            {
                return None;
            }
        }
        // Past a break, each unit must follow every break: one that may be
        // concurrent with one may be owed a top-up (admission.md,
        // "Top-ups"), which only a full resolution finds.
        let frontier = match &self.break_frontier {
            Some(frontier) => {
                let mut frontier = frontier.clone();
                for id in added {
                    if !frontier.admit(log, log.event(*id)?) {
                        return None;
                    }
                }
                Some(frontier)
            }
            None => None,
        };
        Some((added.to_vec(), frontier))
    }

    /// The units of the view that opened, with their content and context,
    /// and each one's verdict by the write rule.
    fn units_of(
        &self,
        space: &Space<'_>,
        log: &Log,
        keys: &impl UnitKeys,
        among: Option<&[EventId]>,
        statuses: Option<&BTreeMap<EventId, Status>>,
        _at_root: Option<EventId>,
    ) -> Vec<OpenedUnit> {
        let Some(system) = self.system_stream else {
            return Vec::new();
        };
        let mut out = Vec::new();
        // List copies belong to each unit's own past, so context is
        // cached per unit, even when units share a roster place.
        let mut capabilities_at: BTreeMap<AuthorAtUnit, (Capabilities, Option<ContentOutcome>)> =
            BTreeMap::new();
        let ids = match among {
            Some(ids) => {
                let mut ids = ids.to_vec();
                ids.sort_unstable_by_key(|&id| (log.height(id).unwrap_or(0), id));
                ids
            }
            None => log.canonical_in(space.view()),
        };
        for id in ids {
            let event = log.event(id).expect("a view's events are placed");
            if event.kind() != kind::UNIT {
                continue;
            }
            let status = statuses
                .and_then(|statuses| statuses.get(&id))
                .or_else(|| space.status(id));
            let Some(status) = status else {
                continue;
            };
            let valid = status.is_valid();
            // The verdict before the seal: a unit neither valid nor finally
            // refused is not opened here for the first time (units.md, 3.2
            // A unit, at a member). A unit whose verdict is not decided, such as one held pending
            // (units.md, 3.15 "Pending, never applied"), is never applied:
            // one never handed waits to be, and one handed before is handed
            // again, so that its stream stops applying its content and
            // rebuilds (units.md, 3.8 Rebuilds).
            let decided = valid || matches!(status.class().map(Class::sort), Some(Sort::Final));
            if !decided && !self.handed.contains_key(&id) {
                continue;
            }
            // A unit not yet handed to its stream needs its content, and so
            // does one of a stream about to load from a snapshot, which is
            // handed again after the cover.
            let reloads = |unit: &Unit| {
                self.pending_streams
                    .iter()
                    .any(|entry| entry.stream == unit.body.stream)
            };
            let handed = self.handed.contains_key(&id)
                && !self.unit_reads.unit(event).is_ok_and(|unit| reloads(&unit));
            let opened = if handed {
                self.unit_reads.read_open(event, keys, Some(&system))
            } else {
                self.unit_reads.unit(event).and_then(|unit| {
                    let inner = self.unit_reads.open_whole(&unit, keys, Some(&system))?;
                    Ok((unit, inner))
                })
            };
            let Ok((unit, inner)) = opened else {
                continue;
            };
            // The author's capabilities at the unit's place: those of its
            // strongest path (units.md, 3.17 "Capability checks"). With no
            // path found, the content waits for a log not held, or is
            // refused: never checked as an unnarrowed writer's.
            let author = event.author().0;
            // What forgetting froze of the unit, at its own place, wins
            // over any reading of a place the replica no longer holds.
            let frozen = self
                .frozen_content
                .get(&id)
                .filter(|_| self.kept_frozen(log, &id))
                .map(|frozen| {
                    (
                        frozen.capabilities.clone(),
                        crate::frozen::unreached(frozen),
                    )
                });
            let (capabilities, unreached) = match frozen {
                Some(frozen) => frozen,
                None => capabilities_at
                    .entry((id, author))
                    .or_insert_with_key(|_| unit_capabilities(space.author_reach(id)))
                    .clone(),
            };
            // Content that is not applied for now waits, as content whose
            // author's capabilities wait for a log does: a unit whose
            // verdict is undecided, with its class.
            let unreached = if decided {
                unreached.filter(|_| valid)
            } else {
                Some(ContentOutcome::Waiting(
                    status
                        .class()
                        .map_or(ErrorClass::Pending.name(), Class::name),
                ))
            };
            let height = log.height(id).unwrap_or(0);
            let check = content_check(
                &unit.body.stream,
                &system,
                &inner.type_,
                inner.opening.as_ref(),
                |_| true,
            );
            let snapshot = unit
                .body
                .compacts
                .clone()
                .map(|compacts| (compacts, inner.excluded.clone(), event.parents().to_vec()));
            out.push(OpenedUnit {
                id,
                stream: unit.body.stream,
                type_: inner.type_.clone(),
                #[cfg(feature = "ext-restricted-spaces")]
                copied_from: inner.copied_from.map(|c| (c.space, c.event)),
                opening: inner.opening.clone(),
                snapshot,
                adapter_type: inner
                    .opening
                    .as_ref()
                    .map_or_else(|| inner.type_.clone(), |o| o.type_.clone()),
                check,
                valid,
                height,
                capabilities,
                unreached,
                // A restricted space's key references carry its parent's
                // state.
                #[cfg(feature = "ext-restricted-spaces")]
                restricted: self.restricted_parent().is_some(),
                unit,
                inner,
            });
        }
        out
    }

    /// Hands units to their streams: every unit of the view, or with
    /// `appended`, those added since the units handed last.
    fn hand_units(&mut self, units: Vec<OpenedUnit>, registry: &AdapterRegistry, appended: bool) {
        let mut rebuild = BTreeSet::new();
        let mut snapshots = Vec::new();
        #[cfg(feature = "ext-restricted-spaces")]
        if !appended {
            self.restricted.clear_units();
        }
        #[cfg(not(feature = "ext-restricted-spaces"))]
        let _ = appended;
        for opened in units {
            #[cfg(feature = "ext-restricted-spaces")]
            if opened.valid
                && let Some(late) = opened.copied_from
            {
                self.restricted.copied.insert(late);
            }
            if let Some(opening) = &opened.opening {
                self.openings
                    .entry(opened.stream)
                    .or_insert_with(|| opening.clone());
            }
            #[cfg(feature = "ext-file-versions")]
            if !opened.unit.body.supersedes.is_empty() {
                let predecessors = opened
                    .unit
                    .body
                    .supersedes
                    .iter()
                    .map(|named| named.predecessor)
                    .collect();
                self.superseding
                    .insert(opened.id, (opened.stream, predecessors));
            }
            // A valid unit whose author's capabilities were not found: its
            // content waits or is refused, judged again at each resolution.
            match opened.unreached {
                Some(outcome) => {
                    self.unreached.insert(opened.id, outcome);
                }
                None => {
                    self.unreached.remove(&opened.id);
                }
            }
            if let Some((compacts, excluded, parents)) = &opened.snapshot
                && opened.valid
                && opened.check.is_ok()
                && opened.unreached.is_none()
            {
                snapshots.push((
                    opened.id,
                    opened.stream,
                    compacts.clone(),
                    excluded.clone(),
                    parents.clone(),
                ));
            }
            if let Err(class) = opened.check {
                self.refused_content.insert(opened.id, class_name(class));
                continue;
            }
            // A move unit's content is its move record, which no adapter
            // reads (ext-restricted-spaces.md, "Moved documents"); without
            // the extension it is kept and ignored.
            if opened.type_ == frasil_units::types::MOVE {
                #[cfg(feature = "ext-restricted-spaces")]
                if let Err(class) = self.restricted.take_move(
                    opened.id,
                    opened.stream,
                    &opened.inner.content,
                    opened.valid,
                ) {
                    self.refused_content.insert(opened.id, class_name(class));
                    continue;
                }
                #[cfg(not(feature = "ext-restricted-spaces"))]
                self.refused_content
                    .insert(opened.id, ErrorClass::UnknownAdapter.name());
                continue;
            }
            let Some(stream) = (match self.streams.entry(opened.stream) {
                std::collections::btree_map::Entry::Occupied(entry) => Some(entry.into_mut()),
                std::collections::btree_map::Entry::Vacant(entry) => registry
                    .stream(&opened.adapter_type)
                    .map(|runtime| entry.insert(runtime)),
            }) else {
                self.refused_content
                    .insert(opened.id, ErrorClass::UnknownAdapter.name());
                continue;
            };
            let valid = opened.valid;
            // Its stream applies its content only once its author's
            // capabilities are found.
            let applies = valid && opened.unreached.is_none();
            match self.handed.get(&opened.id).cloned() {
                None => {
                    stream.receive(opened.stream_unit());
                    self.handed.insert(
                        opened.id,
                        Handed {
                            stream: opened.stream,
                            valid,
                            applies,
                            capabilities: opened.capabilities.clone(),
                        },
                    );
                    // The stream holds the content now; the system stream's
                    // is read again at each refresh.
                    if Some(opened.stream) != self.system_stream {
                        self.unit_reads.release_content(opened.id);
                    }
                }
                Some(handed) => {
                    // A verdict, or the capabilities the roster or a
                    // granted space's facts give its author, changed: the
                    // stream judges its content again (units.md, 3.8
                    // Rebuilds; 3.17 "Capability checks").
                    let mut changes = Vec::new();
                    if handed.applies != applies {
                        changes.push(stream.set_valid(&opened.id.0, applies));
                    }
                    if handed.capabilities != opened.capabilities {
                        changes.push(
                            stream.set_capabilities(&opened.id.0, opened.capabilities.clone()),
                        );
                    }
                    for change in changes {
                        match change {
                            frasil_units::runtime::VerdictChange::None => {}
                            frasil_units::runtime::VerdictChange::Rebuild => {
                                rebuild.insert(opened.stream);
                            }
                            frasil_units::runtime::VerdictChange::InsideSnapshot => {
                                stream.drop_snapshot();
                                self.bases.remove(&opened.stream);
                            }
                        }
                    }
                    if handed.valid != valid
                        || handed.applies != applies
                        || handed.capabilities != opened.capabilities
                    {
                        self.handed.insert(
                            opened.id,
                            Handed {
                                stream: opened.stream,
                                valid,
                                applies,
                                capabilities: opened.capabilities.clone(),
                            },
                        );
                    }
                }
            }
        }
        for stream in rebuild {
            if let Some(runtime) = self.streams.get_mut(&stream) {
                runtime.rebuild();
            }
        }
        self.drop_refused_snapshots();
        for (id, stream, compacts, excluded, parents) in snapshots {
            if !self.used_snapshots.contains(&id)
                && !self.bad_compactions.contains(&id)
                && self.snapshot_accepted(&id)
            {
                self.snapshot_candidates
                    .insert(id, (stream, compacts, excluded, parents));
            }
        }
        self.take_snapshots();
    }

    /// Checks the valid snapshot units a refresh handed over, and uses the
    /// state of one whose cover the stream holds none of (units.md,
    /// "Checking, using and settling a snapshot"). Only a snapshot unit
    /// whose content its stream accepted is a candidate ("Using": "its
    /// content is not refused"), and a seed never replaces a snapshot
    /// whose cover is not empty.
    /// Runs again once more objects are held.
    pub(crate) fn take_snapshots(&mut self) {
        let candidates: Vec<_> = self
            .snapshot_candidates
            .iter()
            .map(|(id, (stream, compacts, excluded, parents))| {
                (
                    *id,
                    *stream,
                    compacts.clone(),
                    excluded.clone(),
                    parents.clone(),
                )
            })
            .collect();
        for (id, stream, compacts, excluded, parents) in candidates {
            if self.oversized_states.contains(&compacts.object) {
                self.bad_compactions.insert(id);
            }
            if self.used_snapshots.contains(&id)
                || self.bad_compactions.contains(&id)
                || !self.may_use_snapshot(&id, &stream, &compacts)
            {
                self.snapshot_candidates.remove(&id);
                continue;
            }
            let Some(log) = self.log.as_ref() else {
                return;
            };
            let Some(unit) = log.event(id).and_then(|e| Unit::from_event(e.clone()).ok()) else {
                continue;
            };
            let checked = crate::compaction::check(log, &unit, &parents);
            if checked == Some(false) {
                self.bad_compactions.insert(id);
                continue;
            }
            let of = |x: EventId| crate::compaction::stream_of(log, x);
            let mut cover: BTreeSet<[u8; 32]> =
                frasil_units::compaction::cover_set(log, of, &compacts.covers, &stream)
                    .into_iter()
                    .map(|x| x.0)
                    .collect();
            cover.extend(compacts.covers.iter().map(|pair| pair.unit.0));
            cover.extend(compacts.stubs.iter().map(|stub| stub.id.0));
            // ext-file-versions.md, section 3.5: a key 8 that is present
            // and differs from the replica's own derivation.
            #[cfg(feature = "ext-file-versions")]
            if checked == Some(true)
                && !unit.body.supersedes.is_empty()
                && let Some(runtime) = self.streams.get(&stream)
                && runtime.adapter_type() == frasil_adapter_blobs::TYPE
                && let Some(derived) = runtime.compact(&cover)
                && !frasil_adapter_blobs::versions::supersedes_hold(
                    &derived.supersedes,
                    &unit.body.supersedes,
                )
            {
                self.bad_compactions.insert(id);
                continue;
            }
            // A replica that holds units of the cover rebuilds from them,
            // and may use the snapshot once it settles; one that holds none
            // loads the snapshot's state in their place.
            if cover.iter().any(|x| log.event(EventId(*x)).is_some()) {
                if let Some(candidate) = self.snapshot_candidates.remove(&id)
                    && checked == Some(true)
                {
                    self.checked_snapshots.insert(id, candidate);
                }
                continue;
            }
            self.load_snapshot(id, stream, &compacts, &excluded, cover);
        }
    }

    /// Loads a snapshot's state in place of its cover: `true` once the
    /// stream uses it. A snapshot whose object fails is `BadCompaction`.
    /// One the replica may not use (see [`Self::may_use_snapshot`]) is not
    /// loaded.
    fn load_snapshot(
        &mut self,
        id: EventId,
        stream: StreamId,
        compacts: &frasil_units::body::Compacts,
        excluded: &[EventId],
        cover: BTreeSet<[u8; 32]>,
    ) -> bool {
        if !self.may_use_snapshot(&id, &stream, compacts) {
            return false;
        }
        {
            let Some(type_) = self.streams.get(&stream).map(|r| r.adapter_type()) else {
                return false;
            };
            let Some(bytes) = self.object_or_want(&compacts.object) else {
                return false;
            };
            // Bytes that do not hash to the locator the unit names are not
            // its object, and no fault of its author: they are dropped and
            // the object is fetched again (units.md, "Sync", objects).
            if !self.is_object(&compacts.object, &bytes) {
                return false;
            }
            let Ok(checked) = frasil_units::objects::check_stored(&bytes, &compacts.object) else {
                self.bad_compactions.insert(id);
                return false;
            };
            let Some((key, _)) = self.object_key(&checked.header.key_reference) else {
                return false;
            };
            let Ok(plaintext) = frasil_units::objects::read_object(
                &bytes,
                &self.space,
                Some(&key),
                &compacts.object,
            ) else {
                self.bad_compactions.insert(id);
                return false;
            };
            let Ok(snapshot) =
                frasil_units::snapshot::StreamSnapshot::read(&plaintext, &stream, type_)
            else {
                self.bad_compactions.insert(id);
                return false;
            };
            let excluded: BTreeSet<[u8; 32]> = excluded.iter().map(|x| x.0).collect();
            let supersedes = self
                .log
                .as_ref()
                .and_then(|log| log.event(id))
                .and_then(|event| Unit::from_event(event.clone()).ok())
                .map(|unit| unit.body.supersedes)
                .unwrap_or_default();
            if let Some(runtime) = self.streams.get_mut(&stream)
                && runtime.use_snapshot(snapshot.state, cover, excluded, supersedes)
            {
                self.used_snapshots.insert(id);
                self.bases.insert(stream, id);
                self.checked_snapshots.remove(&id);
                true
            } else {
                self.bad_compactions.insert(id);
                false
            }
        }
    }

    /// Whether a snapshot unit's content was accepted (units.md, "Checking,
    /// using and settling a snapshot", "Using"): the unit was handed to its
    /// stream, valid by the write rule, and its adapter applied it. A unit
    /// that failed `WrongStream` or the stream check was never handed; one
    /// whose content the adapter refused, or ignored, shows so; one the
    /// stream's base includes was not handed over, and is older than it.
    fn snapshot_accepted(&self, id: &EventId) -> bool {
        self.handed.get(id).is_some_and(|handed| handed.valid)
            && !self.unreached.contains_key(id)
            && matches!(
                self.content_outcome(id),
                Some(ContentOutcome::Applied | ContentOutcome::Waiting(_))
            )
    }

    /// Whether a stream may load this snapshot's state: its content was
    /// accepted, and, for a seed, the stream uses no snapshot whose cover
    /// is not empty. A seed covers nothing, so its state stands in for no
    /// unit ("Using": "in place of the units it covers").
    fn may_use_snapshot(
        &self,
        id: &EventId,
        stream: &StreamId,
        compacts: &frasil_units::body::Compacts,
    ) -> bool {
        let seed_over_base = compacts.covers.is_empty()
            && self
                .streams
                .get(stream)
                .is_some_and(|runtime| !runtime.base_cover().is_empty());
        self.snapshot_accepted(id) && !seed_over_base
    }

    /// Stops using each snapshot whose unit is now refused, by the write
    /// rule or as content (units.md, "Checking, using and settling a
    /// snapshot", "Using"; "Rebuilds"): it is no longer used or checked,
    /// and a stream whose base it is drops that state and rebuilds from the
    /// units it holds. A snapshot whose unit is not handed over, as one the
    /// stream's base includes, is left as it is.
    fn drop_refused_snapshots(&mut self) {
        let refused: Vec<EventId> = self
            .used_snapshots
            .iter()
            .chain(self.checked_snapshots.keys())
            .filter(|id| {
                self.handed.get(id).is_some_and(|handed| {
                    !handed.valid
                        || self.unreached.contains_key(id)
                        || matches!(
                            self.content_outcome(id),
                            Some(ContentOutcome::Refused(_) | ContentOutcome::Counted)
                        )
                })
            })
            .copied()
            .collect();
        for id in refused {
            self.used_snapshots.remove(&id);
            self.checked_snapshots.remove(&id);
            self.stable_snapshots.remove(&id);
            let based: Vec<StreamId> = self
                .bases
                .iter()
                .filter(|(_, base)| **base == id)
                .map(|(stream, _)| *stream)
                .collect();
            for stream in based {
                self.bases.remove(&stream);
                if let Some(runtime) = self.streams.get_mut(&stream) {
                    runtime.drop_snapshot();
                }
            }
        }
    }

    /// Uses a checked snapshot whose cover this replica holds (units.md,
    /// "Checking, using and settling a snapshot"): its state in place of
    /// the cover, as a replica that holds none would, so that the cover can
    /// be collected. `true` once the stream uses it.
    pub(crate) fn use_checked_snapshot(&mut self, id: EventId) -> bool {
        let Some((stream, compacts, excluded, _)) = self.checked_snapshots.get(&id).cloned() else {
            return false;
        };
        let Some(log) = self.log.as_ref() else {
            return false;
        };
        let of = |x: EventId| crate::compaction::stream_of(log, x);
        let mut cover: BTreeSet<[u8; 32]> =
            frasil_units::compaction::cover_set(log, of, &compacts.covers, &stream)
                .into_iter()
                .map(|x| x.0)
                .collect();
        cover.extend(compacts.covers.iter().map(|pair| pair.unit.0));
        cover.extend(compacts.stubs.iter().map(|stub| stub.id.0));
        self.load_snapshot(id, stream, &compacts, &excluded, cover)
    }

    /// Checked snapshots whose cover this replica holds, not yet used.
    pub(crate) fn checked_snapshots(&self) -> impl Iterator<Item = &EventId> {
        self.checked_snapshots.keys()
    }

    /// Whether a checked or used snapshot is stable in the merged view.
    pub(crate) fn is_stable_snapshot(&self, id: &EventId) -> bool {
        self.stable_snapshots.contains(id)
    }

    // -- What the device reads

    /// An event's status at the last refresh.
    pub fn status(&self, id: &EventId) -> Option<&Status> {
        self.statuses.get(id)
    }

    /// The roster events void as `HigherRank` at the last refresh: attempts
    /// on an administrator of a higher rank, or grants above the author's
    /// own (roster.md, 3.6 Authority at the place), each with its author.
    pub(crate) fn rank_attempts(&self) -> Vec<(EventId, DeviceId)> {
        let higher = frasil_space::RosterClass::from(frasil_space::SpaceClass::HigherRank);
        let Some(log) = self.log.as_ref() else {
            return Vec::new();
        };
        self.statuses
            .iter()
            .filter(|(_, status)| status.class() == Some(higher))
            .filter_map(|(id, _)| log.event(*id).map(|event| (*id, *event.author())))
            .collect()
    }

    /// Why the space could not be resolved at the last refresh, if it
    /// could not: the genesis waits for its root (`NoTwin`), or cannot be
    /// used.
    pub fn unresolved(&self) -> Option<RosterClass> {
        self.unresolved
    }

    /// The roster of the merged view.
    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    /// The space policy of the merged view.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The valid events of the last refresh.
    pub fn valid(&self) -> &BTreeSet<EventId> {
        &self.valid
    }

    /// The space's system stream, once the genesis is opened.
    pub fn system_stream(&self) -> Option<StreamId> {
        self.system_stream
    }

    /// The current content state.
    pub fn current(&self) -> Option<&RotationSet> {
        if self.current.is_none() {
            return self.bootstrap.as_ref().map(|(state, _)| state);
        }
        self.current.as_ref()
    }

    /// The current grant state.
    pub fn grant_current(&self) -> Option<&RotationSet> {
        self.grant_current.as_ref()
    }

    /// The kind of space the application made it, as its descriptor names
    /// it (roster.md, "The space descriptor").
    pub(crate) fn application(&self) -> Option<&str> {
        self.application.as_deref()
    }

    /// Whether this device has been a member of the space since the
    /// replica was loaded.
    pub(crate) fn was_member(&self) -> bool {
        self.was_member
    }

    /// Whether this device presents its upload credentials to peers: it
    /// writes, or it was a member and is one no longer, so that what it
    /// signed before it left, its own removal among them, still reaches a
    /// peer. A peer does not judge membership; replicas judge what it
    /// stored (overview.md, "A removed member").
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) fn uploads(&self, me: &DeviceId) -> bool {
        match self.level_of(me) {
            Some(level) => level >= Level::Write,
            None => self.was_member,
        }
    }

    /// A device's level in the merged view: its highest through every
    /// path (roster.md, "Grants of spaces and effective membership").
    pub fn level_of(&self, device: &DeviceId) -> Option<Level> {
        self.effective.get(&device.0).map(|(level, _)| *level)
    }

    /// A device's capabilities in the merged view: those of its strongest
    /// path, merged as roster.md's "Grants of spaces and effective
    /// membership" merges them, over the paths of the current view
    /// (ext-ephemeral.md, 3.5 "Capability checks"). None for a device that
    /// does not reach the space.
    pub fn capabilities_of(&self, device: &DeviceId) -> Capabilities {
        self.frame_capabilities(device).unwrap_or_default()
    }

    /// A frame sender's capabilities in the merged view, as
    /// [`capabilities_of`](Self::capabilities_of) finds them; `None` when
    /// no path of the current view is found. A frame from a sender found in
    /// with no such path is refused (`CapabilityRefused`), never checked as
    /// an unnarrowed writer's (units.md, 3.17 "Capability checks").
    pub fn frame_capabilities(&self, device: &DeviceId) -> Option<Capabilities> {
        self.facts
            .as_ref()
            .and_then(|facts| facts.reach(&device.0, PathsFor::Current))
            .map(|reach| capabilities_from(Some(&reach)))
    }

    /// Whether a device propagates in the merged view.
    pub fn propagates(&self, device: &DeviceId) -> bool {
        self.effective
            .get(&device.0)
            .is_some_and(|(_, propagating)| propagating.is_some())
    }

    /// The keys the log's opened records name, valid or void (crypto.md,
    /// "Keys by their hash").
    pub(crate) fn found_keys(&self) -> &KeyRing {
        &self.found_keys
    }

    /// How many times a refresh resolved the view in full, for tests.
    #[cfg(all(test, feature = "adapter-loro"))]
    pub(crate) fn full_resolutions(&self) -> usize {
        self.full_resolutions
    }

    /// Whether an event of the view waits for keys that hash to its `kc`.
    pub(crate) fn awaits_keys(&self) -> bool {
        self.awaits_keys
    }

    /// Notes the space snapshot adopted, while it is provisional.
    pub(crate) fn set_provisional_snapshot(&mut self, signed: Option<Vec<u8>>) {
        self.provisional_snapshot = signed;
    }

    /// Whether the snapshot this replica adopted is still provisional.
    pub fn snapshot_provisional(&self) -> bool {
        self.provisional_snapshot.is_some()
    }

    /// Notes the sender of the space snapshot adopted, checked once the
    /// view grants this device.
    pub(crate) fn set_snapshot_sender(&mut self, sender: Option<DeviceId>) {
        self.snapshot_sender = sender;
    }

    /// Whether the space snapshot this replica started from is not yet
    /// attributed: its ML-DSA-65 half waits for keys, or the view does not
    /// yet show its sender reaching the space. Until it is, nothing the
    /// snapshot handed goes out under this device's name: no compaction
    /// and no snapshot for another newcomer.
    pub fn snapshot_unconfirmed(&self) -> bool {
        self.provisional_snapshot.is_some() || self.snapshot_sender.is_some()
    }

    /// Checks the adopted snapshot's sender once the view grants `me`
    /// (units.md, "The space snapshot", "Using it"): a sender that reaches
    /// the space confirms it; one that does not was not entitled to hand
    /// the space over, and the base is discarded. Returns whether it was.
    pub(crate) fn check_snapshot_sender(&mut self, me: &DeviceId) -> bool {
        let Some(sender) = self.snapshot_sender else {
            return false;
        };
        if self.level_of(me).is_none() {
            return false;
        }
        if self.level_of(&sender).is_some() {
            self.snapshot_sender = None;
            return false;
        }
        self.discard_base();
        true
    }

    /// Discards the base a space snapshot gave, and what came with it, and
    /// waits for a member's snapshot again: the log is built again from
    /// the events it holds, without the base's stubs; the streams loaded
    /// from the snapshot's entries drop that state; the entries not yet
    /// loaded are forgotten.
    pub(crate) fn discard_base(&mut self) {
        self.provisional_snapshot = None;
        self.snapshot_sender = None;
        self.snapshot_to_keep = None;
        self.awaited_snapshot = None;
        self.wants_snapshot = true;
        if self.base.take().is_none() {
            return;
        }
        self.contradicted_base.clear();
        self.pending_streams.clear();
        for stream in std::mem::take(&mut self.snapshot_streams) {
            if let Some(runtime) = self.streams.get_mut(&stream) {
                runtime.drop_snapshot();
            }
        }
        self.rebuild_log(Vec::new());
        self.base_discarded = true;
    }

    /// Whether the base was discarded since the last call: the device then
    /// stores the log's state without it.
    pub(crate) fn take_base_discarded(&mut self) -> bool {
        std::mem::take(&mut self.base_discarded)
    }

    /// Verifies again every placed event of the log whose ML-DSA-65 half
    /// waited for keys, with the keys `ring` holds (events.md, "The
    /// ML-DSA-65 half"). Returns whether any changed.
    pub(crate) fn verify_pending_hybrid(&mut self, ring: &KeyRing) -> bool {
        self.log
            .as_mut()
            .is_some_and(|log| !log.verify_pending_hybrid(ring).is_empty())
    }

    /// Reads the provisional snapshot again under `keys`: `None` when the
    /// replica holds none.
    pub(crate) fn read_provisional_snapshot(&self, keys: &impl KeySource) -> Option<SnapshotCheck> {
        let signed = self.provisional_snapshot.as_ref()?;
        Some(
            match frasil_units::snapshot::SpaceSnapshot::read(signed, &self.space, keys) {
                Ok(frasil_units::snapshot::ReadSnapshot::Provisional(_)) => {
                    SnapshotCheck::Provisional
                }
                Ok(frasil_units::snapshot::ReadSnapshot::Verified(_)) => SnapshotCheck::Verified,
                Err(_) => SnapshotCheck::Failed,
            },
        )
    }

    /// Applies [`read_provisional_snapshot`](Self::read_provisional_snapshot):
    /// a snapshot that verifies is no longer provisional; one whose half
    /// fails was never its sender's: its base is discarded, and the replica
    /// asks a member for another snapshot (units.md, "The space snapshot",
    /// "Using it").
    pub(crate) fn apply_provisional_snapshot(&mut self, outcome: Option<SnapshotCheck>) {
        match outcome {
            None | Some(SnapshotCheck::Provisional) => {}
            Some(SnapshotCheck::Verified) => self.provisional_snapshot = None,
            Some(SnapshotCheck::Failed) => self.discard_base(),
        }
    }

    /// The devices that reach the space, with their levels: its effective
    /// membership.
    pub fn devices(&self) -> Vec<(DeviceId, Level)> {
        self.effective
            .iter()
            .map(|(device, (level, _))| (DeviceId(*device), *level))
            .collect()
    }

    /// Whether a device reaches the space through a person the roster
    /// grants, as the lists vouch.
    pub(crate) fn reaches_through_person(&self, device: &DeviceId) -> bool {
        self.roster
            .members_in()
            .any(|(member, _)| member.kind == MemberType::Person)
            && self.level_of(device).is_some()
            && self.roster.state(&MemberRef::device(*device)).is_none()
    }

    /// Whether a device was vouched for by the list of a person the roster
    /// names, and is no longer: revoked from it.
    pub(crate) fn ended_through_list(
        &self,
        device: &DeviceId,
        lists: &BTreeMap<[u8; 32], crate::lists::PersonList>,
    ) -> bool {
        self.roster.iter().any(|(member, _)| {
            member.kind == MemberType::Person
                && lists.get(&member.id).is_some_and(|list| {
                    let merged = list.merge();
                    merged.member(device).is_some() && merged.active(device).is_none()
                })
        })
    }

    /// Who wrote a valid unit, as the roster and the lists held at its
    /// place; `None` for a unit this replica did not judge by the full
    /// write rule.
    #[cfg_attr(
        not(any(feature = "adapter-loro", feature = "adapter-records")),
        allow(dead_code)
    )]
    pub(crate) fn authorship(&self, unit: &EventId) -> Option<&Authorship> {
        self.authorship.get(unit)
    }

    /// Signed list events retained in system-stream copies, including a
    /// list's forgotten past.
    pub(crate) fn copied_list_events(&self) -> Vec<Event> {
        let Some(log) = &self.log else {
            return Vec::new();
        };
        let opened = lock(&self.unit_reads.opened);
        log.canonical()
            .into_iter()
            .filter_map(|id| {
                let inner = opened.get(&id)?;
                if inner.type_ != frasil_units::types::LIST {
                    return None;
                }
                let unit = self.unit_reads.unit(log.event(id)?).ok()?;
                if Some(unit.body.stream) != self.system_stream {
                    return None;
                }
                frasil_units::own::read_list_copy(&inner.content).ok()
            })
            .flatten()
            .collect()
    }

    /// List events whose copies are at the snapshot's base.
    pub(crate) fn lists_at_base(&self, heads: &[EventId]) -> BTreeSet<EventId> {
        let Some(log) = &self.log else {
            return BTreeSet::new();
        };
        let mut events = self
            .base
            .as_ref()
            .map(|base| base.lists.clone())
            .unwrap_or_default();
        for (copy, inner) in lock(&self.unit_reads.opened).iter() {
            if inner.type_ != frasil_units::types::LIST {
                continue;
            }
            if !heads.iter().any(|head| {
                copy == head
                    || log.precedes(*copy, *head)
                    || (self.frozen_content.contains_key(copy)
                        && self.checkpoints.kept.as_ref().is_some_and(|kept| {
                            kept.checkpoint == *head || log.precedes(kept.checkpoint, *head)
                        }))
            }) {
                continue;
            }
            if log
                .event(*copy)
                .and_then(|event| self.unit_reads.unit(event).ok())
                .is_none_or(|unit| Some(unit.body.stream) != self.system_stream)
            {
                continue;
            }
            if let Ok(carried) = frasil_units::own::read_list_copy(&inner.content) {
                events.extend(carried.iter().map(Event::id));
            }
        }
        events
    }

    /// The list events this space's `frasil:list` units carry.
    pub(crate) fn list_copies_held(&self) -> BTreeSet<EventId> {
        self.list_copies.clone()
    }

    /// The contents of the valid units of the system stream, of one of
    /// Frasil's own types, that this device opens, in canonical order: such
    /// as a personal space's recovery entries (identity.md, "Fetch keys and
    /// recovery entries").
    pub(crate) fn system_contents(&self, type_: &str) -> Vec<Vec<u8>> {
        let (Some(log), Some(system)) = (self.log.as_ref(), self.system_stream) else {
            return Vec::new();
        };
        let keyring = self.keyring();
        let rotations = Rotations {
            log,
            parts: &self.visible_parts,
            kept: Some(&self.secrets),
        };
        let keys = KeyringKeys {
            keyring: &keyring,
            log: &rotations,
        };
        let mut out = Vec::new();
        for id in log.canonical() {
            if !self.status(&id).is_some_and(Status::is_valid) {
                continue;
            }
            let Some(event) = log.event(id) else {
                continue;
            };
            if event.kind() != kind::UNIT {
                continue;
            }
            let Ok(unit) = self.unit_reads.unit(event) else {
                continue;
            };
            if unit.body.stream != system {
                continue;
            }
            let Ok(inner) = self.unit_reads.open(&unit, &keys, Some(&system)) else {
                continue;
            };
            if inner.type_ == type_ {
                out.push(inner.content.to_vec());
            }
        }
        out
    }

    /// This device's own units the checkpoint in effect makes late, in
    /// canonical order, each with its stream and the sealed part of the
    /// unit that re-submits it (roster.md, 3.15.1 and 3.15.7; units.md,
    /// 3.11, "Re-submission"). A unit already re-submitted, by a unit of
    /// this device whose `resubmits` names it or that carries the same
    /// `copied_from`, is left out, as is a snapshot unit and one this
    /// replica cannot open.
    pub(crate) fn late_units_to_resubmit(&self, me: &DeviceId) -> Vec<LateUnitAgain> {
        let (Some(log), Some(c)) = (self.log.as_ref(), self.checkpoints.facts.last()) else {
            return Vec::new();
        };
        // A unit kept of a forgotten past has its frozen verdict: its
        // ancestry runs through dropped events, so the log cannot tell that
        // it precedes the checkpoint, but it is not late.
        let mut late = frasil_units::late::late_units(log, c);
        late.retain(|late| !self.kept_frozen(log, &late.unit));
        if late.is_empty() {
            return Vec::new();
        }
        let order = frasil_units::late::resubmission_order(log, me, &late);
        self.units_to_resubmit(me, order, |id| log.follows(id, c) == Ok(true))
    }

    /// This device's own units refused by a removal or after a response
    /// (`RefusedByRemoval`, `RefusedAfterResponse`), or as `NotAWriter`,
    /// that some events void (roster.md, 3.14, "Re-submission"), in
    /// canonical order, each with the sealed part of the unit that
    /// re-submits it, leaving out one this device re-submitted already. A
    /// replica that forgot reads the voiding events from what it froze.
    pub(crate) fn refused_units_to_resubmit(&self, me: &DeviceId) -> Vec<LateUnitAgain> {
        let Some(log) = self.log.as_ref() else {
            return Vec::new();
        };
        let classes = [
            frasil_space::RosterClass::from(frasil_space::SpaceClass::RefusedByRemoval),
            frasil_space::RosterClass::from(frasil_space::SpaceClass::RefusedAfterResponse),
            frasil_space::RosterClass::from(frasil_space::SpaceClass::NotAWriter),
        ];
        // Exactly those some events void: a `NotAWriter` unit whose author
        // held there no grant an event voided was never a writer's.
        let order: Vec<EventId> = log
            .canonical()
            .into_iter()
            .filter(|&id| {
                log.event(id)
                    .is_some_and(|e| e.kind() == kind::UNIT && e.author() == me)
            })
            .filter(|id| {
                self.statuses
                    .get(id)
                    .and_then(Status::class)
                    .is_some_and(|class| classes.contains(&class))
                    && !self.unit_voiders(id).is_empty()
            })
            .collect();
        if order.is_empty() {
            return Vec::new();
        }
        self.units_to_resubmit(me, order, |_| true)
    }

    /// The re-submissions of `order`, this device's own units: each opened
    /// and given `resubmits`, but those an own unit for which `counts`
    /// holds re-submitted already.
    fn units_to_resubmit(
        &self,
        me: &DeviceId,
        order: Vec<EventId>,
        counts: impl Fn(EventId) -> bool,
    ) -> Vec<LateUnitAgain> {
        let Some(log) = self.log.as_ref() else {
            return Vec::new();
        };
        let keyring = self.keyring();
        let rotations = Rotations {
            log,
            parts: &self.visible_parts,
            kept: Some(&self.secrets),
        };
        let keys = KeyringKeys {
            keyring: &keyring,
            log: &rotations,
        };
        let open = |id: EventId| -> Option<(Arc<Unit>, Arc<frasil_units::Inner>)> {
            let event = log.event(id)?;
            let unit = self.unit_reads.unit(event).ok()?;
            let inner = self
                .unit_reads
                .open_whole(&unit, &keys, self.system_stream.as_ref())
                .ok()?;
            Some((unit, inner))
        };
        // What this device re-submitted already.
        let mut resubmitted: BTreeSet<EventId> = BTreeSet::new();
        let mut copied: BTreeSet<(EventId, EventId)> = BTreeSet::new();
        for id in log.chain(me) {
            if !counts(id) {
                continue;
            }
            if log.event(id).is_none_or(|event| event.kind() != kind::UNIT) {
                continue;
            }
            if let Some((_, inner)) = open(id) {
                resubmitted.extend(inner.resubmits);
                copied.extend(inner.copied_from.iter().map(|c| (c.space, c.event)));
            }
        }
        let mut out = Vec::new();
        for id in order {
            if resubmitted.contains(&id) {
                continue;
            }
            let Some((unit, inner)) = open(id) else {
                continue;
            };
            if inner
                .copied_from
                .as_ref()
                .is_some_and(|c| copied.contains(&(c.space, c.event)))
            {
                continue;
            }
            let snapshot = unit.is_snapshot();
            if let Some(inner) = frasil_units::late::resubmission(&inner, id, snapshot) {
                out.push(LateUnitAgain {
                    stream: unit.body.stream,
                    inner,
                    objects: unit.body.objects.to_vec(),
                });
            }
        }
        out
    }

    /// Forgets what came before the last checkpoint in effect (roster.md,
    /// 3.15.6 Forgetting): once the replica judged that checkpoint on its
    /// whole past, it drops the frame events of that past and keeps what the
    /// text lists: the genesis, the checkpoint and its cut, the envelopes of
    /// the checkpoints its cuts reach, the late events whole, every event
    /// after it, the roots and enrolments the cut names, the releases and
    /// restores of its past, and the units, whose content is the streams'
    /// and whose verdicts it holds as it decided them. A dropped event
    /// another kept event cites keeps its height, on which that event is
    /// placed (events.md, "Placement and order"); every dropped ID is kept.
    /// `None` when no checkpoint is in effect, the replica keeps it already,
    /// or it lacks its record; and when an event of the past is in `keep`,
    /// which names this device's own events not yet durable.
    pub(crate) fn forget_past(&mut self, keep: &BTreeSet<EventId>) -> Option<Forgotten> {
        // Never while the chain may still move to a smaller concurrent
        // checkpoint, nor while a rival is held (roster.md, 3.15.4, 3.15.6).
        if self.checkpoints.facts.contested || !self.checkpoints.facts.rivals.is_empty() {
            return None;
        }
        let c = self.checkpoints.facts.last()?;
        if self
            .checkpoints
            .kept
            .as_ref()
            .is_some_and(|kept| kept.checkpoint == c)
        {
            return None;
        }
        let record = self.checkpoints.records.get(&c)?.clone();
        let log = self.log.as_ref()?;
        let genesis = log.id();
        let checkpoint = log.event(c)?;
        let twin = checkpoint.parents().iter().copied().find(|p| {
            log.event(*p)
                .is_some_and(frasil_space::checkpoint::is_skeleton_cut)
        });
        let reached = log.cuts_reach(c).ok()?;
        let mut kept: BTreeSet<EventId> = BTreeSet::from([genesis, c]);
        kept.extend(twin);
        // Of the releases and restores of the checkpoint's past that name a
        // stream, only the maximal ones of each stream are kept, found
        // before anything is dropped: one another follows decides nothing
        // once the checkpoint is in effect, and without what lies between
        // them the replica could no longer order them (roster.md, 3.15.6,
        // "What must be kept").
        let superseded: BTreeSet<EventId> = {
            use frasil_peers::body::{Restored, StorageBody};
            let mut by_stream: BTreeMap<[u8; 16], Vec<EventId>> = BTreeMap::new();
            for event in log.events() {
                if event.kind() != kind::STORAGE || !log.precedes(event.id(), c) {
                    continue;
                }
                if let Ok(
                    StorageBody::Release { stream }
                    | StorageBody::Restore(Restored::Stream(stream)),
                ) = StorageBody::read(event.unverified_body())
                {
                    by_stream.entry(stream).or_default().push(event.id());
                }
            }
            by_stream
                .values()
                .flat_map(|requests| {
                    requests
                        .iter()
                        .copied()
                        .filter(|&x| requests.iter().any(|&y| y != x && log.precedes(x, y)))
                })
                .collect()
        };
        let mut frozen = BTreeMap::new();
        let mut content = Vec::new();
        // The checkpoint's own cut is of its past: kept with its verdict,
        // never judged again (roster.md, 3.15.6, "What must be kept").
        if let Some(twin) = twin
            && let Some(status) = self.statuses.get(&twin)
        {
            frozen.insert(twin, *status);
        }
        let mut dropped = Vec::new();
        for id in log.canonical() {
            if kept.contains(&id) {
                continue;
            }
            let event = log.event(id)?;
            if !log.precedes(id, c) {
                // After the checkpoint, or late: kept whole.
                kept.insert(id);
                continue;
            }
            if event.kind() == kind::UNIT
                || (crate::checkpoints::kept_storage(event) && !superseded.contains(&id))
            {
                kept.insert(id);
                if let Some(status) = self.statuses.get(&id) {
                    frozen.insert(id, *status);
                }
                if event.kind() == kind::UNIT && !self.frozen_content.contains_key(&id) {
                    content.push(id);
                }
                continue;
            }
            if keep.contains(&id) {
                return None;
            }
            dropped.push(id);
        }
        if dropped.is_empty() {
            return None;
        }
        let mut new = Log::new(log.genesis().clone()).ok()?;
        let mut order: Vec<(u64, EventId)> = kept
            .iter()
            .filter(|&&id| id != genesis)
            .map(|&id| (log.height(id).unwrap_or(0), id))
            .collect();
        order.sort_unstable();
        // The stubs the log held already: a snapshot's base.
        let stubs: BTreeMap<EventId, frasil_events::Stub> =
            log.stubs().map(|stub| (stub.id, *stub)).collect_map();
        for stub in stubs.values() {
            new.add_stub(*stub);
        }
        // A dropped parent of a kept event keeps its height, and nothing
        // else (events.md, "Placement and order").
        let mut heights: BTreeMap<EventId, u64> = BTreeMap::new();
        for (_, id) in &order {
            let event = log.event(*id)?;
            for parent in event.parents() {
                if kept.contains(parent) || stubs.contains_key(parent) {
                    continue;
                }
                let Some(height) = log.event(*parent).and(log.height(*parent)) else {
                    continue;
                };
                let height = height.max(1);
                new.mark_dropped_at(*parent, height);
                heights.insert(*parent, height);
            }
            let _ = new.place(event.clone());
        }
        for id in &reached {
            if let Some(event) = log.event(*id)
                && !kept.contains(id)
            {
                let _ = new.keep_envelope(event.clone());
            }
        }
        // What each dropped event's `dropped` record keeps: its kind, and
        // for a parent of a kept event its height.
        for id in &dropped {
            let Some(kind) = log.event(*id).map(Event::kind) else {
                continue;
            };
            self.checkpoints.dropped_origins.insert(
                *id,
                frasil_store::tables::DroppedOrigin::Held {
                    kind,
                    height: heights.get(id).copied(),
                },
            );
        }
        for id in &dropped {
            new.mark_dropped(*id);
            self.statuses.remove(id);
            self.verified.remove(id);
            self.first_sight.remove(id);
            self.opened_bodies.remove(id);
        }
        self.log = Some(new);
        self.appendable = None;
        self.citable = None;
        self.changed_log = true;
        self.changed_for_others = true;
        self.checkpoints.kept = Some(frasil_space::Kept {
            checkpoint: c,
            record,
        });
        self.checkpoints.kept_id = Some(c);
        self.checkpoints.frozen.extend(frozen);
        // What the space froze of each kept unit at its place, with what its
        // adapter made of the content there (units.md, "The past of a kept
        // checkpoint").
        let frozen_units = match &self.checkpoints.facts.frozen_units {
            Some((at, units)) if *at == c => units.clone(),
            _ => BTreeMap::new(),
        };
        let mut newly = Vec::new();
        for id in content {
            let Some(unit) = frozen_units.get(&id) else {
                continue;
            };
            let frozen =
                frasil_units::frozen::Frozen::of(unit, self.refused_content.get(&id).copied());
            self.frozen_content.insert(id, frozen.clone());
            newly.push((id, frozen));
        }
        self.checkpoints.freeze = None;
        Some(Forgotten {
            checkpoint: c,
            dropped,
            frozen: newly,
        })
    }

    /// Starts from the checkpoint a space snapshot names (roster.md, 3.15.6,
    /// "Starting from a checkpoint"; units.md, "The space snapshot", keys
    /// 12 to 14): the replica keeps the envelopes of the checkpoints its
    /// cuts reach, reads its record with the object key handed over, and
    /// takes it as its kept checkpoint once it is in effect in what it holds
    /// after it.
    /// Takes at load the checkpoint a newcomer started from, by its
    /// `state` key 7 (at-rest.md, "Starting from a checkpoint"): kept once
    /// its record reads with the record key restored beside it.
    pub(crate) fn start_from_kept(&mut self, checkpoint: EventId) {
        self.checkpoints.kept_id = Some(checkpoint);
    }

    pub(crate) fn start_from_checkpoint(
        &mut self,
        checkpoint: EventId,
        record_key: [u8; 32],
        envelopes: Vec<Event>,
    ) {
        self.checkpoints.kept_id = Some(checkpoint);
        self.checkpoints
            .object_keys
            .insert(checkpoint, Zeroizing::new(record_key));
        match &mut self.log {
            Some(log) => {
                for event in envelopes {
                    let _ = log.keep_envelope(event);
                }
            }
            None => self.checkpoints.envelopes.extend(envelopes),
        }
    }

    /// Takes a peer's `Missing` for events a replica that starts from a
    /// checkpoint waits for: the peer truncated them, so each is a parent in
    /// the checkpoint's past, kept as dropped (roster.md, 3.15.6). Returns
    /// the events placed.
    pub(crate) fn drop_truncated(&mut self, ids: &[EventId]) -> Vec<EventId> {
        if self.checkpoints.kept_id.is_none() {
            return Vec::new();
        }
        let Some(log) = self.log.as_mut() else {
            return Vec::new();
        };
        let wanted: BTreeSet<EventId> = log.wanted().into_iter().collect();
        let mut placed = Vec::new();
        for id in ids {
            if !wanted.contains(id) || log.contains(*id) || log.stub(*id).is_some() {
                continue;
            }
            placed.extend(log.drop_parent(*id));
        }
        placed
    }

    /// What the log's `state` record keeps of its checkpoints beside key 7
    /// (`frasil_store::checkpoint_state`): the record object keys a
    /// snapshot handed over, every event the replica dropped, and the
    /// envelopes of the checkpoints its kept checkpoint's cuts reach.
    pub(crate) fn checkpoint_state(&self) -> frasil_store::checkpoint_state::CheckpointState {
        use frasil_store::checkpoint_state::Dropped;
        use frasil_store::tables::DroppedOrigin;
        let record_keys = self
            .checkpoints
            .object_keys
            .iter()
            .map(|(c, key)| (c.0, frasil_store::tables::Secret::new(**key)))
            .collect();
        // An event held as a stub was dropped by this device, with its
        // kind; one without was answered `Missing` (at-rest.md, the
        // `dropped` table).
        let (mut dropped, kept_envelopes): (Vec<Dropped>, Vec<Vec<u8>>) = match self.log.as_ref() {
            Some(log) => (
                log.dropped_ids()
                    .map(|id| Dropped {
                        id: id.0,
                        origin: self
                            .checkpoints
                            .dropped_origins
                            .get(&id)
                            .copied()
                            .unwrap_or_else(|| {
                                log.stub(id).map_or(DroppedOrigin::Missing, |stub| {
                                    DroppedOrigin::Held {
                                        kind: stub.kind,
                                        height: None,
                                    }
                                })
                            }),
                    })
                    .collect(),
                log.kept_envelopes().map(Event::signed).collect(),
            ),
            // Before the genesis is placed: what waits to be taken.
            None => (
                Vec::new(),
                self.checkpoints
                    .envelopes
                    .iter()
                    .map(Event::signed)
                    .collect(),
            ),
        };
        dropped.extend(self.checkpoints.restored_dropped.iter().map(|id| {
            Dropped {
                id: id.0,
                origin: self
                    .checkpoints
                    .dropped_origins
                    .get(id)
                    .copied()
                    .unwrap_or_else(|| {
                        self.log.as_ref().and_then(|log| log.stub(*id)).map_or(
                            DroppedOrigin::Missing,
                            |stub| DroppedOrigin::Held {
                                kind: stub.kind,
                                height: None,
                            },
                        )
                    }),
            }
        }));
        dropped.sort_by_key(|d| d.id);
        dropped.dedup_by_key(|d| d.id);
        frasil_store::checkpoint_state::CheckpointState {
            record_keys,
            dropped,
            kept_envelopes,
        }
    }

    /// Takes, at load, what the log's `state` record keeps of its
    /// checkpoints ([`Self::checkpoint_state`]). A replica that started
    /// from a checkpoint a snapshot named and has not forgotten since
    /// (no key 7) keeps that checkpoint again, read with the record key the
    /// snapshot handed over. The dropped IDs are taken once the log's
    /// events are placed ([`Self::take_restored_dropped`]).
    pub(crate) fn restore_checkpoint_state(
        &mut self,
        forgot: bool,
        restored: frasil_store::checkpoint_state::CheckpointState,
    ) {
        let envelopes: Vec<Event> = restored
            .kept_envelopes
            .iter()
            .filter_map(|signed| frasil_events::decode(signed).ok())
            .collect();
        for (c, key) in &restored.record_keys {
            self.checkpoints
                .object_keys
                .insert(EventId(*c), Zeroizing::new(*key.expose()));
        }
        if !forgot
            && self.checkpoints.kept_id.is_none()
            && let Some((c, _)) = restored.record_keys.last()
        {
            self.checkpoints.kept_id = Some(EventId(*c));
        }
        match &mut self.log {
            Some(log) => {
                for event in envelopes {
                    let _ = log.keep_envelope(event);
                }
            }
            None => self.checkpoints.envelopes.extend(envelopes),
        }
        for dropped in &restored.dropped {
            self.checkpoints
                .dropped_origins
                .insert(EventId(dropped.id), dropped.origin);
        }
        self.checkpoints
            .restored_dropped
            .extend(restored.dropped.into_iter().map(|d| EventId(d.id)));
    }

    /// Whether the replica dropped events it held, by its `dropped`
    /// records: a log that forgot, rather than one that only started from a
    /// checkpoint.
    pub(crate) fn forgot_some(&self) -> bool {
        self.checkpoints
            .dropped_origins
            .values()
            .any(|origin| matches!(origin, frasil_store::tables::DroppedOrigin::Held { .. }))
    }

    /// Takes the dropped IDs read at load, once the log's events are
    /// placed: each is kept as dropped, at the height its `dropped` record
    /// keeps for a parent of a kept event (events.md, "Placement and
    /// order"), so that the kept events are placed at the heights they were
    /// judged at; a parent without one adds nothing to a height, as a
    /// peer's `Missing` made it (roster.md, 3.15.6). Returns the events
    /// that placed.
    pub(crate) fn take_restored_dropped(&mut self) -> Vec<EventId> {
        let ids = std::mem::take(&mut self.checkpoints.restored_dropped);
        if ids.is_empty() {
            return Vec::new();
        }
        let Some(log) = self.log.as_mut() else {
            self.checkpoints.restored_dropped = ids;
            return Vec::new();
        };
        let ids: Vec<EventId> = ids
            .into_iter()
            .filter(|&id| !log.contains(id) && log.witnessed(id).is_none())
            .collect();
        // Every height first, so that an event released by its last
        // dropped parent counts them all.
        for &id in &ids {
            match self.checkpoints.dropped_origins.get(&id) {
                Some(frasil_store::tables::DroppedOrigin::Held {
                    height: Some(height),
                    ..
                }) => log.mark_dropped_at(id, *height),
                _ => log.mark_dropped(id),
            };
        }
        let mut placed = Vec::new();
        for id in ids {
            placed.extend(log.release_dropped(id));
        }
        placed
    }

    /// Takes, at load, a log whose past before `checkpoint` this device
    /// forgot, and the verdicts its event records keep, which the replica
    /// holds for the events of that past it kept (roster.md, 3.15.6). The
    /// dropped parents its kept events cite are taken with their heights
    /// once the log's events are placed ([`Self::take_restored_dropped`]).
    pub(crate) fn set_forgotten(
        &mut self,
        checkpoint: EventId,
        recorded: BTreeMap<EventId, Status>,
    ) {
        self.checkpoints.kept_id = Some(checkpoint);
        self.checkpoints.recorded = recorded;
    }

    /// The space principals in force: each granted space, its grantee
    /// rotation, that rotation's grant key, and the space's level here.
    pub(crate) fn principals(
        &self,
    ) -> &[(
        EventId,
        EventId,
        Box<[u8; frasil_crypto::sizes::XWING_PUBLIC]>,
        Level,
    )] {
        &self.principals
    }

    /// Whether the author administered at this event's place. The caller
    /// also checks the event's verdict, since a void event grants nothing.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) fn authored_as_administrator(&self, event: &EventId) -> bool {
        self.administrator_authors.contains(event)
    }

    /// Whether this complete, fully opened direct-device-only log cannot
    /// change when another log changes. Keep the fast path conservative:
    /// units, foreign refs, held/void events and partial bases all opt out.
    pub(crate) fn independent_of_other_logs(&self) -> bool {
        #[cfg(feature = "partial-replicas")]
        if self.partial.is_some() {
            return false;
        }
        #[cfg(feature = "ext-restricted-spaces")]
        if self.restricted.parent.is_some() {
            return false;
        }
        self.base.is_none()
            && self.staged.is_empty()
            && self.undecided.is_empty()
            && self.unresolved.is_none()
            && self.refs_named.is_empty()
            && self.roster.members_in().all(|(member, state)| {
                member.kind == frasil_space::MemberType::Device && state.session.is_none()
            })
            && self.log.as_ref().is_some_and(|log| {
                log.pending().next().is_none()
                    && log.stubs().next().is_none()
                    && log.events().all(|event| match event.kind() {
                        kind::SPACE => {
                            matches!(self.statuses.get(&event.id()), Some(Status::Valid(_)))
                                && self.opened_bodies.contains_key(&event.id())
                        }
                        kind::STORAGE => true,
                        _ => false,
                    })
            })
    }

    /// The events of a log that the view's events name in their sealed
    /// refs.
    pub(crate) fn named_in(&self, log: &EventId) -> Vec<EventId> {
        self.refs_named
            .iter()
            .filter(|(l, _)| l == log)
            .map(|(_, id)| *id)
            .collect()
    }

    /// Keeps a member device's head statement (units.md, 3.13 "Head
    /// statements"): unless one kept of that device is shown no older, and
    /// in place of each kept one it shows older. A statement is shown
    /// older than another once the replica holds the other's heads and
    /// each of its own heads is among them or in their past. A device's
    /// heads only grow, but a receiver may lack a newer statement's heads,
    /// and a statement lists at most 256, so two statements are not always
    /// ordered: both are kept then, and a replayed older statement never
    /// takes a newer one's place. Returns whether it was kept.
    pub(crate) fn keep_statement(
        &mut self,
        statement: frasil_units::statement::HeadStatement,
    ) -> bool {
        use frasil_units::statement::HeadStatement;
        /// The most statements kept of one device.
        const KEPT: usize = 8;
        let log = self.log.as_ref();
        // Whether `older` is shown no newer than `newer`.
        let shown = |newer: &HeadStatement, older: &HeadStatement| {
            if newer.heads == older.heads {
                return true;
            }
            let Some(log) = log else {
                return false;
            };
            if !newer.heads.iter().all(|h| log.contains(*h)) {
                return false;
            }
            let past = crate::outbox::past_of(log, &newer.heads);
            older.heads.iter().all(|h| past.contains(h))
        };
        let kept = self
            .statements
            .entry(statement.device.device_id())
            .or_default();
        if kept.iter().any(|k| shown(k, &statement)) {
            return false;
        }
        kept.retain(|k| !shown(&statement, k));
        kept.push(statement);
        if kept.len() > KEPT {
            // One whose heads are all held tells nothing more to ask for:
            // it goes first, else the one kept longest.
            let held = log.and_then(|log| {
                kept.iter()
                    .position(|k| k.heads.iter().all(|h| log.contains(*h)))
            });
            kept.remove(held.unwrap_or(0));
        }
        true
    }

    /// The head statements kept of each member device, by device ID.
    pub fn statements(&self) -> &BTreeMap<DeviceId, Vec<frasil_units::statement::HeadStatement>> {
        &self.statements
    }

    /// The heads of a device's kept statements that the replica does not
    /// hold, to ask of that device (units.md, 3.13 "Head statements"). A
    /// partial replica asks for none: it fetches out of its frame and
    /// streams only what it witnesses.
    pub(crate) fn stated_lacking_of(&self, device: &DeviceId) -> Vec<EventId> {
        if self.partial.is_some() {
            return Vec::new();
        }
        let heads: BTreeSet<EventId> = self
            .statements
            .get(device)
            .into_iter()
            .flatten()
            .flat_map(|s| s.heads.iter().copied())
            .filter(|h| !self.holds(*h))
            .collect();
        heads.into_iter().collect()
    }

    /// Notes statements' heads asked of their authors: peers are asked for
    /// them too, once.
    pub(crate) fn note_stated_asked(&mut self, heads: &[EventId]) {
        self.stated_asked.extend(heads.iter().copied());
    }

    /// Statements' heads asked of their authors and still not held.
    pub(crate) fn stated_asked_lacking(&self) -> Vec<EventId> {
        self.stated_asked
            .iter()
            .copied()
            .filter(|h| !self.holds(*h))
            .collect()
    }

    /// Whether a head was asked of a statement's author.
    pub(crate) fn stated_asked(&self, head: &EventId) -> bool {
        self.stated_asked.contains(head)
    }

    /// Drops a device's statements that name any of these heads, which
    /// the device answered `Missing` for: junk (`BadStatement`). Returns
    /// the heads named.
    pub(crate) fn drop_statements_naming(
        &mut self,
        device: &DeviceId,
        ids: &[EventId],
    ) -> Vec<EventId> {
        let Some(kept) = self.statements.get_mut(device) else {
            return Vec::new();
        };
        let mut named: BTreeSet<EventId> = BTreeSet::new();
        kept.retain(|s| {
            let hit: Vec<EventId> = s
                .heads
                .iter()
                .copied()
                .filter(|h| ids.contains(h))
                .collect();
            named.extend(hit.iter().copied());
            hit.is_empty()
        });
        if kept.is_empty() {
            self.statements.remove(device);
        }
        for id in &named {
            self.stated_asked.remove(id);
        }
        named.into_iter().collect()
    }

    /// A stream's opening, as its units carry it.
    pub fn opening_of(&self, stream: &StreamId) -> Option<frasil_units::stream::Opening> {
        self.openings.get(stream).cloned()
    }

    /// Snapshot units whose check failed (`BadCompaction`).
    pub fn bad_compactions(&self) -> &BTreeSet<EventId> {
        &self.bad_compactions
    }

    /// Snapshot units whose state this replica loaded in place of their
    /// cover.
    pub fn used_snapshots(&self) -> &BTreeSet<EventId> {
        &self.used_snapshots
    }

    /// Whether an event is a valid roster event of the merged view.
    pub(crate) fn is_roster(&self, id: &EventId) -> bool {
        self.roster_events.contains(id)
    }

    /// The heals the view calls for at the last refresh.
    pub(crate) fn heals(&self) -> &[crate::healing::HealDue] {
        &self.heals
    }

    /// The space events and units whose body keys members admitted "from
    /// now on" are owed, at the last resolution (admission.md, "Top-ups").
    pub(crate) fn top_ups(&self) -> &[EventId] {
        &self.top_ups
    }

    /// Inside devices that derive no current state, at the last resolution
    /// (keys.md, "Deliveries").
    pub(crate) fn lacking(&self) -> Option<&crate::healing::Lacking> {
        self.lacking.as_ref()
    }

    /// Other content states inside devices are entitled to and lack, at the
    /// last resolution (keys.md, "Deliveries", item 2).
    pub(crate) fn entitled_lacking(&self) -> &[crate::healing::Lacking] {
        &self.entitled
    }

    /// Why the heal test fires, for each graph whose test fires at the
    /// last refresh: `"outside"` or `"unreachable"`, with whether it is the
    /// grant graph's.
    pub fn heal_test(&self) -> Vec<(bool, &'static str)> {
        self.heals
            .iter()
            .map(|h| (h.kind == Kind::Grant, h.reason.name()))
            .collect()
    }

    /// The grant seeds this device holds of the space's rotations.
    pub(crate) fn grant_seeds(&self) -> BTreeMap<EventId, [u8; 32]> {
        self.secrets
            .iter()
            .filter_map(|(id, s)| s.grant.as_deref().map(|g| (*id, *g)))
            .collect_map()
    }

    /// What a granting space reads of this one, after its last resolution.
    pub(crate) fn facts(&self) -> Option<&crate::granted::GrantedFacts> {
        self.facts.as_ref()
    }

    /// The content key of a state, derived from rotations held, or a merged
    /// state's key received whole; and whether it is provisional.
    pub(crate) fn state_key(&self, state: &RotationSet) -> Option<(Secret, bool)> {
        let inputs: Option<Zeroizing<Vec<[u8; 32]>>> = state
            .ids()
            .iter()
            .map(|id| {
                self.secrets
                    .get(id)
                    .and_then(|s| s.content.as_deref().copied())
            })
            .collect::<Option<Vec<_>>>()
            .map(Zeroizing::new);
        if let Some(inputs) = inputs {
            return state_secret(SecretKind::Content, &self.space, state, &inputs)
                .ok()
                .map(|key| (key, false));
        }
        if let Some((claimed, key)) = &self.bootstrap
            && claimed == state
            && !self.states.contains_key(state)
        {
            return Some((key.clone(), true));
        }
        self.states.get(state).map(|key| (key.clone(), true))
    }

    /// The content key an object's or a stream entry's key reference
    /// names: a rotation set's, or in a restricted space the restricted
    /// reference's (ext-restricted-spaces.md).
    pub(crate) fn object_key(&self, reference: &[u8]) -> Option<(Secret, bool)> {
        #[cfg(feature = "ext-restricted-spaces")]
        return self.reference_key(reference);
        #[cfg(not(feature = "ext-restricted-spaces"))]
        self.state_key(&RotationSet::decode(reference).ok()?)
    }

    /// A placed unit's stream.
    #[cfg_attr(not(feature = "ext-restricted-spaces"), allow(dead_code))]
    pub(crate) fn unit_stream(&self, id: &EventId) -> Option<StreamId> {
        if let Some(handed) = self.handed.get(id) {
            return Some(handed.stream);
        }
        crate::compaction::stream_of(self.log.as_ref()?, *id)
    }

    /// A placed event's stream, for a unit; `None` for an event that is no
    /// unit, such as a key's or the roster's. A unit is read once and kept
    /// with its reading, so that the feeds that ask of every event placed
    /// neither copy nor parse it again.
    pub(crate) fn stream_of_event(&self, id: &EventId) -> Option<StreamId> {
        if let Some(handed) = self.handed.get(id) {
            return Some(handed.stream);
        }
        let event = self.log.as_ref()?.event(*id)?;
        if event.kind() != kind::UNIT || event.is_genesis() {
            return None;
        }
        self.unit_reads
            .unit(event)
            .ok()
            .map(|unit| unit.body.stream)
    }

    /// The upload seed of a state, derived from rotations held.
    pub(crate) fn state_upload(&self, state: &RotationSet) -> Option<Secret> {
        let inputs: Option<Zeroizing<Vec<[u8; 32]>>> = state
            .ids()
            .iter()
            .map(|id| {
                self.secrets
                    .get(id)
                    .and_then(|s| s.upload.as_deref().copied())
            })
            .collect::<Option<Vec<_>>>()
            .map(Zeroizing::new);
        state_secret(SecretKind::Upload, &self.space, state, &inputs?).ok()
    }

    /// The grant seed of a grant state, derived from rotations held.
    pub(crate) fn state_grant(&self, state: &RotationSet) -> Option<Secret> {
        let inputs: Option<Zeroizing<Vec<[u8; 32]>>> = state
            .ids()
            .iter()
            .map(|id| {
                self.secrets
                    .get(id)
                    .and_then(|s| s.grant.as_deref().copied())
            })
            .collect::<Option<Vec<_>>>()
            .map(Zeroizing::new);
        state_secret(SecretKind::Grant, &self.space, state, &inputs?).ok()
    }

    /// Whether an event is accepted in full and judged (events.md,
    /// "Accepted in full, and what is cited"): valid, or void with a final
    /// class. Pending, held and dropped events are not.
    pub fn accepted(&self, id: &EventId) -> bool {
        accepts(&self.statuses, id)
    }

    /// What a device cites as parents: the heads of the view of events
    /// accepted in full, every space event maximal among the space events
    /// of that view (units.md, "What a writer does", item 3), and `prev`.
    pub fn parents(&self, prev: Option<EventId>) -> Vec<EventId> {
        let Some(log) = &self.log else {
            return Vec::new();
        };
        let current = self.citable_at == (log.placed_count(), log.revision());
        let (citable, mut parents) = match &self.citable {
            Some((citable, heads)) if current => (Cow::Borrowed(citable), heads.clone()),
            _ => {
                let citable = log.citable(|event| self.accepted(&event.id()));
                let heads = log.heads_in(&citable).into_iter().collect();
                (Cow::Owned(citable), heads)
            }
        };
        let space_events: Vec<EventId> = log
            .frame_events()
            .filter(|e| e.kind() == kind::SPACE)
            .map(Event::id)
            .filter(|id| citable.contains(id))
            .collect();
        for id in &space_events {
            if !space_events
                .iter()
                .any(|other| other != id && log.precedes(*id, *other))
            {
                parents.insert(*id);
            }
        }
        parents.extend(prev);
        // A device that follows a checkpoint cites nothing concurrent with
        // it (roster.md, 3.15.7, "Following").
        let mut parents = crate::checkpoints::fence(
            log,
            self.checkpoints.facts.following,
            prev,
            parents.into_iter().collect(),
        );
        // Nor anything after a checkpoint it builds on no event of: one that
        // drops it as an administrator, or whose record it has not agreed
        // with (roster.md, 3.15.7 "Voting", section 4).
        let avoided = self.checkpoints.facts.avoided();
        if !avoided.is_empty() {
            parents.retain(|&p| {
                Some(p) == prev
                    || crate::checkpoints::reaches_avoided(log, &avoided, &[p]).is_none()
            });
        }
        // At most 256 parents (events.md, "Limits"): keep the space events
        // and prev, then the newest heads.
        if parents.len() > frasil_events::kind::MAX_PARENTS {
            parents.sort_by_key(|id| {
                let space = log.event(*id).is_some_and(|e| e.kind() == kind::SPACE);
                (
                    !(space || Some(*id) == prev),
                    std::cmp::Reverse(log.height(*id)),
                )
            });
            parents.truncate(frasil_events::kind::MAX_PARENTS);
        }
        parents
    }

    /// Whether a device forked its chain in this space (events.md, "Chains
    /// and evidence of a fork").
    pub fn forked(&self, author: &DeviceId) -> bool {
        self.forks.iter().any(|(forked, _)| forked == author)
    }

    /// The heads of the view this device may cite: events accepted in
    /// full, with their past (events.md, "Accepted in full, and what is
    /// cited").
    pub fn citable_heads(&self) -> Vec<EventId> {
        let Some(log) = &self.log else {
            return Vec::new();
        };
        if let Some((_, heads)) = &self.citable
            && self.citable_at == (log.placed_count(), log.revision())
        {
            return heads.iter().copied().collect();
        }
        let citable = log.citable(|event| self.accepted(&event.id()));
        log.heads_in(&citable)
    }

    /// The heads of everything placed: what this replica tells another in
    /// `Heads`.
    pub fn heads(&self) -> Vec<EventId> {
        self.log.as_ref().map(Log::heads).unwrap_or_default()
    }

    /// The parents the replica waits for, and at a partial replica the
    /// events it fetches to learn heights.
    pub fn wanted(&self) -> Vec<EventId> {
        match &self.log {
            Some(log) => {
                let mut wanted = log.wanted();
                // An event known only through a stub its unit's judgement
                // may take back.
                wanted.extend(log.provisional_stubs());
                wanted.extend(
                    self.heights_wanted
                        .iter()
                        .filter(|id| !log.contains(**id) && log.witnessed(**id).is_none()),
                );
                // The carriers of stubs a `Missing` named, and not the
                // events they stub, which the other side cannot serve.
                wanted.retain(|id| !self.carried.values().any(|ids| ids.contains(id)));
                wanted.extend(self.carried.keys().filter(|c| !self.holds(**c)));
                // What a replica that started from a snapshot's checkpoint
                // fetches of the frame before its world: the cut, then the
                // roots and enrolments it names.
                wanted.extend(crate::checkpoints::start_fetches(log, &self.checkpoints));
                // The past of a rival of the kept checkpoint, fetched from a
                // member or peer that kept it (roster.md, 3.15.6).
                wanted.extend(
                    self.checkpoints
                        .facts
                        .rival_wanted
                        .iter()
                        .filter(|id| !log.contains(**id)),
                );
                wanted.sort_unstable();
                wanted.dedup();
                wanted
            }
            None => vec![self.space],
        }
    }

    /// The persisted state of an event, for its `event` record.
    pub(crate) fn event_state(&self, id: &EventId) -> (EventState, Option<&'static str>) {
        match self.statuses.get(id) {
            Some(Status::Valid(_)) => (EventState::Valid, None),
            Some(Status::Void { class, .. }) => match class.sort() {
                Sort::Final => (EventState::Refused, Some(class.name())),
                Sort::Held => (EventState::HeldSealed, None),
                _ if class.name() == "NoHybridKey" => (EventState::PendingNoHybridKey, None),
                _ => (EventState::Pending, None),
            },
            None => (EventState::Pending, None),
        }
    }

    /// Whether every signature half of an event verified.
    pub(crate) fn verified(&self, id: &EventId) -> bool {
        self.verified.contains_key(id)
    }

    /// An event whose every signature half verified: what reads its body
    /// to act on it takes it from here (events.md, 3.3 The ML-DSA-65 half).
    pub(crate) fn verified_event(&self, id: &EventId) -> Option<&VerifiedEvent> {
        self.verified.get(id)
    }

    // -- Streams

    /// The streams the replica reads, with their adapter types: every
    /// stream a unit named, and none opened for a lent document and not yet
    /// written in, which exists from its first unit.
    pub fn streams(&self) -> impl Iterator<Item = (&StreamId, &'static str)> {
        self.streams
            .iter()
            .filter(|(_, s)| !s.is_empty())
            .map(|(id, s)| (id, s.adapter_type()))
    }

    /// Opens a stream's runtime before its first unit, for a document lent
    /// to the application: an empty state the lent document is a reference
    /// to. A stream that exists already is left as it is. `false` for an
    /// adapter type the registry lacks.
    #[cfg(feature = "adapter-loro")]
    pub(crate) fn open_stream(
        &mut self,
        stream: StreamId,
        adapter_type: &str,
        registry: &AdapterRegistry,
    ) -> bool {
        match self.streams.entry(stream) {
            std::collections::btree_map::Entry::Occupied(_) => true,
            std::collections::btree_map::Entry::Vacant(entry) => {
                match registry.stream(adapter_type) {
                    Some(runtime) => {
                        entry.insert(runtime);
                        true
                    }
                    None => false,
                }
            }
        }
    }

    /// A stream's runtime.
    pub fn stream(&self, stream: &StreamId) -> Option<&dyn StreamRuntime> {
        self.streams.get(stream).map(|s| &**s)
    }

    /// What became of a unit's content.
    pub fn content_outcome(&self, id: &EventId) -> Option<ContentOutcome> {
        if let Some(class) = self.refused_content.get(id) {
            return Some(ContentOutcome::Refused(class));
        }
        if let Some(outcome) = self.unreached.get(id) {
            return Some(*outcome);
        }
        let handed = self.handed.get(id)?;
        self.streams.get(&handed.stream)?.outcome(&id.0)
    }

    /// The units of a stream this device wrote, newest last, for its
    /// `stream_prev`.
    /// The units that carried supersessions and that this replica refused:
    /// by the write rule, as content, or as a snapshot whose check failed
    /// (ext-file-versions.md, 3.10 A superseding unit refused). Each with
    /// its stream and the handles of the current entries whose objects it
    /// superseded, which a peer may collect while this replica shows them.
    #[cfg(feature = "ext-file-versions")]
    pub(crate) fn refused_superseding(&self) -> Vec<(EventId, StreamId, Vec<[u8; 16]>)> {
        self.superseding
            .iter()
            .filter(|(id, _)| {
                self.refused_content.contains_key(*id)
                    || self.bad_compactions.contains(*id)
                    || (self.handed.get(*id).is_some_and(|handed| !handed.valid)
                        && !matches!(self.unreached.get(*id), Some(ContentOutcome::Waiting(_))))
                    || matches!(
                        self.content_outcome(id),
                        Some(ContentOutcome::Refused(_) | ContentOutcome::Counted)
                    )
            })
            .map(|(id, (stream, predecessors))| {
                let handles = self
                    .streams
                    .get(stream)
                    .and_then(|runtime| {
                        runtime
                            .as_any()
                            .downcast_ref::<frasil_units::runtime::Stream<frasil_adapter_blobs::Blobs>>()
                    })
                    .map(|blobs| {
                        blobs
                            .state()
                            .current()
                            .filter(|(_, entry)| predecessors.contains(&entry.object))
                            .map(|(handle, _)| *handle)
                            .collect()
                    })
                    .unwrap_or_default();
                (*id, *stream, handles)
            })
            .collect()
    }

    /// The Blobs streams that have supersessions at all, so that the cadence
    /// reads the log for those alone.
    #[cfg(feature = "ext-file-versions")]
    pub(crate) fn supersession_streams(&self) -> Vec<StreamId> {
        self.streams
            .iter()
            .filter(|(_, runtime)| {
                runtime
                    .as_any()
                    .downcast_ref::<frasil_units::runtime::Stream<frasil_adapter_blobs::Blobs>>()
                    .is_some_and(|blobs| !blobs.state().versions().set().is_empty())
            })
            .map(|(stream, _)| *stream)
            .collect()
    }

    /// `first` of ext-file-versions.md, section 3.11: this device's first
    /// sight of the earliest log unit of a stream, outside every snapshot's
    /// cover, that carries a supersession.
    #[cfg(feature = "ext-file-versions")]
    pub(crate) fn first_supersession(&self, stream: &StreamId) -> Option<Reading> {
        let log = self.log.as_ref()?;
        let units: Vec<Unit> = log
            .events()
            .filter(|event| event.kind() == kind::UNIT)
            .filter_map(|event| Unit::from_event(event.clone()).ok())
            .filter(|unit| unit.body.stream == *stream)
            .collect();
        let of = |id: EventId| crate::compaction::stream_of(log, id);
        let covered: BTreeSet<EventId> = units
            .iter()
            .filter_map(|unit| unit.body.compacts.as_ref())
            .flat_map(|compacts| {
                frasil_units::compaction::cover_set(log, of, &compacts.covers, stream)
            })
            .collect();
        units
            .iter()
            .filter(|unit| !unit.is_snapshot() && !unit.body.supersedes.is_empty())
            .filter(|unit| !covered.contains(&unit.id()))
            .filter_map(|unit| self.first_sight(&unit.id()).copied())
            .min_by_key(|reading| reading.timeline)
    }

    pub(crate) fn last_unit_in(&self, stream: &StreamId, author: &DeviceId) -> Option<EventId> {
        let log = self.log.as_ref()?;
        log.chain_rev(author).find(|id| {
            log.event(*id)
                .and_then(|e| self.unit_reads.unit(e).ok())
                .is_some_and(|u| u.body.stream == *stream)
        })
    }
}

/// An object's ID: the first half of its locator (units.md, "Objects").
pub(crate) fn object_id(locator: &Locator) -> [u8; 32] {
    let mut id = [0; 32];
    id.copy_from_slice(&locator[..32]);
    id
}

/// A unit that opened, with what its adapter needs.
/// A snapshot unit's stream, declaration, `excluded` and parents.
type SnapshotCandidate = (
    StreamId,
    frasil_units::body::Compacts,
    Vec<EventId>,
    Vec<EventId>,
);

/// An author's key at a unit's place, the place given by its heads.
type AuthorAtUnit = (EventId, [u8; 32]);

struct OpenedUnit {
    id: EventId,
    stream: StreamId,
    /// The unit's own type: a move unit's is `frasil:move`.
    type_: String,
    /// The late write a unit re-applies (sealed key 4).
    #[cfg(feature = "ext-restricted-spaces")]
    copied_from: Option<(EventId, EventId)>,
    adapter_type: String,
    opening: Option<frasil_units::stream::Opening>,
    /// A snapshot unit's declaration, `excluded` and parents.
    snapshot: Option<(frasil_units::body::Compacts, Vec<EventId>, Vec<EventId>)>,
    check: Result<(), UnitError>,
    /// Whether it is valid by the write rule.
    valid: bool,
    /// Its height in the log.
    height: u64,
    /// Its author's capabilities at its place.
    capabilities: Capabilities,
    /// For a valid unit whose author's capabilities were not found, what
    /// becomes of its content: it waits, or is refused; for a unit handed
    /// before whose verdict is undecided, it waits.
    unreached: Option<ContentOutcome>,
    /// Whether its key reference carries a restricted space's parent state.
    #[cfg(feature = "ext-restricted-spaces")]
    restricted: bool,
    unit: Arc<Unit>,
    inner: Arc<frasil_units::Inner>,
}

impl OpenedUnit {
    /// The unit as its stream receives it: its context and content are
    /// built only when it is handed over.
    fn stream_unit(&self) -> StreamUnit {
        let context = frasil_units::runtime::context(
            &self.unit,
            &self.inner,
            self.height,
            self.capabilities.clone(),
        );
        #[cfg(feature = "ext-restricted-spaces")]
        let context = context.with_restricted(self.restricted);
        StreamUnit {
            context,
            content: self.inner.content.to_vec(),
            // A unit whose author's capabilities were not found is counted,
            // never applied.
            valid: self.valid && self.unreached.is_none(),
        }
    }
}

fn class_name(class: UnitError) -> &'static str {
    class.name()
}

/// The capabilities a unit's author holds at its place, and, when none was
/// found, what becomes of the unit's content (units.md, 3.17 "Capability
/// checks"): it waits (`Pending`) while a path cannot be judged for lack of
/// a log, and is refused (`CapabilityRefused`) otherwise. Never the
/// capabilities of an unnarrowed writer.
fn unit_capabilities(reach: AuthorReach) -> (Capabilities, Option<ContentOutcome>) {
    match reach {
        AuthorReach::Reached(reach) => (capabilities_from(Some(&reach)), None),
        AuthorReach::Unjudged => (
            Capabilities::default(),
            Some(ContentOutcome::Waiting(ErrorClass::Pending.name())),
        ),
        AuthorReach::Unreached => (
            Capabilities::default(),
            Some(ContentOutcome::Refused(
                ErrorClass::CapabilityRefused.name(),
            )),
        ),
    }
}

/// The capabilities an adapter's checks read from how a writer reaches a
/// space: none when no path holds.
pub(crate) fn capabilities_from(reach: Option<&Reach>) -> Capabilities {
    let Some(reach) = reach else {
        return Capabilities::default();
    };
    let extends = reach
        .extends
        .iter()
        .map(|name| Capability::new(name.clone(), Mode::Extends));
    let narrows = reach
        .narrows
        .iter()
        .map(|name| Capability::new(name.clone(), Mode::Narrows));
    Capabilities::new(extends.chain(narrows))
}

/// What one pass of taking keys found.
#[derive(Default)]
struct Taken {
    rotations: BTreeMap<EventId, RotationSecrets>,
    states: BTreeMap<RotationSet, Secret>,
}

impl Taken {
    fn is_empty(&self) -> bool {
        self.rotations.is_empty() && self.states.is_empty()
    }
}

/// The `Path`s a partial replica asks for (units.md, "Partial replicas",
/// "Proven order"): for each event its resolution holds pending on an event
/// whose order against it is not proven, a path each way; the peer answers
/// the one that exists.
fn paths_wanted(space: &Space<'_>, log: &Log) -> BTreeSet<(EventId, EventId)> {
    let mut out = BTreeSet::new();
    for &id in space.view() {
        let Some(Status::Void {
            class,
            by: Some(by),
        }) = space.status(id)
        else {
            continue;
        };
        if Class::name(*class) != "Pending" || !log.contains(*by) && log.witnessed(*by).is_none() {
            continue;
        }
        if log.proves_before(id, *by) || log.proves_before(*by, id) {
            continue;
        }
        out.insert((id, *by));
        out.insert((*by, id));
    }
    out
}

/// Resolves the log as the replica does: every event placed, but those
/// resting on a stub that a pending snapshot unit gave of its own, which
/// are held apart from the view until the replica judges that unit
/// (units.md, "Where stubs come from"). For each such unit the log placed,
/// whole, also returns whether the write rule finds it valid or refuses
/// it; one it does neither for is not listed.
fn resolve_held_apart<'a>(
    log: &'a Log,
    options: Options<'a>,
    partial: bool,
) -> (Result<Space<'a>, RosterClass>, BTreeMap<EventId, bool>) {
    let resolve = |view: Option<&BTreeSet<EventId>>| {
        #[cfg(feature = "partial-replicas")]
        {
            Space::resolve_as(
                log,
                view,
                options,
                if partial {
                    frasil_space::Replica::Partial
                } else {
                    frasil_space::Replica::Full
                },
            )
        }
        #[cfg(not(feature = "partial-replicas"))]
        {
            let _ = partial;
            Space::resolve(log, view, options)
        }
    };
    let apart = log.resting_on_provisional();
    if apart.is_empty() {
        return (resolve(None), BTreeMap::new());
    }
    let mut verdicts = BTreeMap::new();
    if let Ok(whole) = resolve(None) {
        for source in log.provisional_sources() {
            match whole.status(source) {
                Some(status) if status.is_valid() => {
                    verdicts.insert(source, true);
                }
                Some(status) if status.class().map(Class::sort) == Some(Sort::Final) => {
                    verdicts.insert(source, false);
                }
                _ => {}
            }
        }
    }
    let view: BTreeSet<EventId> = log
        .canonical()
        .into_iter()
        .filter(|id| !apart.contains(id))
        .collect();
    (resolve(Some(&view)), verdicts)
}

/// A provisional space snapshot read again under the device's keys
/// (units.md, "The space snapshot", "Using it", step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapshotCheck {
    /// No keys that hash to the sender's `kc` yet.
    Provisional,
    /// Its ML-DSA-65 half verifies.
    Verified,
    /// Its ML-DSA-65 half fails: it was never its sender's.
    Failed,
}

/// The stubs that snapshot units a `Missing` named carry (units.md,
/// "Sync", step 4), each with its signer: a snapshot unit's `stubs`, under
/// its compactor's signature ("Placing against stubs"). Only the stubs of
/// the events each carrier was named for, and only from a carrier placed
/// and `valid`: a stub counts only from a source the replica has judged
/// ("Where stubs come from").
fn carried_stubs(
    log: &Log,
    reads: &UnitReads,
    carried: &BTreeMap<EventId, BTreeSet<EventId>>,
    valid: impl Fn(EventId) -> bool,
) -> Vec<(DeviceId, frasil_units::Stub)> {
    let mut out = Vec::new();
    for (carrier, ids) in carried {
        let Some(event) = log.event(*carrier).filter(|_| valid(*carrier)) else {
            continue;
        };
        let Ok(unit) = reads.unit(event) else {
            continue;
        };
        let stubs = unit
            .body
            .compacts
            .as_ref()
            .map(|compacts| compacts.stubs.clone())
            .unwrap_or_default();
        out.extend(
            stubs
                .into_iter()
                .filter(|stub| ids.contains(&stub.id))
                .map(|stub| (*event.author(), stub)),
        );
    }
    out
}

/// The body keys `frasil:body-keys` units of the system stream carry
/// (units.md, "Frasil's own units"), from every such unit this device
/// opens, whatever its verdict: a key is checked against its event's
/// commitment before use, and serves only provisionally.
fn take_body_keys(
    log: &Log,
    reads: &UnitReads,
    keys: &impl UnitKeys,
    system: Option<&StreamId>,
) -> Vec<(EventId, [u8; 32])> {
    body_key_units(log, reads, keys, system)
        .into_iter()
        .flat_map(|(_, pairs)| pairs)
        .collect()
}

/// For each event, the `frasil:body-keys` units of the system stream this
/// device opens that carry its body key.
fn body_key_carriers(
    log: &Log,
    reads: &UnitReads,
    keys: &impl UnitKeys,
    system: Option<&StreamId>,
) -> BTreeMap<EventId, Vec<EventId>> {
    let mut out: BTreeMap<EventId, Vec<EventId>> = BTreeMap::new();
    for (unit, pairs) in body_key_units(log, reads, keys, system) {
        for (id, _) in pairs {
            out.entry(id).or_default().push(unit);
        }
    }
    out
}

/// Each `frasil:body-keys` unit of the system stream this device opens,
/// with the pairs it carries.
fn body_key_units(
    log: &Log,
    reads: &UnitReads,
    keys: &impl UnitKeys,
    system: Option<&StreamId>,
) -> Vec<(EventId, Vec<frasil_units::own::BodyKey>)> {
    let mut out = Vec::new();
    for event in log.events() {
        if event.kind() != kind::UNIT {
            continue;
        }
        let Ok(unit) = reads.unit(event) else {
            continue;
        };
        if system.is_some_and(|system| unit.body.stream != *system) {
            continue;
        }
        let Ok(inner) = reads.open(&unit, keys, system) else {
            continue;
        };
        // Until the genesis opens, the replica does not know the system
        // stream, which the genesis names: a member granted with history
        // after a break holds only states it cannot open the genesis with,
        // and the genesis's body key is in a `frasil:body-keys` unit of the
        // system stream (admission.md, "The newcomer's snapshot"). A unit
        // of the system stream is the one kind with no stream opening
        // (units.md, "The sealed part"), so such a unit is taken here; each
        // key is checked against its event's commitment before use.
        if inner.type_ != frasil_units::types::BODY_KEYS
            || (system.is_none() && inner.opening.is_some())
        {
            continue;
        }
        if let Ok(pairs) = frasil_units::own::read_body_keys(&inner.content) {
            out.push((event.id(), pairs));
        }
    }
    out
}

/// Who wrote a unit valid by the write rule: its attribution at its place
/// (roster.md, 3.11, "Attribution"), each path left after step 5 with its
/// label there, by type then ID. The same at every device: one that kept
/// everything reads it at the unit's place, one that forgot that place
/// from what it froze, and neither reads the current roster for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Authorship {
    /// The paths, with their labels at the unit's place.
    pub(crate) paths: Vec<(MemberRef, Option<String>)>,
}

impl Authorship {
    /// The label of the author's own device path, when the roster granted
    /// the device directly there.
    #[cfg(any(feature = "adapter-loro", feature = "adapter-records"))]
    pub(crate) fn device_name(&self, device: &DeviceId) -> Option<String> {
        self.paths
            .iter()
            .find(|(member, _)| *member == MemberRef::device(*device))
            .and_then(|(_, label)| label.clone())
    }

    /// The person paths, with their labels, by ID.
    #[cfg(any(feature = "adapter-loro", feature = "adapter-records"))]
    pub(crate) fn persons(&self) -> Vec<([u8; 32], Option<String>)> {
        self.paths
            .iter()
            .filter(|(member, _)| member.kind == MemberType::Person)
            .map(|(member, label)| (member.id, label.clone()))
            .collect()
    }
}

/// Where each list event reached the space: the first `frasil:list` unit
/// of the system stream, in canonical order, that carries it.
fn list_copy_places(
    log: &Log,
    reads: &UnitReads,
    keys: &impl UnitKeys,
    system: Option<&StreamId>,
) -> BTreeMap<EventId, EventId> {
    let Some(system) = system else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for id in log.canonical() {
        let Some(event) = log.event(id) else {
            continue;
        };
        if event.kind() != kind::UNIT {
            continue;
        }
        let Ok(unit) = reads.unit(event) else {
            continue;
        };
        if unit.body.stream != *system {
            continue;
        }
        let Ok(inner) = reads.open(&unit, keys, Some(system)) else {
            continue;
        };
        if inner.type_ != frasil_units::types::LIST {
            continue;
        }
        if let Ok(events) = frasil_units::own::read_list_copy(&inner.content) {
            for copied in events {
                out.entry(copied.id()).or_insert(id);
            }
        }
    }
    out
}

/// The events that void each unit among `among` that the write rule voids
/// in `space` (roster.md, 3.14).
fn unit_voiders(
    space: &Space<'_>,
    among: impl Iterator<Item = EventId>,
) -> BTreeMap<EventId, Vec<EventId>> {
    among
        .filter(|&id| {
            space
                .log()
                .event(id)
                .is_some_and(|e| e.kind() == kind::UNIT)
                && space.status(id).is_some_and(|status| !status.is_valid())
        })
        .map(|id| (id, space.voiders(id)))
        .filter(|(_, voiders)| !voiders.is_empty())
        .collect()
}

/// Each unit's authorship (`Authorship`) among `among`: its attribution
/// at its own place, for a unit valid by the write rule that some path
/// reached ([`Space::attribution`]).
fn authorship(
    space: &Space<'_>,
    among: impl Iterator<Item = EventId>,
) -> BTreeMap<EventId, Authorship> {
    among
        .filter_map(|id| {
            let paths = space.attribution(id)?;
            Some((id, Authorship { paths }))
        })
        .collect()
}

/// The list events `frasil:list` units of the system stream carry
/// (identity.md, "Sealed list copies"), from every such unit this device
/// opens: each is checked as a list event where it is placed.
fn take_list_copies(
    log: &Log,
    reads: &UnitReads,
    keys: &impl UnitKeys,
    system: Option<&StreamId>,
) -> Vec<Vec<u8>> {
    let Some(system) = system else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for event in log.events() {
        if event.kind() != kind::UNIT {
            continue;
        }
        let Ok(unit) = reads.unit(event) else {
            continue;
        };
        if unit.body.stream != *system {
            continue;
        }
        let Ok(inner) = reads.open(&unit, keys, Some(system)) else {
            continue;
        };
        if inner.type_ != frasil_units::types::LIST {
            continue;
        }
        if let Ok(events) = frasil_units::own::read_list_copy(&inner.content) {
            out.extend(events.iter().map(Event::signed));
        }
    }
    out
}

/// The space principals in force in the merged roster, each with the grant
/// key the notice that admitted it names (keys.md, "Notices and space
/// principals").
fn principals_in_force<H: frasil_space::keygraph::History>(
    space: &Space<'_>,
    log: &Log,
    graph: &frasil_space::keygraph::KeyGraph<'_, H>,
) -> Vec<(
    EventId,
    EventId,
    Box<[u8; frasil_crypto::sizes::XWING_PUBLIC]>,
    Level,
)> {
    let mut out = Vec::new();
    for (member, membership) in graph.members(Kind::Content) {
        let frasil_space::keygraph::Member::Principal(principal) = member else {
            continue;
        };
        let public = log.canonical().into_iter().rev().find_map(|id| {
            space.opened(id).and_then(|opened| {
                opened
                    .inner
                    .notices
                    .iter()
                    .find(|n| n.space == principal.space && n.rotation == principal.rotation)
                    .map(|n| n.public.clone())
            })
        });
        if let Some(public) = public {
            out.push((
                principal.space,
                principal.rotation,
                public,
                membership.level,
            ));
        }
    }
    out
}

/// Trial decryption of space wraps (keys.md, "Reading key names, bundles,
/// wraps and links"): a device of a granted space tries each space wrap
/// with the grant keys it holds of that space's rotations. A wrap's info
/// names the granted space and its grantee rotation, so a key of another
/// space or rotation fails as `Decrypt`; the device tries them before it
/// can open the notice that names the rotation.
fn take_space_wraps(
    space: Option<&Space<'_>>,
    log: &Log,
    parts: &VisibleParts,
    grant_seeds: &BTreeMap<EventId, BTreeMap<EventId, [u8; 32]>>,
    held: &BTreeMap<EventId, RotationSecrets>,
    taken: &mut Taken,
    tried: &mut SpaceWrapsTried,
) {
    let space_id = log.id();
    let keys: Vec<(EventId, EventId, frasil_keys::derive::GrantKey)> = grant_seeds
        .iter()
        .filter(|(t, _)| **t != space_id)
        .flat_map(|(t, seeds)| {
            seeds
                .iter()
                .map(move |(r, seed)| (*t, *r, GrantKey::derive(seed)))
        })
        .collect();
    if keys.is_empty() {
        return;
    }
    for id in log.canonical() {
        let Some(event) = log.event(id) else {
            continue;
        };
        let Some(visible_part) = parts.of(event) else {
            continue;
        };
        for (index, delivery) in visible_part.deliveries.iter().enumerate() {
            if delivery.space_wraps.is_empty() {
                continue;
            }
            let Some(key_name) = &delivery.key_name else {
                continue;
            };
            let Some(state) = state_of(key_name, id) else {
                continue;
            };
            if let [rotation] = state.ids()
                && (held.get(rotation).is_some_and(|s| s.content.is_some())
                    || taken
                        .rotations
                        .get(rotation)
                        .is_some_and(|s| s.content.is_some()))
            {
                continue;
            }
            // A grant key that opened none of this delivery's space wraps
            // never tries them again.
            let trial = |(t, r, key): &(EventId, EventId, GrantKey)| {
                (
                    id,
                    index,
                    *t,
                    *r,
                    frasil_crypto::primitives::sha256(&[&key.public[..]]),
                )
            };
            let live: Vec<&(EventId, EventId, GrantKey)> = keys
                .iter()
                .filter(|key| !tried.contains(&trial(key)))
                .collect();
            let opened = delivery.space_wraps.iter().find_map(|wrap| {
                live.iter().find_map(|(t, r, key)| {
                    frasil_keys::wraps::open_space_wrap(
                        wrap,
                        &space_id.0,
                        Some(key_name),
                        delivery.grant_name.as_ref(),
                        t,
                        r,
                        &key.xwing_seed,
                    )
                    .ok()
                })
            });
            if opened.is_none() {
                tried.extend(live.iter().map(|key| trial(key)));
            }
            let Some(bundle) = opened else {
                continue;
            };
            match state.ids() {
                [rotation] => {
                    if let Some((keys, is_break)) = rotation_facts(space, log, parts, *rotation) {
                        let slots = take_rotation(&bundle, &keys, is_break);
                        taken.rotations.entry(*rotation).or_default().merge(&slots);
                    }
                }
                _ => {
                    if let Some(content) = bundle.content() {
                        taken
                            .states
                            .entry(state.clone())
                            .or_insert_with(|| Zeroizing::new(*content));
                    }
                }
            }
        }
    }
}

/// Trial decryption for removal wraps (keys.md, "Trial decryption"): each
/// rotation this device holds `Sealed`, lacking its key, has its own
/// deliveries tried once for a removal wrap naming this device. Rotations
/// in the past of an event this device opened are skipped: a device
/// admitted "from now on" cannot open the rotations before its admission,
/// and none of them removes it. Returns the body keys found, each matched
/// against its event's commitment.
fn take_removal_wraps(
    space: &Space<'_>,
    log: &Log,
    parts: &VisibleParts,
    me: &Me,
    held: &BTreeMap<EventId, RotationSecrets>,
    bodies: &BTreeMap<EventId, Vec<Secret>>,
    tried: &mut BTreeSet<EventId>,
) -> Vec<(EventId, Secret)> {
    let canonical = log.canonical();
    let candidates: Vec<(EventId, Arc<VisiblePart>)> = canonical
        .iter()
        .filter(|id| {
            !tried.contains(id)
                && space.opened(**id).is_none()
                && !bodies.contains_key(id)
                && held.get(id).is_none_or(|s| s.content.is_none())
        })
        .filter_map(|id| {
            let visible = parts.of(log.event(*id)?)?;
            visible.rotates().then_some((*id, visible))
        })
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    let space_id = log.id();
    let mut out = Vec::new();
    // Each rotation the device holds sealed, once, whatever later event
    // it opened: what it reads of the rotation does not hang on the order
    // its events came in (keys.md, "Trial decryption").
    for (id, visible) in candidates {
        tried.insert(id);
        let found = visible
            .deliveries
            .iter()
            .filter(|d| matches!(d.key_name, Some(KeyName::SelfRef(_))))
            .find_map(|delivery| {
                frasil_keys::wraps::find_removal_wrap(
                    &delivery.wraps,
                    &space_id.0,
                    delivery.key_name.as_ref()?,
                    delivery.grant_name.as_ref(),
                    &me.device,
                    &me.xwing_seed,
                    &visible.commitment,
                )
            });
        if let Some((_, key)) = found {
            out.push((id, key));
        }
    }
    out
}

/// The key name's state: a self reference names the carrying event's own
/// rotation.
fn state_of(name: &KeyName, carrying: EventId) -> Option<RotationSet> {
    match name {
        KeyName::SelfRef(_) => Some(RotationSet::single(carrying)),
        other => other.as_set().cloned(),
    }
}

/// A rotation's visible keys and its `break`, as far as this device can
/// read them.
fn rotation_facts(
    space: Option<&Space<'_>>,
    log: &Log,
    parts: &VisibleParts,
    rotation: EventId,
) -> Option<(RotationKeys, Option<bool>)> {
    let event = log.event(rotation)?;
    let keys = *parts.of(event)?.rotation()?;
    let is_break = space
        .and_then(|space| space.opened(rotation))
        .map(|o| o.inner.is_break);
    Some((keys, is_break))
}

/// Keys.md, "Taking a key": every delivery that names a state this device
/// lacks is tried, and every link under a state it holds is followed.
fn take_keys(
    space: Option<&Space<'_>>,
    log: &Log,
    parts: &VisibleParts,
    me: &Me,
    held: &BTreeMap<EventId, RotationSecrets>,
    held_states: &BTreeMap<RotationSet, Secret>,
    tried: &mut WrapsTried,
) -> Taken {
    let mut taken = Taken::default();
    let space_id = log.id();
    let content_of = |taken: &Taken, id: &EventId| -> Option<[u8; 32]> {
        held.get(id)
            .and_then(|s| s.content.as_deref().copied())
            .or_else(|| {
                taken
                    .rotations
                    .get(id)
                    .and_then(|s| s.content.as_deref().copied())
            })
    };
    let grant_of = |taken: &Taken, id: &EventId| -> Option<[u8; 32]> {
        held.get(id)
            .and_then(|s| s.grant.as_deref().copied())
            .or_else(|| {
                taken
                    .rotations
                    .get(id)
                    .and_then(|s| s.grant.as_deref().copied())
            })
    };
    let secret = |taken: &Taken, state: &RotationSet, kind: SecretKind| -> Option<Secret> {
        let inputs: Option<Zeroizing<Vec<[u8; 32]>>> = state
            .ids()
            .iter()
            .map(|id| match kind {
                SecretKind::Grant => grant_of(taken, id),
                _ => content_of(taken, id),
            })
            .collect::<Option<Vec<_>>>()
            .map(Zeroizing::new);
        match inputs {
            Some(inputs) => state_secret(kind, &space_id, state, &inputs).ok(),
            None if kind == SecretKind::Content => held_states
                .get(state)
                .or_else(|| taken.states.get(state))
                .cloned(),
            None => None,
        }
    };
    // Whether this device writes in the space as resolved, asked only once
    // a delivery could bring an upload seed it lacks: a member raised from
    // `read` holds the content key already, and receives the upload seed
    // beside it (keys.md, "Checks against the event and its place").
    let mut writes: Option<bool> = None;
    let mut writes_here = || {
        *writes.get_or_insert_with(|| {
            space.is_some_and(|space| {
                space
                    .effective_at(space.valid_roster(), 0, &[])
                    .get(&me.device.0)
                    .is_some_and(|(level, _)| *level >= Level::Write)
            })
        })
    };
    for id in log.canonical() {
        let Some(event) = log.event(id) else {
            continue;
        };
        // Deliveries are visible: a device tries them before it can open
        // anything (keys.md, "Trial decryption").
        let Some(visible_part) = parts.of(event) else {
            continue;
        };
        let opened = space.and_then(|space| space.opened(id));
        let genesis_nonce;
        let log_bytes: &[u8] = if id == space_id {
            genesis_nonce = visible_part.nonce.unwrap_or_default();
            &genesis_nonce
        } else {
            &space_id.0
        };
        // Deliveries.
        for (index, delivery) in visible_part.deliveries.iter().enumerate() {
            let Some(key_name) = &delivery.key_name else {
                continue;
            };
            let Some(state) = state_of(key_name, id) else {
                continue;
            };
            let grant_state = delivery.grant_name.as_ref().and_then(|n| state_of(n, id));
            let lacks_content = secret(&taken, &state, SecretKind::Content).is_none();
            let lacks_grant = grant_state
                .as_ref()
                .is_some_and(|g| secret(&taken, g, SecretKind::Grant).is_none());
            // Trial decryption only where the named rotations are events of
            // the log this device holds.
            let in_log = state.ids().iter().all(|r| log.contains(*r))
                && grant_state
                    .as_ref()
                    .is_none_or(|g| g.ids().iter().all(|r| log.contains(*r)));
            // A slot it lacks of a single rotation whose content key it
            // holds: the upload seed (keys.md, "Taking a key").
            let lacks_upload = || match state.ids() {
                [rotation] => {
                    held.get(rotation).is_none_or(|s| s.upload.is_none())
                        && taken
                            .rotations
                            .get(rotation)
                            .is_none_or(|s| s.upload.is_none())
                }
                _ => false,
            };
            if !in_log || !(lacks_content || lacks_grant || (lacks_upload() && writes_here())) {
                continue;
            }
            let Some((_, bundle)) = me.find_wrap(
                &delivery.wraps,
                log_bytes,
                Some(key_name),
                delivery.grant_name.as_ref(),
                (id, index),
                tried,
            ) else {
                continue;
            };
            match state.ids() {
                [rotation] => {
                    let Some((keys, is_break)) = rotation_facts(space, log, parts, *rotation)
                    else {
                        continue;
                    };
                    let slots = take_rotation(&bundle, &keys, is_break);
                    let entry = taken.rotations.entry(*rotation).or_default();
                    entry.merge(&slots);
                }
                _ => {
                    if let Some(content) = bundle.content() {
                        taken
                            .states
                            .entry(state.clone())
                            .or_insert_with(|| Zeroizing::new(*content));
                    }
                }
            }
            // A grant state of one rotation named apart from the content
            // state: its grant seed, checked against its commitment.
            if let (Some(grant_state), Some(seed)) = (&grant_state, bundle.grant())
                && grant_state != &state
                && let [rotation] = grant_state.ids()
                && let Some((keys, is_break)) = rotation_facts(space, log, parts, *rotation)
                && grant_matches(seed, &keys, is_break)
            {
                taken.rotations.entry(*rotation).or_default().grant = Some(Zeroizing::new(*seed));
            }
        }
        // Links are sealed: followed once the event opens. While the space
        // does not resolve, a rotation whose own key this device holds is
        // opened here: a device reached only by a rotation made after the
        // genesis's state, such as a person's device a cascade reaches,
        // follows its link back, without which it never opens the genesis
        // (keys.md, "Links"). Each state a link reaches is checked against
        // its rotation's commitment, as below.
        let unresolved;
        let inner = match opened {
            Some(opened) => &opened.inner,
            None if space.is_none() => {
                let Some(keys) = visible_part.rotation() else {
                    continue;
                };
                let Some(content) = content_of(&taken, &id) else {
                    continue;
                };
                if read_credential(&content).public != keys.read {
                    continue;
                }
                let key =
                    frasil_keys::derive::body_key(&content, log_bytes, event.author(), event.seq());
                let Ok(inner) = visible_part.open(&key, log_bytes, event.author(), event.seq())
                else {
                    continue;
                };
                unresolved = inner;
                &unresolved
            }
            None => continue,
        };
        for link in &inner.links {
            let Some(under) = state_of(&link.under, id) else {
                continue;
            };
            let reaches = &link.reaches;
            let kind = match link.kind {
                LinkKind::Content => SecretKind::Content,
                LinkKind::Grant => SecretKind::Grant,
            };
            if secret(&taken, reaches, kind).is_some() {
                continue;
            }
            let Some(under_secret) = secret(&taken, &under, kind) else {
                continue;
            };
            let Ok(reached) = link.open_read(log_bytes, &under_secret) else {
                continue;
            };
            match (reaches.ids(), kind) {
                ([rotation], SecretKind::Content) => {
                    if let Some((keys, _)) = rotation_facts(space, log, parts, *rotation)
                        && read_credential(&reached).public == keys.read
                    {
                        taken.rotations.entry(*rotation).or_default().content = Some(reached);
                    }
                }
                ([rotation], SecretKind::Grant) => {
                    if let Some((keys, is_break)) = rotation_facts(space, log, parts, *rotation)
                        && grant_matches(&reached, &keys, is_break)
                    {
                        taken.rotations.entry(*rotation).or_default().grant = Some(reached);
                    }
                }
                (_, SecretKind::Content) => {
                    taken.states.entry(reaches.clone()).or_insert(reached);
                }
                _ => {}
            }
        }
    }
    // Keep only what is new.
    taken.rotations.retain(|id, secrets| {
        let mine = held.get(id);
        let new_content = secrets.content.is_some() && mine.is_none_or(|m| m.content.is_none());
        let new_upload = secrets.upload.is_some() && mine.is_none_or(|m| m.upload.is_none());
        let new_grant = secrets.grant.is_some() && mine.is_none_or(|m| m.grant.is_none());
        new_content || new_upload || new_grant
    });
    taken
        .states
        .retain(|state, _| !held_states.contains_key(state));
    taken
}

/// Whether a grant seed matches a rotation's commitment, with its `break`
/// when this device can read it, and otherwise under either value: the
/// commitment binds the grant key whatever the `break`.
fn grant_matches(seed: &[u8; 32], keys: &RotationKeys, is_break: Option<bool>) -> bool {
    let key = GrantKey::derive(seed);
    match is_break {
        Some(is_break) => key.commitment(is_break) == keys.grant_commitment,
        None => {
            key.commitment(false) == keys.grant_commitment
                || key.commitment(true) == keys.grant_commitment
        }
    }
}

/// A single rotation's bundle, slot by slot (keys.md, "Taking a key").
fn take_rotation(
    bundle: &frasil_keys::bundle::Bundle,
    keys: &RotationKeys,
    is_break: Option<bool>,
) -> RotationSecrets {
    let slots = take_slots(bundle, keys, is_break.unwrap_or(false));
    let mut secrets = RotationSecrets {
        content: slots.content,
        upload: slots.upload,
        grant: slots.grant,
    };
    if secrets.grant.is_none()
        && is_break.is_none()
        && let Some(seed) = bundle.grant()
        && grant_matches(seed, keys, None)
    {
        secrets.grant = Some(Zeroizing::new(*seed));
    }
    // An upload seed is only ever taken beside its content key.
    if secrets.content.is_none() {
        secrets.upload = None;
    }
    secrets
}

#[cfg(all(test, debug_assertions, feature = "adapter-loro"))]
mod cache_tests;

#[cfg(all(test, debug_assertions, feature = "adapter-loro"))]
mod roster_cache_tests;

#[cfg(all(test, debug_assertions, feature = "adapter-loro"))]
mod checkpoint_cache_tests;

#[cfg(all(test, feature = "adapter-loro"))]
mod forget_content_tests;

#[cfg(all(test, feature = "adapter-loro"))]
mod withhold_tests;

#[cfg(all(test, feature = "adapter-loro"))]
mod key_ring_tests;

#[cfg(test)]
mod base_tests;
