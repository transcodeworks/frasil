//! Checkpoints (roster.md, 3.15): which events follow a checkpoint, when one
//! is valid and when it takes effect, the world after it, and the verdicts
//! of a replica that holds a space's whole history and of one that keeps
//! only a checkpoint and what follows it.
//!
//! A **checkpoint** is a roster event whose roster part is of type 2
//! ([`CheckpointPart`]); it names a record ([`Record`]) that travels as an
//! object. [`Checkpointed`] judges a view of a space's log with them:
//!
//! - **What follows a checkpoint** is read from envelopes (events.md,
//!   "Cuts"): an event follows `c` when its cuts reach `c`. The order among
//!   checkpoints reads the envelopes the log holds and those the replica
//!   keeps beyond it ([`Inputs::envelopes`]).
//! - **A checkpoint's validity** is judged on its own past alone
//!   ([`Checkpointed::validity`]), in order:
//!
//!   ```text
//!   1. The event alone and its cuts.                                  else that class / BadCuts
//!      Its record reads from its object;                              else Sealed (held) / BadCheckpoint /
//!                                                                          ExtensionRequired (held)
//!      no checkpoint in its past (with a predecessor p, p and the
//!      events after p there) is held for its record.                  else Pending (held)
//!   2. Without a predecessor: no checkpoint its cuts reach is valid.  else BadCheckpoint
//!      With a predecessor p: p is a checkpoint its cuts reach, and
//!      every checkpoint its cuts reach is at or before p, or after p; else BadCheckpoint
//!      no valid checkpoint its cuts reach is after p;                 else CheckpointPending
//!      p is valid;                                                    else BadCheckpoint
//!      p is in effect in the view of p and the events after p in its
//!      past, and that view holds no other valid checkpoint.           else CheckpointPending
//!   3. Its signature, under keys of that past and of other logs.      else NoHybridKey (held) / BadSignature
//!   4. Its author's fork point, in its past, is above its seq.        else Forked
//!   5. Its author is in at administer in the roster of its past.      else NotAnAdministrator
//!   6. keys.md's checks against it as a genesis.                      else that class
//!   7. Its twin, at a replica that checks twins: key 15 names a
//!      skeleton cut it cites (read from its parents, without the
//!      cut), every other parent in the cut's past, and the cut
//!      passes peers.md's checks of a cut (steps 1 to 7).               else TwinRequired / BadTwin
//!   8. Its record equals, byte for byte, the record of its past,
//!      space members' keys 18 to 20 left out of both.                 else BadCheckpoint
//!   9. The cut agrees with the record, at a replica that checks twins:
//!      its slot entries, and its standing entries those the record
//!      gives ([`standing_entries`]).                                  else BadTwin
//!   ```
//!
//! - **Votes and effect**: the electorate is the record's administrators
//!   that do not extend `frasil.dormant`, less those excused for good: one
//!   whose fork the checkpoint's world shows, or one that a judged roster
//!   event after it, by another administrator of the record than the
//!   checkpoint's author and whose
//!   signature verified, removes, demotes or marks dormant, whatever that
//!   event's verdict ([`Checkpointed::electorate`]). A device votes by any
//!   event after the checkpoint whose signature verifies, whose cuts are
//!   correct and reach no concurrent checkpoint; a checkpoint is stable
//!   when its whole electorate voted ([`Checkpointed::waiting_for`] names
//!   who it still waits for). Starting from no checkpoint, or the kept one,
//!   the stable valid checkpoint with the smallest ID among those whose
//!   predecessor is the current one takes effect, and so on: the **chain
//!   in effect**.
//! - **Verdicts** ([`Checkpointed::judge`]): with a chain `c1, …, ck`,
//!   events in `c1`'s past have the verdicts of that past alone; each `ci`
//!   is valid; events after `ci` in `c(i+1)`'s past have their verdicts in
//!   `ci`'s world over that past; events after `ck` theirs in `ck`'s world;
//!   every other event is `Late`. Without a chain, the view is resolved as
//!   roster.md's sections 3.1 to 3.14 say, each checkpoint with its own
//!   verdict.
//!
//! - **Held for a record**: a checkpoint whose record object the replica
//!   lacks is `Sealed`, and every event in whose past it is `Pending`,
//!   whichever world would judge it; the rest is judged as if they had not
//!   arrived. A checkpoint whose record uses a key or member type a later
//!   document defines (roster.md, 2.8, step 3) is held so too, it and every
//!   event in whose past it is as `ExtensionRequired`: the replica never
//!   votes for it, never cites it, never starts from it, and needs a later
//!   version ([`Judged::needs_later_rules`]). Steps 2 to 6, which read no
//!   record, still judge it in order where its past is held, with the
//!   predecessor keys 2 and 3 of its record's map name: one that fails one
//!   of them, such as a writer's (`NotAnAdministrator`), is void for good,
//!   as any checkpoint, and holds nothing; one a step holds (`NoHybridKey`)
//!   stays held, the later steps waiting; one that passes them all stays
//!   `ExtensionRequired`.
//! - **A rival** ([`Checkpointed::rivals`]): at a replica that forgot under
//!   its kept checkpoint, a concurrent checkpoint with a smaller ID that
//!   could take a place in its chain and that is stable in what it holds,
//!   or whose stability it cannot work out, holds every event pending. One
//!   whose record a later document's key or member type holds is judged by
//!   what keys 2 and 3 of its record give and counts as stable: it is a
//!   rival whenever it names a predecessor that would let it take a place,
//!   and the replica needs a later version, until it holds the rival's past
//!   and the steps that read no record settle it.
//! - **Requests across a checkpoint** ([`Checkpointed::placement`],
//!   [`Checkpointed::undecided`], [`Checkpointed::request_state`],
//!   [`Checkpointed::late_requests`]): where a request stands against the
//!   chain in effect, the checkpoints that can still take effect, an
//!   erasure that waits for them, and the requests a client signs again.
//!
//! The world of a checkpoint is [`crate::checkpoint_world`]'s: the same
//! resolution, over a log rooted at the checkpoint, with the record
//! standing for the genesis. A replica that forgot what came before its
//! kept checkpoint ([`Kept`]) runs the same function on the same inputs.
//!
//! What other parts of Frasil give this module, as inputs:
//!
//! - **The record object's plaintext** ([`RecordObjects`]): units.md's
//!   "Reading an object" under the checkpoint's locator, with the
//!   checkpoint's content key or the record's object key handed to a
//!   newcomer. Missing, or an object that does not open, holds the
//!   checkpoint `Sealed`; one that opens and does not match is
//!   `BadCheckpoint`.
//! - **Kept checkpoint envelopes** ([`Inputs::envelopes`]): the envelopes
//!   of checkpoints a replica keeps beyond what its log holds (events.md,
//!   "Cuts", "Ordering needs envelopes").
//! - **Administrator slots** ([`AdministratorSlots`]): the skeleton's
//!   binding of each administrator to its slot and pseudonym, which a
//!   record names (key 13). Without it a record names no slot.

use crate::change::{Change, Op};
use crate::checkpoint_record::{
    HeardMember, InviteStatus, MemberEntry, Record, RecordNotice, SlotEntry,
};
use crate::checkpoint_world::WorldLog;
use crate::member::{CapabilityMode, Level, MemberRef, MemberType};
use crate::part::CheckpointPart;
use crate::policy::Policy;
use crate::screen::{Body, Keyring, ScreenContext, screen_body};
use crate::space::{Checkpointing, Options, Space, Status, Valid};
use crate::state::{MemberState, Roster, Seniority, Standing};
use crate::{RosterClass, SpaceClass};
use frasil_base::ErrorClass;
use frasil_base::collect::CollectMap;
use frasil_crypto::device::{DeviceId, DeviceKeys, KeySource};
use frasil_events::cuts::{self, Checkpoints, CutsCheck, HeldEnvelopes};
use frasil_events::{Event, EventId, Log, kind};
use frasil_keys::context::{Context, check_context};
use frasil_peers::body::SlotId;
use frasil_peers::cut::RecordSlot;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;

mod frozen;
mod requests;
mod standing;

pub use frasil_peers::body::StandingEntry;
pub use frasil_peers::cut::{Dormancy, StandingMember};
pub use frozen::FrozenUnit;
pub use requests::{LateRequest, Placement, RequestState};
pub use standing::standing_entries;

/// The capability that marks an administrator a checkpoint does not wait
/// for (roster.md, 3.15.4 Votes and effect): a space recovery member is
/// granted with it, extending.
pub const DORMANT: &str = "frasil.dormant";

/// What units.md's object reading gives of a checkpoint's record object
/// (roster.md, "The record object").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordObject {
    /// The replica lacks the object, or a key that opens it: the checkpoint
    /// is held `Sealed`, with every event after it, until it arrives.
    Missing,
    /// The object opened under its locator: its plaintext, which the
    /// checkpoint's `size` and `digest` must match.
    Opened(Vec<u8>),
    /// The object, under the keys that should open it, fails units.md's
    /// reading: the locator binds that very object, so the checkpoint is
    /// `BadCheckpoint`.
    Refused,
    /// The record requires a later document's rules, with its epoch and
    /// previous checkpoint when those fields read and the epoch matches.
    Extension(Option<(u64, Option<EventId>)>),
    /// The object and its typed record read and match the checkpoint.
    Read(Arc<Record>),
    /// Validated comparison summary, awaiting derivation of the past.
    Summary(Arc<crate::RecordSummary>),
}

/// The record objects a replica holds: units.md reads each under the
/// checkpoint's locator and content key, or the object key a snapshot
/// handed over (units.md, "Objects", "The space snapshot").
pub trait RecordObjects {
    /// The record object of `checkpoint`, whose roster part is `part`.
    fn record_object(&self, checkpoint: EventId, part: &CheckpointPart) -> RecordObject;
}

/// No record object held.
impl RecordObjects for () {
    fn record_object(&self, _: EventId, _: &CheckpointPart) -> RecordObject {
        RecordObject::Missing
    }
}

/// Plaintexts already read, by checkpoint.
impl RecordObjects for BTreeMap<EventId, Vec<u8>> {
    fn record_object(&self, checkpoint: EventId, _: &CheckpointPart) -> RecordObject {
        match self.get(&checkpoint) {
            Some(plaintext) => RecordObject::Opened(plaintext.clone()),
            None => RecordObject::Missing,
        }
    }
}

/// The skeleton's binding of administrators to their slots (peers.md),
/// which a record names in key 13. A resolution that checks twins gives its
/// own ([`Space::administrator_slots`]), which [`Checkpointed`] reads first.
pub trait AdministratorSlots {
    /// The slot of the administrator `device`, and the pseudonym enrolled
    /// in it, if the skeleton holds one.
    fn slot(&self, device: &DeviceId) -> Option<SlotEntry>;
}

/// The administrator slots a resolution read, by device.
impl AdministratorSlots for BTreeMap<DeviceId, SlotEntry> {
    fn slot(&self, device: &DeviceId) -> Option<SlotEntry> {
        self.get(device).cloned()
    }
}

/// The administrators of a record, each with its `slot` (key 13) as the
/// twin check of its checkpoint's cut reads it (peers.md, "Skeleton cuts";
/// [`frasil_peers::cut::check_against_record`]): every device member at
/// `administer`, in the record's order. An entry without key 13, or whose
/// slot is not a slot reference, gives none; empty pseudonym bytes name no
/// enrolled pseudonym.
pub fn record_slots(record: &Record) -> Vec<Option<RecordSlot>> {
    record
        .members
        .iter()
        .filter(|entry| entry.member.kind == MemberType::Device && entry.level == Level::Administer)
        .map(|entry| {
            let slot = entry.slot.as_ref()?;
            let index = u8::try_from(slot.index).ok()?;
            let pseudonym = match slot.pseudonym.len() {
                0 => None,
                _ => Some(DeviceId(slot.pseudonym.as_slice().try_into().ok()?)),
            };
            Some(RecordSlot {
                slot: SlotId::new(slot.commitment, index, slot.maker),
                pseudonym,
            })
        })
        .collect()
}

/// The checkpoint a replica keeps after it forgot what came before it
/// (roster.md, 3.15.6 Forgetting, and starting from a checkpoint): it judged
/// it on its whole past, or it took it from a snapshot once it was in
/// effect in what it holds after it. Its record is trusted.
#[derive(Debug, Clone)]
pub struct Kept {
    /// The kept checkpoint.
    pub checkpoint: EventId,
    /// Its record.
    pub record: Arc<Record>,
}

/// What [`Checkpointed`] reads.
#[derive(Clone, Copy)]
pub struct Inputs<'a> {
    /// The space's log: every event the replica holds is placed in it, or
    /// for one that forgot, the genesis, stubs of what it forgot, the kept
    /// checkpoint and what follows it.
    pub log: &'a Log,
    /// What a space's resolution reads beyond its log.
    pub options: Options<'a>,
    /// The record objects held.
    pub objects: &'a dyn RecordObjects,
    /// Envelopes of checkpoints the replica keeps beyond its log.
    pub envelopes: &'a dyn HeldEnvelopes,
    /// The skeleton's administrator slots, for the records this replica
    /// derives; `None` names no slot.
    pub slots: Option<&'a dyn AdministratorSlots>,
}

impl core::fmt::Debug for Inputs<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Inputs")
            .field("space", &self.log.id())
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

/// The envelopes the log holds, then those the replica keeps: the log's
/// own kept envelopes and those [`Inputs::envelopes`] gives; and the cuts
/// of the log's stubs.
struct Envelopes<'a> {
    log: &'a Log,
    kept: &'a dyn HeldEnvelopes,
}

impl HeldEnvelopes for Envelopes<'_> {
    fn held_envelope(&self, id: EventId) -> Option<&Event> {
        self.log.held_envelope(id)
    }

    fn kept_envelope(&self, id: EventId) -> Option<&Event> {
        self.log
            .kept_envelope(id)
            .or_else(|| self.kept.envelope(id))
    }

    fn stub_cuts(&self, id: EventId) -> Option<cuts::Cuts> {
        self.log.stub_cuts(id).or_else(|| self.kept.stub_cuts(id))
    }

    /// A parent the replica dropped when it forgot, by the log's note or
    /// what it keeps beside it: it contributes no cuts and is never waited
    /// for (roster.md, 3.15.6, "Dropped parents").
    fn dropped(&self, id: EventId) -> bool {
        HeldEnvelopes::dropped(self.log, id) || self.kept.dropped(id)
    }

    /// An event the log placed: an ID it or a declared cut names that the
    /// replica neither holds, keeps nor dropped reaches nothing
    /// (roster.md, 3.15.6, "Envelopes it fetches").
    fn placed(&self, id: EventId) -> bool {
        HeldEnvelopes::placed(self.log, id)
    }
}

/// A view judged with its checkpoints.
#[derive(Debug, Clone)]
pub struct Judged {
    /// Every event's status.
    pub statuses: BTreeMap<EventId, Status>,
    /// The chain in effect, oldest first.
    pub chain: Vec<EventId>,
    /// The roster of the view: that of the last world.
    pub roster: Roster,
    /// The space policy of the view.
    pub policy: Policy,
    /// Whether a hook a later document defines holds this view: a roster
    /// part of a type from 3 (roster.md, 3.16 Rules this replica lacks), a
    /// descriptor of a kind from 3 or with a key from 5 ("The space
    /// descriptor"), or a checkpoint, held or a rival, whose record uses a
    /// record key from 9, a member-entry key from 22 or a member type from
    /// 4 ("The checkpoint record"). The replica signs nothing more in the
    /// log and tells the application the space needs a version it lacks.
    pub needs_later_rules: bool,
}

/// A member of a pending checkpoint's electorate that has not voted
/// (roster.md, 3.15.4, "Waiting for").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiting {
    /// The administrator.
    pub device: DeviceId,
    /// The last event of it the replica holds, by `seq`.
    pub last: Option<EventId>,
    /// Whether the checkpoint hears it (record key 8) rather than keeps it
    /// at `administer`: an application offers a recovery member's excuse
    /// for a heard member that outranks every remaining administrator.
    pub heard: bool,
}

/// The order of authority (roster.md, 3.2 "Outranks"): `255 - rank`, then
/// seniority; the smaller key outranks.
pub type AuthorityKey = (u8, Seniority);

/// Why a device's client never cites or votes for a checkpoint not in
/// effect (roster.md, 3.15.7, "Contested checkpoints").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Contest {
    /// The checkpoint's record hears the device: its past lowered it from
    /// `administer` only by members it outranks.
    Heard,
    /// A valid roster event of the device's view, concurrent with the
    /// checkpoint, lowers its author or an administrator its record keeps,
    /// signed by a member that outranks the one it lowers.
    Lowered {
        /// The lowering event.
        event: EventId,
        /// The member it lowers.
        target: DeviceId,
    },
}

/// A device member a valid roster event lowers from `administer` at its
/// place (roster.md, 3.15.4, heard members): removes, demotes below
/// `administer` or extends `frasil.dormant` to, while it is at
/// `administer` without `frasil.dormant` there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lowered {
    /// The device lowered.
    pub device: DeviceId,
    /// Its rank at the event's place.
    pub rank: Option<u8>,
    /// Its seniority there.
    pub seniority: Seniority,
}

impl Lowered {
    /// Its key in the order of authority.
    pub fn authority_key(&self) -> AuthorityKey {
        (
            crate::change::MAX_RANK - self.rank.unwrap_or(0),
            self.seniority,
        )
    }
}

/// A valid roster event of a resolved view that lowers administrators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lowering {
    /// The event.
    pub event: EventId,
    /// Its author.
    pub author: DeviceId,
    /// Its author's key in the order of authority at its place, if in.
    pub by: Option<AuthorityKey>,
    /// The administrators it lowers.
    pub targets: Vec<Lowered>,
}

/// A roster event of a resolved view as excuses read it (roster.md,
/// 3.15.4): its author, whether its signature verified, whether it is held,
/// and for each change of a device member, the device, whether it removes
/// or changes it, and whether it lowers it (removes, demotes below
/// `administer` or extends `frasil.dormant` to).
#[derive(Debug, Clone)]
struct Excusal {
    event: EventId,
    author: DeviceId,
    verified: bool,
    held: bool,
    targets: Vec<(DeviceId, bool, bool)>,
}

/// The most senior administrator slot made for a device that is out in a
/// skeleton, with its seniority and the root or enrolment of the pseudonym
/// enrolled in it, if one is: what a standing entry names for a member a
/// checkpoint hears (peers.md, "Storage events").
type OutSlot = (frasil_peers::derive::Seniority, SlotId, Option<EventId>);

/// What a resolution of a view gives the checkpoint rules: owned, so that
/// it outlives the log a world builds.
#[derive(Debug)]
struct Outcome {
    statuses: BTreeMap<EventId, Status>,
    roster: Roster,
    policy: Policy,
    forks: BTreeMap<DeviceId, u64>,
    /// The events whose signature verified in full.
    verified: BTreeSet<EventId>,
    /// The keys the view's grants and the world root's record carry, by
    /// device.
    keys: BTreeMap<DeviceId, Arc<DeviceKeys>>,
    /// The events resolved, the genesis of a world left out.
    view: BTreeSet<EventId>,
    needs_later_rules: bool,
    /// The administrator slots of the skeleton the resolution read, when it
    /// checks twins outside a checkpoint's world.
    slots: BTreeMap<DeviceId, SlotEntry>,
    /// For each device, the most senior administrator slot made for it that
    /// is out in that skeleton, with its seniority: what a heard member's
    /// standing entry names (peers.md, "Storage events").
    out_slots: BTreeMap<DeviceId, OutSlot>,
    /// Each invite key in, or out only by valid successors, with what its
    /// successors in the view say of it (roster.md, 2.8).
    invites: Vec<InviteFact>,
    /// What the view's valid events say of each granted space, the root of
    /// a world left out (roster.md, 2.8).
    spaces: BTreeMap<EventId, SpaceFact>,
    /// The opened roster events of the view, the root of a world left out,
    /// as excuses read them (roster.md, 3.15.4).
    excusals: Vec<Excusal>,
    /// The valid roster events of the view, the root left out, that lower
    /// administrators, with their authors' standing (roster.md, 3.15.4,
    /// heard members).
    lowerings: Vec<Lowering>,
    /// The valid roster events of the view, the root left out, that grant
    /// a device `administer` or change it to `administer`.
    raises: Vec<(EventId, DeviceId)>,
    /// The view's causal order among the events above, as pairs `(a, b)`
    /// with `a` in `b`'s past.
    raised_after: BTreeSet<(EventId, EventId)>,
}

/// An invite key as a record derives it from a view.
#[derive(Debug, Clone)]
struct InviteFact {
    member: MemberRef,
    /// Its state while in; `None` once out by valid successors.
    state: Option<MemberState>,
    /// The highest status its successors in the view give it.
    status: InviteStatus,
    /// The claimant of its valid successor in the view.
    claimant: Option<MemberRef>,
    /// Its invite grant's `claims` and `expires_at`.
    claims: Option<u64>,
    expires_at: Option<u64>,
    keys: Option<Arc<DeviceKeys>>,
}

/// What a view's valid events say of one granted space.
#[derive(Debug, Clone, Default)]
struct SpaceFact {
    /// The notices of the events no other carrying event for that space
    /// follows, by encoding.
    notices: BTreeMap<Vec<u8>, RecordNotice>,
    /// A "from now on" notice for it is carried.
    floor: bool,
    /// The space's event IDs that sealed refs name.
    named: BTreeSet<EventId>,
}

impl Outcome {
    fn of(space: &Space<'_>, genesis_counts: bool) -> Self {
        let genesis = space.log().id();
        let view: BTreeSet<EventId> = space
            .view()
            .iter()
            .copied()
            .filter(|&id| genesis_counts || id != genesis)
            .collect();
        let statuses = view
            .iter()
            .filter_map(|&id| space.status(id).map(|status| (id, *status)))
            .collect_map();
        let mut keys = BTreeMap::new();
        for (member, state) in space.roster().members_in() {
            let Some(device) = member.device_id() else {
                continue;
            };
            let found = state
                .keys
                .clone()
                .or_else(|| space.screened().keys().device_keys(&device).map(Arc::new))
                .or_else(|| {
                    space
                        .root_keys()
                        .and_then(|ring| ring.device_keys(&device))
                        .map(Arc::new)
                });
            if let Some(found) = found {
                keys.insert(device, found);
            }
        }
        let needs_later_rules = space.screened().genesis().descriptor.kind.is_reserved()
            || space.screened().later_rules().iter().any(|&id| {
                space.status(id).and_then(Status::class)
                    == Some(RosterClass::from(ErrorClass::ExtensionRequired))
            });
        let (slots, out_slots) = if space.world().is_none() {
            (space.administrator_slots(), space.administrator_slots_out())
        } else {
            (BTreeMap::new(), BTreeMap::new())
        };
        // Every author of the view, by the keys any source gives: what the
        // checkpoint's signature is checked under (roster.md, 3.15.2, step 3).
        for &id in &view {
            let Some(event) = space.log().event(id) else {
                continue;
            };
            let device = *event.author();
            if keys.contains_key(&device) {
                continue;
            }
            let found = space
                .screened()
                .keys()
                .device_keys(&device)
                .or_else(|| space.root_keys().and_then(|ring| ring.device_keys(&device)));
            if let Some(found) = found {
                keys.insert(device, Arc::new(found));
            }
        }
        let invites = invite_facts(space, &statuses);
        let spaces = space_facts(space, &statuses);
        let excusals = excusal_facts(space, &view, &statuses);
        let (lowerings, raises) = lowering_facts(space);
        // Which raise follows which lowering, read once here.
        let mut raised_after = BTreeSet::new();
        for lowering in &lowerings {
            for &(raise, _) in &raises {
                if space.log().precedes(lowering.event, raise) {
                    raised_after.insert((lowering.event, raise));
                }
            }
        }
        // The keys of every lowered device, which a record's heard members
        // carry.
        for lowering in &lowerings {
            for target in &lowering.targets {
                if keys.contains_key(&target.device) {
                    continue;
                }
                let found = space
                    .screened()
                    .keys()
                    .device_keys(&target.device)
                    .or_else(|| {
                        space
                            .root_keys()
                            .and_then(|ring| ring.device_keys(&target.device))
                    });
                if let Some(found) = found {
                    keys.insert(target.device, Arc::new(found));
                }
            }
        }
        Self {
            invites,
            spaces,
            excusals,
            lowerings,
            raises,
            raised_after,
            slots,
            out_slots,
            statuses,
            roster: space.roster().clone(),
            policy: *space.policy(),
            forks: space.forks().iter().map(|(a, p)| (*a, p)).collect_map(),
            verified: view
                .iter()
                .copied()
                .filter(|&id| space.screened().counts_as_evidence(id))
                .collect(),
            keys,
            view,
            needs_later_rules,
        }
    }

    fn status(&self, id: EventId) -> Option<Status> {
        self.statuses.get(&id).copied()
    }
}

/// A checkpoint's record, as this replica reads it.
#[derive(Debug, Clone)]
enum RecordState {
    /// Missing, or not opened: the checkpoint is held.
    Unreadable,
    /// Opened, and not the one the checkpoint names: `BadCheckpoint`.
    Bad,
    /// Opened and the one the checkpoint names, using a key or member type
    /// a later document defines (roster.md, 2.8, step 3): the checkpoint is
    /// held as `ExtensionRequired`. Its `epoch` and `previous`, as keys 2
    /// and 3 alone give them ([`crate::checkpoint_record::read_link`]),
    /// when they read.
    Extension(Option<(u64, Option<EventId>)>),
    /// Read.
    Read(Arc<Record>),
    /// Validated comparison summary, awaiting derivation of the past.
    Summary(Arc<crate::RecordSummary>),
}

/// The classes that hold an event: a vote held so does not count until it
/// is judged.
fn held_class(status: &Status) -> bool {
    status.class().is_some_and(|class| {
        [
            ErrorClass::Sealed,
            ErrorClass::Pending,
            ErrorClass::NoHybridKey,
            ErrorClass::ExtensionRequired,
            ErrorClass::BadSeal,
        ]
        .iter()
        .any(|held| class == RosterClass::from(*held))
    })
}

fn checkpoint_status() -> Status {
    Status::Valid(Valid::Checkpoint)
}

/// A world's outcomes, by its root and the events it holds.
type Worlds = BTreeMap<(EventId, BTreeSet<EventId>), Rc<Outcome>>;

/// A space's log judged with its checkpoints (roster.md, 3.15).
pub struct Checkpointed<'a> {
    inputs: Inputs<'a>,
    kept: Option<Kept>,
    parts: RefCell<BTreeMap<EventId, Option<Option<CheckpointPart>>>>,
    records: RefCell<BTreeMap<EventId, RecordState>>,
    /// Whether each checkpoint whose record a later document's key holds
    /// stays held ([`Self::extension_required`]).
    held_records: RefCell<BTreeMap<EventId, bool>>,
    validity: RefCell<BTreeMap<EventId, Status>>,
    worlds: RefCell<Worlds>,
    plains: RefCell<BTreeMap<BTreeSet<EventId>, Rc<Outcome>>>,
    judged: RefCell<BTreeMap<BTreeSet<EventId>, Rc<Judged>>>,
    /// Checkpoints known stable, each over the events it was found stable
    /// over: stable over any set that holds those ([`Self::seed_stable`]).
    stable_seed: BTreeMap<EventId, BTreeSet<EventId>>,
    /// The checkpoints this judgement found stable, each over the events
    /// it was found stable over ([`Self::found_stable`]).
    found_stable: RefCell<BTreeMap<EventId, BTreeSet<EventId>>>,
    /// The checkpoint whose world's resolutions are kept
    /// ([`Self::keep_world`]), and those kept, by the events of the world.
    keep_world: Cell<Option<EventId>>,
    kept_worlds: RefCell<BTreeMap<BTreeSet<EventId>, crate::space::Resolved>>,
    /// At a replica that forgot, the events of its kept checkpoint's past
    /// that it keeps ([`Self::set_kept_past`]).
    kept_past: BTreeSet<EventId>,
}

impl core::fmt::Debug for Checkpointed<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Checkpointed")
            .field("inputs", &self.inputs)
            .field("kept", &self.kept.as_ref().map(|kept| kept.checkpoint))
            .finish_non_exhaustive()
    }
}

impl<'a> Checkpointed<'a> {
    /// A replica's log, with every event held, or with what it kept after
    /// `kept`.
    pub fn new(inputs: Inputs<'a>, kept: Option<Kept>) -> Self {
        Self {
            inputs,
            kept,
            parts: RefCell::default(),
            records: RefCell::default(),
            held_records: RefCell::default(),
            validity: RefCell::default(),
            worlds: RefCell::default(),
            plains: RefCell::default(),
            judged: RefCell::default(),
            stable_seed: BTreeMap::new(),
            found_stable: RefCell::default(),
            keep_world: Cell::new(None),
            kept_worlds: RefCell::default(),
            kept_past: BTreeSet::new(),
        }
    }

    /// Takes as known the judgement of the events `held`, as an earlier
    /// judgement of the same log made it under the same keys, other logs,
    /// record objects and envelopes: a judgement of a set of events is a
    /// function of that set and those, so it would be made again the same.
    /// What a replica keeps of the past of the first checkpoint of its
    /// chain, which every judgement reads and none changes.
    pub fn seed_judged(&mut self, held: BTreeSet<EventId>, judged: Judged) {
        self.judged.get_mut().insert(held, Rc::new(judged));
    }

    /// The judgement of the events `held` this one made or was given, if
    /// any: what a later judgement takes with [`Self::seed_judged`].
    pub fn judged_over(&self, held: &BTreeSet<EventId>) -> Option<Judged> {
        self.judged
            .borrow()
            .get(held)
            .map(|judged| (**judged).clone())
    }

    /// Keeps the resolutions of `c`'s world this judgement makes, so that
    /// [`Self::take_world`] hands one over: a replica resumes it as units
    /// after `c` arrive ([`Space::resolve_appended_world`]) instead of
    /// judging the world again.
    pub fn keep_world(&self, c: EventId) {
        self.keep_world.set(Some(c));
    }

    /// The resolution of `c`'s world over the events of `held` that are
    /// `c` or follow it, as this judgement made it, when `c` is the
    /// checkpoint [`Self::keep_world`] named and the world resolved.
    pub fn take_world(
        &self,
        c: EventId,
        held: &BTreeSet<EventId>,
    ) -> Option<crate::space::Resolved> {
        if self.keep_world.get() != Some(c) {
            return None;
        }
        let members: BTreeSet<EventId> = held
            .iter()
            .copied()
            .filter(|&id| id == c || self.follows_known(id, c))
            .collect();
        self.kept_worlds.borrow_mut().remove(&members)
    }

    /// The checkpoints among `members` other than `c` whose record this
    /// replica cannot read: in `c`'s world each is held, with every event
    /// after it ([`Self::presets_after`]).
    pub fn unreadable_in(&self, c: EventId, members: &BTreeSet<EventId>) -> Vec<EventId> {
        members
            .iter()
            .copied()
            .filter(|&id| id != c && self.is_checkpoint(id) && !self.readable(id))
            .collect()
    }

    /// The verdicts decided before the procedure, in `c`'s world, for
    /// events `added` to it since it was built (`world` holds them now):
    /// those the world's presets give them over the larger set of members,
    /// with `unreadable` the checkpoints of the world whose record this
    /// replica cannot read ([`Self::unreadable_in`]). An added checkpoint
    /// is left out, for its caller judges the world again.
    pub fn presets_after(
        &self,
        c: EventId,
        world: &WorldLog,
        unreadable: &[EventId],
        added: &[EventId],
    ) -> BTreeMap<EventId, Status> {
        let mut out = BTreeMap::new();
        for &id in added {
            if id == c {
                continue;
            }
            let Some(event) = self.log().event(id) else {
                continue;
            };
            match self.cuts_check(id) {
                CutsCheck::Bad => {
                    out.insert(id, Status::void_with(frasil_events::EventClass::BadCuts));
                }
                CutsCheck::Pending(_) => {
                    out.insert(id, Status::void_with(ErrorClass::Pending));
                }
                CutsCheck::Correct => {
                    let mut mixed = false;
                    let mut waiting = false;
                    for &p in event.parents() {
                        if Some(p) == event.prev() || p == c {
                            continue;
                        }
                        match self.follows(p, c) {
                            Ok(true) => {}
                            Ok(false) => mixed = true,
                            Err(_) => waiting = true,
                        }
                    }
                    if mixed {
                        out.insert(id, Status::void_with(SpaceClass::MixedCut));
                    } else if waiting {
                        out.insert(id, Status::void_with(ErrorClass::Pending));
                    }
                }
            }
            if unreadable.iter().any(|&u| world.log().precedes(u, id)) {
                out.insert(id, Status::void_with(ErrorClass::Pending));
            }
        }
        out
    }

    /// Takes as known that each checkpoint of `stable` is stable over the
    /// events it maps to, as an earlier judgement of the same log found it
    /// ([`Self::found_stable`]). Stability only grows as events arrive
    /// (roster.md, 3.15.4: a vote is never taken back, and excuses only
    /// accumulate), so each is stable over any set of events that holds
    /// those, and [`Self::stable`] answers so without counting its votes
    /// again.
    pub fn seed_stable(&mut self, stable: BTreeMap<EventId, BTreeSet<EventId>>) {
        self.stable_seed = stable;
    }

    /// The checkpoints this judgement found stable, each with the events
    /// it was found stable over: what a later judgement of the same log
    /// takes with [`Self::seed_stable`].
    pub fn found_stable(&self) -> BTreeMap<EventId, BTreeSet<EventId>> {
        self.found_stable.borrow().clone()
    }

    /// Takes the records of checkpoints read by an earlier judgement of the
    /// same log: a record object is bound to its checkpoint by digest
    /// (roster.md, "The record object"), so the record read once is the
    /// one read again.
    pub fn seed_records(&mut self, records: impl IntoIterator<Item = (EventId, Arc<Record>)>) {
        let mut held = self.records.borrow_mut();
        for (c, record) in records {
            held.entry(c).or_insert(RecordState::Read(record));
        }
    }

    /// Takes the final validity verdicts of checkpoints an earlier
    /// judgement of the same log, with the same kept checkpoint, found: a
    /// checkpoint is judged on its own past alone (roster.md, 3.15.2), and
    /// a final verdict does not change as events arrive. Held verdicts are
    /// left out, and judged again.
    pub fn seed_validity(&mut self, known: impl IntoIterator<Item = (EventId, Status)>) {
        let mut held = self.validity.borrow_mut();
        for (c, status) in known {
            if !held_class(&status) {
                held.entry(c).or_insert(status);
            }
        }
    }

    /// The validity verdicts this judgement reached that are final, to
    /// seed a later one with [`Self::seed_validity`].
    pub fn final_validity(&self) -> BTreeMap<EventId, Status> {
        self.validity
            .borrow()
            .iter()
            .filter(|(_, status)| !held_class(status))
            .map(|(c, status)| (*c, *status))
            .collect_map()
    }

    fn log(&self) -> &'a Log {
        self.inputs.log
    }

    fn envelopes(&self) -> Envelopes<'a> {
        Envelopes {
            log: self.inputs.log,
            kept: self.inputs.envelopes,
        }
    }

    fn keys(&self) -> &'a Keyring {
        self.inputs.options.keys
    }

    // -- Reading the log: which events are checkpoints, what each declares

    /// A space event's checkpoint part: `Some(None)` for an event that is
    /// not a checkpoint, `None` while the replica cannot open it.
    pub fn checkpoint_part(&self, id: EventId) -> Option<Option<CheckpointPart>> {
        if let Some(known) = self.parts.borrow().get(&id) {
            return known.clone();
        }
        let found = match self.envelopes().held_envelope(id) {
            None => None,
            Some(event) if !cuts::may_be_checkpoint(event) => Some(None),
            Some(event) => {
                let in_past = |_: EventId| true;
                let context = ScreenContext {
                    space: self.log().id(),
                    limits: &self.inputs.options.limits,
                    in_past: &in_past,
                };
                match screen_body(event, &context, self.keys()) {
                    Body::Opened(opened) => Some(opened.checkpoint().cloned()),
                    Body::Held(_) => None,
                    Body::Refused(_) | Body::Void(_) => Some(None),
                }
            }
        };
        self.parts.borrow_mut().insert(id, found.clone());
        found
    }

    /// Whether an event is a checkpoint this replica opened.
    pub fn is_checkpoint(&self, id: EventId) -> bool {
        matches!(self.checkpoint_part(id), Some(Some(_)))
    }

    /// A checkpoint the replica holds the envelope of but cannot open is
    /// taken as one where only a checkpoint can stand: in another's cuts.
    fn maybe_checkpoint(&self, id: EventId) -> bool {
        !matches!(self.checkpoint_part(id), Some(None))
    }

    fn record_state(&self, c: EventId) -> RecordState {
        if let Some(state) = self.records.borrow().get(&c) {
            return state.clone();
        }
        let state = match &self.kept {
            Some(kept) if kept.checkpoint == c => RecordState::Read(Arc::clone(&kept.record)),
            _ => match self.checkpoint_part(c) {
                Some(Some(part)) => match self.inputs.objects.record_object(c, &part) {
                    RecordObject::Missing => RecordState::Unreadable,
                    RecordObject::Refused => RecordState::Bad,
                    RecordObject::Extension(link) => RecordState::Extension(link),
                    RecordObject::Read(record) => RecordState::Read(record),
                    RecordObject::Summary(summary) => RecordState::Summary(summary),
                    RecordObject::Opened(plaintext) => match Record::read_object(&plaintext, &part)
                    {
                        Ok(record) => RecordState::Read(Arc::new(record)),
                        Err(class) if class.shared() == Some(ErrorClass::ExtensionRequired) => {
                            RecordState::Extension(
                                crate::checkpoint_record::read_link(&plaintext)
                                    .filter(|(epoch, _)| *epoch == part.epoch),
                            )
                        }
                        Err(_) => RecordState::Bad,
                    },
                },
                _ => RecordState::Unreadable,
            },
        };
        let held_cut = self.inputs.options.twins == crate::Twins::Skeleton
            && self
                .envelopes()
                .held_envelope(c)
                .and_then(frasil_peers::skeleton::named_twin)
                .and_then(|id| self.log().event(id))
                .is_some_and(|event| {
                    event.kind() == frasil_events::kind::STORAGE
                        && frasil_peers::body::StorageBody::read(event.unverified_body())
                            .is_err_and(|class| {
                                class.shared() == Some(ErrorClass::ExtensionRequired)
                            })
                });
        let state = match state {
            RecordState::Read(record) if held_cut => {
                RecordState::Extension(Some((record.epoch, record.previous)))
            }
            RecordState::Summary(summary) if held_cut => {
                RecordState::Extension(Some((summary.epoch, summary.previous)))
            }
            other => other,
        };
        self.records.borrow_mut().insert(c, state.clone());
        state
    }

    /// A checkpoint's record, once read and matched against the checkpoint.
    pub fn record(&self, c: EventId) -> Option<Arc<Record>> {
        match self.record_state(c) {
            RecordState::Read(record) => Some(record),
            RecordState::Summary(_) => {
                self.validity(c);
                match self.records.borrow().get(&c) {
                    Some(RecordState::Read(record)) => Some(Arc::clone(record)),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Whether this replica can read a checkpoint's record, matched or not:
    /// it holds the object, and no later document's key or member type
    /// holds it, or one does and a step that reads no record voided the
    /// checkpoint for good ([`Self::extension_required`]).
    fn readable(&self, c: EventId) -> bool {
        match self.record_state(c) {
            RecordState::Bad | RecordState::Read(_) | RecordState::Summary(_) => true,
            RecordState::Extension(_) => !self.extension_required(c),
            RecordState::Unreadable => false,
        }
    }

    /// Whether a checkpoint's record uses a record key from 9, a
    /// member-entry key from 22 or a member type from 4, which later
    /// documents define and this implementation does not (roster.md, 2.8
    /// The checkpoint record, step 3): the checkpoint is held as
    /// `ExtensionRequired`, with every event after it. The replica never
    /// votes for it, never cites it, and a newcomer never starts from it;
    /// it tells the application that the space needs a version it lacks.
    /// Steps 2 to 6 of its validity, which read no record, still decide it
    /// (roster.md, 3.15.2, "A record held for a later document's key"): one
    /// that one of them voids for good, such as a writer's, is judged as any
    /// void checkpoint instead, and is not held; so is one a step holds for
    /// another reason, such as a checkpoint in its past held for its record.
    pub fn extension_required(&self, c: EventId) -> bool {
        let RecordState::Extension(link) = self.record_state(c) else {
            return false;
        };
        if let Some(&known) = self.held_records.borrow().get(&c) {
            return known;
        }
        let held = link.is_none()
            || self.log().event(c).is_none()
            || self.validity(c).class() == Some(RosterClass::from(ErrorClass::ExtensionRequired));
        self.held_records.borrow_mut().insert(c, held);
        held
    }

    /// The checkpoints an event's cuts reach (events.md, "Cuts"); none for
    /// an event whose envelope is not held.
    ///
    /// # Errors
    ///
    /// The checkpoints whose envelopes the walk waits for: the replica
    /// neither holds nor keeps them, and what reads the answer is pending
    /// until it fetches them, never void.
    pub fn reach(&self, id: EventId) -> Result<BTreeSet<EventId>, Vec<EventId>> {
        let envelopes = self.envelopes();
        match envelopes.envelope(id) {
            Some(event) => cuts::reach(&envelopes, event.cuts()),
            None => Ok(BTreeSet::new()),
        }
    }

    /// Whether checkpoint `x` is at or before checkpoint `y`.
    ///
    /// # Errors
    ///
    /// As [`cuts::at_or_before`]: the envelopes the answer waits for.
    pub fn at_or_before(&self, x: EventId, y: EventId) -> Result<bool, Vec<EventId>> {
        cuts::at_or_before(&self.envelopes(), x, y)
    }

    /// Whether two checkpoints are concurrent.
    ///
    /// # Errors
    ///
    /// As [`cuts::concurrent`]: the envelopes the answer waits for.
    pub fn concurrent(&self, x: EventId, y: EventId) -> Result<bool, Vec<EventId>> {
        cuts::concurrent(&self.envelopes(), x, y)
    }

    /// Whether an event follows checkpoint `c`: its cuts reach `c`.
    ///
    /// # Errors
    ///
    /// The envelopes the answer waits for, when the walk has not found `c`
    /// and could not go below them.
    pub fn follows(&self, id: EventId, c: EventId) -> Result<bool, Vec<EventId>> {
        let envelopes = self.envelopes();
        match envelopes.envelope(id) {
            Some(event) => cuts::follows(&envelopes, event, c),
            None => Ok(false),
        }
    }

    /// Whether an event follows `c`, as the rules that only gather what
    /// follows read it: an event whose following waits for envelopes is not
    /// gathered yet, so a vote or an event after `c` counts only once the
    /// replica can place it. Its own verdict is `Pending` ([`Self::judge`]).
    fn follows_known(&self, id: EventId, c: EventId) -> bool {
        self.follows(id, c) == Ok(true)
    }

    /// An event's cuts checked against its parents.
    pub fn cuts_check(&self, id: EventId) -> CutsCheck {
        let envelopes = self.envelopes();
        match envelopes.held_envelope(id) {
            Some(event) => cuts::check(&envelopes, self, event),
            None => CutsCheck::Pending(vec![id]),
        }
    }

    /// Whether the replica holds `c` and every event of its past whole: a
    /// replica that forgot cannot judge on a past it does not hold.
    fn past_complete(&self, c: EventId) -> bool {
        let log = self.log();
        let mut events = log.past(c);
        events.insert(c);
        events.iter().all(|&id| {
            log.event(id)
                .is_some_and(|event| event.parents().iter().all(|p| log.contains(*p)))
        })
    }

    // -- Resolutions

    /// A view resolved with no checkpoint in effect: each checkpoint with
    /// its own verdict.
    fn plain(&self, view: &BTreeSet<EventId>) -> Rc<Outcome> {
        if let Some(hit) = self.plains.borrow().get(view) {
            return Rc::clone(hit);
        }
        let presets = self.presets_outside(view);
        let outcome = match Space::resolve_checkpointed(
            self.log(),
            Some(view),
            self.inputs.options,
            Checkpointing {
                presets,
                world: None,
            },
        ) {
            Ok(space) => Outcome::of(&space, true),
            Err(class) => unusable(view, class),
        };
        let outcome = Rc::new(outcome);
        self.plains
            .borrow_mut()
            .insert(view.clone(), Rc::clone(&outcome));
        outcome
    }

    /// The world of checkpoint `c` over `view`: `c` and the events of
    /// `view` that follow it.
    fn world(&self, c: EventId, view: &BTreeSet<EventId>) -> Rc<Outcome> {
        let members: BTreeSet<EventId> = view
            .iter()
            .copied()
            .filter(|&id| id == c || self.follows_known(id, c))
            .collect();
        let key = (c, members.clone());
        if let Some(hit) = self.worlds.borrow().get(&key) {
            return Rc::clone(hit);
        }
        let outcome = match (WorldLog::new(self.log(), c, &members), self.record(c)) {
            (Ok(world), Some(record)) => {
                let presets = self.presets_in_world(&world, c, &members);
                let skeleton = match self.inputs.options.twins {
                    crate::Twins::Skeleton => self.world_skeleton(c, &members),
                    crate::Twins::Assumed => None,
                };
                match world.resolve_with_skeleton(self.inputs.options, &record, presets, skeleton) {
                    Ok(space) => {
                        let mut outcome = Outcome::of(&space, false);
                        if self.inputs.options.twins == crate::Twins::Skeleton {
                            (outcome.slots, outcome.out_slots) =
                                self.world_slots(c, &record, &members, &space);
                        }
                        if self.keep_world.get() == Some(c)
                            && let Some(resolved) = space.into_resolved_world()
                        {
                            self.kept_worlds
                                .borrow_mut()
                                .insert(members.clone(), resolved);
                        }
                        outcome
                    }
                    Err(class) => unusable(&members, class),
                }
            }
            (Err(class), _) => unusable(&members, class),
            (_, None) => unusable(&members, ErrorClass::Sealed.into()),
        };
        let outcome = Rc::new(outcome);
        self.worlds.borrow_mut().insert(key, Rc::clone(&outcome));
        outcome
    }

    /// The skeleton a replica reads in `c`'s world over `members` (roster.md,
    /// 3.15.5, Skeleton): the skeleton after `c`'s cut, its slots in and
    /// enrolled to the pseudonyms of the roots and enrolments its entries
    /// name, over the skeleton events after `c`, whatever a peer's rule
    /// says of that cut. A later cut among them is judged on its own past,
    /// and the skeleton does not move to it. `None` when `c` names no cut
    /// the log holds, which a checkpoint in effect always does.
    fn world_skeleton(
        &self,
        c: EventId,
        members: &BTreeSet<EventId>,
    ) -> Option<frasil_peers::skeleton::Skeleton<'a>> {
        let log = self.log();
        let cut = log
            .event(c)
            .and_then(frasil_peers::skeleton::named_twin)
            .filter(|&cut| log.event(cut).is_some())?;
        let body = log.event(cut).and_then(frasil_peers::cut::read_cut)?;
        let members: BTreeSet<EventId> = members.iter().copied().filter(|&id| id != c).collect();
        let held: BTreeSet<EventId> = members.iter().copied().chain([cut]).collect();
        let envelopes = self.envelopes();
        let peer = frasil_peers::cut::PeerCuts::truncated(log, &envelopes, held, cut);
        let presets = peer
            .cuts()
            .map(|(id, _)| id)
            .filter(|&id| id != cut && members.contains(&id))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|id| (id, peer.validity(id)))
            .collect_map();
        Some(frasil_peers::skeleton::Skeleton::after_cut(
            log, cut, &body, members, presets,
        ))
    }

    /// The administrator slots of the skeleton in `c`'s world over
    /// `members` (roster.md, 3.15.5, Skeleton), by the device each was made
    /// for: the skeleton after `c`'s cut, its slots in and enrolled to the
    /// pseudonyms its entries name, over the skeleton events after `c`,
    /// whatever a peer's rule says of that cut; a later cut is left out,
    /// since the skeleton moves to it only with its checkpoint. A slot of
    /// the cut maps to the device whose member entry in `c`'s record names
    /// it in key 13; another, to the device the roster event that made it
    /// grants. Of two slots of one device, the most senior. What the record
    /// of a checkpoint whose predecessor is `c` names in key 13; and, apart,
    /// the most senior slot of each device that is out there, which that
    /// checkpoint's cut names for a member it hears.
    #[allow(clippy::type_complexity)]
    fn world_slots(
        &self,
        c: EventId,
        record: &Record,
        members: &BTreeSet<EventId>,
        space: &Space<'_>,
    ) -> (BTreeMap<DeviceId, SlotEntry>, BTreeMap<DeviceId, OutSlot>) {
        let log = self.log();
        let Some(cut) = log
            .event(c)
            .and_then(frasil_peers::skeleton::named_twin)
            .filter(|&cut| log.event(cut).is_some())
        else {
            return Default::default();
        };
        let Some(body) = log.event(cut).and_then(frasil_peers::cut::read_cut) else {
            return Default::default();
        };
        let held: BTreeSet<EventId> = members
            .iter()
            .copied()
            .filter(|&id| id != c)
            .filter(|&id| {
                log.event(id)
                    .is_none_or(|event| frasil_peers::cut::read_cut(event).is_none())
            })
            .chain([cut])
            .collect();
        let envelopes = self.envelopes();
        let peer = frasil_peers::cut::PeerCuts::truncated(log, &envelopes, held, cut);
        let skeleton = peer.skeleton();
        let base: BTreeSet<SlotId> = body.slots.iter().map(|entry| entry.slot).collect();
        let mapping: BTreeMap<SlotId, DeviceId> = record
            .members
            .iter()
            .filter_map(|entry| {
                let slot = entry.slot.as_ref()?;
                let index = u8::try_from(slot.index).ok()?;
                Some((
                    SlotId::new(slot.commitment, index, slot.maker),
                    DeviceId(entry.member.id),
                ))
            })
            .collect_map();
        let mut found: BTreeMap<DeviceId, (frasil_peers::derive::Seniority, SlotId)> =
            BTreeMap::new();
        let mut out: BTreeMap<DeviceId, (frasil_peers::derive::Seniority, SlotId)> =
            BTreeMap::new();
        for (&slot, state) in skeleton.merged() {
            let device = match base.contains(&slot) {
                true => mapping.get(&slot).copied(),
                false => space.slot_device_in(&skeleton, slot),
            };
            let (Some(device), Some(seniority)) = (device, skeleton.seniority(slot)) else {
                continue;
            };
            let into = match state.is_in {
                true => &mut found,
                false => &mut out,
            };
            let better = into.get(&device).is_none_or(|(held, _)| seniority < *held);
            if better {
                into.insert(device, (seniority, slot));
            }
        }
        let out = out
            .into_iter()
            .map(|(device, (seniority, slot))| {
                let enrolled = frasil_peers::cut::enrolment_of(&skeleton, slot);
                (device, (seniority, slot, enrolled))
            })
            .collect_map();
        let found = found
            .into_iter()
            .map(|(device, (_, slot))| {
                let enrolled = skeleton.merged().get(&slot).and_then(|s| s.enrolled);
                (
                    device,
                    SlotEntry {
                        commitment: slot.reference.commitment,
                        index: u64::from(slot.reference.index),
                        maker: slot.maker,
                        pseudonym: enrolled.map(|p| p.0.to_vec()).unwrap_or_default(),
                    },
                )
            })
            .collect_map();
        (found, out)
    }

    /// The verdicts decided before the procedure in a view with no
    /// checkpoint in effect: cuts that do not match, and each checkpoint's
    /// own validity; then what follows a checkpoint whose record this
    /// replica cannot read is held.
    fn presets_outside(&self, view: &BTreeSet<EventId>) -> BTreeMap<EventId, Status> {
        let genesis = self.log().id();
        let mut out = BTreeMap::new();
        for &id in view {
            if id == genesis {
                continue;
            }
            match self.cuts_check(id) {
                CutsCheck::Bad => {
                    out.insert(id, Status::void_with(frasil_events::EventClass::BadCuts));
                }
                CutsCheck::Pending(_) => {
                    out.insert(id, Status::void_with(ErrorClass::Pending));
                }
                CutsCheck::Correct => {
                    if self.is_checkpoint(id) {
                        out.insert(id, self.validity(id));
                    }
                }
            }
        }
        self.hold_unreadable(view, &mut out, |a, b| self.log().precedes(a, b));
        out
    }

    /// The verdicts decided before the procedure in the world of `c`:
    /// events with cuts that do not match are void (`BadCuts`); an event
    /// after `c` one of whose parents other than its `prev` is neither `c`
    /// nor after `c` is void (`MixedCut`); a later checkpoint has the
    /// verdict of its own past.
    fn presets_in_world(
        &self,
        world: &WorldLog,
        c: EventId,
        members: &BTreeSet<EventId>,
    ) -> BTreeMap<EventId, Status> {
        let mut out = BTreeMap::new();
        for &id in members {
            if id == c {
                continue;
            }
            let Some(event) = self.log().event(id) else {
                continue;
            };
            match self.cuts_check(id) {
                CutsCheck::Bad => {
                    out.insert(id, Status::void_with(frasil_events::EventClass::BadCuts));
                    continue;
                }
                CutsCheck::Pending(_) => {
                    out.insert(id, Status::void_with(ErrorClass::Pending));
                    continue;
                }
                CutsCheck::Correct => {}
            }
            // A parent whose following waits for envelopes holds the event
            // (`Pending`), never voids it.
            let mut mixed = false;
            let mut waiting = false;
            for &p in event.parents() {
                if Some(p) == event.prev() || p == c {
                    continue;
                }
                match self.follows(p, c) {
                    Ok(true) => {}
                    Ok(false) => mixed = true,
                    Err(_) => waiting = true,
                }
            }
            if mixed {
                out.insert(id, Status::void_with(SpaceClass::MixedCut));
            } else if waiting {
                out.insert(id, Status::void_with(ErrorClass::Pending));
            }
        }
        let log = world.log();
        let mut order: Vec<EventId> = members
            .iter()
            .copied()
            .filter(|&id| id != c && !out.contains_key(&id) && self.is_checkpoint(id))
            .collect();
        order.sort_by_key(|&id| (log.height(id).unwrap_or(0), id));
        for id in order {
            let status = self.validity(id);
            out.insert(id, status);
        }
        let view: BTreeSet<EventId> = members.iter().copied().filter(|&id| id != c).collect();
        self.hold_unreadable(&view, &mut out, |a, b| log.precedes(a, b));
        out
    }

    /// A checkpoint whose record this replica cannot read is held as one it
    /// cannot open (`Sealed`), with every event after it (`Pending`); one
    /// whose record a later document's key or member type holds, and every
    /// event after it, as `ExtensionRequired`.
    fn hold_unreadable(
        &self,
        view: &BTreeSet<EventId>,
        out: &mut BTreeMap<EventId, Status>,
        precedes: impl Fn(EventId, EventId) -> bool,
    ) {
        let held: Vec<EventId> = view
            .iter()
            .copied()
            .filter(|&id| self.is_checkpoint(id) && !self.readable(id))
            .collect();
        if held.is_empty() {
            return;
        }
        let extension: Vec<EventId> = held
            .iter()
            .copied()
            .filter(|&id| self.extension_required(id))
            .collect();
        for &id in &held {
            let class = match extension.contains(&id) {
                true => ErrorClass::ExtensionRequired,
                false => ErrorClass::Sealed,
            };
            out.insert(id, Status::void_with(class));
        }
        for &id in view {
            if held.contains(&id) || !held.iter().any(|&h| precedes(h, id)) {
                continue;
            }
            let class = match extension.iter().any(|&x| precedes(x, id)) {
                true => ErrorClass::ExtensionRequired,
                false => ErrorClass::Pending,
            };
            out.insert(id, Status::void_with(class));
        }
    }

    // -- A checkpoint: its record, its validity, its votes

    /// roster.md, 3.15.2 A checkpoint's validity, in order, on its own past
    /// alone: [`Valid::Checkpoint`], or void with its class. The kept
    /// checkpoint is valid.
    pub fn validity(&self, c: EventId) -> Status {
        if self.kept.as_ref().is_some_and(|kept| kept.checkpoint == c) {
            return checkpoint_status();
        }
        if let Some(&known) = self.validity.borrow().get(&c) {
            return known;
        }
        // A cycle never arises, since a checkpoint's validity reads only
        // checkpoints its cuts reach; guard anyway.
        self.validity
            .borrow_mut()
            .insert(c, Status::void_with(ErrorClass::Pending));
        let status = match self.judge_validity(c) {
            Ok(()) => checkpoint_status(),
            Err(class) => Status::void_with(class),
        };
        self.validity.borrow_mut().insert(c, status);
        status
    }

    fn judge_validity(&self, c: EventId) -> Result<(), RosterClass> {
        let log = self.log();
        let event = log.event(c).ok_or(ErrorClass::Pending)?;
        match self.checkpoint_part(c) {
            Some(Some(_)) => {}
            Some(None) => return Err(ErrorClass::Malformed.into()),
            None => return Err(ErrorClass::Sealed.into()),
        }
        // 1. The event alone and its cuts; its record; no checkpoint held
        //    for its record in its past (with a predecessor, in the part of
        //    its past that is the predecessor's world).
        match self.cuts_check(c) {
            CutsCheck::Bad => return Err(frasil_events::EventClass::BadCuts.into()),
            CutsCheck::Pending(_) => return Err(ErrorClass::Pending.into()),
            CutsCheck::Correct => {}
        }
        // A record held for a later document's key (roster.md, 3.15.2, "A
        // record held for a later document's key"): steps 2 to 6, which
        // read no record, still decide it in order, with the predecessor
        // keys 2 and 3 of its record's map name. A failure is final; a step
        // that holds it holds it there; one that passes them all stays
        // held. A replica that forgot cannot run them, and holds it.
        let held = RosterClass::from(ErrorClass::ExtensionRequired);
        let state = self.record_state(c);
        let (record, previous) = match state.clone() {
            RecordState::Unreadable => return Err(ErrorClass::Sealed.into()),
            RecordState::Bad => return Err(SpaceClass::BadCheckpoint.into()),
            RecordState::Extension(None) => return Err(held),
            RecordState::Extension(Some(_)) if self.kept.is_some() => return Err(held),
            RecordState::Extension(Some((_, previous))) => (None, previous),
            RecordState::Summary(summary) => (None, summary.previous),
            RecordState::Read(record) => {
                let previous = record.previous;
                (Some(record), previous)
            }
        };
        let past = log.past(c);
        let pool = past.iter().copied().filter(|&x| match previous {
            None => true,
            Some(p) => x == p || self.follows_known(x, p),
        });
        if pool
            .collect::<Vec<_>>()
            .into_iter()
            .any(|x| self.is_checkpoint(x) && !self.readable(x))
        {
            return Err(ErrorClass::Pending.into());
        }
        // An order that waits for envelopes holds the checkpoint
        // (`Pending`): none of the final classes below is read without it.
        let pending = |_: Vec<EventId>| RosterClass::from(ErrorClass::Pending);
        let reach = self.reach(c).map_err(pending)?;
        let reached: Vec<EventId> = reach
            .iter()
            .copied()
            .filter(|&x| self.maybe_checkpoint(x))
            .collect();
        let valid_checkpoint = |x: EventId| {
            self.kept.as_ref().is_some_and(|kept| kept.checkpoint == x)
                || (self.is_checkpoint(x) && self.validity(x).is_valid())
        };
        // 2. The predecessor.
        let world = match previous {
            None => {
                // It names none, past a valid checkpoint: decidable at a
                // replica that forgot, which keeps the one its cuts reach.
                if reached.iter().any(|&x| valid_checkpoint(x)) {
                    return Err(SpaceClass::BadCheckpoint.into());
                }
                if !self.past_complete(c) {
                    // A checkpoint concurrent with the kept one, at a
                    // replica that forgot its past: held (roster.md,
                    // 3.15.6).
                    return Err(ErrorClass::Pending.into());
                }
                self.plain(&past)
            }
            Some(p) => {
                let mut concurrent = false;
                let mut later = false;
                for &x in &reached {
                    concurrent |= self.concurrent(x, p).map_err(pending)?;
                    later |=
                        x != p && self.at_or_before(p, x).map_err(pending)? && valid_checkpoint(x);
                }
                // A valid checkpoint after `p` has `p` among the checkpoints
                // its cuts reach and every checkpoint of its past readable:
                // `p` is a checkpoint with a readable record, even to a
                // replica that forgot `p` and cannot open it now, which so
                // judges as one that kept it.
                let known = later
                    || self.kept.as_ref().is_some_and(|kept| kept.checkpoint == p)
                    || (self.is_checkpoint(p) && self.readable(p));
                if !known || !reach.contains(&p) || concurrent {
                    return Err(SpaceClass::BadCheckpoint.into());
                }
                if later {
                    return Err(SpaceClass::CheckpointPending.into());
                }
                if !self.validity(p).is_valid() {
                    return Err(SpaceClass::BadCheckpoint.into());
                }
                let mut held = self.past_in_world(p, c).map_err(pending)?;
                held.remove(&c);
                held.insert(p);
                if held
                    .iter()
                    .any(|&i| i != p && self.is_checkpoint(i) && self.validity(i).is_valid())
                {
                    return Err(SpaceClass::CheckpointPending.into());
                }
                if !self.stable(p, &held) {
                    return Err(SpaceClass::CheckpointPending.into());
                }
                self.world(p, &held)
            }
        };
        // 3. Its signature, under keys of its past as its world lets a
        //    replica take them, and the other logs it holds: it waits for
        //    step 2, so no key from before a kept checkpoint is needed.
        let author = *event.author();
        let keys = world
            .keys
            .get(&author)
            .map(|keys| keys.keys.clone())
            .filter(|keys| keys.commitment() == event.kc())
            .or_else(|| self.inputs.options.others.hybrid_keys(event.kc()));
        match crate::screen::check_signature(event, keys.as_ref()) {
            crate::screen::Signature::Verified => {}
            // Held either way, a held record as `ExtensionRequired`.
            crate::screen::Signature::NoHybridKey if matches!(state, RecordState::Extension(_)) => {
                return Err(held);
            }
            crate::screen::Signature::NoHybridKey => return Err(ErrorClass::NoHybridKey.into()),
            crate::screen::Signature::BadSignature => {
                return Err(ErrorClass::BadSignature.into());
            }
        }
        // 4. Its author's fork point.
        if world
            .forks
            .get(&author)
            .is_some_and(|&point| event.seq() >= point)
        {
            return Err(ErrorClass::Forked.into());
        }
        // 5. Its author in at administer.
        let me = world.roster.state(&MemberRef::device(author));
        if me.is_none_or(|state| state.level != Level::Administer) {
            return Err(ErrorClass::NotAnAdministrator.into());
        }
        // 6. keys.md's checks against it as a genesis: its author is at
        //    `administer`, which never carries `session` (roster.md, 3.6),
        //    so it propagates, and a checkpoint is a grant rotation exactly
        //    when the space is not restricted (roster.md, 3.15.2, "Step 6").
        let opened_facts = {
            let in_past = |_: EventId| true;
            let context = ScreenContext {
                space: log.id(),
                limits: &self.inputs.options.limits,
                in_past: &in_past,
            };
            match screen_body(event, &context, self.keys()) {
                Body::Opened(opened) => opened.facts(),
                _ => return Err(ErrorClass::Sealed.into()),
            }
        };
        let context = Context::checkpoint(true, self.descriptor_restricted());
        check_context(Some(opened_facts), &context)?;
        if record.is_none() && !matches!(state, RecordState::Summary(_)) {
            return Err(held);
        }
        // 7. Its twin, the skeleton cut key 15 names, by peers.md's checks
        //    of a cut: before the record, whose `slot` entries read the
        //    skeleton after the predecessor's cut, which a valid cut proves
        //    in effect in its past (roster.md, 3.15.2, "Why the twin comes
        //    before the record").
        let skeleton = self.inputs.options.twins == crate::Twins::Skeleton;
        if skeleton {
            self.twin_cut(c, event)?;
        }
        // 8. Its record, byte for byte, space members' keys 18 to 20 left
        //    out of both (roster.md, 2.8).
        let derived = self
            .record_of(&world, previous)
            .ok_or(SpaceClass::BadCheckpoint)?;
        let record = match state {
            RecordState::Summary(summary) => {
                if derived.compared_digest() != summary.compared_digest {
                    return Err(SpaceClass::BadCheckpoint.into());
                }
                Arc::new(derived.with_space_fields(&summary.space_fields))
            }
            _ => {
                let record = record.ok_or(SpaceClass::BadCheckpoint)?;
                if derived.compared_digest() != record.compared_digest() {
                    return Err(SpaceClass::BadCheckpoint.into());
                }
                record
            }
        };
        // 9. The cut against the record (roster.md, 3.15.8, "Twins and the
        //    skeleton"; peers.md, "Skeleton cuts"): its slot entries, and
        //    its standing entries exactly those the record gives.
        if skeleton {
            let bad = || RosterClass::from(frasil_peers::PeersClass::BadTwin);
            let twin = frasil_peers::skeleton::named_twin(event).ok_or_else(bad)?;
            let cut = log
                .event(twin)
                .and_then(frasil_peers::cut::read_cut)
                .ok_or_else(bad)?;
            frasil_peers::cut::check_against_record(log, &cut, &record_slots(&record))
                .map_err(|_| bad())?;
            frasil_peers::cut::check_standing(&cut, &self.standing_of(&record, &world))
                .map_err(|_| bad())?;
        }
        self.records
            .borrow_mut()
            .insert(c, RecordState::Read(record));
        Ok(())
    }

    /// Step 7 of a checkpoint's validity (roster.md, 3.15.2): visible key
    /// 15 names a skeleton cut (`TwinRequired`), which the checkpoint cites,
    /// read from its own parents without the cut (`BadTwin`: a peer holds
    /// such a cut pending, `Unnamed`, and never serves it); every other
    /// parent of the checkpoint is in the cut's past, and the cut passes
    /// peers.md's checks of a cut (section 3.21, steps 1 to 7) run over what
    /// the replica holds: a replica that forgot runs them as a peer that
    /// truncated under its kept checkpoint's cut (`BadTwin`). A cut the
    /// checkpoint cites is a parent, which the log holds once it holds the
    /// checkpoint, so `NoTwin` does not arise here.
    fn twin_cut(&self, c: EventId, event: &Event) -> Result<(), RosterClass> {
        let log = self.log();
        let bad = || RosterClass::from(frasil_peers::PeersClass::BadTwin);
        let twin = frasil_peers::skeleton::named_twin(event).ok_or(SpaceClass::TwinRequired)?;
        if !event.parents().contains(&twin) {
            return Err(bad());
        }
        if !log.contains(twin) || log.event(twin).is_none() {
            return Err(frasil_peers::PeersClass::NoTwin.into());
        }
        let is_cut = log
            .event(twin)
            .and_then(frasil_peers::cut::read_cut)
            .is_some();
        let all: BTreeSet<EventId> = log.canonical().into_iter().collect();
        let (named, validity) =
            self.with_peer_cuts(all, |peer| (peer.checkpoint_of(twin), peer.validity(twin)));
        if !is_cut || named != Some(c) {
            return Err(bad());
        }
        // Its past is the cut's past and the cut: the skeleton peers read
        // of the cut's past is the one the record reads.
        let before = log.past(twin);
        if event
            .parents()
            .iter()
            .any(|&x| x != twin && log.event(x).is_some() && !before.contains(&x))
        {
            return Err(bad());
        }
        match validity {
            frasil_peers::skeleton::Status::Valid => Ok(()),
            frasil_peers::skeleton::Status::Void { class, .. }
                if class == frasil_peers::PeersClass::from(ErrorClass::Pending) =>
            {
                Err(ErrorClass::Pending.into())
            }
            frasil_peers::skeleton::Status::Void { .. } => Err(bad()),
        }
    }

    /// Runs `f` on the skeleton cuts of the events `held` as peers.md's
    /// rule judges them (section 3.21), which is one function of the
    /// skeleton events that a peer and a client apply alike: the peers
    /// crate's [`frasil_peers::cut::PeerCuts`], at a replica that forgot as
    /// at a peer that truncated under its kept checkpoint's cut. A
    /// checkpoint's twin check and whether a cut is in effect read it here;
    /// the skeleton of a checkpoint's world reads the same function from
    /// that checkpoint's cut.
    fn with_peer_cuts<R>(
        &self,
        held: BTreeSet<EventId>,
        f: impl FnOnce(&frasil_peers::cut::PeerCuts<'_>) -> R,
    ) -> R {
        let log = self.log();
        let envelopes = self.envelopes();
        let kept_cut = self
            .kept
            .as_ref()
            .and_then(|kept| log.event(kept.checkpoint))
            .and_then(frasil_peers::skeleton::named_twin)
            .filter(|&cut| log.event(cut).is_some());
        let peer = match kept_cut {
            Some(cut) => frasil_peers::cut::PeerCuts::truncated(log, &envelopes, held, cut),
            None => frasil_peers::cut::PeerCuts::new(log, Some(&held)),
        };
        f(&peer)
    }

    /// Whether skeleton cut `cut` is in effect over the events `held` by
    /// peers.md's rule (section 3.21, "In effect at the peer"): what a
    /// client reads of its own view to know when it may truncate, propose
    /// or enrol again, as a peer reads it of what it holds. Neither is
    /// authoritative over the other; they agree once they hold the same
    /// skeleton events.
    pub fn cut_in_effect(&self, held: &BTreeSet<EventId>, cut: EventId) -> bool {
        self.with_peer_cuts(held.clone(), |peer| peer.in_effect(cut))
    }

    /// What skeleton cut `cut` waits for over the events `held`, by the
    /// peers crate's [`frasil_peers::cut::PeerCuts::tally`]: its waited
    /// slots, the lowerings that excuse them and their votes, which
    /// [`Self::cut_in_effect`] reads with the cut's validity. `None` for an
    /// event that is no cut held there.
    pub fn cut_tally(
        &self,
        held: &BTreeSet<EventId>,
        cut: EventId,
    ) -> Option<frasil_peers::cut::Tally> {
        self.with_peer_cuts(held.clone(), |peer| peer.tally(cut))
    }

    /// Whether the space is restricted, from its genesis's descriptor.
    fn descriptor_restricted(&self) -> bool {
        let genesis = self.log().genesis();
        let in_past = |_: EventId| true;
        let context = ScreenContext {
            space: self.log().id(),
            limits: &self.inputs.options.limits,
            in_past: &in_past,
        };
        match screen_body(genesis, &context, self.keys()) {
            Body::Opened(opened) => opened
                .genesis()
                .is_some_and(|g| g.descriptor.kind == crate::DescriptorKind::Restricted),
            _ => false,
        }
    }

    /// `x`'s past in `c`'s world: what it reaches through events that
    /// follow `c`, itself included, among the events the replica holds.
    ///
    /// # Errors
    ///
    /// The envelopes it waits for: an event of `x`'s past whose following
    /// is unknown could be in the world, so the answer is pending.
    fn past_in_world(&self, c: EventId, x: EventId) -> Result<BTreeSet<EventId>, Vec<EventId>> {
        let log = self.log();
        let mut pool = log.past(x);
        pool.insert(x);
        let mut members = BTreeSet::new();
        for id in pool {
            if self.follows(id, c)? {
                members.insert(id);
            }
        }
        let mut out = BTreeSet::from([x]);
        // Walk x's parents among the events that follow c.
        let mut stack = vec![x];
        while let Some(current) = stack.pop() {
            let Some(event) = log.event(current) else {
                continue;
            };
            for &parent in event.parents() {
                if members.contains(&parent) && out.insert(parent) {
                    stack.push(parent);
                }
            }
        }
        Ok(out)
    }

    /// roster.md, 3.15.3 The record of a view: the roster, policy, chain
    /// tips and fork points of a resolved view, with the epoch; each invite
    /// key in or out only by valid successors, with its status; each
    /// granted space's notices, floor and names. With a predecessor, the
    /// predecessor's tips, invite statuses and space entries count as its
    /// world's root holds them. `None` when a device member's or invite
    /// key's keys are not held.
    fn record_of(&self, outcome: &Outcome, previous: Option<EventId>) -> Option<Record> {
        let before = match previous {
            None => None,
            Some(p) => Some(self.record(p)?),
        };
        let earlier = |member: &MemberRef| before.as_ref().and_then(|r| r.entry(member));
        let mut members = Vec::new();
        for (member, state) in outcome.roster.members_in() {
            if member.kind == MemberType::Invite {
                continue;
            }
            let keys = match member.kind {
                MemberType::Device => Some(Arc::clone(outcome.keys.get(&DeviceId(member.id))?)),
                _ => None,
            };
            let device = DeviceId(member.id);
            let slot = (member.kind == MemberType::Device && state.level == Level::Administer)
                .then(|| {
                    outcome
                        .slots
                        .slot(&device)
                        .or_else(|| self.inputs.slots?.slot(&device))
                })
                .flatten();
            let mut entry = MemberEntry::of(*member, state, keys, slot);
            if member.kind == MemberType::Space {
                let fact = outcome.spaces.get(&EventId(member.id));
                let prior = earlier(member);
                entry.notices = match fact.filter(|f| !f.notices.is_empty()) {
                    Some(fact) => fact.notices.values().cloned().collect(),
                    None => prior.map(|e| e.notices.clone()).unwrap_or_default(),
                };
                entry.floor = prior.is_some_and(|e| e.floor) || fact.is_some_and(|f| f.floor);
                let mut named: BTreeSet<EventId> = prior
                    .map(|e| e.named.iter().copied().collect())
                    .unwrap_or_default();
                if let Some(fact) = fact {
                    named.extend(fact.named.iter().copied());
                }
                entry.named = named.into_iter().collect();
            }
            members.push(entry);
        }
        for fact in &outcome.invites {
            let prior = earlier(&fact.member);
            let mut status = prior.and_then(|e| e.invite).unwrap_or(InviteStatus::Open);
            let mut claimant = prior.and_then(|e| e.claimant);
            if fact.claimant.is_some() {
                claimant = fact.claimant;
            }
            if fact.status.rank() > status.rank() {
                status = fact.status;
            }
            let keys = Some(Arc::clone(fact.keys.as_ref()?));
            if status == InviteStatus::Claimed {
                members.push(MemberEntry::claimed(keys, fact.member, claimant?));
                continue;
            }
            let Some(state) = &fact.state else {
                continue;
            };
            let mut entry = MemberEntry::of(fact.member, state, keys, None);
            entry.expires_at = fact.expires_at;
            entry.claims = fact.claims;
            entry.invite = Some(status);
            members.push(entry);
        }
        let (mut tips, epoch) = match &before {
            None => (BTreeMap::new(), 1),
            Some(record) => (record.tips.clone(), record.epoch + 1),
        };
        // Each author's greatest seq, the smaller ID on a tie. A skeleton
        // cut is left out: it names the record's object, so the record
        // cannot count it.
        for &id in &outcome.view {
            let Some(event) = self.log().event(id) else {
                continue;
            };
            if is_skeleton_cut(event) {
                continue;
            }
            let current = tips.get(event.author()).map_or(0, |&(seq, _)| seq);
            if event.seq() > current {
                tips.insert(*event.author(), (event.seq(), id));
            }
        }
        // The heard members (roster.md, 3.15.4): kept are the record's
        // administrators without `frasil.dormant`.
        let kept: BTreeSet<DeviceId> = members
            .iter()
            .filter(|entry| {
                entry.member.kind == MemberType::Device
                    && entry.level == Level::Administer
                    && !extends_dormant(&entry.capabilities)
            })
            .filter_map(|entry| entry.member.device_id())
            .collect();
        let mut heard = Vec::new();
        for (device, (seniority, rank)) in heard_of(outcome, &kept) {
            heard.push(HeardMember {
                device,
                seniority: (seniority.epoch, seniority.height, seniority.grant),
                rank,
                keys: Arc::clone(outcome.keys.get(&device)?),
            });
        }
        Some(Record {
            epoch,
            previous,
            members,
            policy: outcome.policy,
            tips,
            forks: outcome.forks.clone(),
            heard,
        })
    }

    /// The record a checkpoint over `past` names (roster.md, 3.15.3): what
    /// a client that proposes one seals into its record object. `past` is
    /// the checkpoint's causal past as the client holds it, closed under
    /// parents. `None` too while the order of `past` waits for envelopes.
    pub fn record_for(&self, past: &BTreeSet<EventId>) -> Option<Record> {
        let judged = self.judge(past);
        let previous = judged.chain.last().copied();
        self.record_naming(past, previous)
    }

    /// The record a checkpoint over `past` that names `previous` as its
    /// predecessor carries (roster.md, 3.15.3): without one, the record of
    /// `past` resolved with no checkpoint in effect, each checkpoint with
    /// its own verdict; with predecessor `p`, the record of `p`'s world over
    /// `p` and the events of `past` that `past`'s heads reach through events
    /// after `p`. An honest client names the last checkpoint in effect
    /// ([`Self::record_for`]); a replica derives any other to judge the
    /// checkpoint that names it. `None` while the order of `past` waits for
    /// envelopes, or a member's keys are not held.
    pub fn record_naming(
        &self,
        past: &BTreeSet<EventId>,
        previous: Option<EventId>,
    ) -> Option<Record> {
        let outcome = self.outcome_naming(past, previous)?;
        self.record_of(&outcome, previous)
    }

    /// The resolution a record over `past` naming `previous` reads: `past`
    /// with no checkpoint in effect, or `previous`'s world over it and the
    /// events of `past` its heads reach through events after it. `None`
    /// while that order waits for envelopes.
    fn outcome_naming(
        &self,
        past: &BTreeSet<EventId>,
        previous: Option<EventId>,
    ) -> Option<Rc<Outcome>> {
        match previous {
            None => Some(self.plain(past)),
            Some(previous) => {
                let heads = self.log().heads_in(past);
                let mut held = BTreeSet::from([previous]);
                for head in heads {
                    if head == previous || self.follows(head, previous).ok()? {
                        held.extend(self.past_in_world(previous, head).ok()?);
                    }
                }
                Some(self.world(previous, &held))
            }
        }
    }

    /// roster.md, 3.15.7 "Voting": whether checkpoint `c`'s record equals,
    /// byte for byte and with its space members' keys 18 to 20, the record
    /// this replica derives from `c`'s past. An administrator's client votes
    /// for a valid checkpoint only once this holds, after it fetched the
    /// granted spaces' logs and the lists the key events of that past wait
    /// on; one whose entries differ it never votes for. `None` while the
    /// record cannot be read or derived.
    pub fn record_agrees(&self, c: EventId) -> Option<bool> {
        if !matches!(
            self.record_state(c),
            RecordState::Read(_) | RecordState::Summary(_)
        ) {
            return None;
        }
        let part = self.checkpoint_part(c)??;
        let derived = self.record_for(&self.log().past(c))?;
        Some(derived.record_digest() == part.digest)
    }

    /// The electorate of `c` over the events `held` (roster.md, 3.15.4):
    /// the administrators of its record that do not extend
    /// `frasil.dormant` and the members it hears (record key 8), less those
    /// excused for good ([`Self::excused`]). Excuses only accumulate, so a
    /// checkpoint in effect never leaves effect as events arrive.
    pub fn electorate(&self, c: EventId, held: &BTreeSet<EventId>) -> BTreeSet<DeviceId> {
        let named = self.named(c);
        let excused = self.excused(c, held);
        named
            .keys()
            .copied()
            .filter(|device| !excused.contains(device))
            .collect()
    }

    /// The members `c` waits for before any excuse, each with its key in
    /// the order of authority: its record's administrators without
    /// `frasil.dormant`, by their entries' rank and seniority, and the
    /// members it hears, by theirs.
    fn named(&self, c: EventId) -> BTreeMap<DeviceId, AuthorityKey> {
        let Some(record) = self.record(c) else {
            return BTreeMap::new();
        };
        let space = self.log().id();
        let mut out: BTreeMap<DeviceId, AuthorityKey> = record
            .members
            .iter()
            .filter(|entry| {
                entry.is_in()
                    && entry.level == Level::Administer
                    && !extends_dormant(&entry.capabilities)
            })
            .filter_map(|entry| Some((entry.member.device_id()?, entry_key(&space, entry))))
            .collect_map();
        for heard in &record.heard {
            out.insert(
                heard.device,
                (
                    crate::change::MAX_RANK - heard.rank,
                    heard.full_seniority(&space),
                ),
            );
        }
        out
    }

    /// The members of `c`'s electorate excused for good over the events
    /// `held` (roster.md, 3.15.4): one whose fork the world of `c` shows;
    /// one that lowers itself by a judged roster event after `c` (a heard
    /// member's checked under the keys key 8 gives it); and one that a
    /// judged roster event after `c` whose signature verified removes,
    /// demotes below `administer` or extends `frasil.dormant` to, whatever
    /// that event's verdict, signed by an administrator of the record that
    /// outranks it (`c`'s author too) or by a recovery member of a rank at
    /// least its own.
    pub fn excused(&self, c: EventId, held: &BTreeSet<EventId>) -> BTreeSet<DeviceId> {
        let Some(record) = self.record(c) else {
            return BTreeSet::new();
        };
        let named = self.named(c);
        let space = self.log().id();
        let administrators: BTreeMap<DeviceId, AuthorityKey> = record
            .members
            .iter()
            .filter(|entry| entry.is_in() && entry.level == Level::Administer)
            .filter_map(|entry| Some((entry.member.device_id()?, entry_key(&space, entry))))
            .collect_map();
        let mut view = held.clone();
        view.insert(c);
        let world = self.world(c, &view);
        let mut excused: BTreeSet<DeviceId> = named
            .keys()
            .copied()
            .filter(|device| world.forks.contains_key(device))
            .collect();
        for excusal in &world.excusals {
            if excusal.event == c {
                continue;
            }
            let author = excusal.author;
            if !excusal.verified {
                // A heard member's own events are checked under the keys
                // the record gives it.
                if !named.contains_key(&author) || administrators.contains_key(&author) {
                    continue;
                }
                if !self.verifies_as_heard(&record, excusal.event) {
                    continue;
                }
            } else if excusal.held {
                continue;
            }
            for &(target, removes_or_changes, lowers) in &excusal.targets {
                if target == author {
                    // It lowers itself: it accepts.
                    if removes_or_changes && named.contains_key(&target) {
                        excused.insert(target);
                    }
                    continue;
                }
                let (Some(by), Some(of)) = (administrators.get(&author), named.get(&target)) else {
                    continue;
                };
                if !lowers {
                    continue;
                }
                if by < of || self.recovery(&record, &author, &target, of) {
                    excused.insert(target);
                }
            }
        }
        excused
    }

    /// Whether `x` is a recovery member of `c`'s record that may excuse a
    /// member whose key in the order of authority is `target` (roster.md,
    /// 3.15.4): at `administer` there with `frasil.dormant`, of a rank at
    /// least the target's, and either so in the predecessor's record or,
    /// without a predecessor, granted (by the grant its seniority names in
    /// `c`'s past) by the target `of`, or by another member the record
    /// keeps at `administer` or hears and that outranks the target by the
    /// record's ranks and seniorities, not as they stood at the grant: the
    /// record decides it, so that a peer reads the same from the cut's
    /// standing entries (peers.md, "Storage events").
    fn recovery(
        &self,
        record: &Record,
        x: &DeviceId,
        of: &DeviceId,
        target: &AuthorityKey,
    ) -> bool {
        let Some(mine) = record.entry(&MemberRef::device(*x)) else {
            return false;
        };
        if mine.level != Level::Administer || !extends_dormant(&mine.capabilities) {
            return false;
        }
        let target_rank = crate::change::MAX_RANK - target.0;
        if mine.rank.unwrap_or(0) < target_rank {
            return false;
        }
        if let Some(previous) = record.previous {
            return self.record(previous).is_some_and(|prev| {
                prev.entry(&MemberRef::device(*x)).is_some_and(|entry| {
                    entry.level == Level::Administer && extends_dormant(&entry.capabilities)
                })
            });
        }
        let grant = mine.seniority.2;
        let Some(granter) = self.log().event(grant).map(|event| *event.author()) else {
            // A replica that forgot the grant cannot tell who signed it: a
            // rival whose stability rests on this excuse is one whose
            // stability it cannot work out, which counts as stable
            // (roster.md, 3.15.6, "A rival"). Only a checkpoint with no
            // predecessor reaches here at such a replica.
            return self.log().is_dropped(grant);
        };
        if granter == *x {
            return false;
        }
        if granter == *of {
            return true;
        }
        let space = self.log().id();
        let by = record
            .members
            .iter()
            .find(|entry| {
                entry.member == MemberRef::device(granter) && entry.level == Level::Administer
            })
            .map(|entry| entry_key(&space, entry))
            .or_else(|| {
                record.heard_member(&granter).map(|heard| {
                    (
                        crate::change::MAX_RANK - heard.rank,
                        heard.full_seniority(&space),
                    )
                })
            });
        by.is_some_and(|by| by <= *target)
    }

    /// Whether event `id`'s signature verifies under the keys `record`'s
    /// key 8 gives its author.
    fn verifies_as_heard(&self, record: &Record, id: EventId) -> bool {
        let Some(event) = self.log().event(id) else {
            return false;
        };
        record
            .heard_member(event.author())
            .is_some_and(|heard| event.verify_hybrid(Some(&heard.keys.keys)).is_ok())
    }

    /// The members `c`'s record hears (key 8), by device.
    pub fn heard(&self, c: EventId) -> BTreeMap<DeviceId, HeardMember> {
        self.record(c)
            .map(|record| {
                record
                    .heard
                    .iter()
                    .map(|heard| (heard.device, heard.clone()))
                    .collect_map()
            })
            .unwrap_or_default()
    }

    /// The valid roster events of the resolution of `view` with no
    /// checkpoint in effect that lower administrators, each with its
    /// author's standing and the members it lowers (roster.md, 3.15.4,
    /// heard members): what a client reads to tell whether a checkpoint is
    /// contested ([`Self::contest`]).
    pub fn lowerings(&self, view: &BTreeSet<EventId>) -> Vec<Lowering> {
        self.plain(view).lowerings.clone()
    }

    /// roster.md, 3.15.7, "Contested checkpoints": why `device`, whose
    /// view is `view`, never cites or votes for checkpoint `c`, if it is
    /// contested for it: `c`'s record hears `device`; or a valid roster
    /// event of `view` (resolved with no checkpoint in effect), concurrent
    /// with `c`, lowers `c`'s author or an administrator `c`'s record keeps,
    /// signed by a member that outranks the one it lowers. `None` when it
    /// is not contested, or `c`'s record cannot be read. A client stops
    /// treating it so once it takes effect without the device, the device
    /// removes itself, or the lowering is void in its view.
    pub fn contest(
        &self,
        device: &DeviceId,
        c: EventId,
        view: &BTreeSet<EventId>,
    ) -> Option<Contest> {
        let record = self.record(c)?;
        if record.heard_member(device).is_some() {
            return Some(Contest::Heard);
        }
        let log = self.log();
        let mut kept: BTreeSet<DeviceId> = record.administrators().collect();
        kept.extend(log.event(c).map(|e| *e.author()));
        let rivals: BTreeSet<EventId> = view
            .iter()
            .copied()
            .filter(|&x| x != c && !log.precedes(x, c) && !log.precedes(c, x))
            .filter(|&x| log.event(x).is_some_and(|e| e.kind() == kind::SPACE))
            .collect();
        if rivals.is_empty() {
            return None;
        }
        let outcome = self.plain(view);
        for lowering in &outcome.lowerings {
            if !rivals.contains(&lowering.event) {
                continue;
            }
            let Some(by) = lowering.by else {
                continue;
            };
            for target in &lowering.targets {
                if kept.contains(&target.device) && by < target.authority_key() {
                    return Some(Contest::Lowered {
                        event: lowering.event,
                        target: target.device,
                    });
                }
            }
        }
        None
    }

    /// The devices that voted for `c` among the events `held`: its author,
    /// by `c` itself; another, by any event of it after `c` whose signature
    /// verifies, whose cuts are correct and reach no checkpoint concurrent
    /// with `c`. Any kind below 64 counts; a held event does not.
    pub fn votes(&self, c: EventId, held: &BTreeSet<EventId>) -> BTreeSet<DeviceId> {
        let log = self.log();
        let Some(author) = log.event(c).map(|e| *e.author()) else {
            return BTreeSet::new();
        };
        let mut view = held.clone();
        view.insert(c);
        let world = self.world(c, &view);
        let record = self.record(c);
        let mut out = BTreeSet::from([author]);
        for &id in &world.view {
            if id == c {
                continue;
            }
            let Some(event) = log.event(id) else {
                continue;
            };
            if event.kind() >= kind::FIRST_IGNORABLE
                || self.cuts_check(id) != CutsCheck::Correct
                || out.contains(event.author())
            {
                continue;
            }
            if world.verified.contains(&id) {
                if world.status(id).is_some_and(|s| held_class(&s)) {
                    continue;
                }
            } else {
                // A heard member's event, which the world gives no key
                // for, counts when its signature verifies under the keys
                // the record gives it.
                let Some(record) = record.as_ref() else {
                    continue;
                };
                if !self.verifies_as_heard(record, id) {
                    continue;
                }
            }
            // An event whose order waits for envelopes is no vote yet.
            let Ok(reach) = self.reach(id) else {
                continue;
            };
            let exclusive = reach
                .into_iter()
                .filter(|&x| self.maybe_checkpoint(x))
                .all(|x| self.concurrent(x, c) == Ok(false));
            if exclusive {
                out.insert(*event.author());
            }
        }
        out
    }

    /// roster.md, 3.15.4 "Waiting for": the members of a pending
    /// checkpoint's electorate that have not voted among the events
    /// `held`, each with the last event of it the replica holds, so that an
    /// application shows whom the checkpoint waits for, and an
    /// administrator can remove one that will not return or mark it
    /// dormant.
    pub fn waiting_for(&self, c: EventId, held: &BTreeSet<EventId>) -> Vec<Waiting> {
        let after: BTreeSet<EventId> = held
            .iter()
            .copied()
            .filter(|&x| x == c || self.follows_known(x, c))
            .collect();
        let votes = self.votes(c, &after);
        let heard = self.heard(c);
        let log = self.log();
        self.electorate(c, &after)
            .into_iter()
            .filter(|device| !votes.contains(device))
            .map(|device| Waiting {
                device,
                heard: heard.contains_key(&device),
                last: held
                    .iter()
                    .copied()
                    .filter(|&id| log.event(id).is_some_and(|e| *e.author() == device))
                    .max_by_key(|&id| (log.event(id).map_or(0, Event::seq), id)),
            })
            .collect()
    }

    /// Whether `c` is stable over the events `held`: every member of its
    /// electorate voted for it.
    pub fn stable(&self, c: EventId, held: &BTreeSet<EventId>) -> bool {
        if self
            .stable_seed
            .get(&c)
            .is_some_and(|over| over.is_subset(held))
        {
            return true;
        }
        let votes = self.votes(c, held);
        let stable = self.electorate(c, held).is_subset(&votes);
        if stable {
            let mut found = self.found_stable.borrow_mut();
            // The smallest set it was found stable over serves best.
            if found.get(&c).is_none_or(|over| held.len() < over.len()) {
                found.insert(c, held.clone());
            }
        }
        stable
    }

    // -- A replica's verdicts

    /// The chain in effect over the events `held`: starting from no
    /// checkpoint, or the kept one, the valid stable checkpoint with the
    /// smallest ID among those whose predecessor is the current one and
    /// that follow it takes effect, and so on.
    pub fn chain(&self, held: &BTreeSet<EventId>) -> Vec<EventId> {
        let base = self.kept.as_ref().map(|kept| kept.checkpoint);
        let mut chain: Vec<EventId> = base.into_iter().collect();
        let mut current = base;
        loop {
            let mut candidates = Vec::new();
            for &id in held {
                if Some(id) == current || !self.is_checkpoint(id) {
                    continue;
                }
                let Some(record) = self.record(id) else {
                    continue;
                };
                if record.previous != current {
                    continue;
                }
                if let Some(current) = current
                    && !self.follows_known(id, current)
                {
                    continue;
                }
                if !self.validity(id).is_valid() {
                    continue;
                }
                let after: BTreeSet<EventId> = held
                    .iter()
                    .copied()
                    .filter(|&x| x == id || self.follows_known(x, id))
                    .collect();
                if self.stable(id, &after) {
                    candidates.push(id);
                }
            }
            let Some(next) = candidates.into_iter().min() else {
                return chain;
            };
            chain.push(next);
            current = Some(next);
        }
    }

    /// The rivals of the kept checkpoint among the events `held`
    /// (roster.md, 3.15.6, "A rival"): at a replica that forgot under its
    /// kept checkpoint `c`, or started from it, each checkpoint `x`
    /// concurrent with `c` that names as predecessor `c`'s predecessor, a
    /// checkpoint `c`'s cuts reach, or none; whose ID is smaller than that
    /// of a checkpoint of `c`'s chain it could replace (`c`, or one `c`'s
    /// cuts reach after the one `x` names, any of them when it names none);
    /// that passes what the replica can check of it without its past (its
    /// cuts, its record, keys.md's checks as a genesis); and that is stable
    /// in what the replica holds after it, its votes checked under the keys
    /// its record carries and those of the events after it. One whose
    /// stability the replica cannot work out from what it holds (a
    /// checkpoint after it whose validity needs the forgotten past, say)
    /// counts as stable. While one is held, every event the replica holds
    /// is `Pending` ([`Self::judge`]); a client fetches the rival's past, or
    /// starts again from a snapshot that names the rival's chain. Empty at
    /// a replica that kept everything.
    ///
    /// A checkpoint whose record a later document's key or member type
    /// holds ([`Self::extension_required`]) is judged by what keys 2 and 3
    /// of its record give: its votes cannot be checked, so it counts as
    /// stable. Such a rival can never be judged: the replica holds every
    /// event and needs a later version.
    pub fn rivals(&self, held: &BTreeSet<EventId>) -> BTreeSet<EventId> {
        let Some(kept) = &self.kept else {
            return BTreeSet::new();
        };
        let base = kept.checkpoint;
        let previous = kept.record.previous;
        let reached = self.reach(base).unwrap_or_default();
        let restricted = self.descriptor_restricted();
        let mut out = BTreeSet::new();
        for &x in held {
            if x == base || !self.is_checkpoint(x) || self.concurrent(x, base) != Ok(true) {
                continue;
            }
            let (named, extension) = match self.record_state(x) {
                RecordState::Read(record) => (record.previous, false),
                RecordState::Summary(summary) => (summary.previous, false),
                // One that a step reading no record voided is settled.
                RecordState::Extension(Some((_, previous))) if self.extension_required(x) => {
                    (previous, true)
                }
                _ => continue,
            };
            if self.cuts_check(x) != CutsCheck::Correct {
                continue;
            }
            let replaceable: BTreeSet<EventId> = match named {
                None => reached.iter().copied().chain([base]).collect(),
                Some(q) if Some(q) == previous || reached.contains(&q) => reached
                    .iter()
                    .copied()
                    .filter(|&y| y != q && self.at_or_before(q, y) == Ok(true))
                    .chain([base])
                    .collect(),
                Some(_) => continue,
            };
            if !replaceable.iter().any(|&y| x < y) {
                continue;
            }
            // keys.md's checks as a genesis (roster.md, 3.15.2, step 6),
            // which read the event alone.
            let Some(event) = self.log().event(x) else {
                continue;
            };
            let in_past = |_: EventId| true;
            let context = ScreenContext {
                space: self.log().id(),
                limits: &self.inputs.options.limits,
                in_past: &in_past,
            };
            let facts = match screen_body(event, &context, self.keys()) {
                Body::Opened(opened) => opened.facts(),
                _ => continue,
            };
            if check_context(Some(facts), &Context::checkpoint(true, restricted)).is_err() {
                continue;
            }
            // Its votes are checked under the keys its record carries, which
            // this replica cannot read: it cannot work out its stability.
            if extension {
                out.insert(x);
                continue;
            }
            // Judged apart, so that what it cannot tell leaves no verdict
            // behind.
            let apart = Checkpointed::new(self.inputs, self.kept.clone());
            let after: BTreeSet<EventId> = held
                .iter()
                .copied()
                .filter(|&y| y == x || apart.follows_known(y, x))
                .collect();
            let unknowable = after
                .iter()
                .any(|&y| y != x && apart.is_checkpoint(y) && held_class(&apart.validity(y)));
            if unknowable || apart.stable(x, &after) {
                out.insert(x);
            }
        }
        out
    }

    /// The verdicts of a replica that holds `held` (roster.md, 3.15.5,
    /// "Verdicts"). A replica that forgot holds its kept checkpoint and
    /// what follows it; its genesis, which it keeps, is valid.
    pub fn judge(&self, held: &BTreeSet<EventId>) -> Rc<Judged> {
        if let Some(hit) = self.judged.borrow().get(held) {
            return Rc::clone(hit);
        }
        let judged = Rc::new(self.judge_uncached(held));
        self.judged
            .borrow_mut()
            .insert(held.clone(), Rc::clone(&judged));
        judged
    }

    fn judge_uncached(&self, held: &BTreeSet<EventId>) -> Judged {
        let log = self.log();
        let genesis = log.id();
        // A checkpoint whose record object this replica lacks is held
        // (`Sealed`), with every event in whose past it is, whichever world
        // that event would be in; the replica judges the rest as if it had
        // not received them (roster.md, "The record object").
        let unreadable: BTreeSet<EventId> = held
            .iter()
            .copied()
            .filter(|&id| self.is_checkpoint(id) && !self.readable(id))
            .collect();
        let blocked: BTreeSet<EventId> = held
            .iter()
            .copied()
            .filter(|&id| {
                unreadable.contains(&id) || unreadable.iter().any(|&u| log.precedes(u, id))
            })
            .collect();
        if !blocked.is_empty() {
            let rest: BTreeSet<EventId> = held.difference(&blocked).copied().collect();
            let mut judged = (*self.judge(&rest)).clone();
            // A record using a later document's key or member type holds
            // the checkpoint and every event after it as `ExtensionRequired`
            // (roster.md, 2.8, step 3).
            let extension: BTreeSet<EventId> = unreadable
                .iter()
                .copied()
                .filter(|&id| self.extension_required(id))
                .collect();
            for &id in &blocked {
                let class =
                    if extension.contains(&id) || extension.iter().any(|&x| log.precedes(x, id)) {
                        ErrorClass::ExtensionRequired
                    } else if unreadable.contains(&id) {
                        ErrorClass::Sealed
                    } else {
                        ErrorClass::Pending
                    };
                judged.statuses.insert(id, Status::void_with(class));
            }
            if !extension.is_empty() {
                judged.needs_later_rules = true;
            }
            // Such a checkpoint as a rival of the kept one (roster.md,
            // 3.15.6) can never be judged: every other event it holds is
            // pending.
            if self.kept.is_some()
                && !extension.is_empty()
                && self.rivals(held).iter().any(|&x| extension.contains(&x))
            {
                for (&id, status) in &mut judged.statuses {
                    if id != genesis && !blocked.contains(&id) {
                        *status = Status::void_with(ErrorClass::Pending);
                    }
                }
            }
            return judged;
        }
        let mut judged = self.judge_readable(held);
        // A rival (roster.md, 3.15.6): the replica cannot tell whether it is
        // valid, so whether its kept checkpoint stays in effect. It holds
        // pending every event it holds: the kept checkpoint and what follows
        // it, and the late events, which are in the rival's past or after
        // it if the rival wins.
        if self.kept.is_some() && !self.rivals(held).is_empty() {
            for (&id, status) in &mut judged.statuses {
                if id != genesis {
                    *status = Status::void_with(ErrorClass::Pending);
                }
            }
        }
        judged
    }

    /// The verdicts of a view in which every checkpoint's record reads.
    fn judge_readable(&self, held: &BTreeSet<EventId>) -> Judged {
        let log = self.log();
        let genesis = log.id();
        let chain = self.chain(held);
        let Some(&last) = chain.last() else {
            let outcome = self.plain(held);
            return Judged {
                statuses: outcome.statuses.clone(),
                chain,
                roster: outcome.roster.clone(),
                policy: outcome.policy,
                needs_later_rules: outcome.needs_later_rules,
            };
        };
        let mut statuses = BTreeMap::new();
        let mut needs_later_rules = false;
        if self.kept.is_none() {
            let before = self.judge(&log.past(chain[0]));
            statuses.extend(before.statuses.iter().map(|(&id, &s)| (id, s)));
            needs_later_rules |= before.needs_later_rules;
        }
        for pair in chain.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            // `b`'s validity read this past in `a`'s world, so it is known;
            // were it not, its events would stay unjudged and be held below.
            let Ok(view) = self.past_in_world(a, b) else {
                continue;
            };
            let world = self.world(a, &view);
            statuses.extend(
                world
                    .statuses
                    .iter()
                    .filter(|&(&id, _)| id != a)
                    .map(|(&id, &s)| (id, s)),
            );
            statuses.insert(a, checkpoint_status());
            needs_later_rules |= world.needs_later_rules;
        }
        let after: BTreeSet<EventId> = held
            .iter()
            .copied()
            .filter(|&x| x == last || self.follows_known(x, last))
            .collect();
        let world = self.world(last, &after);
        statuses.extend(
            world
                .statuses
                .iter()
                .filter(|&(&id, _)| id != last)
                .map(|(&id, &s)| (id, s)),
        );
        statuses.insert(last, checkpoint_status());
        needs_later_rules |= world.needs_later_rules;
        let unreadable: BTreeSet<EventId> = held
            .iter()
            .copied()
            .filter(|&id| self.is_checkpoint(id) && !self.readable(id))
            .collect();
        let extension: BTreeSet<EventId> = unreadable
            .iter()
            .copied()
            .filter(|&id| self.extension_required(id))
            .collect();
        needs_later_rules |= !extension.is_empty();
        for &id in held {
            if statuses.contains_key(&id) {
                continue;
            }
            let status = if id == genesis {
                Status::Valid(Valid::Genesis)
            } else if extension.contains(&id) || extension.iter().any(|&x| log.precedes(x, id)) {
                Status::void_with(ErrorClass::ExtensionRequired)
            } else if unreadable.contains(&id) {
                Status::void_with(ErrorClass::Sealed)
            } else if unreadable.iter().any(|&u| log.precedes(u, id)) {
                Status::void_with(ErrorClass::Pending)
            } else if self.follows(id, last).is_err() {
                // Whether it follows the checkpoint in effect waits for
                // envelopes: held, never late.
                Status::void_with(ErrorClass::Pending)
            } else if log.event(id).is_some_and(|e| e.kind() == kind::UNIT) {
                Status::void_by(SpaceClass::Late, last)
            } else {
                Status::void_with(SpaceClass::Late)
            };
            statuses.insert(id, status);
        }
        Judged {
            statuses,
            chain,
            roster: world.roster.clone(),
            policy: world.policy,
            needs_later_rules,
        }
    }
}

/// The world a replica's key graph is rooted at (keys.md, "Keys after a
/// checkpoint"): the last checkpoint of the chain in effect, the log of its
/// world over the events the replica holds after it, its record and the
/// verdicts decided before the procedure. A replica that holds everything
/// and one that forgot build the same one.
#[derive(Debug, Clone)]
pub struct KeyWorld {
    log: WorldLog,
    record: Arc<Record>,
    presets: BTreeMap<EventId, Status>,
}

impl KeyWorld {
    /// The checkpoint the key graph is rooted at.
    pub fn checkpoint(&self) -> EventId {
        self.log.root()
    }

    /// The world's log.
    pub fn log(&self) -> &WorldLog {
        &self.log
    }

    /// The checkpoint's record.
    pub fn record(&self) -> &Record {
        &self.record
    }

    /// Its world's log, which a replica keeps to resume the world's
    /// resolution as units arrive ([`WorldLog::append`]).
    pub fn into_log(self) -> WorldLog {
        self.log
    }

    /// The world resolved, as [`Checkpointed::judge`] resolves it: a
    /// [`Space`] whose root is the checkpoint, which
    /// [`crate::keygraph::SpaceHistory`] reads as a key graph rooted there.
    ///
    /// # Errors
    ///
    /// As [`WorldLog::resolve`].
    pub fn resolve<'a>(&'a self, options: Options<'a>) -> Result<Space<'a>, RosterClass> {
        self.log
            .resolve(options, &self.record, self.presets.clone())
    }
}

impl Checkpointed<'_> {
    /// The world the key graph of a replica that holds `held` is rooted
    /// at: that of the last checkpoint of its chain in effect; `None` with
    /// no chain, where the key graph reads the view as it always does.
    pub fn key_world(&self, held: &BTreeSet<EventId>) -> Option<KeyWorld> {
        let last = *self.judge(held).chain.last()?;
        let members: BTreeSet<EventId> = held
            .iter()
            .copied()
            .filter(|&x| x == last || self.follows_known(x, last))
            .collect();
        let log = WorldLog::new(self.log(), last, &members).ok()?;
        let record = self.record(last)?;
        let presets = self.presets_in_world(&log, last, &members);
        Some(KeyWorld {
            log,
            record,
            presets,
        })
    }

    /// Where each event `held` holds stands against the last checkpoint of
    /// its chain in effect (keys.md, "Keys after a checkpoint"): what
    /// [`frasil_keys::checkpoint::plan_forgetting`] and the other rules
    /// rooted at a checkpoint read. An event whose following waits for
    /// envelopes is left [`Side::Unknown`](frasil_keys::checkpoint::Side).
    /// `None` with no chain in effect.
    pub fn sides(&self, held: &BTreeSet<EventId>) -> Option<frasil_keys::checkpoint::Sides> {
        let last = *self.judge(held).chain.last()?;
        let log = self.log();
        let mut sides = frasil_keys::checkpoint::Sides::new(last);
        for &id in held {
            let Ok(follows) = self.follows(id, last) else {
                continue;
            };
            let side =
                frasil_keys::checkpoint::Side::of_held(id == last, follows, log.precedes(id, last));
            sides.insert(id, side);
        }
        Some(sides)
    }
}

/// Which space events are checkpoints, for the cuts check: one this
/// replica opened and found of roster part type 2; `None` while it cannot
/// open it.
impl Checkpoints for Checkpointed<'_> {
    fn is_checkpoint(&self, event: &Event) -> Option<bool> {
        self.checkpoint_part(event.id()).map(|part| part.is_some())
    }
}

/// The verdicts of a view a replica cannot use at all: every event held
/// with the class the genesis fails with.
fn unusable(view: &BTreeSet<EventId>, class: RosterClass) -> Outcome {
    Outcome {
        statuses: view
            .iter()
            .map(|&id| (id, Status::void_with(class)))
            .collect_map(),
        roster: Roster::default(),
        policy: Policy::default(),
        forks: BTreeMap::new(),
        verified: BTreeSet::new(),
        keys: BTreeMap::new(),
        view: view.clone(),
        needs_later_rules: false,
        slots: BTreeMap::new(),
        out_slots: BTreeMap::new(),
        invites: Vec::new(),
        spaces: BTreeMap::new(),
        excusals: Vec::new(),
        lowerings: Vec::new(),
        raises: Vec::new(),
        raised_after: BTreeSet::new(),
    }
}

/// The changes an event of a resolved space makes: the record's grants at
/// the root of a world, an opened body's otherwise.
fn changes_of<'s>(space: &'s Space<'_>, id: EventId) -> &'s [Change] {
    if let Some(world) = space.world()
        && world.root == id
    {
        return &world.changes;
    }
    space.opened(id).map_or(&[], |opened| opened.changes())
}

/// Whether an event's status voids it as a raced claim.
fn raced_class(status: &Status) -> bool {
    #[cfg(feature = "ext-invite-links")]
    {
        status.class()
            == Some(RosterClass::from(
                crate::ext_invite_links::InviteClass::ClaimRaced,
            ))
    }
    #[cfg(not(feature = "ext-invite-links"))]
    {
        let _ = status;
        false
    }
}

/// roster.md, 2.8: each invite key in, or out only by valid successors
/// (the root of a world counting as one for a key its record shows
/// claimed), with the status its successors in the view give it.
fn invite_facts(space: &Space<'_>, statuses: &BTreeMap<EventId, Status>) -> Vec<InviteFact> {
    let log = space.log();
    let root = space.world().map(|world| world.root);
    let mut out = Vec::new();
    for (member, standing) in space.roster().iter() {
        if member.kind != MemberType::Invite {
            continue;
        }
        let state = match standing {
            Standing::In(state) => Some((**state).clone()),
            Standing::Out { removed_by } => {
                let by_successors = !removed_by.is_empty()
                    && removed_by.iter().all(|&r| {
                        Some(r) == root || crate::ext::is_successor(changes_of(space, r))
                    });
                if !by_successors {
                    // Revoked or closed: it leaves the record.
                    continue;
                }
                None
            }
        };
        let mut status = InviteStatus::Open;
        let mut claimant = None;
        for &id in space.view() {
            let changes = changes_of(space, id);
            if Some(id) == root
                || !crate::ext::is_successor(changes)
                || log.event(id).is_none_or(|e| e.author().0 != member.id)
            {
                continue;
            }
            let mine = match statuses.get(&id) {
                Some(s) if s.is_valid() => InviteStatus::Claimed,
                Some(s) if raced_class(s) => InviteStatus::Raced,
                _ => InviteStatus::Used,
            };
            if mine == InviteStatus::Claimed {
                claimant = changes
                    .iter()
                    .find(|c| c.op == Op::Succeed)
                    .and_then(|c| c.member);
            }
            if mine.rank() > status.rank() {
                status = mine;
            }
        }
        // Its invite grant, the first in canonical order among the grants
        // in force beneath its state, or among every grant of it once out.
        let mut grants: Vec<EventId> = match &state {
            Some(state) => state.grants.iter().copied().collect(),
            None => space.view().iter().copied().collect(),
        };
        grants.sort_by_key(|&g| (log.height(g).unwrap_or(0), g));
        let grant = grants.into_iter().find_map(|g| {
            changes_of(space, g)
                .iter()
                .find(|c| c.op == Op::Grant && c.member == Some(*member))
        });
        let device = DeviceId(member.id);
        let keys = state
            .as_ref()
            .and_then(|s| s.keys.clone())
            .or_else(|| grant.and_then(|g| g.keys.clone()))
            .or_else(|| space.screened().keys().device_keys(&device).map(Arc::new))
            .or_else(|| {
                space
                    .root_keys()
                    .and_then(|ring| ring.device_keys(&device))
                    .map(Arc::new)
            });
        out.push(InviteFact {
            member: *member,
            state,
            status,
            claimant,
            claims: grant.and_then(|g| g.claims),
            expires_at: grant.and_then(|g| g.expires_at),
            keys,
        });
    }
    out
}

/// roster.md, 2.8: for each granted space, the notices of the valid events
/// of the view carrying one for it that no other such event follows, each
/// with its carrying event's author; whether one of them is "from now on";
/// and the space's event IDs that valid events' sealed refs name. The root
/// of a world is left out: the record's own entries stand for it.
fn space_facts(
    space: &Space<'_>,
    statuses: &BTreeMap<EventId, Status>,
) -> BTreeMap<EventId, SpaceFact> {
    let log = space.log();
    let root = space.root();
    let valid: Vec<EventId> = statuses
        .iter()
        .filter(|&(&id, status)| id != root && status.is_valid())
        .map(|(&id, _)| id)
        .collect();
    let mut carriers: BTreeMap<EventId, Vec<EventId>> = BTreeMap::new();
    let mut out: BTreeMap<EventId, SpaceFact> = BTreeMap::new();
    for &id in &valid {
        if let Some(opened) = space.opened(id) {
            for n in &opened.inner.notices {
                carriers.entry(n.space).or_default().push(id);
                if n.from_now_on {
                    out.entry(n.space).or_default().floor = true;
                }
            }
        }
        for r in space.refs_of(id) {
            out.entry(r.log).or_default().named.insert(r.id);
        }
    }
    for (granted, events) in carriers {
        let fact = out.entry(granted).or_default();
        for &e in &events {
            if events.iter().any(|&f| f != e && space.precedes(e, f)) {
                continue;
            }
            let Some(author) = log.event(e).map(|ev| *ev.author()) else {
                continue;
            };
            let Some(opened) = space.opened(e) else {
                continue;
            };
            for n in opened.inner.notices.iter().filter(|n| n.space == granted) {
                let notice = RecordNotice {
                    rotation: n.rotation,
                    public: n.public.clone(),
                    from_now_on: n.from_now_on,
                    author,
                };
                let key = frasil_base::cbor::Value::Array(vec![
                    frasil_base::cbor::Value::Bytes(notice.rotation.0.to_vec()),
                    frasil_base::cbor::Value::Bytes(notice.public.to_vec()),
                    frasil_base::cbor::Value::Unsigned(u64::from(notice.from_now_on)),
                    frasil_base::cbor::Value::Bytes(notice.author.0.to_vec()),
                ])
                .encode();
                fact.notices.insert(key, notice);
            }
        }
    }
    out
}

/// Whether capabilities extend `frasil.dormant`.
fn extends_dormant<'c>(capabilities: impl IntoIterator<Item = &'c crate::Capability>) -> bool {
    capabilities
        .into_iter()
        .any(|c| c.name == DORMANT && c.mode == CapabilityMode::Extends)
}

/// Whether a change lowers its member: removes it, demotes it below
/// `administer` or extends `frasil.dormant` to it.
fn lowers(change: &Change) -> bool {
    change.op == Op::Remove
        || (change.op == Op::Change
            && (change.level.is_some_and(|l| l < Level::Administer)
                || extend_dormant_change(change)))
}

fn extend_dormant_change(change: &Change) -> bool {
    change
        .capabilities
        .iter()
        .flatten()
        .any(|c| c.name == DORMANT && c.mode == CapabilityMode::Extends)
}

/// A record entry's key in the order of authority, with the hash of the
/// space and its member ID.
fn entry_key(space: &EventId, entry: &MemberEntry) -> AuthorityKey {
    let (epoch, height, grant) = entry.seniority;
    (
        crate::change::MAX_RANK - entry.rank.unwrap_or(0),
        Seniority {
            epoch,
            height,
            hash: crate::state::seniority_hash(space, &entry.member.id),
            grant,
        },
    )
}

/// roster.md, 3.15.4, excuses: each opened roster event of the view, the
/// root of a world left out, whatever its verdict, with its author, whether
/// its signature verified, whether it is held, and its changes of device
/// members.
fn excusal_facts(
    space: &Space<'_>,
    view: &BTreeSet<EventId>,
    statuses: &BTreeMap<EventId, Status>,
) -> Vec<Excusal> {
    let root = space.root();
    let mut out = Vec::new();
    for &id in view {
        if id == root {
            continue;
        }
        let Some(opened) = space.opened(id).filter(|o| o.is_roster()) else {
            continue;
        };
        let Some(author) = space.log().event(id).map(|e| *e.author()) else {
            continue;
        };
        let targets: Vec<(DeviceId, bool, bool)> = opened
            .changes()
            .iter()
            .filter_map(|change| {
                let device = change.member?.device_id()?;
                Some((
                    device,
                    matches!(change.op, Op::Remove | Op::Change),
                    lowers(change),
                ))
            })
            .collect();
        if !targets.is_empty() {
            out.push(Excusal {
                event: id,
                author,
                verified: space.screened().counts_as_evidence(id),
                held: statuses.get(&id).is_some_and(held_class),
                targets,
            });
        }
    }
    out
}

/// What the heard members of a view read (roster.md, 3.15.4): each valid
/// roster event, the root left out, that lowers an administrator at its
/// place, with its author's key at that place; each valid roster event
/// that grants a device `administer` or changes it to `administer`.
fn lowering_facts(space: &Space<'_>) -> (Vec<Lowering>, Vec<(EventId, DeviceId)>) {
    let root = space.root();
    let mut lowerings = Vec::new();
    let mut raises = Vec::new();
    for &id in space.view() {
        if id == root {
            continue;
        }
        let Some(opened) = space.opened(id).filter(|o| o.is_roster()) else {
            continue;
        };
        let Some(author) = space.log().event(id).map(|e| *e.author()) else {
            continue;
        };
        let place = space.place_of(id);
        let roster = space.roster_at(&place);
        let by = space.author_state_at(id).map(|state| state.authority_key());
        if !space.valid_roster().contains(&id) {
            continue;
        }
        let mut targets = Vec::new();
        for change in opened.changes() {
            let Some(device) = change.member.and_then(|m| m.device_id()) else {
                continue;
            };
            if matches!(change.op, Op::Grant | Op::Change)
                && change.level == Some(Level::Administer)
            {
                raises.push((id, device));
            }
            let Some(state) = roster.state(&MemberRef::device(device)) else {
                continue;
            };
            if state.level != Level::Administer || extends_dormant(&state.capabilities) {
                continue;
            }
            if lowers(change) {
                targets.push(Lowered {
                    device,
                    rank: state.rank,
                    seniority: state.seniority,
                });
            }
        }
        if !targets.is_empty() {
            lowerings.push(Lowering {
                event: id,
                author,
                by,
                targets,
            });
        }
    }
    (lowerings, raises)
}

/// roster.md, 3.15.4, heard members of a resolved view: each device that a
/// valid roster event of the view lowered from `administer`, that `kept`
/// (the record's administrators without `frasil.dormant`) does not hold,
/// and that no such event lowered while signed by itself or by a member
/// that outranks it at its place. A lowering after which a valid event of
/// the view raised it back to `administer` does not count. Each maps to
/// the smallest of its seniorities and the highest of its ranks at those
/// places.
fn heard_of(outcome: &Outcome, kept: &BTreeSet<DeviceId>) -> BTreeMap<DeviceId, (Seniority, u8)> {
    let mut found: BTreeMap<DeviceId, (bool, Seniority, u8)> = BTreeMap::new();
    for lowering in &outcome.lowerings {
        for target in &lowering.targets {
            let raised = outcome.raises.iter().any(|&(raise, device)| {
                device == target.device && outcome.raised_after.contains(&(lowering.event, raise))
            });
            if raised {
                continue;
            }
            let excusing = lowering.author == target.device
                || lowering.by.is_some_and(|by| by < target.authority_key());
            let rank = target.rank.unwrap_or(0);
            let entry = found
                .entry(target.device)
                .or_insert((false, target.seniority, rank));
            entry.0 |= excusing;
            entry.1 = entry.1.min(target.seniority);
            entry.2 = entry.2.max(rank);
        }
    }
    found
        .into_iter()
        .filter(|(device, (excused, _, _))| !excused && !kept.contains(device))
        .map(|(device, (_, seniority, rank))| (device, (seniority, rank)))
        .collect_map()
}

/// Whether an event is a skeleton cut: a storage event of type 7
/// (peers.md, "Skeleton cuts"), read from its body's type alone.
pub fn is_skeleton_cut(event: &Event) -> bool {
    if event.kind() != kind::STORAGE {
        return false;
    }
    let Ok(value) = frasil_base::cbor::decode(event.unverified_body()) else {
        return false;
    };
    value
        .as_map()
        .ok()
        .and_then(|map| map.get(&STORAGE_TYPE_KEY))
        .and_then(|kind| kind.as_unsigned().ok())
        == Some(SKELETON_CUT)
}

/// A storage body's type key (peers.md, "Storage events").
const STORAGE_TYPE_KEY: u64 = 2;
/// A skeleton cut's storage type (peers.md, "Skeleton cuts").
pub const SKELETON_CUT: u64 = 7;

/// Which space events are checkpoints, as a screened view knows them: one
/// it opened and found of roster part type 2; `None` while it holds one it
/// cannot open, or does not hold it.
impl Checkpoints for crate::ScreenedLog {
    fn is_checkpoint(&self, event: &Event) -> Option<bool> {
        match self.body(event.id())? {
            Body::Opened(opened) => Some(opened.checkpoint().is_some()),
            Body::Held(_) => None,
            Body::Refused(_) | Body::Void(_) => Some(false),
        }
    }
}

/// Which space events are checkpoints, as a resolved view knows them.
impl Checkpoints for Space<'_> {
    fn is_checkpoint(&self, event: &Event) -> Option<bool> {
        Checkpoints::is_checkpoint(self.screened(), event)
    }
}
