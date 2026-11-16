//! The administrator skeleton as a device takes part in it (peers.md, "The
//! skeleton"; roster.md, "The twin").
//!
//! - **Slots.** Each device at `administer` has an administrator slot,
//!   named by its slot reference `[c, index, maker]`: the founder's is
//!   `[c(genesis), 0, the root]`; every other is `[c(R), i, the twin]`,
//!   made by the twin of the valid roster event `R` that granted it, at its
//!   index among `R`'s grants of `administer`.
//! - **Twins.** A roster event that changes who administers is preceded by
//!   its twin: a skeleton change, signed by the author's enrolled
//!   pseudonym, whose commitment `c(R)` derives from `R`'s body key and
//!   self reference and a fresh salt, so it is signed before `R` exists. It grants a slot to
//!   each device `R` grants `administer`, sealing each slot's token to its
//!   grantee, or lowers the slot of the device `R` lowers.
//! - **Enrolment.** A granted device opens its token, draws a fresh
//!   pseudonym, and enrols it in its slot, with the slot keys'
//!   authorization and a binding sealed under `twin_secret(R)`.

use frasil_crypto::device::DeviceId;
use frasil_events::{Event, EventId, Log, kind};
use frasil_peers::body::{ChangeEffect, GrantMap, SlotId, StorageBody};
use frasil_peers::derive::{twin_commitment, twin_secret};
use frasil_peers::skeleton::check_root;
use frasil_space::Space;
use frasil_space::state::administer_changes;
use std::collections::{BTreeMap, BTreeSet};

/// A device's administrator slot, and what made it.
#[derive(Debug, Clone)]
pub(crate) struct SlotInfo {
    /// The slot's reference.
    pub slot: SlotId,
    /// The roster event whose twin made it; the genesis for the root's.
    pub origin: EventId,
    /// The grant map of the twin that made it; none for the root's.
    pub grant: Option<GrantMap>,
}

/// The slots a replica derives from its valid roster events and the
/// skeleton events they name.
#[derive(Debug, Clone, Default)]
pub(crate) struct Slots {
    /// Each administrator's latest slot, by device ID.
    pub by_device: BTreeMap<DeviceId, SlotInfo>,
    /// Each enrolled slot's pseudonym, by its device ID: from the
    /// enrolments valid in the skeleton's resolution (peers.md, 3.12 The
    /// skeleton's resolution), each verified in full under the pseudonym's
    /// own keys and its administrator slot's (3.11, step 3).
    pub enrolled: BTreeMap<SlotId, DeviceId>,
    /// Holding envelopes and their bound devices.
    pub holders: BTreeMap<DeviceId, (EventId, Option<DeviceId>)>,
    /// The log's heads when `enrolled` was derived: the resolution reads
    /// the log alone, so it runs again only when the log changed.
    enrolled_at: Option<Vec<EventId>>,
    /// Whether each root body checked so far passes peers.md's checks of a
    /// root: the outcome depends on the event and the genesis alone, so
    /// the signatures of a root are verified once.
    roots: BTreeMap<EventId, bool>,
}

/// The root of a log, as [`frasil_peers::skeleton::root_of`] finds it: the
/// first storage event in canonical order whose body reads as a root and
/// that passes the checks of a root (peers.md, "The skeleton"), each
/// root's outcome taken from `roots` or recorded there.
fn root_in(log: &Log, roots: &mut BTreeMap<EventId, bool>) -> Option<EventId> {
    log.canonical().into_iter().find(|&id| {
        if let Some(&passes) = roots.get(&id) {
            return passes;
        }
        let Some(event) = log.event(id) else {
            return false;
        };
        let Some(body @ StorageBody::Root { .. }) = storage_body(event) else {
            return false;
        };
        let passes = frasil_peers::body::check_size(event.signed_len()).is_ok()
            && check_root(log, event, &body).is_ok();
        roots.insert(id, passes);
        passes
    })
}

/// A storage event's body, if it reads, as a peer reads it: whether the
/// event's signature verified in full is the caller's question.
pub(crate) fn storage_body(event: &Event) -> Option<StorageBody> {
    (event.kind() == kind::STORAGE)
        .then(|| StorageBody::read(event.unverified_body()).ok())
        .flatten()
}

/// Whether an event is a skeleton event: a storage event of types 0 to 6.
pub(crate) fn is_skeleton(event: &Event) -> bool {
    storage_body(event).is_some_and(|body| body.storage_type().is_skeleton())
}

/// The slots of a resolved space; `previous`, the slots derived before,
/// lends the roots it checked.
pub(crate) fn derive_slots(space: &Space<'_>, log: &Log, previous: &Slots) -> Slots {
    let mut slots = Slots {
        roots: previous.roots.clone(),
        ..Slots::default()
    };
    let mut heads = log.heads();
    heads.sort_unstable();
    let genesis = log.id();
    // The root's slot, the founder's: the root carries no salt.
    let root = root_in(log, &mut slots.roots);
    if let (Some(opened), Some(root)) = (space.opened(genesis), root) {
        let founder = *log.genesis().author();
        let c = twin_commitment(&founder, 1, &twin_secret(&opened.body_key), &[]);
        slots.by_device.insert(
            founder,
            SlotInfo {
                slot: SlotId::new(c, 0, root),
                origin: genesis,
                grant: None,
            },
        );
    }
    for id in log.canonical() {
        if !space.valid_roster().contains(&id) || id == genesis {
            continue;
        }
        let Some(opened) = space.opened(id) else {
            continue;
        };
        let Some(twin) = opened.visible.twin else {
            continue;
        };
        let Some(StorageBody::Change {
            twin: c, effect, ..
        }) = log.event(EventId(twin)).and_then(storage_body)
        else {
            continue;
        };
        let roster = space.roster_at(&space.place_of(id));
        let changes = administer_changes(opened.changes(), &roster);
        match effect {
            ChangeEffect::Grants(maps) => {
                for (index, device) in changes.grants.iter().enumerate() {
                    let Ok(index_byte) = u8::try_from(index) else {
                        continue;
                    };
                    slots.by_device.insert(
                        *device,
                        SlotInfo {
                            slot: SlotId::new(c, index_byte, EventId(twin)),
                            origin: id,
                            grant: maps.get(index).cloned(),
                        },
                    );
                }
            }
            ChangeEffect::Lower(slot) => {
                slots.by_device.retain(|_, info| info.slot != slot);
            }
        }
    }
    // A checkpoint's record carries the slots whose grant events are now
    // outside the resolution. Use that mapping as well as grants after it:
    // replaying only valid_roster would lose every slot made before it.
    if space.skeleton().is_some() {
        let mut current = BTreeMap::new();
        let mut enrolled = BTreeMap::new();
        for (device, entry) in space.administrator_slots() {
            let Ok(index) = u8::try_from(entry.index) else {
                continue;
            };
            let slot = SlotId::new(entry.commitment, index, entry.maker);
            let info = slots
                .by_device
                .get(&device)
                .or_else(|| previous.by_device.get(&device))
                .filter(|info| info.slot == slot)
                .cloned()
                .unwrap_or_else(|| {
                    let grant = match log.event(entry.maker).and_then(storage_body) {
                        Some(StorageBody::Change {
                            effect: ChangeEffect::Grants(maps),
                            ..
                        }) => maps.get(usize::from(index)).cloned(),
                        _ => None,
                    };
                    let origin = log
                        .canonical()
                        .into_iter()
                        .find(|&id| {
                            log.event(id).is_some_and(|event| {
                                event.kind() == kind::SPACE
                                    && frasil_keys::body::VisiblePart::read(
                                        event.unverified_body(),
                                        event.author(),
                                        event.seq(),
                                    )
                                    .is_ok_and(|visible| visible.twin == Some(entry.maker.0))
                            })
                        })
                        .unwrap_or(genesis);
                    SlotInfo {
                        slot,
                        origin,
                        grant,
                    }
                });
            current.insert(device, info);
            if let Ok(id) = <[u8; 32]>::try_from(entry.pseudonym.as_slice()) {
                enrolled.insert(slot, DeviceId(id));
            }
        }
        slots.by_device = current;
        slots.holders = enrolled
            .values()
            .filter_map(|p| space.pseudonym_holder(p).map(|holder| (*p, holder)))
            .collect();
        slots.enrolled = enrolled;
        slots.enrolled_at = Some(heads);
        return slots;
    }
    slots.enrolled = if previous.enrolled_at.as_ref() == Some(&heads) {
        previous.enrolled.clone()
    } else {
        // The resolution's own skeleton when it read the whole log: the
        // same storage events, resolved the same way.
        let whole: BTreeSet<EventId> = log.canonical().into_iter().collect();
        let found = match space
            .skeleton()
            .filter(|skeleton| *skeleton.view() == whole)
        {
            Some(skeleton) => enrolled_in(skeleton, log),
            None => enrolled(log),
        };
        #[cfg(debug_assertions)]
        if crate::replica::check_refreshes() {
            assert_eq!(
                found,
                enrolled(log),
                "enrolments differ from a new skeleton's"
            );
        }
        found
    };
    slots.enrolled_at = Some(heads);
    slots
}

/// The pseudonym enrolled in each administrator slot, as the skeleton's
/// resolution reads the log (peers.md, 3.13 What replicas check: replicas
/// run it over the same storage events as the peer). Only an enrolment
/// that section 3.11 does not refuse counts, so its ML-DSA-65 half and its
/// authorization verified, and only one the resolution finds valid, so
/// neither a second enrolment of its slot nor a concurrent one: a forged
/// or contested enrolment never stands in for the slot's own.
fn enrolled(log: &Log) -> BTreeMap<SlotId, DeviceId> {
    enrolled_in(&frasil_peers::skeleton::Skeleton::new(log, None), log)
}

/// [`enrolled`], read from a skeleton of the whole log.
fn enrolled_in(
    skeleton: &frasil_peers::skeleton::Skeleton<'_>,
    log: &Log,
) -> BTreeMap<SlotId, DeviceId> {
    let mut out = BTreeMap::new();
    for (id, status) in skeleton.statuses() {
        if !status.is_valid() {
            continue;
        }
        if let (Some(StorageBody::Enrol { slot, .. }), Some(event)) =
            (skeleton.body_of(id), log.event(id))
        {
            out.entry(*slot).or_insert(*event.author());
        }
    }
    out
}

/// The skeleton heads of a view: its maximal skeleton events, which a twin
/// or an enrolment cites so that it holds every skeleton event the device
/// holds.
pub(crate) fn skeleton_heads(log: &Log, view: &BTreeSet<EventId>) -> Vec<EventId> {
    let skeleton: Vec<EventId> = view
        .iter()
        .copied()
        .filter(|id| log.event(*id).is_some_and(is_skeleton))
        .collect();
    skeleton
        .iter()
        .copied()
        .filter(|id| !skeleton.iter().any(|o| o != id && log.precedes(*id, *o)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as Json;

    /// peers.json's skeleton history through A1's enrolment, as a log;
    /// with `tamper`, the enrolment's signature has its last byte, in its
    /// ML-DSA-65 half, changed.
    fn through_enrolment(tamper: bool) -> (Log, EventId) {
        let family: Json = frasil_testkit::vectors::family("peers.json", "skeleton");
        let mut log: Option<Log> = None;
        for row in family["events"].as_array().unwrap() {
            let name = row["name"].as_str().unwrap();
            let mut signed = frasil_testkit::hex::decode(row["signed"].as_str().unwrap()).unwrap();
            let enrolment = name == "A1: enrols";
            if enrolment && tamper {
                *signed.last_mut().unwrap() ^= 1;
            }
            let event = frasil_events::decode(&signed).expect("its Ed25519 half verifies");
            let id = event.id();
            match &mut log {
                None => log = Some(Log::new(event).unwrap()),
                Some(log) => {
                    log.place(event).unwrap();
                }
            }
            if enrolment {
                return (log.unwrap(), id);
            }
        }
        panic!("no enrolment in the history");
    }

    /// peers.md, 3.11 step 3 and 3.13: an enrolment counts only once its
    /// signature verifies in full, so one whose ML-DSA-65 half is bad
    /// enrols no pseudonym in its slot.
    #[test]
    fn an_enrolment_whose_mldsa_half_is_bad_derives_no_slot() {
        let (log, id) = through_enrolment(false);
        let author = *log.event(id).unwrap().author();
        let good = enrolled(&log);
        assert_eq!(good.values().copied().collect::<Vec<_>>(), vec![author]);

        let (log, id) = through_enrolment(true);
        assert!(log.event(id).is_some(), "placed, its Ed25519 half verifies");
        assert!(!log.is_verified(id));
        assert!(enrolled(&log).is_empty());
    }
}
