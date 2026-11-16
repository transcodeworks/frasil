//! Compaction from a log (units.md, section 3.5, "Compacting"), and stubs
//! against the events they stand for (section 3.9, "Placing against
//! stubs").
//!
//! A compactor chooses the cut by the snapshot unit's parents. `covers` is
//! exactly the stream past of `s`: for each writer with a unit of the
//! stream in the past of `s`, the pair names that writer's stream frontier
//! there. The **cover** is, for each pair `[w, c]`, the unit `c` and every
//! unit of `w` in the stream with a smaller `seq`. The **boundary stubs**
//! are every unit of the cover that is a parent of an event in the view
//! outside the cover, `s` included, and every stub of an earlier snapshot
//! unit in the cover that is still such a parent.
//!
//! Placing against stubs is `frasil_events::Log`'s: an event is placed once
//! each parent is placed or has a stub, whose height it takes. Here are
//! the checks units.md adds: a stub against the event it stands for
//! ([`check_stub`], [`compare_stub`]).

use crate::UnitClass;
use crate::body::{Cover, Stub};
use crate::stream::StreamId;
use frasil_crypto::device::DeviceId;
use frasil_events::{Cuts, Event, EventId, Log};
use std::collections::{BTreeMap, BTreeSet};

/// Each writer's stream frontier in the past the parents fix: the covers of
/// a snapshot unit of `stream` with these parents. `stream_of` gives a
/// placed unit's stream, and `None` for any other event.
pub fn covers(
    log: &Log,
    stream_of: impl Fn(EventId) -> Option<StreamId>,
    parents: &[EventId],
    stream: &StreamId,
) -> Vec<Cover> {
    let mut past = BTreeSet::new();
    for &parent in parents {
        if log.event(parent).is_some() {
            past.insert(parent);
            past.extend(log.past(parent));
        }
    }
    let mut best: BTreeMap<DeviceId, (u64, EventId)> = BTreeMap::new();
    for id in past {
        if stream_of(id).as_ref() != Some(stream) {
            continue;
        }
        let Some(event) = log.event(id) else {
            continue;
        };
        let entry = (event.seq(), id);
        best.entry(*event.author())
            .and_modify(|held| *held = (*held).max(entry))
            .or_insert(entry);
    }
    best.into_iter()
        .map(|(writer, (_, unit))| Cover { writer, unit })
        .collect()
}

/// The cover of a snapshot unit, as far as the log holds it: for each pair
/// `[w, c]`, the unit `c` and every unit of `w` in the stream with a
/// smaller `seq`.
pub fn cover_set(
    log: &Log,
    stream_of: impl Fn(EventId) -> Option<StreamId>,
    covers: &[Cover],
    stream: &StreamId,
) -> BTreeSet<EventId> {
    let mut cover = BTreeSet::new();
    for pair in covers {
        let Some(last) = log.event(pair.unit) else {
            continue;
        };
        let limit = last.seq();
        for id in log.chain(&pair.writer) {
            let Some(event) = log.event(id) else {
                continue;
            };
            if event.seq() <= limit && stream_of(id).as_ref() == Some(stream) {
                cover.insert(id);
            }
        }
    }
    cover
}

/// The stub of a placed event: its ID, author, `seq`, height and kind,
/// and the cuts it declares (section 2.10).
pub fn stub_of(log: &Log, id: EventId) -> Option<Stub> {
    let event = log.event(id)?;
    Some(Stub {
        id,
        author: *event.author(),
        seq: event.seq(),
        height: log.height(id)?,
        kind: event.kind(),
        stream: None,
        cuts: Cuts::of(event),
    })
}

/// The boundary stubs of a cover (section 3.5, step 3): every unit of the
/// cover that an event of the log outside the cover names as a parent, or
/// that one of `outside_parents` names (the snapshot unit's own parents,
/// before it is placed); and every stub of `earlier` (the stubs of earlier
/// snapshot units in the cover) that such an event or parent list still
/// names. Earlier stubs that nothing outside the cover names are dropped.
pub fn boundary_stubs(
    log: &Log,
    cover: &BTreeSet<EventId>,
    outside_parents: &[EventId],
    earlier: &[Stub],
) -> Vec<Stub> {
    let mut named: BTreeSet<EventId> = outside_parents.iter().copied().collect();
    for event in log.events() {
        if !cover.contains(&event.id()) {
            named.extend(event.parents().iter().copied());
        }
    }
    let mut stubs: BTreeMap<EventId, Stub> = BTreeMap::new();
    for id in named.intersection(cover) {
        if let Some(stub) = stub_of(log, *id) {
            stubs.insert(*id, stub);
        }
    }
    for stub in earlier {
        if named.contains(&stub.id) && !stubs.contains_key(&stub.id) {
            stubs.insert(
                stub.id,
                Stub {
                    stream: None,
                    ..*stub
                },
            );
        }
    }
    stubs.into_values().collect()
}

/// Section 3.9: a replica that holds both an event and a stub of it
/// compares author, `seq`, height, kind and the cuts the stub carries with
/// the ones the event declares (none when the stub carries none). A
/// mismatch is `BadStub`: the replica uses the event and reports the stub's
/// signer. A stub of an event the log does not hold passes.
///
/// # Errors
///
/// `BadStub`.
pub fn check_stub(log: &Log, stub: &Stub) -> Result<(), UnitClass> {
    let Some(event) = log.event(stub.id) else {
        return Ok(());
    };
    match log.height(stub.id) {
        Some(height) => compare_stub(stub, event, height),
        None => Err(UnitClass::BadStub),
    }
}

/// Section 3.9: a stub against the event it names, at the height the
/// replica computed for that event: author, `seq`, height, kind and cuts.
/// The stream a space snapshot's stub carries is not compared here.
///
/// # Errors
///
/// `BadStub` on any mismatch, the event's ID included.
pub fn compare_stub(stub: &Stub, event: &Event, height: u64) -> Result<(), UnitClass> {
    if stub.id != event.id()
        || *event.author() != stub.author
        || event.seq() != stub.seq
        || height != stub.height
        || event.kind() != stub.kind
        || stub.cuts.as_slice() != event.cuts()
    {
        return Err(UnitClass::BadStub);
    }
    Ok(())
}
