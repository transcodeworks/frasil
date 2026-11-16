//! Top-ups as a replica computes them (admission.md, "Top-ups").
//!
//! A member admitted "from now on" opens what its snapshot covers, its
//! break's past, and what is sealed under states it holds, from its break
//! on. A space event or a unit concurrent with the break and sealed under a
//! state from before it stays `Sealed` at the member, and so does
//! everything after it, until a writer hands the member its body key in a
//! `frasil:body-keys` unit.
//!
//! The replica keeps, after each resolution, the space events and units of
//! its view that are in some break's top-up set and whose body key no
//! body-keys unit after that break carries. A unit after the break is
//! sealed under a state the member holds, or one it is delivered as an
//! inside device (keys.md, "Deliveries"). [`Engine::top_up`](crate::advanced::Engine)
//! publishes those whose body key this device holds, after its rank delay.
//!
//! Units appended without a full resolution are kept out of the top-up set
//! only while each follows every break: [`Frontier`] says so from its
//! parents, and a unit it cannot place calls for a full resolution.

use crate::replica::visible;
use frasil_base::collect::CollectMap;
use frasil_crypto::device::DeviceId;
use frasil_events::{Event, EventId, Log, kind};
use frasil_space::Space;
use std::collections::BTreeMap;

/// A set of breaks, one bit per break, by its position among the view's
/// breaks.
#[derive(Clone, Default)]
struct Breaks(Vec<u64>);

impl Breaks {
    fn with(count: usize) -> Self {
        Self(vec![0; count.div_ceil(64)])
    }

    fn insert(&mut self, i: usize) {
        self.0[i / 64] |= 1 << (i % 64);
    }

    fn contains(&self, i: usize) -> bool {
        self.0[i / 64] & (1 << (i % 64)) != 0
    }

    fn extend(&mut self, other: &Self) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a |= b;
        }
    }

    fn is_all(&self, count: usize) -> bool {
        (0..count).all(|i| self.contains(i))
    }
}

/// For each writer, its newest event known to follow every break of the
/// view, by `seq`. An event follows every break when one of its parents is
/// such an event or comes after one in its writer's chain.
#[derive(Clone, Debug, Default)]
pub(crate) struct Frontier(BTreeMap<DeviceId, (u64, EventId)>);

impl Frontier {
    /// Whether `event` follows every break, read from its parents; if so,
    /// it becomes its writer's entry when it is newer.
    pub(crate) fn admit(&mut self, log: &Log, event: &Event) -> bool {
        let follows = event.parents().iter().any(|parent| {
            let Some(p) = log.event(*parent) else {
                return false;
            };
            self.0.get(p.author()).is_some_and(|&(seq, id)| {
                id == *parent || (p.seq() > seq && log.precedes(id, *parent))
            })
        });
        if follows {
            self.record(*event.author(), event.seq(), event.id());
        }
        follows
    }

    fn record(&mut self, author: DeviceId, seq: u64, id: EventId) {
        let entry = self.0.entry(author).or_insert((seq, id));
        if seq > entry.0 {
            *entry = (seq, id);
        }
    }
}

/// What a full resolution finds of top-ups.
#[derive(Debug, Default)]
pub(crate) struct Owed {
    /// The space events and units owed, in canonical order.
    pub ids: Vec<EventId>,
    /// `None` when the view holds no break; otherwise the events known to
    /// follow every break.
    pub frontier: Option<Frontier>,
}

/// The space events and units of a resolved view in a break's top-up set
/// whose body key no `frasil:body-keys` unit after that break carries, in
/// canonical order, and the [`Frontier`] of the events that follow every
/// break. `carried` names, for each event, the body-keys units of the
/// system stream that carry its key; `unit_state` reads the state a unit's
/// key reference names (its own state, in a restricted space).
///
/// A break is a valid rotation that carries `break` (keys.md, 2.6 The space
/// event's body). An event is in its top-up set when it is concurrent with
/// the break and sealed under a state none of whose rotations is the break
/// or follows it: a rotation concurrent with the break is sealed under
/// itself.
///
/// Order is read from the view's parents. A parent outside the view, such
/// as a stub, hides its own past, so an event counts as concurrent with a
/// break only when no such parent in either one's past stands above the
/// other: an event outside the view can lead to an earlier one only from
/// above it.
pub(crate) fn owed(
    space: &Space<'_>,
    log: &Log,
    carried: &BTreeMap<EventId, Vec<EventId>>,
    unit_state: impl Fn(&Event) -> Option<Vec<EventId>>,
) -> Owed {
    let order = log.canonical_in(space.view());
    let breaks: Vec<EventId> = order
        .iter()
        .copied()
        .filter(|id| {
            log.event(*id).is_some_and(|e| !e.is_genesis())
                && space.status(*id).is_some_and(|s| s.is_valid())
                && space
                    .opened(*id)
                    .is_some_and(|o| o.visible.rotates() && o.inner.is_break)
        })
        .collect();
    if breaks.is_empty() {
        return Owed::default();
    }
    let index: BTreeMap<EventId, usize> = order
        .iter()
        .enumerate()
        .map(|(i, id)| (*id, i))
        .collect_map();
    let empty = Breaks::with(breaks.len());
    // The order is canonical, so each event follows its parents: `after`
    // holds the breaks each event equals or follows, `before` those it
    // equals or precedes.
    let mut after = vec![empty.clone(); order.len()];
    let mut before = vec![empty.clone(); order.len()];
    for (j, id) in breaks.iter().enumerate() {
        if let Some(&i) = index.get(id) {
            after[i].insert(j);
            before[i].insert(j);
        }
    }
    // The highest parent outside the view in each event's past.
    let mut hidden = vec![0u64; order.len()];
    for (i, id) in order.iter().enumerate() {
        let Some(event) = log.event(*id) else {
            continue;
        };
        for p in event.parents() {
            let above = match index.get(p) {
                Some(&j) => hidden[j],
                None => log.height(*p).unwrap_or(u64::MAX),
            };
            hidden[i] = hidden[i].max(above);
        }
    }
    let height = |i: usize| log.height(order[i]).unwrap_or(0);
    let parents = |i: usize| -> Vec<usize> {
        log.event(order[i])
            .map(|e| {
                e.parents()
                    .iter()
                    .filter_map(|p| index.get(p).copied())
                    .collect()
            })
            .unwrap_or_default()
    };
    for i in 0..order.len() {
        for p in parents(i) {
            let from = after[p].clone();
            after[i].extend(&from);
        }
    }
    for i in (0..order.len()).rev() {
        let from = before[i].clone();
        for p in parents(i) {
            before[p].extend(&from);
        }
    }
    let mut frontier = Frontier::default();
    let mut out = Vec::new();
    for (i, id) in order.iter().enumerate() {
        let Some(event) = log.event(*id) else {
            continue;
        };
        if after[i].is_all(breaks.len()) {
            frontier.record(*event.author(), event.seq(), *id);
        }
        if event.is_genesis() {
            continue;
        }
        let state: Vec<EventId> = match event.kind() {
            kind::SPACE => {
                let Some(part) = visible(event) else {
                    continue;
                };
                match part.sealed_under() {
                    Some(state) => state.ids().to_vec(),
                    None => vec![*id],
                }
            }
            kind::UNIT => match unit_state(event) {
                Some(state) => state,
                None => continue,
            },
            _ => continue,
        };
        // The breaks that a body-keys unit carrying this event follows.
        let mut covered = empty.clone();
        for unit in carried.get(id).into_iter().flatten() {
            if let Some(&u) = index.get(unit) {
                covered.extend(&after[u]);
            }
        }
        let owed = breaks.iter().enumerate().any(|(j, b)| {
            let Some(&b) = index.get(b) else {
                return false;
            };
            let concurrent = !after[i].contains(j)
                && !before[i].contains(j)
                && hidden[b] <= height(i)
                && hidden[i] <= height(b);
            let from_before = state
                .iter()
                .all(|r| index.get(r).is_none_or(|&r| !after[r].contains(j)));
            concurrent && from_before && !covered.contains(j)
        });
        if owed {
            out.push(*id);
        }
    }
    Owed {
        ids: out,
        frontier: Some(frontier),
    }
}
