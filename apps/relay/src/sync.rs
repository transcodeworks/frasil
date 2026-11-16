//! What the peer serves of units.md's sync (units.md, "Sync"; peers.md,
//! "Presenting a credential": fetch and catch-up).
//!
//! **Fetch** serves every stored event of the space. **Catch-up** serves
//! the space's events of kinds 2 and 6; by ID, any parent of an event
//! served on the connection, or a collected parent's stub answer; and the
//! units of the one stream the connection names as the space's system
//! stream. A released stream's units are served to no one, and listings
//! omit them.

use crate::space::Space;
use crate::state::{Grant, sync};
use frasil_crypto::device::DeviceId;
use frasil_events::{Event, EventId, kind};
use frasil_units::body::Cover;
use frasil_units::limits::{MAX_MESSAGE_BYTES, MAX_MESSAGE_ITEMS};
use frasil_units::messages::{Message, Range, StreamWriter, VectorEntry};
use frasil_units::stream::StreamId;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// What a message's keys and wrapping take beyond its events.
const OVERHEAD: usize = 4_096;

/// Splits events into `Events` messages within units.md's limits, each in
/// a `Sync` of the space.
pub(crate) fn events_messages(space: EventId, events: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut batch: Vec<Vec<u8>> = Vec::new();
    let mut bytes = 0usize;
    for event in events {
        let size = event.len() + 9;
        if !batch.is_empty()
            && (batch.len() >= MAX_MESSAGE_ITEMS || bytes + size + OVERHEAD > MAX_MESSAGE_BYTES)
        {
            out.push(sync(
                space,
                Message::Events {
                    events: std::mem::take(&mut batch),
                },
            ));
            bytes = 0;
        }
        bytes += size;
        batch.push(event);
    }
    if !batch.is_empty() {
        out.push(sync(space, Message::Events { events: batch }));
    }
    out
}

/// An answer the peer serves in batches (units.md, "Sync"): the events a
/// connection asked for, by ID in canonical order, as the space held them
/// when it asked, then the messages that follow them. Each batch reads one
/// `Events` message's worth of events with the space's state held, and
/// releases it before the batch is sent, so that an answer holds at most
/// one message of events in memory, whatever the space holds.
///
/// No event of the answer is skipped: its IDs are fixed when the request
/// is read, and each batch takes the next of them in order. An event that
/// is no longer served by then, collected, released or erased meanwhile,
/// is left out, as an answer read then would leave it out. An event stored
/// after the request was read is not in it: live delivery carries it to a
/// subscribed connection, and the next head exchange to any other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answer {
    /// The space.
    pub(crate) space: EventId,
    /// The events to serve, in canonical order.
    ids: Vec<EventId>,
    /// The first not yet served.
    next: usize,
    /// What follows the events, such as `Missing`.
    after: VecDeque<Vec<u8>>,
}

impl Answer {
    /// Whether every part of it was served.
    pub(crate) fn done(&self) -> bool {
        self.next >= self.ids.len() && self.after.is_empty()
    }

    /// Ends its events: what follows them is all that is left.
    pub(crate) fn end_events(&mut self) {
        self.next = self.ids.len();
        self.ids = Vec::new();
    }

    /// The next message of what follows its events.
    pub(crate) fn next_after(&mut self) -> Option<Vec<u8>> {
        self.after.pop_front()
    }

    /// The next batch of its events, as one `Sync` of an `Events` message
    /// within units.md's limits, read from `space`, with their IDs; `None`
    /// once they are all served.
    pub(crate) fn batch(&mut self, space: &Space) -> Option<(Vec<u8>, Vec<EventId>)> {
        let released = space.released_streams();
        let mut events = Vec::new();
        let mut ids = Vec::new();
        let mut bytes = 0usize;
        while let Some(&id) = self.ids.get(self.next) {
            let Some(event) = space
                .log
                .event(id)
                .filter(|_| space.servable(id, &released))
            else {
                self.next += 1;
                continue;
            };
            let size = event.signed_len() + 9;
            if !events.is_empty()
                && (events.len() >= MAX_MESSAGE_ITEMS
                    || bytes + size + OVERHEAD > MAX_MESSAGE_BYTES)
            {
                break;
            }
            bytes += size;
            events.push(event.signed());
            ids.push(id);
            self.next += 1;
        }
        if self.next >= self.ids.len() {
            self.ids = Vec::new();
        }
        (!events.is_empty()).then(|| (sync(self.space, Message::Events { events }), ids))
    }
}

/// What a sync request is answered: messages at once, then, in batches,
/// an answer's events and what follows them.
#[derive(Debug, Default)]
pub(crate) struct Reply {
    /// The messages sent first.
    pub(crate) now: Vec<Vec<u8>>,
    /// The events, and what follows them.
    pub(crate) answer: Option<Answer>,
}

impl Reply {
    fn now(now: Vec<Vec<u8>>) -> Self {
        Self { now, answer: None }
    }
}

/// What one connection may be served of one space.
pub(crate) struct View<'a> {
    space: &'a Space,
    released: BTreeSet<StreamId>,
    grant: &'a mut Grant,
}

impl<'a> View<'a> {
    pub(crate) fn new(space: &'a Space, grant: &'a mut Grant) -> Self {
        let released = space.released_streams();
        Self {
            space,
            released,
            grant,
        }
    }

    /// Whether a listing may show an event: fetch, or catch-up's kinds and
    /// system stream.
    fn listed(&self, id: EventId) -> bool {
        if !self.space.servable(id, &self.released) {
            return false;
        }
        if self.grant.rights.fetch {
            return true;
        }
        if !self.grant.rights.catch_up {
            return false;
        }
        let Some(event) = self.space.log.event(id) else {
            return false;
        };
        match event.kind() {
            kind::SPACE | kind::STORAGE => true,
            kind::UNIT => self
                .space
                .units
                .get(&id)
                .is_some_and(|unit| self.grant.system_stream.as_ref() == Some(&unit.stream)),
            _ => false,
        }
    }

    /// Whether the connection may fetch an event by ID: a listed one, or,
    /// under catch-up, a parent of an event served on it.
    fn by_id(&self, id: EventId) -> bool {
        if self.listed(id) {
            return true;
        }
        self.grant.rights.catch_up
            && self.space.servable(id, &self.released)
            && self.grant.served.iter().any(|served| {
                self.space
                    .log
                    .event(*served)
                    .is_some_and(|event| event.parents().contains(&id))
            })
    }

    fn event(&self, id: EventId) -> Option<&'a Event> {
        self.space.log.event(id)
    }

    /// An answer that serves events, in canonical order, then `after`.
    fn serve(&mut self, mut ids: Vec<EventId>, after: Vec<Vec<u8>>) -> Answer {
        let log = &self.space.log;
        ids.retain(|&id| log.contains(id));
        ids.sort_by_key(|&id| (log.height(id).unwrap_or(0), id));
        ids.dedup();
        Answer {
            space: self.space.id,
            ids,
            next: 0,
            after: after.into(),
        }
    }

    /// The heads and vector of what the connection may list.
    fn heads(&self) -> (Vec<EventId>, Vec<VectorEntry>) {
        let listed: BTreeSet<EventId> = self
            .space
            .log
            .canonical()
            .into_iter()
            .filter(|&id| self.listed(id))
            .collect();
        let mut parents = BTreeSet::new();
        let mut vector: BTreeMap<DeviceId, (u64, EventId)> = BTreeMap::new();
        for &id in &listed {
            let Some(event) = self.event(id) else {
                continue;
            };
            parents.extend(event.parents().iter().copied());
            let entry = (event.seq(), id);
            vector
                .entry(*event.author())
                .and_modify(|held| *held = (*held).max(entry))
                .or_insert(entry);
        }
        let mut heads: Vec<EventId> = listed.difference(&parents).copied().collect();
        heads.truncate(MAX_MESSAGE_ITEMS);
        let vector = vector
            .into_iter()
            .take(MAX_MESSAGE_ITEMS)
            .map(|(author, (seq, id))| VectorEntry { author, seq, id })
            .collect();
        (heads, vector)
    }

    /// `Heads`: the peer's own heads, then what the other side lacks
    /// (units.md, "Sync", the exchange, step 1). A partial replica's
    /// `Heads` name its streams: of units, only those streams' are sent.
    pub(crate) fn on_heads(
        &mut self,
        heads: &[EventId],
        vector: Option<&[VectorEntry]>,
        streams: &[StreamId],
    ) -> Reply {
        let (own, own_vector) = self.heads();
        let out = vec![sync(
            self.space.id,
            Message::Heads {
                heads: own,
                vector: Some(own_vector),
                streams: Vec::new(),
            },
        )];
        let log = &self.space.log;
        let mut past: BTreeSet<EventId> = BTreeSet::new();
        let mut unknown = false;
        for &head in heads {
            if log.contains(head) {
                past.insert(head);
                past.extend(log.past(head));
            } else {
                unknown = true;
            }
        }
        let held: BTreeMap<DeviceId, u64> = vector
            .unwrap_or_default()
            .iter()
            .map(|entry| (entry.author, entry.seq))
            .collect();
        let lacking: Vec<EventId> = log
            .canonical()
            .into_iter()
            .filter(|id| !past.contains(id) && self.listed(*id))
            .filter(|id| {
                frasil_units::messages::sent_after_heads(
                    self.space.units.get(id).map(|unit| &unit.stream),
                    streams,
                    self.grant.system_stream.as_ref(),
                )
            })
            .filter(|id| {
                !unknown
                    || self.event(*id).is_none_or(|event| {
                        held.get(event.author())
                            .is_none_or(|&seq| event.seq() > seq)
                    })
            })
            .collect();
        Reply {
            now: out,
            answer: Some(self.serve(lacking, Vec::new())),
        }
    }

    /// `Want`: events by ID and by author and `seq`; `Missing` for what the
    /// peer cannot serve.
    pub(crate) fn on_want(
        &mut self,
        ids: &[EventId],
        ranges: &[Range],
        kinds: &[u8],
        streams: &[StreamId],
    ) -> Reply {
        if self.grant.rights.catch_up
            && !self.grant.rights.fetch
            && self.grant.system_stream.is_none()
            && let [stream] = streams
        {
            self.grant.system_stream = Some(*stream);
        }
        let mut found = Vec::new();
        let mut missing = Vec::new();
        let mut carried = Vec::new();
        for &id in ids {
            if self.by_id(id) {
                found.push(id);
            } else if let Some(Some(carrier)) = self.space.stubs.get(&id) {
                carried.push((id, *carrier));
            } else {
                missing.push(id);
            }
        }
        for range in ranges {
            for id in self.space.log.chain(&range.author) {
                let Some(event) = self.event(id) else {
                    continue;
                };
                if event.seq() < range.first || event.seq() > range.last {
                    continue;
                }
                if !kinds.is_empty() && !kinds.contains(&event.kind()) {
                    continue;
                }
                if event.kind() == kind::UNIT
                    && !streams.is_empty()
                    && !self
                        .space
                        .units
                        .get(&id)
                        .is_some_and(|unit| streams.contains(&unit.stream))
                {
                    continue;
                }
                if self.listed(id) {
                    found.push(id);
                }
            }
        }
        let mut after = Vec::new();
        if !missing.is_empty() || !carried.is_empty() {
            missing.truncate(MAX_MESSAGE_ITEMS);
            carried.truncate(MAX_MESSAGE_ITEMS);
            after.push(sync(
                self.space.id,
                Message::Missing {
                    ids: missing,
                    carried,
                },
            ));
        }
        Reply {
            now: Vec::new(),
            answer: Some(self.serve(found, after)),
        }
    }

    /// `StreamWant`: `StreamHeads`, then the latest snapshot unit if asked
    /// for, and every unit of the stream after its cover that the other
    /// side lacks (units.md, "Sync", by stream).
    pub(crate) fn on_stream_want(
        &mut self,
        stream: &StreamId,
        held: &[Cover],
        from_snapshot: bool,
    ) -> Reply {
        if !self.grant.rights.fetch {
            if !self.grant.rights.catch_up {
                return Reply::default();
            }
            match self.grant.system_stream {
                None => self.grant.system_stream = Some(*stream),
                Some(system) if system != *stream => return Reply::default(),
                Some(_) => {}
            }
        }
        let units: Vec<EventId> = self
            .space
            .streams
            .get(stream)
            .map(|units| {
                units
                    .iter()
                    .copied()
                    .filter(|&id| self.listed(id))
                    .collect()
            })
            .unwrap_or_default();
        let log = &self.space.log;
        let key = |id: &EventId| (log.height(*id).unwrap_or(0), *id);
        let latest = units
            .iter()
            .copied()
            .filter(|id| {
                self.space
                    .units
                    .get(id)
                    .is_some_and(|unit| unit.compacts.is_some())
            })
            .max_by_key(key);
        let mut writers: BTreeMap<DeviceId, (u64, EventId)> = BTreeMap::new();
        for &id in &units {
            if let Some(event) = self.event(id) {
                let entry = (event.seq(), id);
                writers
                    .entry(*event.author())
                    .and_modify(|held| *held = (*held).max(entry))
                    .or_insert(entry);
            }
        }
        let out = vec![sync(
            self.space.id,
            Message::StreamHeads {
                stream: *stream,
                latest_snapshot: latest,
                writers: writers
                    .iter()
                    .map(|(&writer, &(seq, unit))| StreamWriter { writer, unit, seq })
                    .collect(),
            },
        )];
        let held_seq: BTreeMap<DeviceId, u64> = held
            .iter()
            .filter_map(|cover| {
                self.event(cover.unit)
                    .map(|event| (cover.writer, event.seq()))
            })
            .collect();
        let cover: BTreeSet<EventId> = match (from_snapshot, latest) {
            (true, Some(snapshot)) => self
                .space
                .units
                .get(&snapshot)
                .and_then(|unit| unit.compacts.as_ref())
                .map(|compacts| {
                    frasil_units::compaction::cover_set(
                        log,
                        |id| self.space.units.get(&id).map(|unit| unit.stream),
                        &compacts.covers,
                        stream,
                    )
                })
                .unwrap_or_default(),
            _ => BTreeSet::new(),
        };
        let mut send: Vec<EventId> = units
            .iter()
            .copied()
            .filter(|id| !cover.contains(id))
            .filter(|id| {
                self.event(*id).is_some_and(|event| {
                    held_seq
                        .get(event.author())
                        .is_none_or(|&seq| event.seq() > seq)
                })
            })
            .collect();
        if from_snapshot && let Some(snapshot) = latest {
            send.push(snapshot);
        }
        Reply {
            now: out,
            answer: Some(self.serve(send, Vec::new())),
        }
    }

    /// `PathWant`: a path from one event down to another through parents.
    pub(crate) fn on_path_want(&mut self, from: EventId, to: EventId) -> Reply {
        let log = &self.space.log;
        let mut path = Vec::new();
        if let Some(start) = self.event(from).filter(|_| self.by_id(from))
            && !start.parents().contains(&to)
        {
            {
                // Breadth first from `from`'s parents to an event with `to`
                // among its parents.
                let mut previous: BTreeMap<EventId, EventId> = BTreeMap::new();
                let mut queue: VecDeque<EventId> = start
                    .parents()
                    .iter()
                    .copied()
                    .filter(|&p| log.contains(p) && self.listed(p))
                    .collect();
                let mut seen: BTreeSet<EventId> = queue.iter().copied().collect();
                let mut end = None;
                while let Some(id) = queue.pop_front() {
                    let Some(event) = self.event(id) else {
                        continue;
                    };
                    if event.parents().contains(&to) {
                        end = Some(id);
                        break;
                    }
                    for &parent in event.parents() {
                        if log.contains(parent) && self.listed(parent) && seen.insert(parent) {
                            previous.insert(parent, id);
                            queue.push_back(parent);
                        }
                    }
                }
                if let Some(mut id) = end {
                    let mut ids = vec![id];
                    while let Some(&before) = previous.get(&id) {
                        ids.push(before);
                        id = before;
                    }
                    ids.reverse();
                    ids.truncate(MAX_MESSAGE_ITEMS);
                    path = ids;
                }
            }
        }
        // One message, within units.md's limits: a path longer than it
        // holds is cut, as one past its items is.
        let mut events: Vec<Vec<u8>> = Vec::new();
        let mut bytes = 0usize;
        for event in path.iter().filter_map(|&id| self.event(id)) {
            let size = event.signed_len() + 9;
            if bytes + size + OVERHEAD > MAX_MESSAGE_BYTES {
                break;
            }
            bytes += size;
            events.push(event.signed());
        }
        Reply::now(vec![sync(
            self.space.id,
            Message::Path { from, to, events },
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_split_within_the_limits() {
        let space = EventId([1; 32]);
        let small = vec![vec![0u8; 10]; MAX_MESSAGE_ITEMS + 1];
        assert_eq!(events_messages(space, small).len(), 2);
        let big = vec![vec![0u8; 600_000]; 3];
        assert_eq!(events_messages(space, big).len(), 3);
        assert!(events_messages(space, Vec::new()).is_empty());
    }
}
