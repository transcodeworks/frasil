//! A lent handle's own operations, replayed onto a rebuilt document.
//!
//! When Frasil builds the main document again (adapter-loro.md, section
//! 3.3), what the handle committed that the rebuilt document does not hold
//! is written again under the handle's peer, and nothing of any other peer:
//! each of its changes, in order, is read from the old document as the
//! difference it made at its own parent version (`LoroDoc::diff`), and
//! applied to the rebuilt document as new operations, every position mapped
//! through the stable IDs of the elements around it (Loro's cursors, list
//! item IDs and tree node IDs).
//!
//! - **Where an insertion goes.** After the nearest element before it, where
//!   it was made, that the rebuilt document holds; else before the nearest
//!   one after it; else at the end. An element the rebuilt document holds
//!   deleted still places it.
//! - **What a deletion takes.** The elements it deleted that the rebuilt
//!   document shows; an element it does not hold is already gone.
//! - **Marks** are the change's own operations: each mark or unmark covers
//!   the characters between its anchors that the rebuilt document shows,
//!   whether or not they already had the style, and the handle's own
//!   characters among them; text the rebuilt document restored between
//!   them, which the mark never covered, stays as it is. A style an inserted character only took from the text around
//!   it, as one typed inside another writer's bold text, is not the
//!   change's. Loro writes no operation for a mark that changes nothing,
//!   so bolding text that is already bold leaves nothing to replay.
//!   **Counters** take the same step. **Map keys** take the value the
//!   change set.
//! - **A movable list** is read from the list just before and just after
//!   the change, by slot and by element (Loro names an item by its
//!   insertion; a slot is the place an insertion or a move made). A move
//!   moves the item it moved, wherever the rebuilt document shows it: to
//!   the front or the end when the change left it first or last, else by
//!   its neighbours just after the change; a set sets the item
//!   it set; a deletion deletes the item. Equal values are never confused,
//!   and the result does not depend on how Loro's diff orders the change.
//! - A container or a tree node the change created is created again, and
//!   the change's later operations follow it there.
//! - **What cannot be placed** is left out and reported: an operation in a
//!   container, under a tree node or on a list item (a move, a set) that
//!   only another writer's lost operation made (Frasil never writes
//!   another writer's operations again), and anything Loro refuses.
//!
//! What the replays of one old document into one rebuilt document made
//! there, the characters, items, containers and nodes, is kept as a
//! [`Mapping`] from the old document's IDs, so that a later change, as a
//! late commit to the old reference, is placed by the handle's own
//! replayed elements. When the rebuilt document is itself replayed into a
//! newer one, the mapping follows it ([`Mapping::through`]).

use frasil_adapter_loro::meta::Counter;
use loro::cursor::{Cursor, Side};
use loro::event::{Diff, ListDiffItem};
use loro::json::{JsonOpContent, MovableListOp, TextOp};
use loro::{
    Container, ContainerID, ContainerTrait, ContainerType, Frontiers, ID, IdLp, IdSpan, Lamport,
    LoroDoc, LoroValue, TextDelta, TreeID, TreeParentId, ValueOrContainer,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// What a replay wrote, and what it left out.
#[derive(Debug, Default)]
pub(crate) struct Replayed {
    /// The counter the next replay of the peer starts from.
    pub(crate) next: Counter,
    /// What could not be placed, one line each.
    pub(crate) left_out: Vec<String>,
}

/// What the replays of one old document into one target made there, by
/// the old document's IDs: kept across those replays, so that a later
/// change finds what an earlier one wrote.
#[derive(Debug, Default, Clone)]
pub(crate) struct Mapping {
    /// The old document's peer, whose operations are replayed.
    peer: u64,
    /// Below this counter the target holds the peer's operations as the
    /// old document does, under the same IDs; from it on, an ID of the peer
    /// names in the target what the replays mapped to it, or nothing.
    base: Counter,
    /// Containers the replayed changes created.
    containers: HashMap<ContainerID, ContainerID>,
    /// Tree nodes the replayed changes created.
    nodes: BTreeMap<TreeID, TreeID>,
    /// Text characters and list items the replayed changes inserted.
    elements: HashMap<ID, ID>,
    /// Movable-list items the replayed changes inserted, by element: from
    /// the old document's element to the slot that created it in the
    /// target, until the change is committed, then to the target's
    /// element. A movable list's cursors name slots, which a move replaces,
    /// so its items are found by element ([`Replay::elem`]).
    items: HashMap<IdLp, IdLp>,
    /// The Lamport time of the peer's operation at `base` in the old
    /// document, once it holds one: the peer's elements from it on are
    /// held in the target only as `items` maps them.
    base_lamport: Option<Lamport>,
}

impl Mapping {
    /// For replays of `peer`'s operations into a target that holds them as
    /// they are below `base`.
    pub(crate) fn new(peer: u64, base: Counter) -> Self {
        Self {
            peer,
            base,
            ..Self::default()
        }
    }

    /// Whether an ID of the old document names an operation of the peer
    /// that the target holds only as the replays mapped it.
    fn unheld(&self, peer: u64, counter: Counter) -> bool {
        peer == self.peer && counter >= self.base
    }

    /// [`Mapping::unheld`], for a movable-list element.
    fn unheld_item(&self, elem: IdLp) -> bool {
        elem.peer == self.peer && self.base_lamport.is_some_and(|base| elem.lamport >= base)
    }

    /// The mapping of a reference whose operations of `next`'s peer below
    /// `end` the old target imported under their own IDs, after that target
    /// was replayed into a newer one by `next`: those operations are named
    /// as `next` maps them, and the reference's own from `end` on are its
    /// replays' to map.
    /// `end_lamport` is the Lamport time of the peer's operation at `end`
    /// in the old target, if it holds one.
    pub(crate) fn imported(next: &Self, end: Counter, end_lamport: Option<Lamport>) -> Self {
        let own = |peer: u64, counter: Counter| peer == next.peer && counter >= end;
        let mut map = next.clone();
        map.items.retain(|old, _| {
            !(old.peer == next.peer && end_lamport.is_some_and(|end| old.lamport >= end))
        });
        map.elements.retain(|old, _| !own(old.peer, old.counter));
        map.nodes.retain(|old, _| !own(old.peer, old.counter));
        map.containers.retain(|old, _| match old {
            ContainerID::Normal { peer, counter, .. } => !own(*peer, *counter),
            ContainerID::Root { .. } => true,
        });
        map
    }

    /// Follows the target into a newer one, which `next` replayed it into:
    /// what this mapping names in the old target is named as `next` maps
    /// it, and what `next` left out is dropped.
    pub(crate) fn through(&mut self, next: &Self) {
        let elements = std::mem::take(&mut self.elements);
        self.elements = elements
            .into_iter()
            .filter_map(|(old, at)| {
                if next.unheld(at.peer, at.counter) {
                    next.elements.get(&at).map(|new| (old, *new))
                } else {
                    Some((old, at))
                }
            })
            .collect();
        let containers = std::mem::take(&mut self.containers);
        self.containers = containers
            .into_iter()
            .filter_map(|(old, at)| match &at {
                ContainerID::Normal { peer, counter, .. } if next.unheld(*peer, *counter) => {
                    next.containers.get(&at).map(|new| (old, new.clone()))
                }
                _ => Some((old, at)),
            })
            .collect();
        let items = std::mem::take(&mut self.items);
        self.items = items
            .into_iter()
            .filter_map(|(old, at)| {
                if next.unheld_item(at) {
                    next.items.get(&at).map(|new| (old, *new))
                } else {
                    Some((old, at))
                }
            })
            .collect();
        let nodes = std::mem::take(&mut self.nodes);
        self.nodes = nodes
            .into_iter()
            .filter_map(|(old, at)| {
                if next.unheld(at.peer, at.counter) {
                    next.nodes.get(&at).map(|new| (old, *new))
                } else {
                    Some((old, at))
                }
            })
            .collect();
    }
}

/// The Lamport time of `peer`'s operation at `counter` in `doc`, if it
/// holds it.
pub(crate) fn lamport_at(doc: &LoroDoc, peer: u64, counter: Counter) -> Option<Lamport> {
    let change = doc.get_change(ID::new(peer, counter))?;
    let offset = Lamport::try_from(counter - change.id.counter).ok()?;
    Some(change.lamport + offset)
}

/// Replays onto `target` what `old` holds of the mapping's peer from
/// counter `from` on: the handle's own changes, rebased, under `target`'s
/// peer. What the replay makes is added to `map`.
pub(crate) fn replay_own(
    old: &LoroDoc,
    target: &LoroDoc,
    from: Counter,
    map: &mut Mapping,
) -> Replayed {
    let peer = map.peer;
    let end = old.oplog_vv().get(&peer).copied().unwrap_or(0);
    if from >= end {
        return Replayed {
            next: from,
            left_out: Vec::new(),
        };
    }
    if map.base_lamport.is_none() {
        map.base_lamport = lamport_at(old, peer, map.base);
    }
    let mut replay = Replay {
        old,
        shadow: old.fork(),
        after: old.fork(),
        target,
        map: std::mem::take(map),
        parent: Frontiers::default(),
        marks: Vec::new(),
        first: 0,
        old_elems: HashMap::new(),
        target_elems: HashMap::new(),
        created: Vec::new(),
        left_out: Vec::new(),
    };
    let mut at = from.max(0);
    while at < end {
        let Some(change) = old.get_change(ID::new(peer, at)) else {
            replay
                .left_out
                .push(format!("the old document lacks operation {at} of its peer"));
            break;
        };
        let last = change.id.counter + Counter::try_from(change.len).unwrap_or(1);
        // Loro may have merged earlier operations into this change: the
        // parent of the part to replay is then the peer's operation before
        // it, which a merged change's operations depend on alone.
        let parent = if change.id.counter < at {
            Frontiers::from(ID::new(peer, at - 1))
        } else {
            change.deps.clone()
        };
        let after = Frontiers::from(ID::new(peer, last - 1));
        // The change's own marks, by operation: a style its insertion only
        // took from the text around it is not among them.
        replay.marks = old
            .export_json_in_id_span(IdSpan::new(peer, at, last))
            .into_iter()
            .flat_map(|change| change.ops)
            .filter(|op| op.counter >= at)
            .filter_map(|op| match op.content {
                JsonOpContent::Text(TextOp::Mark { .. }) => Some((op.container, op.counter)),
                _ => None,
            })
            .collect();
        replay.first = at;
        replay.change(&parent, &after);
        at = last;
    }
    target.commit();
    *map = replay.map;
    Replayed {
        next: end.max(from),
        left_out: replay.left_out,
    }
}

struct Replay<'a> {
    old: &'a LoroDoc,
    /// The old document, checked out at each change's parent: where
    /// positions are read.
    shadow: LoroDoc,
    /// The old document, checked out just after each change: where the IDs
    /// of the elements it inserted are read.
    after: LoroDoc,
    target: &'a LoroDoc,
    /// What the replays made in the target, by the old document's IDs.
    map: Mapping,
    /// The parent version of the change being replayed.
    parent: Frontiers,
    /// The mark operations of the change being replayed: their text
    /// container and counter.
    marks: Vec<(ContainerID, Counter)>,
    /// The first counter of the change being replayed.
    first: Counter,
    /// Movable-list elements by slot, in the old document and the target.
    old_elems: HashMap<ID, IdLp>,
    target_elems: HashMap<ID, IdLp>,
    /// Movable-list items the change inserted: the old element, and the
    /// target's slot that holds it, resolved once the change is committed.
    created: Vec<(IdLp, ID)>,
    left_out: Vec<String>,
}

/// The diff of one container, owned.
enum Step {
    Text(Vec<TextDelta>),
    List(Vec<ListDiffItem>),
    Map(Vec<(String, Option<ValueOrContainer>)>),
    Tree(Vec<loro::TreeDiffItem>),
    Counter(f64),
    Unknown,
}

impl Replay<'_> {
    fn leave(&mut self, what: impl Into<String>) {
        self.left_out.push(what.into());
    }

    /// One change: its diff at its parent, applied container by container.
    fn change(&mut self, parent: &Frontiers, after: &Frontiers) {
        let batch = match self.old.diff(parent, after) {
            Ok(batch) => batch,
            Err(error) => {
                self.leave(format!("Loro does not read the change: {error}"));
                return;
            }
        };
        if let Err(error) = self
            .shadow
            .checkout(parent)
            .and_then(|()| self.after.checkout(after))
        {
            self.leave(format!("Loro does not check out the change: {error}"));
            return;
        }
        self.parent = parent.clone();
        let mut steps: Vec<(ContainerID, Step)> = batch
            .iter()
            .map(|(id, diff)| {
                let step = match diff {
                    Diff::Text(delta) => Step::Text(delta.clone()),
                    Diff::List(items) => Step::List(items.clone()),
                    Diff::Map(map) => Step::Map(
                        map.updated
                            .iter()
                            .map(|(key, value)| (key.to_string(), value.clone()))
                            .collect(),
                    ),
                    Diff::Tree(tree) => Step::Tree(tree.diff.clone()),
                    Diff::Counter(value) => Step::Counter(*value),
                    Diff::Unknown => Step::Unknown,
                };
                (id.clone(), step)
            })
            .collect();
        // A container the change created is reached through its parent's
        // step: those that come first wait for it.
        let mut rounds = 0;
        while !steps.is_empty() && rounds < 8 {
            let mut waiting = Vec::new();
            for (id, step) in steps {
                match self.place(&id) {
                    Some(target) => self.apply(&id, &target, step),
                    None => waiting.push((id, step)),
                }
            }
            steps = waiting;
            rounds += 1;
        }
        for (id, _) in steps {
            self.leave(format!(
                "a change in {id}, which only another writer's lost operation made"
            ));
        }
        self.own_marks();
        // Committed, so that the movable-list items the change inserted
        // are named by element in the target, for the changes after it.
        self.target.commit();
        for (old, slot) in std::mem::take(&mut self.created) {
            if let Some(new) = Self::elem_in(self.target, &mut self.target_elems, slot) {
                self.map.items.insert(old, new);
            }
        }
    }

    /// Where a container of the old document is in the target: the one a
    /// replayed change created for it, or itself when the target holds it.
    fn place(&self, id: &ContainerID) -> Option<ContainerID> {
        if let Some(mapped) = self.map.containers.get(id) {
            return Some(mapped.clone());
        }
        if let ContainerID::Normal { peer, counter, .. } = id
            && self.map.unheld(*peer, *counter)
        {
            return None;
        }
        (id.is_root() || self.target.has_container(id)).then(|| id.clone())
    }

    fn apply(&mut self, id: &ContainerID, target: &ContainerID, step: Step) {
        let made = self.map.containers.contains_key(id);
        let result = match step {
            Step::Text(delta) if made => self.target.get_text(target.clone()).apply_delta(&delta),
            Step::Text(delta) => self.text(id, target, &delta),
            Step::List(items) => self.list(id, target, items, made),
            Step::Map(entries) => self.map(target, entries),
            Step::Tree(items) => self.tree(target, items),
            Step::Counter(value) => self.target.get_counter(target.clone()).increment(value),
            Step::Unknown => {
                self.leave(format!(
                    "a change of a kind this version does not read, in {id}"
                ));
                Ok(())
            }
        };
        if let Err(error) = result {
            self.leave(format!("Loro refused a change in {id}: {error}"));
        }
    }

    /// The ID of the element at `pos` of a sequence in the shadow.
    fn shadow_id(&self, id: &ContainerID, pos: usize) -> Option<ID> {
        match id.container_type() {
            ContainerType::Text => self
                .shadow
                .get_text(id.clone())
                .get_cursor(pos, Side::Middle)
                .and_then(|cursor| cursor.id),
            ContainerType::List => self.shadow.get_list(id.clone()).get_id_at(pos),
            ContainerType::MovableList => self
                .shadow
                .get_movable_list(id.clone())
                .get_cursor(pos, Side::Middle)
                .and_then(|cursor| cursor.id),
            _ => None,
        }
    }

    fn shadow_len(&self, id: &ContainerID) -> usize {
        match id.container_type() {
            ContainerType::Text => self.shadow.get_text(id.clone()).len_unicode(),
            ContainerType::List => self.shadow.get_list(id.clone()).len(),
            ContainerType::MovableList => self.shadow.get_movable_list(id.clone()).len(),
            _ => 0,
        }
    }

    fn target_id(&self, target: &ContainerID, pos: usize) -> Option<ID> {
        match target.container_type() {
            ContainerType::Text => self
                .target
                .get_text(target.clone())
                .get_cursor(pos, Side::Middle)
                .and_then(|cursor| cursor.id),
            ContainerType::List => self.target.get_list(target.clone()).get_id_at(pos),
            ContainerType::MovableList => self
                .target
                .get_movable_list(target.clone())
                .get_cursor(pos, Side::Middle)
                .and_then(|cursor| cursor.id),
            _ => None,
        }
    }

    fn target_len(&self, target: &ContainerID) -> usize {
        match target.container_type() {
            ContainerType::Text => self.target.get_text(target.clone()).len_unicode(),
            ContainerType::List => self.target.get_list(target.clone()).len(),
            ContainerType::MovableList => self.target.get_movable_list(target.clone()).len(),
            _ => 0,
        }
    }

    /// Where an element of the old document is in the target, and whether
    /// the target shows it there; `None` when the target does not hold it.
    fn find(&self, target: &ContainerID, element: ID) -> Option<(usize, bool)> {
        let element = match self.map.elements.get(&element) {
            Some(new) => *new,
            None if self.map.unheld(element.peer, element.counter) => return None,
            None => element,
        };
        let cursor = Cursor::new(Some(element), target.clone(), Side::Middle, 0);
        let pos = self.target.get_cursor_pos(&cursor).ok()?.current.pos;
        Some((pos, self.target_id(target, pos) == Some(element)))
    }

    /// Where an insertion made at `pos` of the shadow goes in the target.
    fn anchor(&self, id: &ContainerID, target: &ContainerID, pos: usize) -> usize {
        for before in (0..pos).rev() {
            if let Some((at, shown)) = self
                .shadow_id(id, before)
                .and_then(|element| self.find(target, element))
            {
                return if shown { at + 1 } else { at };
            }
        }
        for after in pos..self.shadow_len(id) {
            if let Some((at, _)) = self
                .shadow_id(id, after)
                .and_then(|element| self.find(target, element))
            {
                return at;
            }
        }
        self.target_len(target)
    }

    /// The ID of the element at `pos` of a sequence just after the change.
    fn after_id(&self, id: &ContainerID, pos: usize) -> Option<ID> {
        match id.container_type() {
            ContainerType::Text => self
                .after
                .get_text(id.clone())
                .get_cursor(pos, Side::Middle)
                .and_then(|cursor| cursor.id),
            ContainerType::List => self.after.get_list(id.clone()).get_id_at(pos),
            ContainerType::MovableList => self
                .after
                .get_movable_list(id.clone())
                .get_cursor(pos, Side::Middle)
                .and_then(|cursor| cursor.id),
            _ => None,
        }
    }

    /// Records that the `count` elements the change inserted at `after`, a
    /// position just after the change, are the target's at `at`.
    fn inserted(
        &mut self,
        id: &ContainerID,
        target: &ContainerID,
        after: usize,
        at: usize,
        count: usize,
    ) {
        for offset in 0..count {
            if let (Some(old), Some(new)) = (
                self.after_id(id, after + offset),
                self.target_id(target, at + offset),
            ) {
                self.map.elements.insert(old, new);
            }
        }
    }

    /// The target positions the target shows of the shadow's elements in
    /// `range`, ascending.
    fn shown(
        &self,
        id: &ContainerID,
        target: &ContainerID,
        range: std::ops::Range<usize>,
    ) -> Vec<usize> {
        let mut out: Vec<usize> = range
            .filter_map(|pos| self.shadow_id(id, pos))
            .filter_map(|element| self.find(target, element))
            .filter(|(_, shown)| *shown)
            .map(|(at, _)| at)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// A change's text edits. Its marks are applied after them, from its
    /// own operations ([`Replay::own_marks`]).
    fn text(
        &mut self,
        id: &ContainerID,
        target: &ContainerID,
        delta: &[TextDelta],
    ) -> loro::LoroResult<()> {
        let text = self.target.get_text(target.clone());
        let mut pos = 0usize;
        let mut after = 0usize;
        for step in delta {
            match step {
                TextDelta::Retain { retain, .. } => {
                    pos += retain;
                    after += retain;
                }
                TextDelta::Insert { insert, .. } => {
                    let at = self.anchor(id, target, pos);
                    text.insert(at, insert)?;
                    let count = insert.chars().count();
                    self.inserted(id, target, after, at, count);
                    after += count;
                }
                TextDelta::Delete { delete } => {
                    for at in self.shown(id, target, pos..pos + delete).into_iter().rev() {
                        text.delete(at, 1)?;
                    }
                    pos += delete;
                }
            }
        }
        Ok(())
    }

    /// The change's own marks and unmarks, in order, each over the
    /// characters it covered that the target shows, from the first to the
    /// last. Loro writes no operation for a mark that changes nothing, so a
    /// style the text already had when the change marked it is not in the
    /// history, and is not replayed.
    fn own_marks(&mut self) {
        for (container, counter) in std::mem::take(&mut self.marks) {
            // A text the replay created took its styles with its delta; one
            // only another writer's lost operation made is reported already.
            if self.map.containers.contains_key(&container) {
                continue;
            }
            let Some(target) = self.place(&container) else {
                continue;
            };
            let Some((key, value, covered)) = self.covered(&container, counter) else {
                self.leave(format!("a mark in {container} that Loro does not read"));
                continue;
            };
            let shown: BTreeSet<usize> = covered
                .into_iter()
                .filter_map(|element| self.find(&target, element))
                .filter(|(_, shown)| *shown)
                .map(|(at, _)| at)
                .collect();
            let (Some(&first), Some(&last)) = (shown.first(), shown.last()) else {
                continue;
            };
            // Between the first and the last: what it covered, and the
            // handle's own characters the replay wrote there, which a later
            // insertion inside the range made after it; not what the
            // rebuilt document restored there, which the mark never covered.
            let own: HashSet<ID> = self.map.elements.values().copied().collect();
            let marked: Vec<usize> = (first..=last)
                .filter(|at| {
                    shown.contains(at)
                        || self
                            .target_id(&target, *at)
                            .is_some_and(|id| own.contains(&id))
                })
                .collect();
            let text = self.target.get_text(target.clone());
            for range in runs(&marked) {
                let done = if value.is_null() {
                    text.unmark(range, &key)
                } else {
                    text.mark(range, &key, value.clone())
                };
                if let Err(error) = done {
                    self.leave(format!("Loro refused a mark in {container}: {error}"));
                }
            }
        }
    }

    /// What a mark operation of the change covered: its style key, its
    /// value (null for an unmark), and the characters between its anchors
    /// when it was made. Read by importing the operation, under a key of
    /// its own, into a copy of the old document just before it, so that the
    /// characters that already had the style show too.
    fn covered(
        &self,
        container: &ContainerID,
        counter: Counter,
    ) -> Option<(String, LoroValue, Vec<ID>)> {
        const PROBE: &str = "frasil-replay-cover";
        let peer = self.map.peer;
        let before = if counter == self.first {
            self.parent.clone()
        } else {
            Frontiers::from(ID::new(peer, counter - 1))
        };
        let copy = self.old.fork_at(&before).ok()?;
        let start = copy.oplog_vv();
        let mut end = start.clone();
        // The mark and the end of its range.
        end.insert(peer, counter + 2);
        let mut schema = self.old.export_json_updates(&start, &end).ok()?;
        let mut found = None;
        for op in schema
            .changes
            .iter_mut()
            .flat_map(|change| change.ops.iter_mut())
        {
            if let JsonOpContent::Text(TextOp::Mark {
                style_key,
                style_value,
                ..
            }) = &mut op.content
            {
                found = Some((
                    std::mem::replace(style_key, PROBE.to_string()),
                    std::mem::replace(style_value, LoroValue::Bool(true)),
                ));
            }
        }
        let (key, value) = found?;
        copy.import_json_updates(schema).ok()?;
        let text = copy.get_text(container.clone());
        let mut covered = Vec::new();
        let mut pos = 0usize;
        for step in text.to_delta() {
            if let TextDelta::Insert { insert, attributes } = step {
                let count = insert.chars().count();
                if attributes.is_some_and(|attributes| attributes.contains_key(PROBE)) {
                    covered.extend((pos..pos + count).filter_map(|at| {
                        text.get_cursor(at, Side::Middle)
                            .and_then(|cursor| cursor.id)
                    }));
                }
                pos += count;
            }
        }
        Some((key, value, covered))
    }

    /// A new container of a kind, in the target, at a list position.
    fn insert_value(
        &mut self,
        target: &ContainerID,
        at: usize,
        value: &ValueOrContainer,
    ) -> loro::LoroResult<()> {
        let movable = target.container_type() == ContainerType::MovableList;
        match value {
            ValueOrContainer::Value(value) => {
                if movable {
                    self.target
                        .get_movable_list(target.clone())
                        .insert(at, value.clone())
                } else {
                    self.target
                        .get_list(target.clone())
                        .insert(at, value.clone())
                }
            }
            ValueOrContainer::Container(child) => {
                let fresh = Container::new(child.get_type());
                let made = if movable {
                    self.target
                        .get_movable_list(target.clone())
                        .insert_container(at, fresh)?
                } else {
                    self.target
                        .get_list(target.clone())
                        .insert_container(at, fresh)?
                };
                self.map.containers.insert(child.id(), made.id());
                Ok(())
            }
        }
    }

    fn list(
        &mut self,
        id: &ContainerID,
        target: &ContainerID,
        items: Vec<ListDiffItem>,
        made: bool,
    ) -> loro::LoroResult<()> {
        let movable = target.container_type() == ContainerType::MovableList;
        if movable && !made {
            return self.movable(id, target);
        }
        let delete = |replay: &Self, at: usize| {
            if movable {
                replay.target.get_movable_list(target.clone()).delete(at, 1)
            } else {
                replay.target.get_list(target.clone()).delete(at, 1)
            }
        };
        let mut pos = 0usize;
        let mut after = 0usize;
        let mut offset = 0isize;
        for item in items {
            match item {
                ListDiffItem::Retain { retain } => {
                    pos += retain;
                    after += retain;
                }
                ListDiffItem::Delete { delete: count } => {
                    if made {
                        // A container the replay created holds the
                        // handle's operations alone: positions are its own.
                        for _ in 0..count {
                            let at = usize::try_from(pos as isize + offset).unwrap_or(0);
                            delete(self, at)?;
                        }
                        offset -= count as isize;
                    } else {
                        for at in (pos..pos + count).rev() {
                            if let Some((where_, true)) = self
                                .shadow_id(id, at)
                                .and_then(|element| self.find(target, element))
                            {
                                delete(self, where_)?;
                            }
                        }
                    }
                    pos += count;
                }
                ListDiffItem::Insert { insert, .. } => {
                    if made {
                        for value in &insert {
                            let at = usize::try_from(pos as isize + offset).unwrap_or(0);
                            self.insert_value(target, at, value)?;
                            offset += 1;
                        }
                        continue;
                    }
                    let start = self.anchor(id, target, pos);
                    for (at, value) in (start..).zip(insert.iter()) {
                        self.insert_value(target, at, value)?;
                        self.inserted(id, target, after, at, 1);
                        after += 1;
                    }
                }
            }
        }
        Ok(())
    }

    /// The element a movable list's slot holds in `doc`: the item its
    /// insertion created, or the item a move put there. Loro names an
    /// element by its insertion's peer and Lamport time, and a move's
    /// operation names the element it moves.
    fn elem_in(doc: &LoroDoc, cache: &mut HashMap<ID, IdLp>, slot: ID) -> Option<IdLp> {
        if let Some(elem) = cache.get(&slot) {
            return Some(*elem);
        }
        let span = IdSpan::new(slot.peer, slot.counter, slot.counter + 1);
        let elem = doc
            .export_json_in_id_span(span)
            .into_iter()
            .flat_map(|change| change.ops)
            .find_map(|op| {
                let JsonOpContent::MovableList(content) = op.content else {
                    return None;
                };
                let len = match &content {
                    MovableListOp::Insert { value, .. } => i32::try_from(value.len()).ok()?,
                    _ => 1,
                };
                if slot.counter < op.counter || slot.counter >= op.counter + len {
                    return None;
                }
                match content {
                    MovableListOp::Insert { .. } => Some(IdLp {
                        peer: slot.peer,
                        lamport: lamport_at(doc, slot.peer, slot.counter)?,
                    }),
                    MovableListOp::Move { elem_id, .. } => Some(elem_id),
                    _ => None,
                }
            })?;
        cache.insert(slot, elem);
        Some(elem)
    }

    /// Where the target shows an element of the old document's movable
    /// list: the one a replayed change created for it, or itself.
    fn item_pos(&mut self, target: &ContainerID, elem: IdLp) -> Option<usize> {
        let elem = match self.map.items.get(&elem) {
            Some(new) => *new,
            None if self.map.unheld_item(elem) => return None,
            None => elem,
        };
        let list = self.target.get_movable_list(target.clone());
        (0..list.len()).find(|&pos| {
            list.get_cursor(pos, Side::Middle)
                .and_then(|cursor| cursor.id)
                .and_then(|slot| Self::elem_in(self.target, &mut self.target_elems, slot))
                == Some(elem)
        })
    }

    /// Sets an item of a movable list in the target.
    fn set_value(
        &mut self,
        target: &ContainerID,
        at: usize,
        value: &ValueOrContainer,
    ) -> loro::LoroResult<()> {
        let list = self.target.get_movable_list(target.clone());
        match value {
            ValueOrContainer::Value(value) => list.set(at, value.clone()),
            ValueOrContainer::Container(child) => {
                let made = list.set_container(at, Container::new(child.get_type()))?;
                self.map.containers.insert(child.id(), made.id());
                Ok(())
            }
        }
    }

    /// A change to a movable list, read from the list just before and
    /// just after it rather than from Loro's diff, whose edit script for
    /// several moves depends on peer IDs. A slot names a place: an item's
    /// insertion makes one, a move makes a new one, and a set keeps it.
    /// So an item whose slot is gone and whose element is found at a new
    /// slot was moved, one whose element is gone was deleted, and a slot
    /// that stayed with another value was set. Moved and new items are
    /// then placed from left to right by their neighbours just after the
    /// change.
    fn movable(&mut self, id: &ContainerID, target: &ContainerID) -> loro::LoroResult<()> {
        let before: Vec<Option<ID>> = (0..self.shadow_len(id))
            .map(|pos| self.shadow_id(id, pos))
            .collect();
        let after_len = self.after.get_movable_list(id.clone()).len();
        let after: Vec<Option<ID>> = (0..after_len).map(|pos| self.after_id(id, pos)).collect();
        let before_slots: HashSet<ID> = before.iter().flatten().copied().collect();
        let after_slots: HashSet<ID> = after.iter().flatten().copied().collect();
        // The items whose slot the change took away: moved or deleted.
        let mut gone: HashMap<IdLp, usize> = HashMap::new();
        for (pos, slot) in before.iter().enumerate() {
            if let Some(slot) = slot
                && !after_slots.contains(slot)
                && let Some(elem) = Self::elem_in(self.old, &mut self.old_elems, *slot)
            {
                gone.insert(elem, pos);
            }
        }
        // Each new slot: an item moved there, or a new item.
        let mut placed: Vec<(usize, Option<IdLp>)> = Vec::new();
        for (at, slot) in after.iter().enumerate() {
            let Some(slot) = slot else {
                self.leave(format!("an item in {id} that Loro does not name"));
                continue;
            };
            if before_slots.contains(slot) {
                continue;
            }
            let elem = Self::elem_in(self.old, &mut self.old_elems, *slot);
            let moved = elem.filter(|elem| gone.contains_key(elem));
            placed.push((at, moved));
        }
        let list = self.target.get_movable_list(target.clone());
        // Deletions: what is gone and not moved.
        let moved: HashSet<IdLp> = placed.iter().filter_map(|(_, elem)| *elem).collect();
        for elem in gone.keys().copied().collect::<Vec<_>>() {
            if !moved.contains(&elem)
                && let Some(where_) = self.item_pos(target, elem)
            {
                list.delete(where_, 1)?;
            }
        }
        // Sets: a slot that stayed, with another value.
        for (at, slot) in after.iter().enumerate() {
            let Some(slot) = slot.filter(|slot| before_slots.contains(slot)) else {
                continue;
            };
            let Some(from) = before.iter().position(|was| *was == Some(slot)) else {
                continue;
            };
            let now = self.after.get_movable_list(id.clone()).get(at);
            let was = self.shadow.get_movable_list(id.clone()).get(from);
            if same_item(was.as_ref(), now.as_ref()) {
                continue;
            }
            let Some(now) = now else { continue };
            match Self::elem_in(self.old, &mut self.old_elems, slot)
                .and_then(|elem| self.item_pos(target, elem))
            {
                Some(where_) => self.set_value(target, where_, &now)?,
                None => self.leave(format!(
                    "a set in {id} of an item that only another writer's lost operation placed"
                )),
            }
        }
        // Moves and new items, left to right. A move to the front or to the
        // end of the list lands there; anything else by its neighbours.
        for (at, moved) in placed {
            let dest = match moved {
                Some(_) if at == 0 => 0,
                Some(_) if at + 1 == after.len() => list.len(),
                _ => self.after_anchor(target, &after, at),
            };
            let now = self.after.get_movable_list(id.clone()).get(at);
            match moved {
                Some(elem) => match self.item_pos(target, elem) {
                    Some(from) => {
                        let to = if dest > from { dest - 1 } else { dest };
                        let to = to.min(list.len().saturating_sub(1));
                        if from != to {
                            list.mov(from, to)?;
                        }
                        self.inserted(id, target, at, to, 1);
                        // Moved and set in one change.
                        let was = gone
                            .get(&elem)
                            .and_then(|pos| self.shadow.get_movable_list(id.clone()).get(*pos));
                        if !same_item(was.as_ref(), now.as_ref())
                            && let Some(now) = now
                        {
                            self.set_value(target, to, &now)?;
                        }
                    }
                    None => self.leave(format!(
                        "a move in {id} of an item that only another writer's lost operation \
                         placed"
                    )),
                },
                None => {
                    let Some(now) = now else { continue };
                    self.insert_value(target, dest, &now)?;
                    let old = after[at]
                        .and_then(|slot| Self::elem_in(self.old, &mut self.old_elems, slot));
                    if let (Some(old), Some(slot)) = (old, self.target_id(target, dest)) {
                        self.created.push((old, slot));
                    }
                    self.inserted(id, target, at, dest, 1);
                }
            }
        }
        Ok(())
    }

    /// Where an item at `at` of a movable list just after the change goes
    /// in the target: after the nearest item before it there that the
    /// target holds (one placed already, or one whose place the change
    /// kept), else before the nearest such one after it, else at the end.
    fn after_anchor(&self, target: &ContainerID, after: &[Option<ID>], at: usize) -> usize {
        for slot in after[..at].iter().rev().flatten() {
            if let Some((pos, shown)) = self.find(target, *slot) {
                return if shown { pos + 1 } else { pos };
            }
        }
        for slot in after[at + 1..].iter().flatten() {
            if let Some((pos, _)) = self.find(target, *slot) {
                return pos;
            }
        }
        self.target_len(target)
    }

    fn map(
        &mut self,
        target: &ContainerID,
        entries: Vec<(String, Option<ValueOrContainer>)>,
    ) -> loro::LoroResult<()> {
        let map = self.target.get_map(target.clone());
        for (key, value) in entries {
            match value {
                None => map.delete(&key)?,
                Some(ValueOrContainer::Value(value)) => map.insert(&key, value)?,
                Some(ValueOrContainer::Container(child)) => {
                    let made = map.insert_container(&key, Container::new(child.get_type()))?;
                    self.map.containers.insert(child.id(), made.id());
                }
            }
        }
        Ok(())
    }

    /// A tree node of the old document in the target: the one a replayed
    /// change created for it, or itself when the target shows it.
    fn node(&self, target: &ContainerID, node: TreeID) -> Option<TreeID> {
        if let Some(mapped) = self.map.nodes.get(&node) {
            return Some(*mapped);
        }
        if self.map.unheld(node.peer, node.counter) {
            return None;
        }
        let tree = self.target.get_tree(target.clone());
        (tree.contains(node) && !tree.is_node_deleted(&node).unwrap_or(true)).then_some(node)
    }

    fn parent(&self, target: &ContainerID, parent: TreeParentId) -> Option<TreeParentId> {
        match parent {
            TreeParentId::Root => Some(TreeParentId::Root),
            TreeParentId::Node(node) => self.node(target, node).map(TreeParentId::Node),
            _ => None,
        }
    }

    fn tree(
        &mut self,
        target: &ContainerID,
        items: Vec<loro::TreeDiffItem>,
    ) -> loro::LoroResult<()> {
        use loro::TreeExternalDiff;
        let tree = self.target.get_tree(target.clone());
        for item in items {
            match item.action {
                TreeExternalDiff::Create { parent, index, .. } => {
                    let Some(parent) = self.parent(target, parent) else {
                        self.leave(format!(
                            "a tree node created under a node that only another writer's lost \
                             operation made, in {target}"
                        ));
                        continue;
                    };
                    let count = tree.children_num(parent).unwrap_or(0);
                    let made = tree.create_at(parent, index.min(count))?;
                    self.map.nodes.insert(item.target, made);
                    if let (Ok(old), Ok(new)) = (
                        self.shadow_meta(target, item.target),
                        tree.get_meta(made).map(|meta| meta.id()),
                    ) {
                        self.map.containers.insert(old, new);
                    }
                }
                TreeExternalDiff::Move { parent, index, .. } => {
                    match (self.node(target, item.target), self.parent(target, parent)) {
                        (Some(node), Some(parent)) => {
                            let count = tree.children_num(parent).unwrap_or(0);
                            tree.mov_to(node, parent, index.min(count))?;
                        }
                        _ => self.leave(format!(
                            "a tree move of or under a node that only another writer's lost \
                             operation made, in {target}"
                        )),
                    }
                }
                TreeExternalDiff::Delete { .. } => {
                    if let Some(node) = self.node(target, item.target) {
                        tree.delete(node)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// The ID of a tree node's metadata map in the old document.
    fn shadow_meta(&self, tree: &ContainerID, node: TreeID) -> loro::LoroResult<ContainerID> {
        self.old
            .get_tree(tree.clone())
            .get_meta(node)
            .map(|meta| meta.id())
    }
}

/// Whether two list items are the same value, or the same container.
fn same_item(was: Option<&ValueOrContainer>, now: Option<&ValueOrContainer>) -> bool {
    match (was, now) {
        (Some(ValueOrContainer::Value(was)), Some(ValueOrContainer::Value(now))) => was == now,
        (Some(ValueOrContainer::Container(was)), Some(ValueOrContainer::Container(now))) => {
            was.id() == now.id()
        }
        (None, None) => true,
        _ => false,
    }
}

/// Ascending positions as runs of consecutive ones.
fn runs(positions: &[usize]) -> Vec<std::ops::Range<usize>> {
    let mut out: Vec<std::ops::Range<usize>> = Vec::new();
    for &at in positions {
        match out.last_mut() {
            Some(run) if run.end == at => run.end = at + 1,
            _ => out.push(at..at + 1),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Mapping, replay_own};
    use loro::{LoroDoc, LoroMap, LoroValue, TextDelta, TreeID, TreeParentId, ValueOrContainer};

    /// Alice's base: text, map, list, movable list, counter and a tree with
    /// two nodes.
    fn base() -> (LoroDoc, TreeID, TreeID) {
        let doc = LoroDoc::new();
        doc.set_peer_id(1).unwrap();
        doc.get_text("body").insert(0, "base text").unwrap();
        let meta = doc.get_map("meta");
        meta.insert("title", "draft").unwrap();
        meta.insert("subtitle", "first").unwrap();
        let tags = doc.get_list("tags");
        tags.push("a").unwrap();
        tags.push("b").unwrap();
        let order = doc.get_movable_list("order");
        order.push("a").unwrap();
        order.push("b").unwrap();
        let tree = doc.get_tree("outline");
        let one = tree.create(TreeParentId::Root).unwrap();
        let two = tree.create(TreeParentId::Root).unwrap();
        doc.commit();
        (doc, one, two)
    }

    fn plain(doc: &LoroDoc) -> String {
        doc.get_text("body").to_string()
    }

    fn values(value: LoroValue) -> Vec<String> {
        match value {
            LoroValue::List(items) => items
                .iter()
                .map(|item| match item {
                    LoroValue::String(text) => text.to_string(),
                    other => format!("{other:?}"),
                })
                .collect(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn only_the_handles_own_operations_are_replayed() {
        let (base, one, two) = base();
        let old = base.fork();
        // Bob, whose units are withdrawn: a deletion, a mark, a counter
        // step, a move, a set, a key deleted, a container value, a list item
        // pushed and one deleted, a tree node created and one deleted.
        old.set_peer_id(9).unwrap();
        let body = old.get_text("body");
        body.delete(0, 5).unwrap();
        body.mark(0..4, "bold", true).unwrap();
        old.get_counter("steps").increment(5.0).unwrap();
        old.get_movable_list("order").mov(0, 1).unwrap();
        let meta = old.get_map("meta");
        meta.insert("title", "bob").unwrap();
        meta.delete("subtitle").unwrap();
        meta.insert_container("box", LoroMap::new())
            .unwrap()
            .insert("x", 1)
            .unwrap();
        let tags = old.get_list("tags");
        tags.delete(0, 1).unwrap();
        tags.push("x").unwrap();
        let tree = old.get_tree("outline");
        tree.create(TreeParentId::Node(one)).unwrap();
        tree.delete(two).unwrap();
        old.commit();
        // Carol, over Bob's: her own changes only.
        old.set_peer_id(3).unwrap();
        old.get_text("body").insert(4, " carol").unwrap();
        old.get_counter("steps").increment(1.0).unwrap();
        old.get_movable_list("order").push("c").unwrap();
        old.get_list("tags").push("c").unwrap();
        old.get_map("meta").insert("carol", true).unwrap();
        let mine = old
            .get_tree("outline")
            .create(TreeParentId::Node(one))
            .unwrap();
        old.get_tree("outline")
            .get_meta(mine)
            .unwrap()
            .insert("name", "carol's")
            .unwrap();
        old.commit();

        let target = base.fork();
        target.set_peer_id(30).unwrap();
        let replayed = replay_own(&old, &target, 0, &mut Mapping::new(3, 0));
        assert!(replayed.left_out.is_empty(), "{:?}", replayed.left_out);
        assert_eq!(
            plain(&target),
            "base text carol",
            "Bob's deletion stays his"
        );
        assert!(
            target
                .get_text("body")
                .to_delta()
                .iter()
                .all(|step| !matches!(
                    step,
                    TextDelta::Insert {
                        attributes: Some(_),
                        ..
                    }
                )),
            "Bob's mark stays his"
        );
        assert_eq!(
            target.get_counter("steps").get_value(),
            1.0,
            "Carol's step alone"
        );
        assert_eq!(
            values(target.get_movable_list("order").get_deep_value()),
            ["a", "b", "c"],
            "Bob's move stays his"
        );
        assert_eq!(
            values(target.get_list("tags").get_deep_value()),
            ["a", "b", "c"],
            "Bob's push and deletion stay his"
        );
        let meta = target.get_map("meta");
        let value = |key: &str| match meta.get(key) {
            Some(ValueOrContainer::Value(value)) => Some(value),
            Some(ValueOrContainer::Container(_)) => Some(LoroValue::from("a container")),
            None => None,
        };
        assert_eq!(value("title"), Some(LoroValue::from("draft")));
        assert_eq!(value("subtitle"), Some(LoroValue::from("first")));
        assert_eq!(value("box"), None, "Bob's container value stays his");
        assert_eq!(value("carol"), Some(LoroValue::from(true)));
        let tree = target.get_tree("outline");
        assert!(
            !tree.is_node_deleted(&two).unwrap(),
            "Bob's deletion stays his"
        );
        let children = tree.children(TreeParentId::Node(one)).unwrap();
        assert_eq!(children.len(), 1, "Carol's node alone");
        assert_eq!(
            tree.get_meta(children[0])
                .unwrap()
                .get("name")
                .map(|v| match v {
                    ValueOrContainer::Value(value) => value,
                    ValueOrContainer::Container(_) => LoroValue::Null,
                }),
            Some(LoroValue::from("carol's")),
            "the node's metadata follows it"
        );
        assert_eq!(replayed.next, old.oplog_vv().get(&3).copied().unwrap());
    }

    #[test]
    fn the_handles_own_marks_and_deletions_are_replayed() {
        let (base, _, _) = base();
        let old = base.fork();
        old.set_peer_id(9).unwrap();
        old.get_text("body").insert(0, "bob ").unwrap();
        old.commit();
        old.set_peer_id(3).unwrap();
        let body = old.get_text("body");
        // "bob base text": Carol marks "base" and deletes " text".
        body.mark(4..8, "bold", true).unwrap();
        body.delete(8, 5).unwrap();
        old.get_list("tags").delete(0, 1).unwrap();
        old.commit();
        let target = base.fork();
        target.set_peer_id(30).unwrap();
        let replayed = replay_own(&old, &target, 0, &mut Mapping::new(3, 0));
        assert!(replayed.left_out.is_empty(), "{:?}", replayed.left_out);
        assert_eq!(plain(&target), "base");
        let bold: Vec<String> = target
            .get_text("body")
            .to_delta()
            .into_iter()
            .filter_map(|step| match step {
                TextDelta::Insert {
                    insert,
                    attributes: Some(attributes),
                } if attributes.contains_key("bold") => Some(insert),
                _ => None,
            })
            .collect();
        assert_eq!(bold, ["base"], "her own mark");
        assert_eq!(values(target.get_list("tags").get_deep_value()), ["b"]);
    }

    /// Bob's text, then Carol's before it, over Alice's base.
    fn carol_over_bob() -> (LoroDoc, LoroDoc) {
        let (base, _, _) = base();
        let old = base.fork();
        old.set_peer_id(9).unwrap();
        old.get_text("body").insert(0, "bob ").unwrap();
        old.commit();
        old.set_peer_id(3).unwrap();
        old.get_text("body").insert(0, "carol ").unwrap();
        old.commit();
        (base, old)
    }

    /// Carol's late change to the old document: text before her own and
    /// inside it, placed only by her own replayed characters.
    fn late(old: &LoroDoc) {
        let body = old.get_text("body");
        // "carol bob base text"
        body.insert(0, "late ").unwrap();
        // After the "l" of "carol".
        body.insert(10, "!").unwrap();
        old.commit();
    }

    #[test]
    fn a_later_replay_finds_what_an_earlier_one_wrote() {
        let (base, old) = carol_over_bob();
        let target = base.fork();
        target.set_peer_id(30).unwrap();
        let mut map = Mapping::new(3, 0);
        let first = replay_own(&old, &target, 0, &mut map);
        assert!(first.left_out.is_empty(), "{:?}", first.left_out);
        assert_eq!(plain(&target), "carol base text");
        late(&old);
        let second = replay_own(&old, &target, first.next, &mut map);
        assert!(second.left_out.is_empty(), "{:?}", second.left_out);
        assert_eq!(plain(&target), "late carol! base text");
    }

    #[test]
    fn a_mapping_follows_its_target_into_a_newer_one() {
        // The old document is replayed into a middle one, which is in turn
        // replayed into the newest: the old document's late change finds
        // Carol's text where the newest holds it.
        let (base, old) = carol_over_bob();
        let middle = base.fork();
        middle.set_peer_id(30).unwrap();
        let mut map = Mapping::new(3, 0);
        let first = replay_own(&old, &middle, 0, &mut map);
        assert_eq!(plain(&middle), "carol base text");
        let newest = base.fork();
        newest.set_peer_id(40).unwrap();
        let mut next = Mapping::new(30, 0);
        replay_own(&middle, &newest, 0, &mut next);
        assert_eq!(plain(&newest), "carol base text");
        map.through(&next);
        late(&old);
        let second = replay_own(&old, &newest, first.next, &mut map);
        assert!(second.left_out.is_empty(), "{:?}", second.left_out);
        assert_eq!(plain(&newest), "late carol! base text");
    }

    #[test]
    fn what_only_another_writers_lost_operations_made_is_reported() {
        let (base, one, _) = base();
        let old = base.fork();
        old.set_peer_id(9).unwrap();
        let bobs_box = old
            .get_map("meta")
            .insert_container("box", LoroMap::new())
            .unwrap();
        let bobs_node = old
            .get_tree("outline")
            .create(TreeParentId::Node(one))
            .unwrap();
        old.get_movable_list("order").push("x").unwrap();
        old.commit();
        old.set_peer_id(3).unwrap();
        bobs_box.insert("y", 2).unwrap();
        old.get_tree("outline")
            .create(TreeParentId::Node(bobs_node))
            .unwrap();
        old.get_movable_list("order").mov(2, 0).unwrap();
        old.get_text("body").insert(0, "carol ").unwrap();
        old.commit();

        let target = base.fork();
        target.set_peer_id(30).unwrap();
        let replayed = replay_own(&old, &target, 0, &mut Mapping::new(3, 0));
        assert_eq!(replayed.left_out.len(), 3, "{:?}", replayed.left_out);
        assert_eq!(plain(&target), "carol base text", "the rest is replayed");
        assert!(target.get_map("meta").get("box").is_none());
        assert_eq!(
            target
                .get_tree("outline")
                .children(TreeParentId::Node(one))
                .map_or(0, |c| c.len()),
            0
        );
        assert_eq!(
            values(target.get_movable_list("order").get_deep_value()),
            ["a", "b"]
        );
    }
}

/// The review's cases: Bob (peer 9) writes, Carol (peer 3) writes over it,
/// Carol's operations are replayed onto Alice's base, and the result is
/// compared with Carol's operations made on the base directly.
#[cfg(test)]
mod cases {
    use super::{Mapping, replay_own};
    use loro::{
        Container, ExportMode, LoroDoc, LoroMap, LoroText, LoroValue, TextDelta, TreeID,
        TreeParentId, ValueOrContainer,
    };

    fn doc(peer: u64) -> LoroDoc {
        let doc = LoroDoc::new();
        doc.set_peer_id(peer).unwrap();
        doc.set_change_merge_interval(-1);
        doc
    }

    /// Alice's base: text, a movable list, a list, a map and a tree node.
    fn base() -> LoroDoc {
        let doc = doc(1);
        doc.get_text("body").insert(0, "base text").unwrap();
        let order = doc.get_movable_list("order");
        let tags = doc.get_list("tags");
        for item in ["a", "b", "c"] {
            order.push(item).unwrap();
            tags.push(item).unwrap();
        }
        let meta = doc.get_map("meta");
        meta.insert("title", "draft").unwrap();
        meta.insert("subtitle", "first").unwrap();
        let tree = doc.get_tree("outline");
        let one = tree.create(TreeParentId::Root).unwrap();
        tree.get_meta(one).unwrap().insert("name", "one").unwrap();
        doc.commit();
        doc
    }

    /// A tree's nodes by name, nested, in order: node IDs differ between
    /// the replay and the oracle.
    fn outline(doc: &LoroDoc, parent: TreeParentId) -> String {
        let tree = doc.get_tree("outline");
        let nodes: Vec<TreeID> = tree.children(parent).unwrap_or_default();
        let names: Vec<String> = nodes
            .into_iter()
            .map(|node| {
                let name = match tree.get_meta(node).ok().and_then(|meta| meta.get("name")) {
                    Some(ValueOrContainer::Value(LoroValue::String(name))) => name.to_string(),
                    _ => "?".into(),
                };
                format!("{name}{}", outline(doc, TreeParentId::Node(node)))
            })
            .collect();
        if names.is_empty() {
            String::new()
        } else {
            format!("({})", names.join(","))
        }
    }

    /// Everything the cases look at: styled text, counter, lists, map and
    /// tree.
    fn show(doc: &LoroDoc) -> String {
        let text: String = doc
            .get_text("body")
            .to_delta()
            .into_iter()
            .map(|step| match step {
                TextDelta::Insert {
                    insert,
                    attributes: Some(attributes),
                } if !attributes.is_empty() => {
                    let mut keys: Vec<String> = attributes.keys().cloned().collect();
                    keys.sort();
                    format!("[{insert}|{}]", keys.join(","))
                }
                TextDelta::Insert { insert, .. } => insert,
                other => format!("{other:?}"),
            })
            .collect();
        let json = |value: LoroValue| serde_json::to_string(&value).unwrap();
        format!(
            "text={text:?} n={} order={} tags={} meta={} outline={}",
            doc.get_counter("n").get_value(),
            json(doc.get_movable_list("order").get_deep_value()),
            json(doc.get_list("tags").get_deep_value()),
            json(doc.get_map("meta").get_deep_value()),
            outline(doc, TreeParentId::Root),
        )
    }

    /// Bob's operations, then Carol's, on a copy of `base`; Carol's are
    /// replayed onto another copy, and `oracle` writes Carol's on a third.
    /// Returns what the replay made, what the oracle made, and what the
    /// replay left out.
    fn case(
        base: &LoroDoc,
        bob: impl FnOnce(&LoroDoc),
        carol: impl FnOnce(&LoroDoc),
        oracle: impl FnOnce(&LoroDoc),
    ) -> (String, String, Vec<String>) {
        let old = base.fork();
        old.set_change_merge_interval(-1);
        old.set_peer_id(9).unwrap();
        bob(&old);
        old.commit();
        old.set_peer_id(3).unwrap();
        carol(&old);
        old.commit();
        let target = base.fork();
        target.set_peer_id(30).unwrap();
        let replayed = replay_own(&old, &target, 0, &mut Mapping::new(3, 0));
        let expected = base.fork();
        expected.set_peer_id(31).unwrap();
        oracle(&expected);
        expected.commit();
        (show(&target), show(&expected), replayed.left_out)
    }

    /// The replay makes what the oracle makes, and leaves nothing out.
    fn placed(
        base: &LoroDoc,
        bob: impl FnOnce(&LoroDoc),
        carol: impl FnOnce(&LoroDoc),
        oracle: impl FnOnce(&LoroDoc),
    ) {
        let (got, want, left_out) = case(base, bob, carol, oracle);
        assert!(left_out.is_empty(), "{left_out:?}");
        assert_eq!(got, want);
    }

    /// The replay makes what the oracle makes, and reports what it left
    /// out.
    fn reported(
        base: &LoroDoc,
        bob: impl FnOnce(&LoroDoc),
        carol: impl FnOnce(&LoroDoc),
        oracle: impl FnOnce(&LoroDoc),
    ) -> Vec<String> {
        let (got, want, left_out) = case(base, bob, carol, oracle);
        assert!(!left_out.is_empty(), "something left out");
        assert_eq!(got, want);
        left_out
    }

    fn noop(_: &LoroDoc) {}

    #[test]
    fn text_typed_over_bobs_text() {
        let b = base();
        // Bob deletes "base "; Carol types where it was, and at the end.
        placed(
            &b,
            |d| d.get_text("body").delete(0, 5).unwrap(),
            |d| d.get_text("body").insert(0, "carol ").unwrap(),
            |d| d.get_text("body").insert(5, "carol ").unwrap(),
        );
        placed(
            &b,
            |d| d.get_text("body").delete(0, 5).unwrap(),
            |d| d.get_text("body").insert(4, " carol").unwrap(),
            |d| d.get_text("body").insert(9, " carol").unwrap(),
        );
        // Bob inserts "bob "; Carol types inside it.
        placed(
            &b,
            |d| d.get_text("body").insert(0, "bob ").unwrap(),
            |d| d.get_text("body").insert(2, "X").unwrap(),
            |d| d.get_text("body").insert(0, "X").unwrap(),
        );
        // Bob deletes "base "; Carol deletes the rest.
        placed(
            &b,
            |d| d.get_text("body").delete(0, 5).unwrap(),
            |d| d.get_text("body").delete(0, 4).unwrap(),
            |d| d.get_text("body").delete(5, 4).unwrap(),
        );
    }

    #[test]
    fn a_style_taken_from_bobs_text_is_not_carols() {
        let b = base();
        // Bob bolds "base"; Carol types Z inside it.
        placed(
            &b,
            |d| d.get_text("body").mark(0..4, "bold", true).unwrap(),
            |d| d.get_text("body").insert(2, "Z").unwrap(),
            |d| d.get_text("body").insert(2, "Z").unwrap(),
        );
        // The same, and Carol bolds "text" in the same commit: Z takes
        // nothing of Bob's bold.
        let carols = |d: &LoroDoc| {
            let text = d.get_text("body");
            text.insert(2, "Z").unwrap();
            text.mark(6..10, "bold", true).unwrap();
        };
        placed(
            &b,
            |d| d.get_text("body").mark(0..4, "bold", true).unwrap(),
            carols,
            carols,
        );
    }

    #[test]
    fn a_chain_of_own_text_changes_over_bobs_text() {
        // Bob inserts "bob "; Carol types XY in it, bolds XY, then deletes
        // "bX": what is left of hers is a bold Y.
        placed(
            &base(),
            |d| d.get_text("body").insert(0, "bob ").unwrap(),
            |d| {
                let text = d.get_text("body");
                text.insert(1, "XY").unwrap();
                d.commit();
                text.mark(1..3, "bold", true).unwrap();
                d.commit();
                text.delete(0, 2).unwrap();
            },
            |d| {
                let text = d.get_text("body");
                text.insert(0, "Y").unwrap();
                text.mark(0..1, "bold", true).unwrap();
            },
        );
    }

    #[test]
    fn a_deletion_bob_made_concurrently_is_carols_too() {
        let b = base();
        let old = b.fork();
        old.set_change_merge_interval(-1);
        old.set_peer_id(9).unwrap();
        old.get_text("body").delete(0, 5).unwrap();
        old.commit();
        let carols = b.fork();
        carols.set_peer_id(3).unwrap();
        carols.get_text("body").delete(0, 5).unwrap();
        carols.commit();
        old.import(&carols.export(ExportMode::all_updates()).unwrap())
            .unwrap();
        let target = b.fork();
        target.set_peer_id(30).unwrap();
        let replayed = replay_own(&old, &target, 0, &mut Mapping::new(3, 0));
        assert!(replayed.left_out.is_empty(), "{:?}", replayed.left_out);
        assert_eq!(target.get_text("body").to_string(), "text");
    }

    #[test]
    fn counters_and_map_keys_are_carols_own() {
        let b = base();
        placed(
            &b,
            |d| d.get_counter("n").increment(5.0).unwrap(),
            |d| d.get_counter("n").increment(1.0).unwrap(),
            |d| d.get_counter("n").increment(1.0).unwrap(),
        );
        placed(
            &b,
            |d| {
                let meta = d.get_map("meta");
                meta.insert("title", "bob").unwrap();
                meta.delete("subtitle").unwrap();
            },
            |d| d.get_map("meta").insert("title", "carol").unwrap(),
            |d| d.get_map("meta").insert("title", "carol").unwrap(),
        );
    }

    #[test]
    fn movable_list_moves_and_sets_over_bobs() {
        let b = base();
        let order = |d: &LoroDoc| d.get_movable_list("order");
        // Bob moves a to the end; Carol pushes d.
        placed(
            &b,
            |d| order(d).mov(0, 2).unwrap(),
            |d| order(d).push("d").unwrap(),
            |d| order(d).push("d").unwrap(),
        );
        // Bob sets b to B; Carol pushes d.
        placed(
            &b,
            |d| order(d).set(1, "B").unwrap(),
            |d| order(d).push("d").unwrap(),
            |d| order(d).push("d").unwrap(),
        );
        // Bob sets b to B; Carol moves that item to the front.
        placed(
            &b,
            |d| order(d).set(1, "B").unwrap(),
            |d| order(d).mov(1, 0).unwrap(),
            |d| order(d).mov(1, 0).unwrap(),
        );
        // Bob moves a to the end; Carol sets it to A.
        placed(
            &b,
            |d| order(d).mov(0, 2).unwrap(),
            |d| order(d).set(2, "A").unwrap(),
            |d| order(d).set(0, "A").unwrap(),
        );
        // Bob sets b to B; Carol sets it to C: Carol's value, not lost.
        placed(
            &b,
            |d| order(d).set(1, "B").unwrap(),
            |d| order(d).set(1, "C").unwrap(),
            |d| order(d).set(1, "C").unwrap(),
        );
        // Bob types elsewhere; Carol moves b to the front.
        placed(
            &b,
            |d| d.get_text("body").insert(0, "z").unwrap(),
            |d| order(d).mov(1, 0).unwrap(),
            |d| order(d).mov(1, 0).unwrap(),
        );
    }

    #[test]
    fn carols_own_moves_and_sets_alone() {
        let b = base();
        let order = |d: &LoroDoc| d.get_movable_list("order");
        // A move earlier, a move later, a set, and a move then a set.
        placed(
            &b,
            noop,
            |d| order(d).mov(2, 0).unwrap(),
            |d| order(d).mov(2, 0).unwrap(),
        );
        placed(
            &b,
            noop,
            |d| order(d).mov(0, 2).unwrap(),
            |d| order(d).mov(0, 2).unwrap(),
        );
        placed(
            &b,
            noop,
            |d| order(d).set(0, "A").unwrap(),
            |d| order(d).set(0, "A").unwrap(),
        );
        placed(
            &b,
            noop,
            |d| {
                order(d).mov(2, 0).unwrap();
                d.commit();
                order(d).set(1, "A").unwrap();
            },
            |d| {
                order(d).mov(2, 0).unwrap();
                order(d).set(1, "A").unwrap();
            },
        );
    }

    #[test]
    fn moves_of_equal_values_are_told_apart() {
        // Carol pushes a second "a", deletes the first and moves the second
        // to index 1, in two commits and in one.
        let order = |d: &LoroDoc| d.get_movable_list("order");
        placed(
            &base(),
            noop,
            |d| {
                order(d).push("a").unwrap();
                d.commit();
                order(d).delete(0, 1).unwrap();
                order(d).mov(2, 1).unwrap();
            },
            |d| {
                order(d).push("a").unwrap();
                order(d).delete(0, 1).unwrap();
                order(d).mov(2, 1).unwrap();
            },
        );
        // The base holds two "a"; Carol deletes the first and moves the
        // second to the front, in one commit.
        let b = base();
        let twice = b.fork();
        twice.set_peer_id(2).unwrap();
        order(&twice).push("a").unwrap();
        twice.commit();
        let carols = |d: &LoroDoc| {
            order(d).delete(0, 1).unwrap();
            order(d).mov(2, 0).unwrap();
        };
        placed(&twice, noop, carols, carols);
    }

    #[test]
    fn several_moves_in_one_change_do_not_depend_on_peer_ids() {
        // Bob moves a to the end; Carol, in one commit, moves d to the
        // front, b after e, and sets c to C. Loro's diff of such a change
        // depends on the peers; the replay does not. d goes to the front,
        // and b after e.
        for (bob, carol, target_peer) in [(9, 3, 30), (3, 9, 30), (2, 100, 1000), (100, 2, 5)] {
            let base = doc(1);
            let order = base.get_movable_list("order");
            for item in ["a", "b", "c", "d", "e"] {
                order.push(item).unwrap();
            }
            base.commit();
            let old = base.fork();
            old.set_change_merge_interval(-1);
            old.set_peer_id(bob).unwrap();
            old.get_movable_list("order").mov(0, 4).unwrap();
            old.commit();
            old.set_peer_id(carol).unwrap();
            let order = old.get_movable_list("order");
            order.mov(2, 0).unwrap();
            order.mov(1, 3).unwrap();
            order.set(1, "C").unwrap();
            old.commit();
            let target = base.fork();
            target.set_peer_id(target_peer).unwrap();
            let replayed = replay_own(&old, &target, 0, &mut Mapping::new(carol, 0));
            assert!(replayed.left_out.is_empty(), "{:?}", replayed.left_out);
            assert_eq!(
                serde_json::to_string(&target.get_movable_list("order").get_deep_value()).unwrap(),
                r#"["d","a","C","e","b"]"#,
                "peers {bob}, {carol}, {target_peer}"
            );
        }
    }

    #[test]
    fn own_marks_over_text_that_had_the_style() {
        let b = base();
        let text = |d: &LoroDoc| d.get_text("body");
        let bold_base = |d: &LoroDoc| {
            text(d).mark(0..4, "bold", true).unwrap();
        };
        // Bob bolds "base"; Carol bolds all "base text": all of it bold.
        let carols = |d: &LoroDoc| {
            text(d).mark(0..9, "bold", true).unwrap();
        };
        placed(&b, bold_base, carols, carols);
        // Carol types Z inside and bolds 0..10 in one commit.
        let carols = |d: &LoroDoc| {
            text(d).insert(2, "Z").unwrap();
            text(d).mark(0..10, "bold", true).unwrap();
        };
        placed(&b, bold_base, carols, carols);
        // Carol types Z after "base", where it takes Bob's bold, and bolds
        // Z and the space after it in one commit: both are bold, by her own
        // mark.
        let carols = |d: &LoroDoc| {
            text(d).insert(4, "Z").unwrap();
            text(d).mark(4..6, "bold", true).unwrap();
        };
        placed(&b, bold_base, carols, carols);
        // Carol types Z inside and makes it italic and bold in one commit:
        // the italic is hers.
        placed(
            &b,
            bold_base,
            |d| {
                text(d).insert(2, "Z").unwrap();
                text(d).mark(2..3, "bold", true).unwrap();
                text(d).mark(2..3, "italic", true).unwrap();
            },
            |d| {
                text(d).insert(2, "Z").unwrap();
                text(d).mark(2..3, "italic", true).unwrap();
            },
        );
    }

    #[test]
    fn text_restored_between_a_marks_anchors_stays_unmarked() {
        // Bob deletes the space of "base text"; Carol bolds "se" and "te"
        // across where it was. Bob's deletion withdrawn, the space is back
        // between them, and Carol's bold never covered it.
        let b = base();
        let (got, _, left_out) = case(
            &b,
            |d| d.get_text("body").delete(4, 1).unwrap(),
            |d| d.get_text("body").mark(2..6, "bold", true).unwrap(),
            noop,
        );
        assert!(left_out.is_empty(), "{left_out:?}");
        assert!(
            got.starts_with(r#"text="ba[se|bold] [te|bold]xt""#),
            "{got}"
        );
    }

    #[test]
    fn a_mark_that_changes_nothing_is_not_in_the_history() {
        // Bob bolds "base"; Carol bolds "base" again, or types Z inside and
        // bolds Z. Loro writes no operation for those marks: Carol's history
        // holds her insertion alone, and the replay cannot tell her bold
        // from the one Z took from Bob's text.
        let b = base();
        let text = |d: &LoroDoc| d.get_text("body");
        let old = b.fork();
        old.set_change_merge_interval(-1);
        old.set_peer_id(9).unwrap();
        text(&old).mark(0..4, "bold", true).unwrap();
        old.commit();
        old.set_peer_id(3).unwrap();
        text(&old).mark(0..4, "bold", true).unwrap();
        old.commit();
        assert_eq!(old.oplog_vv().get(&3), None, "no operation of Carol's");
        text(&old).insert(2, "Z").unwrap();
        text(&old).mark(2..3, "bold", true).unwrap();
        old.commit();
        let ops: Vec<_> = old
            .export_json_in_id_span(loro::IdSpan::new(3, 0, 10))
            .into_iter()
            .flat_map(|change| change.ops)
            .collect();
        assert_eq!(ops.len(), 1, "the insertion alone: {ops:?}");
    }

    #[test]
    fn own_marks_across_bobs_withdrawn_text() {
        let b = base();
        let text = |d: &LoroDoc| d.get_text("body");
        let bobs = |d: &LoroDoc| text(d).insert(5, "bob ").unwrap();
        placed(
            &b,
            bobs,
            |d| text(d).mark(3..11, "bold", true).unwrap(),
            |d| text(d).mark(3..7, "bold", true).unwrap(),
        );
        placed(
            &b,
            bobs,
            |d| text(d).mark(6..13, "bold", true).unwrap(),
            |d| text(d).mark(5..9, "bold", true).unwrap(),
        );
        placed(
            &b,
            bobs,
            |d| {
                text(d).insert(9, "Q").unwrap();
                text(d).mark(3..12, "bold", true).unwrap();
            },
            |d| {
                text(d).insert(5, "Q").unwrap();
                text(d).mark(3..8, "bold", true).unwrap();
            },
        );
    }

    #[test]
    fn own_unmarks() {
        let b = base();
        let text = |d: &LoroDoc| d.get_text("body");
        let unmark = |d: &LoroDoc| text(d).unmark(2..6, "bold").unwrap();
        placed(
            &b,
            |d| text(d).mark(0..9, "bold", true).unwrap(),
            unmark,
            unmark,
        );
        let carols = |d: &LoroDoc| {
            text(d).mark(5..9, "bold", true).unwrap();
            d.commit();
            text(d).unmark(0..9, "bold").unwrap();
        };
        placed(
            &b,
            |d| text(d).mark(0..4, "bold", true).unwrap(),
            carols,
            carols,
        );
        // "base" bold in the base; Bob bolds "text"; Carol unmarks 3..6.
        let held = b.fork();
        held.set_peer_id(2).unwrap();
        text(&held).mark(0..4, "bold", true).unwrap();
        held.commit();
        let unmark = |d: &LoroDoc| text(d).unmark(3..6, "bold").unwrap();
        placed(
            &held,
            |d| text(d).mark(5..9, "bold", true).unwrap(),
            unmark,
            unmark,
        );
        let carols = |d: &LoroDoc| {
            text(d).insert(2, "Z").unwrap();
            text(d).unmark(0..5, "bold").unwrap();
        };
        placed(
            &b,
            |d| text(d).mark(0..4, "bold", true).unwrap(),
            carols,
            carols,
        );
    }

    #[test]
    fn moves_to_the_front_or_the_end_land_there() {
        let b = base();
        let order = |d: &LoroDoc| d.get_movable_list("order");
        // Bob moves a to the end; Carol moves c to the front.
        placed(
            &b,
            |d| order(d).mov(0, 2).unwrap(),
            |d| order(d).mov(1, 0).unwrap(),
            |d| order(d).mov(2, 0).unwrap(),
        );
        // Bob moves c to the front; Carol sets a to A, then moves it to
        // the end.
        placed(
            &b,
            |d| order(d).mov(2, 0).unwrap(),
            |d| {
                order(d).set(1, "A").unwrap();
                d.commit();
                order(d).mov(1, 2).unwrap();
            },
            |d| {
                order(d).set(0, "A").unwrap();
                order(d).mov(0, 2).unwrap();
            },
        );
    }

    #[test]
    fn own_sets_moves_and_deletions_of_one_item() {
        let b = base();
        let order = |d: &LoroDoc| d.get_movable_list("order");
        let same = |carols: fn(&LoroDoc)| placed(&b, noop, carols, carols);
        same(|d| {
            d.get_movable_list("order").set(1, "B").unwrap();
            d.commit();
            d.get_movable_list("order").mov(1, 0).unwrap();
        });
        same(|d| {
            d.get_movable_list("order").set(1, "B").unwrap();
            d.get_movable_list("order").mov(1, 0).unwrap();
        });
        same(|d| {
            d.get_movable_list("order").mov(2, 0).unwrap();
            d.get_movable_list("order").delete(0, 1).unwrap();
        });
        same(|d| {
            d.get_movable_list("order").mov(2, 0).unwrap();
            d.get_movable_list("order").delete(1, 1).unwrap();
        });
        same(|d| {
            d.get_movable_list("order").mov(0, 2).unwrap();
            d.commit();
            d.get_movable_list("order").mov(2, 1).unwrap();
        });
        same(|d| {
            d.get_movable_list("order").mov(2, 0).unwrap();
            d.commit();
            d.get_movable_list("order").mov(0, 2).unwrap();
        });
        same(|d| {
            d.get_movable_list("order").push("d").unwrap();
            d.commit();
            d.get_movable_list("order").mov(0, 3).unwrap();
            d.get_movable_list("order").mov(2, 0).unwrap();
            d.get_movable_list("order").mov(1, 2).unwrap();
        });
        let bobs_x = |d: &LoroDoc| order(d).push("x").unwrap();
        placed(
            &b,
            bobs_x,
            |d| {
                order(d).mov(2, 0).unwrap();
                order(d).set(0, "C").unwrap();
            },
            |d| {
                order(d).mov(2, 0).unwrap();
                order(d).set(0, "C").unwrap();
            },
        );
        placed(
            &b,
            bobs_x,
            |d| {
                order(d).mov(0, 3).unwrap();
                order(d).delete(0, 1).unwrap();
            },
            |d| {
                order(d).mov(0, 2).unwrap();
                order(d).delete(0, 1).unwrap();
            },
        );
        placed(
            &b,
            bobs_x,
            |d| {
                order(d).mov(0, 3).unwrap();
                d.commit();
                order(d).mov(3, 1).unwrap();
            },
            |d| {
                order(d).mov(0, 2).unwrap();
                order(d).mov(2, 1).unwrap();
            },
        );
        placed(
            &b,
            bobs_x,
            |d| {
                order(d).insert(1, "n").unwrap();
                order(d).mov(1, 4).unwrap();
            },
            |d| {
                order(d).insert(1, "n").unwrap();
                order(d).mov(1, 3).unwrap();
            },
        );
    }

    #[test]
    fn carols_own_operations_of_every_kind() {
        let b = base();
        let carols = |d: &LoroDoc| {
            let text = d.get_text("body");
            text.mark(5..9, "bold", true).unwrap();
            text.delete(0, 5).unwrap();
            d.get_counter("n").increment(1.0).unwrap();
            d.get_movable_list("order").mov(2, 0).unwrap();
            d.get_movable_list("order").set(1, "A").unwrap();
            d.get_list("tags").delete(0, 1).unwrap();
            d.get_map("meta").delete("subtitle").unwrap();
            let tree = d.get_tree("outline");
            let one = tree.roots()[0];
            tree.get_meta(one).unwrap().insert("name", "ONE").unwrap();
        };
        placed(
            &b,
            |d| d.get_text("body").insert(9, "!").unwrap(),
            carols,
            carols,
        );
        // A node created, moved under another, which is then deleted.
        let carols = |d: &LoroDoc| {
            let tree = d.get_tree("outline");
            let one = tree.roots()[0];
            let made = tree.create(TreeParentId::Root).unwrap();
            tree.mov(made, TreeParentId::Node(one)).unwrap();
            tree.delete(one).unwrap();
        };
        placed(&b, noop, carols, carols);
        // A plain list, Bob pushing too.
        placed(
            &b,
            |d| d.get_list("tags").push("x").unwrap(),
            |d| {
                let tags = d.get_list("tags");
                tags.insert(4, "y").unwrap();
                tags.delete(0, 1).unwrap();
            },
            |d| {
                let tags = d.get_list("tags");
                tags.push("y").unwrap();
                tags.delete(0, 1).unwrap();
            },
        );
    }

    #[test]
    fn what_has_no_place_is_reported_and_the_rest_placed() {
        let b = base();
        let order = |d: &LoroDoc| d.get_movable_list("order");
        // Carol moves an item only Bob pushed.
        let left = reported(
            &b,
            |d| order(d).push("x").unwrap(),
            |d| order(d).mov(3, 0).unwrap(),
            noop,
        );
        assert!(
            left.iter().any(|line| line.starts_with("a move in")),
            "{left:?}"
        );
        // Then inserts y after it: y goes first.
        reported(
            &b,
            |d| order(d).push("x").unwrap(),
            |d| {
                order(d).mov(3, 0).unwrap();
                d.commit();
                order(d).insert(1, "y").unwrap();
            },
            |d| order(d).insert(0, "y").unwrap(),
        );
        // Carol sets a key in Bob's map.
        reported(
            &b,
            |d| {
                d.get_map("meta")
                    .insert_container("box", LoroMap::new())
                    .unwrap();
            },
            |d| {
                if let Some(ValueOrContainer::Container(Container::Map(map))) =
                    d.get_map("meta").get("box")
                {
                    map.insert("y", 2).unwrap();
                }
            },
            noop,
        );
        // Carol creates a child under Bob's node, names it, moves it to the
        // root.
        let bobs_node = |d: &LoroDoc| {
            let tree = d.get_tree("outline");
            *tree.roots().iter().find(|node| node.peer == 9).unwrap()
        };
        reported(
            &b,
            |d| {
                d.get_tree("outline").create(TreeParentId::Root).unwrap();
            },
            |d| {
                let tree = d.get_tree("outline");
                tree.create(TreeParentId::Node(bobs_node(d))).unwrap();
            },
            noop,
        );
        reported(
            &b,
            |d| {
                d.get_tree("outline").create(TreeParentId::Root).unwrap();
            },
            |d| {
                let tree = d.get_tree("outline");
                let made = tree.create(TreeParentId::Node(bobs_node(d))).unwrap();
                d.commit();
                tree.get_meta(made).unwrap().insert("name", "K").unwrap();
                d.commit();
                tree.mov(made, TreeParentId::Root).unwrap();
            },
            noop,
        );
        // Carol types in Bob's text container, then sets the key to a
        // string of her own.
        reported(
            &b,
            |d| {
                d.get_map("meta")
                    .insert_container("note", LoroText::new())
                    .unwrap();
            },
            |d| {
                if let Some(ValueOrContainer::Container(Container::Text(text))) =
                    d.get_map("meta").get("note")
                {
                    text.insert(0, "hi").unwrap();
                }
                d.commit();
                d.get_map("meta").insert("note", "plain").unwrap();
            },
            |d| d.get_map("meta").insert("note", "plain").unwrap(),
        );
    }
}
