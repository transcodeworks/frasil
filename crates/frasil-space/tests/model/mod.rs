//! keys.json's histories read as a key-graph [`History`].
//!
//! Each history names its members and their devices, and its events by
//! label, with their causal parents, kinds, targets and secrets. A
//! checkpoint gives the events one device holds, the valid set roster.md
//! decided for them, and the wraps, links and gaps it holds.
//!
//! - **The roster of a set of valid events** follows roster.md over the
//!   grants, removals and demotions these histories hold: a member's grants
//!   in force are those no removal of it has in its past; its level is the
//!   highest of them, lowered by each demotion that has one of them in its
//!   past.
//! - **What voids a removal, and stability,** follow roster.md's attacks
//!   among them: a valid removal or demotion voids its target's concurrent
//!   actions, and a removal a concurrent grant of its target; a voiding is
//!   stable once every administrator device signed a valid event that has
//!   the removal and every voider in its past.
//! - **A granted space** is named `T`, its principals `T@R`, and the past of
//!   each of its rotations is given (`grantee_rotations`). A grant whose
//!   target is `T@R` grants the space T and carries a notice for `R`. The
//!   devices still in T, as the replica holds T's log, are the checkpoint's
//!   input (`foreign_current`); a checkpoint that names no devices for T
//!   does not hold T's log.
//! - **A checkpoint's world** (`world_of`, keys.md, "Keys after a
//!   checkpoint"): the view is rooted at the checkpoint, which stands as its
//!   genesis. Its record grants each member it names at the root, a
//!   principal `T@R` as a grant of T with a notice of `R` the root carries
//!   (and admits where the replica holds T's log), names the rotations of
//!   `named` in the root's refs, shows the invite keys of `raced` raced and
//!   gives the spaces of `floor` a floor.
//! - **A revoked device** (`revoked`, a checkpoint's input) is one its
//!   person's list revoked: no longer among the person's devices, though
//!   the wraps it received stay its own. A notice admits its principal only where the
//!   replica holds T's log and did not refuse it (`refused_notice`); its
//!   event stands either way.

#![allow(dead_code)]

use frasil_events::{EventId, Ref};
use frasil_keys::RotationSet;
use frasil_space::Level;
use frasil_space::keygraph::{
    Artifact, EventFacts, Grant, History, KeyGraph, Kind, Member, Membership, NoticeFacts, Role,
    Rotation,
};
use frasil_testkit::hex;
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};

/// The name a vector gives a level.
pub fn level_name(level: Level) -> &'static str {
    match level {
        Level::Read => "read",
        Level::Write => "write",
        Level::Administer => "administer",
    }
}

fn level(name: &str) -> Level {
    match name {
        "read" => Level::Read,
        "write" => Level::Write,
        "administer" => Level::Administer,
        other => panic!("{other}"),
    }
}

/// What a roster change of the history is.
#[derive(Debug, Clone)]
struct Change {
    kind: String,
    /// The member it targets, `T` for `T@R`.
    target: String,
    level: Level,
    with_history: bool,
    session: bool,
}

/// One checkpoint of a history, as a key-graph history.
pub struct Model {
    space: EventId,
    genesis: EventId,
    labels: BTreeMap<EventId, String>,
    ids: BTreeMap<String, EventId>,
    past: BTreeMap<EventId, BTreeSet<EventId>>,
    facts: BTreeMap<EventId, EventFacts<String, String>>,
    changes: BTreeMap<EventId, Change>,
    secrets: BTreeMap<EventId, BTreeMap<String, [u8; 32]>>,
    members: BTreeMap<String, Vec<String>>,
    member_of: BTreeMap<String, String>,
    spaces: BTreeMap<String, EventId>,
    /// Each granted space's rotations, by ID, with their pasts.
    grantee: BTreeMap<EventId, BTreeSet<EventId>>,
    view: BTreeSet<EventId>,
    valid: BTreeSet<EventId>,
    /// Each granted space's current devices, by the space's name, as the
    /// checkpoint's replica holds its log.
    foreign_current: BTreeMap<String, BTreeSet<String>>,
    /// The events whose notice this replica refused.
    refused: BTreeSet<EventId>,
    /// The devices their persons' lists revoked.
    revoked: BTreeSet<String>,
    /// Each checkpoint's record: its members with their level, history and
    /// session.
    records: BTreeMap<EventId, Vec<(String, Level, bool, bool)>>,
    /// The checkpoint the view is rooted at, for a checkpoint's world.
    world: Option<EventId>,
    /// The invite keys the root's record shows raced.
    raced: Vec<String>,
    /// The granted spaces the root's record gives a floor, by ID.
    floors: BTreeSet<EventId>,
}

/// A granted space's ID, from its name.
fn space_id(name: &str) -> EventId {
    EventId(super::common::named(&format!("granted space/{name}")))
}

/// A granted space's rotation's ID, from its label.
fn rotation_id(name: &str) -> EventId {
    EventId(super::common::named(&format!("granted rotation/{name}")))
}

impl Model {
    /// The view of one checkpoint of a history.
    pub fn new(history: &Json, checkpoint: &Json) -> Self {
        let space = EventId(hex::decode_array(history["space"].as_str().unwrap()).unwrap());
        let members: BTreeMap<String, Vec<String>> = history["members"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(m, ds)| {
                let ds = ds
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|d| d.as_str().unwrap().to_owned())
                    .collect();
                (m.clone(), ds)
            })
            .collect();
        // A device's member, for roster.md's attacks: members that are no
        // principal first.
        let mut member_of = BTreeMap::new();
        for principal in [false, true] {
            for (m, ds) in &members {
                if m.contains('@') == principal {
                    for d in ds {
                        member_of.entry(d.clone()).or_insert_with(|| m.clone());
                    }
                }
            }
        }
        let mut spaces = BTreeMap::new();
        for m in members.keys() {
            if let Some((t, _)) = m.split_once('@') {
                spaces.insert(t.to_owned(), space_id(t));
            }
        }
        let mut grantee = BTreeMap::new();
        if let Some(rotations) = history.get("grantee_rotations").and_then(Json::as_object) {
            for (r, past) in rotations {
                let past = past
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| rotation_id(p.as_str().unwrap()))
                    .collect();
                grantee.insert(rotation_id(r), past);
            }
        }
        let mut model = Self {
            space,
            genesis: space,
            labels: BTreeMap::new(),
            ids: BTreeMap::new(),
            past: BTreeMap::new(),
            facts: BTreeMap::new(),
            changes: BTreeMap::new(),
            secrets: BTreeMap::new(),
            members,
            member_of,
            spaces,
            grantee,
            view: BTreeSet::new(),
            valid: BTreeSet::new(),
            foreign_current: BTreeMap::new(),
            refused: BTreeSet::new(),
            revoked: BTreeSet::new(),
            records: BTreeMap::new(),
            world: None,
            raced: Vec::new(),
            floors: BTreeSet::new(),
        };
        for event in history["events"].as_array().unwrap() {
            model.add(event);
        }
        if let Some(root) = checkpoint["world_of"].as_str() {
            let root = model.ids[root];
            model.genesis = root;
            model.world = Some(root);
            let event = history["events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["label"].as_str() == Some(model.labels[&root].as_str()))
                .unwrap();
            let record = &event["record"];
            model.raced = record["raced"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m.as_str().unwrap().to_owned())
                .collect();
            model.floors = record["floor"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| {
                    model
                        .spaces
                        .get(t.as_str().unwrap())
                        .copied()
                        .unwrap_or_else(|| space_id(t.as_str().unwrap()))
                })
                .collect();
        }
        model.view = model.labelled(&checkpoint["events"]);
        model.valid = model.labelled(&checkpoint["valid"]);
        if let Some(revoked) = checkpoint.get("revoked").and_then(Json::as_array) {
            model.revoked = revoked
                .iter()
                .map(|d| d.as_str().unwrap().to_owned())
                .collect();
        }
        if let Some(current) = checkpoint.get("foreign_current").and_then(Json::as_object) {
            for (t, devices) in current {
                let devices = devices
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|d| d.as_str().unwrap().to_owned())
                    .collect();
                model.foreign_current.insert(t.clone(), devices);
            }
        }
        model
    }

    /// An event's label.
    pub fn label(&self, id: EventId) -> &str {
        &self.labels[&id]
    }

    fn labelled(&self, labels: &Json) -> BTreeSet<EventId> {
        labels
            .as_array()
            .unwrap()
            .iter()
            .map(|l| self.ids[l.as_str().unwrap()])
            .collect()
    }

    /// `T@R` as a ref or a notice names it.
    fn split(&self, principal: &str) -> (EventId, EventId) {
        let (t, r) = principal.split_once('@').unwrap();
        (self.spaces[t], rotation_id(r))
    }

    fn add(&mut self, event: &Json) {
        let text = |key: &str| event[key].as_str().unwrap_or_default().to_owned();
        let label = text("label");
        let id = EventId(hex::decode_array(&text("id")).unwrap());
        let kind = text("kind");
        if kind == "genesis" {
            self.genesis = id;
        }
        self.labels.insert(id, label.clone());
        self.ids.insert(label, id);
        let mut past = BTreeSet::new();
        for parent in event["parents"].as_array().unwrap() {
            let parent = self.ids[parent.as_str().unwrap()];
            past.insert(parent);
            past.extend(self.past[&parent].iter().copied());
        }
        self.past.insert(id, past);
        let role = match kind.as_str() {
            "genesis" => Role::Genesis,
            "grant" | "remove" | "demote" | "succeed" | "checkpoint" => Role::Roster,
            "key" => Role::Key,
            "unit" => Role::Unit,
            other => panic!("{other}"),
        };
        let mut facts = EventFacts::new(text("author"), role);
        if event["rotates"].as_bool() == Some(true) {
            facts.rotation = Some(Rotation {
                grant: event["grant_rotation"].as_bool().unwrap(),
                is_break: event["break"].as_bool().unwrap(),
            });
        }
        if let Some(reference) = event["key_reference"].as_str() {
            facts.key_reference = Some(self.state(reference));
        }
        let target = text("target");
        let (base, principal) = match target.split_once('@') {
            Some((t, _)) => (t.to_owned(), true),
            None => (target.clone(), false),
        };
        let change = Change {
            kind: kind.clone(),
            target: base.clone(),
            level: event["level"].as_str().map_or(Level::Read, level),
            with_history: event["history"].as_str() != Some("from now on"),
            session: event["session"].as_bool().unwrap_or(false),
        };
        match kind.as_str() {
            "grant" => {
                facts.grants.push(Grant {
                    member: base.clone(),
                    with_history: change.with_history,
                    session: change.session,
                });
                if principal {
                    let (space, rotation) = self.split(&target);
                    facts.notices.push(NoticeFacts {
                        space,
                        rotation,
                        from_now_on: !change.with_history,
                    });
                }
            }
            "remove" => facts.removes.push(base.clone()),
            // ext-invite-links.md: a successor, signed by the invite key,
            // naming its claimant as the target.
            #[cfg(feature = "ext-invite-links")]
            "succeed" => {
                facts.successor = Some(frasil_space::ext_invite_links::Succession {
                    invite: self.member_of[&text("author")].clone(),
                    claimant: base.clone(),
                });
            }
            _ => {}
        }
        if let Some(notice) = event.get("notice") {
            let (space, _) = self.split(notice["principal"].as_str().unwrap());
            facts.notices.push(NoticeFacts {
                space,
                rotation: rotation_id(notice["grantee_rotation"].as_str().unwrap()),
                from_now_on: notice["from_now_on"].as_bool().unwrap(),
            });
        }
        // A checkpoint's record: its members granted at it; a principal's
        // notice and the record's names carried by it.
        if let Some(record) = event.get("record") {
            let mut members = Vec::new();
            for (m, state) in record["members"].as_object().unwrap() {
                let with_history = state["history"].as_bool().unwrap();
                let entry = (
                    m.split_once('@').map_or(m.as_str(), |(t, _)| t).to_owned(),
                    level(state["level"].as_str().unwrap()),
                    with_history,
                    state["session"].as_bool().unwrap(),
                );
                if m.contains('@') {
                    let (space, rotation) = self.split(m);
                    facts.notices.push(NoticeFacts {
                        space,
                        rotation,
                        from_now_on: !with_history,
                    });
                }
                members.push(entry);
            }
            for r in record["named"].as_array().unwrap() {
                let (log, rotation) = self.split(r.as_str().unwrap());
                facts.refs.push(Ref { log, id: rotation });
            }
            self.records.insert(id, members);
        }
        if event["refused_notice"].as_bool() == Some(true) {
            self.refused.insert(id);
        }
        for r in event["refs"].as_array().into_iter().flatten() {
            let (log, rotation) = self.split(r.as_str().unwrap());
            facts.refs.push(Ref { log, id: rotation });
        }
        facts.refs.sort_unstable();
        if let Some(secrets) = event["secrets"].as_object() {
            let secrets = secrets
                .iter()
                .map(|(k, v)| (k.clone(), hex::decode_array(v.as_str().unwrap()).unwrap()))
                .collect();
            self.secrets.insert(id, secrets);
        }
        self.facts.insert(id, facts);
        self.changes.insert(id, change);
    }

    /// The key graph of the checkpoint's view and valid set.
    pub fn key_graph(&self) -> KeyGraph<'_, Self> {
        KeyGraph::new(self, self.valid.clone())
    }

    /// A rotation's secret of one kind.
    pub fn secret(&self, rotation: EventId, kind: &str) -> Option<[u8; 32]> {
        self.secrets.get(&rotation)?.get(kind).copied()
    }

    /// A state, from its rotations' labels joined by `+`.
    pub fn state(&self, name: &str) -> RotationSet {
        RotationSet::new(name.split('+').map(|l| self.ids[l])).unwrap()
    }

    /// A state's name: its rotations' labels in canonical order, joined by
    /// `+`.
    pub fn state_name(&self, state: &RotationSet) -> String {
        state
            .ids()
            .iter()
            .map(|i| self.labels[i].as_str())
            .collect::<Vec<_>>()
            .join("+")
    }

    /// A member's name: `T@R` for a principal.
    pub fn member_name(&self, member: &Member<String>) -> String {
        match member {
            Member::Roster(m) => m.clone(),
            Member::Principal(p) => {
                let t = self.spaces.iter().find(|(_, i)| **i == p.space).unwrap().0;
                let r = self
                    .grantee
                    .keys()
                    .copied()
                    .chain(
                        self.facts
                            .values()
                            .flat_map(|f| f.notices.iter().map(|n| n.rotation)),
                    )
                    .find(|&r| r == p.rotation)
                    .and_then(|r| self.rotation_label(r))
                    .unwrap();
                format!("{t}@{r}")
            }
        }
    }

    fn rotation_label(&self, rotation: EventId) -> Option<String> {
        self.members
            .keys()
            .filter_map(|m| m.split_once('@'))
            .map(|(_, r)| r)
            .find(|r| rotation_id(r) == rotation)
            .map(str::to_owned)
    }

    /// The checkpoint's artifacts: `wrap <kind> <state> to <device>`,
    /// `link <kind> <under> > <reaches>`, `gap <kind> <state>`.
    pub fn artifacts(&self, list: &Json) -> Vec<Artifact<String>> {
        list.as_array()
            .unwrap()
            .iter()
            .map(|a| {
                let a = a.as_str().unwrap();
                let mut words = a.splitn(3, ' ');
                let what = words.next().unwrap();
                let kind = match words.next().unwrap() {
                    "content" => Kind::Content,
                    "grant" => Kind::Grant,
                    other => panic!("{other}"),
                };
                let rest = words.next().unwrap();
                match what {
                    "wrap" => {
                        let (state, device) = rest.split_once(" to ").unwrap();
                        Artifact::Wrap {
                            kind,
                            state: self.state(state),
                            device: device.to_owned(),
                        }
                    }
                    "link" => {
                        let (under, reaches) = rest.split_once(" > ").unwrap();
                        Artifact::Link {
                            kind,
                            under: self.state(under),
                            reaches: self.state(reaches),
                        }
                    }
                    "gap" => Artifact::Gap {
                        kind,
                        state: self.state(rest),
                    },
                    other => panic!("{other}"),
                }
            })
            .collect()
    }

    // -- roster.md's rules over these histories

    fn concurrent(&self, a: EventId, b: EventId) -> bool {
        a != b && !self.past[&b].contains(&a) && !self.past[&a].contains(&b)
    }

    /// The level an event's kind needs.
    fn need(kind: &str) -> Level {
        match kind {
            "grant" | "remove" | "demote" => Level::Administer,
            _ => Level::Write,
        }
    }

    /// Whether valid roster event `x` voids concurrent event `e`.
    fn attacks(&self, x: EventId, e: EventId) -> bool {
        let (xe, ee) = (&self.changes[&x], &self.changes[&e]);
        if !matches!(xe.kind.as_str(), "remove" | "demote") || !self.concurrent(x, e) {
            return false;
        }
        let author = &self.facts[&e].author;
        let am = self.member_of[author].clone();
        if ee.kind == "demote" && ee.target == am {
            return false;
        }
        if xe.kind == "remove" && xe.target == am {
            return true;
        }
        if xe.kind == "demote" && xe.target == am && xe.level < Self::need(&ee.kind) {
            return true;
        }
        ee.kind == "grant" && xe.kind == "remove" && xe.target == ee.target
    }

    fn roster_events(&self, valid: &BTreeSet<EventId>) -> BTreeSet<EventId> {
        valid
            .iter()
            .copied()
            .filter(|i| matches!(self.facts[i].role, Role::Genesis | Role::Roster))
            .collect()
    }
}

impl History for Model {
    type Device = String;
    type Member = String;

    fn space(&self) -> EventId {
        self.space
    }

    fn genesis(&self) -> EventId {
        self.genesis
    }

    fn events(&self) -> BTreeSet<EventId> {
        self.view.clone()
    }

    fn facts(&self, id: EventId) -> &EventFacts<String, String> {
        &self.facts[&id]
    }

    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        self.past[&later].contains(&earlier)
    }

    fn roster(&self, place: &BTreeSet<EventId>) -> BTreeMap<String, Membership> {
        type Granted = (EventId, Level, bool, bool);
        let mut grants: BTreeMap<String, Vec<Granted>> = BTreeMap::new();
        let mut removals: BTreeMap<String, Vec<EventId>> = BTreeMap::new();
        let mut demotions: BTreeMap<String, Vec<EventId>> = BTreeMap::new();
        for &i in place {
            let c = &self.changes[&i];
            match c.kind.as_str() {
                "genesis" => grants.entry(c.target.clone()).or_default().push((
                    i,
                    Level::Administer,
                    true,
                    false,
                )),
                "grant" => grants.entry(c.target.clone()).or_default().push((
                    i,
                    c.level,
                    c.with_history,
                    c.session,
                )),
                // The root of a checkpoint's world grants its record's
                // members.
                "checkpoint" if Some(i) == self.world => {
                    for (m, level, with_history, session) in &self.records[&i] {
                        grants.entry(m.clone()).or_default().push((
                            i,
                            *level,
                            *with_history,
                            *session,
                        ));
                    }
                }
                "remove" => removals.entry(c.target.clone()).or_default().push(i),
                "demote" => demotions.entry(c.target.clone()).or_default().push(i),
                // ext-invite-links.md: the invite key is out, and its
                // claimant holds the invite's grant from the successor on.
                #[cfg(feature = "ext-invite-links")]
                "succeed" => {
                    let invite = self.member_of[&self.facts[&i].author].clone();
                    removals.entry(invite.clone()).or_default().push(i);
                    let grant = place
                        .iter()
                        .copied()
                        .filter(|&g| {
                            let gc = &self.changes[&g];
                            gc.kind == "grant"
                                && gc.target == invite
                                && (g == i || self.past[&i].contains(&g))
                        })
                        .max_by_key(|&g| (self.past[&g].len(), g));
                    if let Some(g) = grant {
                        let gc = &self.changes[&g];
                        grants.entry(c.target.clone()).or_default().push((
                            i,
                            gc.level,
                            gc.with_history,
                            gc.session,
                        ));
                    }
                }
                _ => {}
            }
        }
        let mut out = BTreeMap::new();
        for (m, gs) in grants {
            let removed = removals.get(&m).cloned().unwrap_or_default();
            let in_force: Vec<Granted> = gs
                .into_iter()
                .filter(|g| !removed.iter().any(|&r| self.past[&r].contains(&g.0)))
                .collect();
            let Some(mut level) = in_force.iter().map(|g| g.1).max() else {
                continue;
            };
            for &d in demotions.get(&m).into_iter().flatten() {
                if in_force.iter().any(|g| self.past[&d].contains(&g.0)) {
                    level = level.min(self.changes[&d].level);
                }
            }
            let mut ids: Vec<EventId> = in_force.iter().map(|g| g.0).collect();
            ids.sort_unstable();
            out.insert(
                m,
                Membership {
                    level,
                    with_history: in_force.iter().any(|g| g.2),
                    session: in_force.iter().all(|g| g.3),
                    grants: ids,
                },
            );
        }
        out
    }

    fn devices(&self, member: &String) -> Vec<String> {
        self.members
            .get(member)
            .into_iter()
            .flatten()
            .filter(|d| !self.revoked.contains(*d))
            .cloned()
            .collect()
    }

    fn space_of(&self, member: &String) -> Option<EventId> {
        self.spaces.get(member).copied()
    }

    fn voiders(&self, valid: &BTreeSet<EventId>, removal: EventId) -> Vec<EventId> {
        let mut out: Vec<EventId> = self
            .roster_events(valid)
            .into_iter()
            .filter(|&x| x != self.genesis && self.attacks(x, removal))
            .collect();
        out.sort_unstable();
        out
    }

    fn stable(&self, valid: &BTreeSet<EventId>, removal: EventId) -> bool {
        let mut need = vec![removal];
        need.extend(self.voiders(valid, removal));
        let roster = self.roster(&self.roster_events(valid));
        let administrators = roster
            .iter()
            .filter(|(_, s)| s.level == Level::Administer)
            .flat_map(|(m, _)| self.devices(m));
        for d in administrators {
            let signed = valid.iter().any(|&e| {
                self.facts[&e].author == d
                    && need.iter().all(|&n| n == e || self.past[&e].contains(&n))
            });
            if !signed {
                return false;
            }
        }
        true
    }

    fn grantee_le(&self, _space: EventId, earlier: EventId, rotation: EventId) -> Option<bool> {
        self.grantee
            .get(&rotation)
            .map(|past| past.contains(&earlier))
    }

    fn grantee_rotation(&self, _space: EventId, event: EventId) -> Option<bool> {
        self.grantee.contains_key(&event).then_some(true)
    }

    fn principal_devices(&self, space: EventId, rotation: EventId) -> Vec<String> {
        let t = self.spaces.iter().find(|(_, i)| **i == space).unwrap().0;
        let r = self.rotation_label(rotation).unwrap_or_default();
        self.members
            .get(&format!("{t}@{r}"))
            .cloned()
            .unwrap_or_default()
    }

    fn grantee_current(&self, space: EventId) -> Option<BTreeSet<String>> {
        let t = self.spaces.iter().find(|(_, i)| **i == space)?.0;
        self.foreign_current.get(t).cloned()
    }

    fn admits(&self, event: EventId, notice: &NoticeFacts) -> bool {
        !self.refused.contains(&event) && self.grantee_current(notice.space).is_some()
    }

    fn world_root(&self) -> Option<EventId> {
        self.world
    }

    fn record_floor(&self, space: EventId) -> bool {
        self.floors.contains(&space)
    }

    #[cfg(feature = "ext-invite-links")]
    fn record_raced(&self) -> Vec<String> {
        self.raced.clone()
    }
}
