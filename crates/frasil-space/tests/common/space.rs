//! Resolving the roster vectors' histories and comparing each view with
//! what the vector says of it.
//!
//! The vectors give every event byte for byte, but not the prefix each
//! history's builder derived its inputs under: the rotations' content keys
//! (`<prefix>/<event name>/content-key`, `genesis` for the genesis) and the
//! Ed25519 seeds of devices that sign nothing (`<prefix>/<name>/ed25519`,
//! the vector file's note). [`prefix`] reads it from `history_prefixes`;
//! each is checked against the genesis's nonce, `<prefix>/nonce`.

use super::{bytes, example, keyring, log_of, text};
use frasil_base::errors::Class;
use frasil_crypto::device::DeviceId;
use frasil_events::{Event, EventId, Log, decode};
use frasil_identity::DeviceList;
use frasil_keys::body::VisiblePart;
use frasil_space::keygraph::GrantedNotices;
use frasil_space::{
    CapabilityMode, HeldList, HistoryMode, KeyEventChecks, Keyring, Limits, MemberRef, MemberType,
    Options, OtherLogs, Space, Standing, Status, Twins, UnitBodies, UnitBody, Valid,
};
use serde_json::{Map, Value as Json, json};
use std::collections::{BTreeMap, BTreeSet};

/// The prefix the reference's builder used for a history, by its name:
/// roster.json's `history_prefixes`, the cases' table.
pub fn prefix(history: &str) -> String {
    prefix_at(&["cases", history])
}

/// A prefix of roster.json's `history_prefixes`, by its path.
pub fn prefix_at(path: &[&str]) -> String {
    let mut value = super::family("history_prefixes");
    for key in path {
        value = value[*key].clone();
    }
    value
        .as_str()
        .unwrap_or_else(|| panic!("no prefix at {path:?}"))
        .to_owned()
}

/// The prefix of the team space a history grants: its `team_prefix`.
pub fn team_prefix(history: &Json) -> String {
    text(history, "team_prefix").to_owned()
}

/// units.md's reading of a unit, as the reference stands in for it: a unit
/// whose body starts `sealed under no key` does not open, and one whose
/// body starts `unit with refs:` carries the refs encoded after it.
pub struct StandIn;

const NO_KEY: &[u8] = b"sealed under no key";
const WITH_REFS: &[u8] = b"unit with refs:";

impl UnitBodies for StandIn {
    fn list_events_at(&self, _log: &Log, _event: EventId) -> Option<Vec<EventId>> {
        None
    }

    fn open(&self, unit: &Event) -> UnitBody {
        let body = unit.unverified_body();
        if body.starts_with(NO_KEY) {
            return UnitBody::Held(frasil_base::ErrorClass::Sealed.into());
        }
        match body.strip_prefix(WITH_REFS) {
            Some(refs) => match frasil_events::refs::decode_refs_bytes(refs) {
                Ok(refs) => UnitBody::Opened(refs),
                Err(class) => UnitBody::Void(class.into()),
            },
            None => UnitBody::Opened(Vec::new()),
        }
    }
}

/// One history's log and the names the vectors give its events, devices,
/// persons and spaces.
pub struct Fixture {
    pub prefix: String,
    pub events: Vec<(String, Event)>,
    pub log: Log,
    pub keys: Keyring,
    pub event_names: BTreeMap<EventId, String>,
    pub member_names: BTreeMap<MemberRef, String>,
    pub limits: Limits,
}

impl Fixture {
    /// A history's events, named, its log and every rotation's content key
    /// under its prefix.
    pub fn new(prefix: &str, history: &Json) -> Self {
        let events = super::events(history);
        let log = log_of(&events);
        let genesis = &events[0].1;
        let visible =
            VisiblePart::read(genesis.unverified_body(), genesis.author(), genesis.seq()).unwrap();
        assert_eq!(
            visible.nonce.map(|n| n.to_vec()),
            Some(example(&format!("{prefix}/nonce"))[..16].to_vec()),
            "{prefix}: the genesis's nonce"
        );
        let keys = keyring(prefix, &events, &[]);
        let mut fixture = Self {
            prefix: prefix.to_owned(),
            events,
            log,
            keys,
            event_names: BTreeMap::new(),
            member_names: BTreeMap::new(),
            limits: Limits::PROTOCOL,
        };
        fixture.name_events(history);
        fixture
    }

    /// Names the events and authors of a history of this or another log.
    pub fn name_events(&mut self, history: &Json) {
        for event in history.as_array().unwrap() {
            let decoded = decode(&bytes(event, "signed")).unwrap();
            self.event_names
                .insert(decoded.id(), text(event, "name").to_owned());
            self.member_names.insert(
                MemberRef::device(*decoded.author()),
                text(event, "author").to_owned(),
            );
        }
    }

    /// Names a member the vectors name, a device that signs nothing by its
    /// seed under this history's prefix.
    pub fn name_device(&mut self, name: &str) {
        if self.member_names.values().any(|n| n == name) {
            return;
        }
        let seed = example(&format!("{}/{name}/ed25519", self.prefix));
        self.member_names
            .insert(MemberRef::device(device_id_of(&seed)), name.to_owned());
    }

    /// The member ID of a device the vectors name: its device ID.
    pub fn device_key(&self, name: &str) -> [u8; 32] {
        self.member_names
            .iter()
            .find(|(m, n)| *n == name && m.kind == MemberType::Device)
            .unwrap_or_else(|| panic!("no device {name:?}"))
            .0
            .id
    }

    /// The ID of the event a history names so.
    pub fn id(&self, name: &str) -> EventId {
        *self
            .event_names
            .iter()
            .find(|(_, n)| *n == name)
            .unwrap_or_else(|| panic!("no event {name:?}"))
            .0
    }

    /// The view a vector's `holds` gives: every event, or these.
    pub fn view(&self, holds: &Json) -> Option<BTreeSet<EventId>> {
        match holds {
            Json::String(every) => {
                assert_eq!(every, "every event");
                None
            }
            Json::Array(names) => {
                Some(names.iter().map(|n| self.id(n.as_str().unwrap())).collect())
            }
            other => panic!("holds: {other}"),
        }
    }

    /// The view of the genesis and the events a summary names.
    pub fn view_of_summary(&self, summary: &Json) -> BTreeSet<EventId> {
        let mut view: BTreeSet<EventId> = summary["events"]
            .as_object()
            .unwrap()
            .keys()
            .map(|n| self.id(n))
            .collect();
        view.insert(self.log.id());
        view
    }

    pub fn name_of(&self, id: EventId) -> String {
        self.event_names
            .get(&id)
            .cloned()
            .unwrap_or_else(|| format!("{id:?}"))
    }

    pub fn member_name(&self, member: &MemberRef) -> String {
        self.member_names
            .get(member)
            .cloned()
            .unwrap_or_else(|| format!("{member:?}"))
    }

    /// Resolves a view.
    pub fn resolve<'a>(
        &'a self,
        view: Option<&BTreeSet<EventId>>,
        keys: &'a Keyring,
        others: &'a OtherLogs<'a>,
    ) -> Result<Space<'a>, frasil_space::RosterClass> {
        // keys.md's step 8, and the notice checks over the granted spaces
        // the view holds. The resolved space borrows them for as long as
        // `others`; each resolution leaks one small struct, a test's cost.
        let notices: &'a GrantedNotices<'a> = Box::leak(Box::new(GrantedNotices::new(others)));
        let options = Options {
            keys,
            limits: self.limits,
            others,
            units: if self.prefix.starts_with("roster/list-place/") {
                let mut copies = BTreeMap::new();
                for (copy_name, list_name) in [
                    ("a1 copies A's first event", "a1 starts the list"),
                    ("b1 copies B's first event", "b1 starts the list"),
                    ("a1 copies the add of d", "a1 adds d to A"),
                    ("b1 copies the add of d", "b1 adds d to B"),
                    ("a1 copies the revocation of d", "a1 revokes d from A"),
                    (
                        "b1 copies the add of e, after e's unit",
                        "b1 adds e to B, copied nowhere yet",
                    ),
                ] {
                    if let Some((&copy, _)) = self
                        .event_names
                        .iter()
                        .find(|(_, name)| name.as_str() == copy_name)
                    {
                        let carried = self
                            .event_names
                            .iter()
                            .find(|(_, name)| name.as_str() == list_name)
                            .map(|(id, _)| *id)
                            .or_else(|| {
                                let author = if copy_name.starts_with("a1") {
                                    "a1"
                                } else {
                                    "b1"
                                };
                                others
                                    .lists
                                    .values()
                                    .filter_map(|list| list.list())
                                    .find(|list| {
                                        self.member_names
                                            .get(&MemberRef::device(*list.log().genesis().author()))
                                            .is_some_and(|name| name == author)
                                    })
                                    .map(|list| list.log().id())
                            })
                            .expect("the copied list event");
                        copies.insert(copy, carried);
                    }
                }
                Box::leak(Box::new(ModelCopies(copies)))
            } else {
                &StandIn
            },
            twins: Twins::Assumed,
            key_checks: KeyEventChecks::Context,
            notices: Some(notices),
        };
        let space = Space::resolve(&self.log, view, options)?;
        // Each event's place, as found once over the view, is the one the
        // walk through its past finds.
        for &id in space.view() {
            assert_eq!(
                space.place_of(id),
                space.place_of_by_walking(id),
                "the place of {id:?}"
            );
        }
        Ok(space)
    }

    /// The status of an event, as the vectors write it.
    pub fn show(&self, status: &Status) -> String {
        match status {
            Status::Valid(Valid::Genesis | Valid::Rules | Valid::Checkpoint) => "valid".into(),
            Status::Valid(Valid::Agreed) => "valid (agreed)".into(),
            Status::Valid(Valid::Seniority) => "valid (seniority)".into(),
            Status::Valid(Valid::Kept) => "valid (kept)".into(),
            Status::Void { class, by } => match by {
                Some(by) => format!("{} by {}", class.name(), self.name_of(*by)),
                None => class.name().to_owned(),
            },
        }
    }

    /// A view's summary, as the reference's builder writes it; `extra`
    /// adds forks, frontiers, duels and re-submissions.
    pub fn summary(&self, space: &Space<'_>, extra: bool) -> Json {
        let genesis = self.log.id();
        let order = self.log.canonical_in(space.view());
        let mut events = Map::new();
        for &id in &order {
            if id != genesis {
                events.insert(
                    self.name_of(id),
                    json!(self.show(space.status(id).unwrap())),
                );
            }
        }
        let mut roster = Map::new();
        for (member, standing) in space.roster().iter() {
            let entry = match standing {
                Standing::Out { .. } => json!("removed"),
                Standing::In(state) => {
                    let mut entry = Map::new();
                    let kind = match member.kind {
                        MemberType::Device => "device",
                        MemberType::Person => "person",
                        MemberType::Space => "space",
                        _ => "invite",
                    };
                    entry.insert("type".into(), json!(kind));
                    entry.insert("level".into(), json!(state.level.name()));
                    let history = match state.history {
                        HistoryMode::WithHistory => "with history",
                        HistoryMode::FromNowOn => "from now on",
                    };
                    entry.insert("history".into(), json!(history));
                    entry.insert(
                        "seniority".into(),
                        json!(frasil_testkit::hex::encode(state.seniority.hash)),
                    );
                    if let Some(rank) = state.rank {
                        entry.insert("rank".into(), json!(rank));
                    }
                    if !state.capabilities.is_empty() {
                        let mut caps: Vec<(String, &str)> = state
                            .capabilities
                            .iter()
                            .map(|c| {
                                let mode = match c.mode {
                                    CapabilityMode::Extends => "extends",
                                    CapabilityMode::Narrows => "narrows",
                                };
                                (c.name.clone(), mode)
                            })
                            .collect();
                        caps.sort();
                        entry.insert("capabilities".into(), json!(caps));
                    }
                    if let Some(label) = &state.label {
                        entry.insert("label".into(), json!(label));
                    }
                    if let Some(session) = state.session {
                        entry.insert(
                            "session".into(),
                            json!(frasil_testkit::hex::encode(session)),
                        );
                    }
                    if let Some(replaces) = state.replaces {
                        entry.insert(
                            "replaces".into(),
                            json!(self.member_name(&MemberRef::person(replaces))),
                        );
                    }
                    Json::Object(entry)
                }
            };
            roster.insert(self.member_name(member), entry);
        }
        let mut out = Map::new();
        out.insert("events".into(), Json::Object(events));
        out.insert("roster".into(), Json::Object(roster));
        let rotations: Vec<String> = space
            .rotations()
            .into_iter()
            .map(|id| self.name_of(id))
            .collect();
        out.insert("rotations_maximal".into(), json!(rotations));
        let mut voided = Map::new();
        for &id in &order {
            let voiders = space.voiders(id);
            if !voiders.is_empty() {
                let names: Vec<String> = voiders.into_iter().map(|v| self.name_of(v)).collect();
                voided.insert(self.name_of(id), json!(names));
            }
        }
        if !voided.is_empty() {
            out.insert("voided_by".into(), Json::Object(voided));
        }
        if !extra {
            return Json::Object(out);
        }
        if !space.forks().is_empty() {
            let forked: Map<String, Json> = space
                .forks()
                .iter()
                .map(|(author, seq)| (self.member_name(&MemberRef::device(*author)), json!(seq)))
                .collect();
            out.insert("forked".into(), Json::Object(forked));
        }
        let frontiers = space.frontiers();
        if !frontiers.is_empty() {
            let mut all = Map::new();
            for (x, heads) in frontiers {
                let heads: Map<String, Json> = heads
                    .into_iter()
                    .map(|(d, i)| {
                        (
                            self.member_name(&MemberRef::device(DeviceId(d))),
                            json!(self.name_of(i)),
                        )
                    })
                    .collect();
                all.insert(self.name_of(x), json!({ "heads": heads }));
            }
            out.insert("frontiers".into(), Json::Object(all));
        }
        let duels = space.duels();
        if !duels.is_empty() {
            let list: Vec<Json> = duels
                .into_iter()
                .map(|(a, b)| {
                    let mut voided = Map::new();
                    for side in [a, b] {
                        let names: Vec<String> = space
                            .voided_by(side)
                            .unwrap()
                            .into_iter()
                            .map(|i| self.name_of(i))
                            .collect();
                        voided.insert(self.name_of(side), json!(names));
                    }
                    json!({ "pair": [self.name_of(a), self.name_of(b)], "voided_by": voided })
                })
                .collect();
            out.insert("duels".into(), json!(list));
        }
        let resubmit = space.resubmissions();
        if !resubmit.is_empty() {
            let map: Map<String, Json> = resubmit
                .into_iter()
                .map(|(d, ids)| {
                    let names: Vec<String> = ids.into_iter().map(|i| self.name_of(i)).collect();
                    (
                        self.member_name(&MemberRef::device(DeviceId(d))),
                        json!(names),
                    )
                })
                .collect();
            out.insert("resubmit".into(), Json::Object(map));
        }
        Json::Object(out)
    }
}

/// A person's list, as held: its events, or those a view's `lists_held`
/// names (`"every event"` or a list of names).
pub fn held_list(events: &Json, held: &Json) -> HeldList {
    let events = events.as_array().unwrap();
    let holds = |name: &str| match held {
        Json::String(every) => {
            assert_eq!(every, "every event");
            true
        }
        Json::Array(names) => names.iter().any(|n| n.as_str() == Some(name)),
        other => panic!("lists_held: {other}"),
    };
    assert!(
        holds(text(&events[0], "name")),
        "a held list holds its first event"
    );
    let mut list = DeviceList::new(&bytes(&events[0], "signed")).unwrap();
    for event in &events[1..] {
        if holds(text(event, "name")) {
            list.insert(&bytes(event, "signed")).unwrap();
        }
    }
    HeldList::new(list)
}

/// Every event of a person's list.
pub fn whole_list(events: &Json) -> HeldList {
    held_list(events, &json!("every event"))
}

/// The keys of a summary the comparison reads: `extra` adds those only the
/// builder's full summary has.
fn compared(expected: &Json, extra: bool) -> Json {
    let mut out = Map::new();
    let keys: &[&str] = if extra {
        &[
            "events",
            "roster",
            "rotations_maximal",
            "voided_by",
            "forked",
            "frontiers",
            "duels",
            "resubmit",
        ]
    } else {
        &["events", "roster", "rotations_maximal", "voided_by"]
    };
    for key in keys {
        if let Some(value) = expected.get(*key) {
            out.insert((*key).into(), value.clone());
        }
    }
    Json::Object(out)
}

/// Compares a view with what the vector says of it, returning the
/// differences.
pub fn differences(
    fixture: &Fixture,
    space: &Space<'_>,
    expected: &Json,
    extra: bool,
    label: &str,
) -> Vec<String> {
    let want = compared(expected, extra);
    let got = compared(&fixture.summary(space, extra), extra);
    let mut out = Vec::new();
    let keys: BTreeSet<&String> = want
        .as_object()
        .unwrap()
        .keys()
        .chain(got.as_object().unwrap().keys())
        .collect();
    for key in keys {
        let (w, g) = (&want[key.as_str()], &got[key.as_str()]);
        if w != g {
            out.push(format!(
                "{label}: {key}\n  want {}\n  got  {}",
                serde_json::to_string(w).unwrap(),
                serde_json::to_string(g).unwrap()
            ));
        }
    }
    out
}

/// The names of the roster entries a summary gives, for the devices that
/// sign nothing.
pub fn roster_names(summary: &Json) -> Vec<String> {
    summary["roster"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// Every name a frontier, a duel or a re-submission gives a device.
pub fn device_names(summary: &Json) -> Vec<String> {
    let mut out = roster_names(summary);
    if let Some(frontiers) = summary["frontiers"].as_object() {
        for f in frontiers.values() {
            out.extend(f["heads"].as_object().unwrap().keys().cloned());
        }
    }
    if let Some(forked) = summary["forked"].as_object() {
        out.extend(forked.keys().cloned());
    }
    if let Some(resubmit) = summary["resubmit"].as_object() {
        out.extend(resubmit.keys().cloned());
    }
    out
}

/// Names the persons and spaces of other logs by the vectors' names.
pub fn name_other(fixture: &mut Fixture, name: &str, id: [u8; 32], kind: MemberType) {
    let member = match kind {
        MemberType::Person => MemberRef::person(id),
        _ => MemberRef {
            kind: MemberType::Space,
            id,
        },
    };
    fixture.member_names.insert(member, name.to_owned());
}

/// The space ID of a team's history.
pub fn space_id(history: &Json) -> [u8; 32] {
    decode(&bytes(&history[0], "signed")).unwrap().id().0
}

/// The person ID of a list's events.
pub fn person_id(events: &Json) -> [u8; 32] {
    space_id(events)
}

/// A device of the vectors, named under a prefix: its identity seed is the
/// example `<prefix>/<name>/ed25519`, its ML-DSA-65 seed the fixture
/// derivation (crypto.md, "A device's keys"), and its X-Wing key that of
/// the example `<prefix>/<name>/xwing`, as identity.py's builder makes it.
pub fn list_device(prefix: &str, name: &str) -> frasil_identity::MemberKeys {
    let identity_seed = example(&format!("{prefix}/{name}/ed25519"));
    frasil_identity::MemberKeys::from_seeds(
        &identity_seed,
        &frasil_crypto::fixtures::fixture_xwing_seed(&identity_seed),
        &frasil_crypto::fixtures::fixture_mldsa_seed(&identity_seed),
    )
}

/// A recovery agent of a list the vectors give: as [`list_device`], with
/// no X-Wing key.
pub fn list_agent(prefix: &str, name: &str) -> frasil_identity::MemberKeys {
    let identity_seed = example(&format!("{prefix}/{name}/ed25519"));
    frasil_identity::MemberKeys::without_xwing(
        &identity_seed,
        &frasil_crypto::fixtures::fixture_mldsa_seed(&identity_seed),
    )
}

/// The first event of a list that a device starts, rebuilt by
/// identity.py's conventions under the list's prefix.
pub fn first_list_event(prefix: &str, name: &str) -> Vec<u8> {
    DeviceList::first_event(&list_device(prefix, name))
}

/// The member a roster event's first change names.
pub fn first_member(fixture: &Fixture, event: &str) -> MemberRef {
    let screened = super::screen(&fixture.log, &fixture.keys).unwrap();
    screened.opened(fixture.id(event)).unwrap().changes()[0]
        .member
        .unwrap()
}

/// The device ID of a vectors' device by its identity seed: its ML-DSA-65
/// and X-Wing seeds are crypto.md's fixture derivations.
pub fn device_id_of(seed: &[u8; 32]) -> DeviceId {
    frasil_crypto::fixtures::FixtureKeys::from_identity_seed(seed).device_id()
}

struct ModelCopies(BTreeMap<EventId, EventId>);
impl UnitBodies for ModelCopies {
    fn open(&self, event: &Event) -> UnitBody {
        StandIn.open(event)
    }
    fn list_events_at(&self, log: &Log, event: EventId) -> Option<Vec<EventId>> {
        Some(
            self.0
                .iter()
                .filter(|(copy, _)| **copy == event || log.precedes(**copy, event))
                .map(|(_, carried)| *carried)
                .collect(),
        )
    }
}
