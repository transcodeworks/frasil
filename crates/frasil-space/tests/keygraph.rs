//! keys.json's key-graph families (keys.md, sections 3.4 to 3.13):
//! `notices`, `taking_keys`, `ranks`, `rotation_delay`, `cascades`,
//! `gap_keys` and `histories`.
//!
//! The histories give each checkpoint's view as data: its events with their
//! causal parents, the valid set roster.md decided, and the wraps, links and
//! gaps it holds. [`model::Model`] reads them as a key-graph history: the
//! roster of a set of valid events, stability and what voids a removal
//! follow roster.md's rules over the history's grants, removals and
//! demotions, which is all these histories hold. The key graph computes the
//! rest.

mod common;
mod model;

use common::{class, example};
use frasil_base::time::Reading;
use frasil_events::EventId;
use frasil_keys::body::{Delivery, RotationKeys, Seal, VisiblePart};
use frasil_keys::bundle::Bundle;
use frasil_keys::{KeyName, RotationSet};
use frasil_space::graph::{GrantInForce, GrantTarget, SpaceGrants};
use frasil_space::keygraph::{
    Artifact, Cascade, ChangeKind, EventFacts, GapKeyDecision, History, Holdings, KeyGraph,
    KeySource, Kind, Member, Membership, NoticeFacts, cascade, cascade_candidates, check_notice,
    delay, gap_keys, heal_candidates, own_delivery, plan, rank_order, rank_value, seal_mismatch,
    take_slots, tries,
};
use frasil_space::{DescriptorKind, GranteeRotation, Level};
use frasil_testkit::hex;
use model::Model;
use serde_json::{Value as Json, json};
use std::collections::{BTreeMap, BTreeSet};

const FILE: &str = "keys.json";

fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

fn bytes(value: &Json, key: &str) -> Vec<u8> {
    hex::decode(text(value, key)).unwrap()
}

fn array<const N: usize>(value: &Json, key: &str) -> [u8; N] {
    bytes(value, key).try_into().unwrap()
}

fn reading(value: &Json) -> Reading {
    Reading {
        timeline: value["timeline"].as_u64().unwrap(),
        wall: value["wall"].as_u64(),
        run: value["run"].as_u64().unwrap(),
    }
}

// -- notices

#[test]
fn notices() {
    for case in family("notices").as_array().unwrap() {
        let name = text(case, "name");
        let notice = &case["notice"];
        let public: [u8; frasil_crypto::sizes::XWING_PUBLIC] = array(notice, "public");
        let from_now_on = notice["from_now_on"].as_bool().unwrap();
        let grantee = case["grantee_commitment"]
            .as_str()
            .map(|c| GranteeRotation {
                valid: case["grantee_valid"].as_bool().unwrap(),
                grant_commitment: Some(hex::decode_array(c).unwrap()),
            });
        let stale = case["stale"].as_bool().unwrap_or(false);
        let propagates = case["author_propagates_there"].as_bool();
        let got = check_notice(&public, from_now_on, grantee.as_ref(), stale, propagates);
        assert_eq!(
            class(got).unwrap_or("accepted"),
            text(case, "result"),
            "notices / {name}"
        );
    }
}

// -- taking_keys

#[test]
fn taking_keys() {
    let vectors = family("taking_keys");
    // The removal whose own wrap the checks open: its visible keys, from
    // space_event_bodies.
    let bodies: Json = frasil_testkit::vectors::family(FILE, "space_event_bodies");
    let commits = &bodies["commitments_of_new_rotation"];
    let rotation = RotationKeys {
        grant_commitment: array(commits, "grant"),
        read: array(commits, "read"),
        upload: array(commits, "upload"),
    };
    for case in vectors["commitment_checks"].as_array().unwrap() {
        let bundle = Bundle::read(&bytes(case, "bundle")).unwrap();
        let taken = take_slots(&bundle, &rotation, false);
        let mut kept: Vec<&str> = taken.kept().iter().map(|s| s.name()).collect();
        kept.sort_unstable();
        let dropped: Vec<&str> = taken.dropped.iter().map(|s| s.name()).collect();
        let want = |key: &str| -> Vec<&str> {
            case[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect()
        };
        assert_eq!(kept, want("kept"), "{}", text(case, "name"));
        assert_eq!(dropped, want("dropped"), "{}", text(case, "name"));
    }
    for case in vectors["provisional_keys"].as_array().unwrap() {
        let source = match text(case, "key_source") {
            "derived" => KeySource::Derived,
            "wrapped" => KeySource::Wrapped,
            other => panic!("{other}"),
        };
        assert_eq!(
            frasil_base::errors::Class::name(seal_mismatch(source)),
            text(case, "on_mismatch")
        );
    }
    let trial = &vectors["trial_decryption"];
    let in_log: BTreeSet<EventId> = trial["rotations_in_log"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| EventId(hex::decode_array(r.as_str().unwrap()).unwrap()))
        .collect();
    let held: BTreeSet<Vec<u8>> = trial["held"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| hex::decode(h.as_str().unwrap()).unwrap())
        .collect();
    for case in trial["cases"].as_array().unwrap() {
        let name = KeyName::decode(&bytes(case, "key_name"), false).unwrap();
        let entitled = case["entitled"].as_bool().unwrap();
        let tried = tries(
            &[&name],
            |r| in_log.contains(r),
            |n| held.contains(&n.encode()),
            |_| entitled,
        );
        assert_eq!(
            tried,
            case["tried"].as_bool().unwrap(),
            "{}",
            text(case, "name")
        );
    }
    let caps = &vectors["caps"];
    assert_eq!(
        caps["max_wraps_per_event"].as_u64(),
        Some(frasil_keys::limits::MAX_WRAPS_PER_EVENT as u64)
    );
    assert_eq!(
        caps["max_deliveries_per_event"].as_u64(),
        Some(frasil_keys::limits::MAX_DELIVERIES_PER_EVENT as u64)
    );
    // "0x01, 0x647a, then 1233 zero bytes".
    let mut dummy = vec![0x01, 0x64, 0x7a];
    dummy.resize(frasil_keys::limits::WRAP_BYTES, 0);
    let author = frasil_crypto::device::DeviceId([7u8; 32]);
    let state = RotationSet::single(EventId([1; 32]));
    for case in caps["cases"].as_array().unwrap() {
        let wraps = case["wraps"].as_u64().unwrap_or(1) as usize;
        let space_wraps = case["space_wraps"].as_u64().unwrap_or(0) as usize;
        let deliveries = case["deliveries"].as_u64().unwrap_or(1) as usize;
        let delivery = Delivery {
            key_name: Some(KeyName::Set(state.clone())),
            grant_name: None,
            wraps: vec![dummy.clone(); wraps],
            space_wraps: vec![dummy.clone(); space_wraps],
        };
        let body = VisiblePart {
            seal: Seal::Under(state.clone()),
            deliveries: vec![delivery; deliveries],
            sealed: vec![0; 64],
            nonce: None,
            commitment: [0; 32],
            twin: None,
        };
        let got = VisiblePart::read(&body.encode(), &author, 5);
        assert_eq!(
            class(got).unwrap_or("accepted"),
            text(case, "result"),
            "{}",
            text(case, "name")
        );
    }
}

// -- ranks, rotation_delay and gap_keys

#[test]
fn ranks() {
    let vectors = family("ranks");
    let space: [u8; 32] = array(&vectors, "space");
    let trigger = bytes(&vectors, "trigger");
    let rows = vectors["ranks"].as_array().unwrap();
    let identities: Vec<[u8; 32]> = rows.iter().map(|r| array(r, "device_id")).collect();
    let order = rank_order(&space, &trigger, &identities);
    for row in rows {
        let identity: [u8; 32] = array(row, "device_id");
        let rank = rank_value(&space, &trigger, &identity);
        assert_eq!(hex::encode(rank.digest), text(row, "digest"));
        assert_eq!(rank.value, row["value"].as_u64().unwrap());
        let position = order.iter().position(|d| *d == identity).unwrap() as u64;
        assert_eq!(position, row["position"].as_u64().unwrap());
        assert_eq!(
            delay(position, 2),
            row["delay_seconds_at_step_2"].as_u64().unwrap()
        );
    }
    for row in vectors["delays"].as_array().unwrap() {
        let got = delay(
            row["position"].as_u64().unwrap(),
            row["step"].as_u64().unwrap(),
        );
        assert_eq!(got, row["delay_seconds"].as_u64().unwrap());
    }
    // The candidates for P's cascade after bob leaves the team, from the
    // cascades family's spaces after that change.
    let candidates = &vectors["cascade_candidates"];
    let after = &family("cascades")[0];
    assert_eq!(text(after, "name"), "bob leaves the team");
    let world = Spaces::new(after, "after", "persons");
    let p: [u8; 32] = array(candidates, "space");
    assert_eq!(world.id("P").0, p);
    let devices =
        cascade_candidates(&world.spaces, &world.persons, world.id("P"), world.id("T")).unwrap();
    let names: Vec<String> = devices.iter().map(|d| world.device_name(d)).collect();
    // Each device's ID: its identity seed, with crypto.md's fixture
    // ML-DSA-65 and X-Wing seeds.
    let identity = |name: &str| {
        let seed = example(&format!("spaces/device/{name}/ed25519"));
        frasil_crypto::fixtures::FixtureKeys::from_identity_seed(&seed)
            .device_id()
            .0
    };
    let trigger = bytes(candidates, "trigger");
    let keys: Vec<[u8; 32]> = names.iter().map(|n| identity(n)).collect();
    let order = rank_order(&p, &trigger, &keys);
    let rows = candidates["ranks"].as_array().unwrap();
    assert_eq!(order.len(), rows.len(), "{names:?}");
    let step = candidates["rotation_step"].as_u64().unwrap();
    for row in rows {
        let name = text(row, "device");
        let key = identity(name);
        assert_eq!(hex::encode(key), text(row, "device_id"));
        let position = order.iter().position(|d| *d == key).unwrap() as u64;
        assert_eq!(position, row["position"].as_u64().unwrap(), "{name}");
        assert_eq!(
            rank_value(&p, &trigger, &key).value,
            row["value"].as_u64().unwrap()
        );
        assert_eq!(
            delay(position, step),
            row["delay_seconds"].as_u64().unwrap()
        );
    }
    for name in candidates["not_candidates"].as_object().unwrap().keys() {
        assert!(!names.contains(name), "{name} is no candidate");
    }
}

#[test]
fn rotation_delay() {
    for case in family("rotation_delay").as_array().unwrap() {
        let got = delay(
            case["rank"].as_u64().unwrap(),
            case["step"].as_u64().unwrap(),
        );
        assert_eq!(got, case["delay"].as_u64().unwrap(), "{case}");
    }
}

#[test]
fn gap_keys_decisions() {
    for case in family("gap_keys").as_array().unwrap() {
        let got = gap_keys(
            case["stable"].as_bool().unwrap(),
            &reading(&case["first_sight"]),
            &reading(&case["now"]),
            case["timeout"].as_u64().unwrap(),
        );
        let want = match text(case, "outcome") {
            "Wrap" => GapKeyDecision::Wrap,
            "Wait" => GapKeyDecision::Wait,
            other => panic!("{other}"),
        };
        assert_eq!(got, want, "{case}");
    }
}

// -- cascades

/// A cascade case's spaces by name, with the persons' devices.
struct Spaces {
    names: BTreeMap<String, EventId>,
    devices: BTreeMap<[u8; 32], String>,
    spaces: BTreeMap<EventId, SpaceGrants>,
    persons: BTreeMap<[u8; 32], Vec<[u8; 32]>>,
}

fn device_id(name: &str) -> [u8; 32] {
    common::named(&format!("device/{name}"))
}

fn person_id(name: &str) -> [u8; 32] {
    common::named(&format!("person/{name}"))
}

fn level(name: &str) -> Level {
    match name {
        "read" => Level::Read,
        "write" => Level::Write,
        "administer" => Level::Administer,
        other => panic!("{other}"),
    }
}

impl Spaces {
    fn new(case: &Json, spaces_key: &str, persons_key: &str) -> Self {
        let list = case[spaces_key].as_array().unwrap();
        let names: BTreeMap<String, EventId> = list
            .iter()
            .map(|s| (text(s, "name").to_owned(), EventId(array(s, "id"))))
            .collect();
        let mut devices = BTreeMap::new();
        let mut persons = BTreeMap::new();
        for (person, ds) in case[persons_key].as_object().unwrap() {
            let mut ids = Vec::new();
            for d in ds.as_array().unwrap() {
                let name = d.as_str().unwrap();
                devices.insert(device_id(name), name.to_owned());
                ids.push(device_id(name));
            }
            persons.insert(person_id(person), ids);
        }
        let mut spaces = BTreeMap::new();
        for s in list {
            assert_eq!(text(s, "kind"), "space");
            let mut grants = Vec::new();
            for g in s["grants"].as_array().unwrap() {
                let target = text(g, "target");
                let target = match text(g, "kind") {
                    "device" => {
                        devices.insert(device_id(target), target.to_owned());
                        GrantTarget::Device(device_id(target))
                    }
                    "person" => GrantTarget::Person(person_id(target)),
                    "space" => GrantTarget::Space(names[target]),
                    other => panic!("{other}"),
                };
                grants.push(GrantInForce {
                    event: EventId(array(g, "event")),
                    target,
                    level: level(text(g, "level")),
                    session: g["session"].as_bool().unwrap(),
                    capabilities: Vec::new(),
                });
            }
            spaces.insert(
                names[text(s, "name")],
                SpaceGrants {
                    kind: DescriptorKind::Space,
                    parent: None,
                    grants,
                },
            );
        }
        Self {
            names,
            devices,
            spaces,
            persons,
        }
    }

    fn id(&self, name: &str) -> EventId {
        self.names[name]
    }

    fn name(&self, id: &EventId) -> &str {
        self.names.iter().find(|(_, i)| *i == id).unwrap().0
    }

    fn device_name(&self, device: &[u8; 32]) -> String {
        self.devices[device].clone()
    }
}

#[test]
fn cascades() {
    for case in family("cascades").as_array().unwrap() {
        let name = text(case, "name");
        let (persons_before, persons_after) = if case.get("persons").is_some() {
            ("persons", "persons")
        } else {
            ("persons_before", "persons_after")
        };
        let before = Spaces::new(case, "before", persons_before);
        let after = Spaces::new(case, "after", persons_after);
        let changed = before.names.get(text(case, "changed")).copied();
        let change = match text(case, "change") {
            "removal" => ChangeKind::Removal,
            "break" => ChangeKind::Break,
            "grant-heal" => ChangeKind::GrantHeal,
            other => panic!("{other}"),
        };
        let got = cascade(
            &before.spaces,
            &after.spaces,
            &before.persons,
            &after.persons,
            changed,
            change,
        )
        .unwrap();
        let mut devices = before.devices.clone();
        devices.extend(after.devices.clone());
        let got: BTreeMap<String, String> = got
            .iter()
            .map(|(space, verdict)| {
                let verdict = match verdict {
                    Cascade::Rotates(lost) if lost.is_empty() => "rotates".to_owned(),
                    Cascade::Rotates(lost) => {
                        let mut lost: Vec<&str> =
                            lost.iter().map(|d| devices[d].as_str()).collect();
                        lost.sort_unstable();
                        format!("rotates: loses {}", lost.join(", "))
                    }
                    Cascade::KeepsItsKey => "keeps its key".to_owned(),
                    Cascade::Breaks => "breaks".to_owned(),
                    Cascade::NotReached => "not reached".to_owned(),
                };
                (after.name(space).to_owned(), verdict)
            })
            .collect();
        let want: BTreeMap<String, String> = case["result"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
            .collect();
        assert_eq!(got, want, "cascades / {name}");
    }
}

// -- histories

/// Every difference between a checkpoint as the key graph computes it and
/// as the vector gives it.
fn check_checkpoint(model: &Model, checkpoint: &Json, label: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut check = |what: &str, got: Json, want: &Json| {
        if got != *want {
            out.push(format!("{label}: {what}\n  got  {got}\n  want {want}"));
        }
    };
    let graph = model.key_graph();
    // A view after gap_key_timeout has passed.
    let timed_out = checkpoint["timed_out"].as_bool().unwrap_or(false);
    // Each principal's floor: this space's responses to the granted
    // space's breaks before which it is entitled to nothing.
    for (principal, want) in checkpoint
        .get("principal_floor")
        .and_then(Json::as_object)
        .into_iter()
        .flatten()
    {
        let member = graph
            .members(Kind::Content)
            .into_keys()
            .find(|m| model.member_name(m) == *principal);
        let got: Vec<&str> = match &member {
            Some(Member::Principal(p)) => graph.floors(p).iter().map(|&f| model.label(f)).collect(),
            _ => Vec::new(),
        };
        check(&format!("floor of {principal}"), json!(got), want);
    }
    // The merged roster.
    let roster: serde_json::Map<String, Json> = graph
        .members(Kind::Content)
        .iter()
        .map(|(m, s)| {
            (
                model.member_name(m),
                json!({"level": model::level_name(s.level), "session": s.session}),
            )
        })
        .collect();
    check("roster", Json::Object(roster), &checkpoint["roster"]);
    // The current states and their secrets.
    let content = graph.current(Kind::Content).unwrap();
    let grant = graph.current(Kind::Grant).unwrap();
    let content_key = graph
        .current_secret(Kind::Content, |r| model.secret(r, "content"))
        .unwrap();
    let grant_seed = graph
        .current_secret(Kind::Grant, |r| model.secret(r, "grant"))
        .unwrap();
    let current = json!({
        "content": model.state_name(&content),
        "content_key": hex::encode(*content_key),
        "grant": model.state_name(&grant),
        "grant_seed": hex::encode(*grant_seed),
    });
    check("current", current, &checkpoint["current"]);
    // The deliveries each graph calls for, with the first device present
    // that can make each.
    let room: Vec<String> = checkpoint["room"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap().to_owned())
        .collect();
    let artifacts = model.artifacts(&checkpoint["artifacts"]);
    for (kind, key) in [(Kind::Content, "content"), (Kind::Grant, "grant")] {
        let p = plan(&graph, &artifacts, kind, &room, timed_out);
        let by = |d: &Option<String>| d.clone().unwrap_or_else(|| "nobody in the room".into());
        let wraps: Vec<String> = p
            .wraps
            .iter()
            .map(|w| {
                format!(
                    "{} to {} by {} ({})",
                    model.state_name(&w.state),
                    w.device,
                    by(&w.by),
                    w.why.name()
                )
            })
            .collect();
        let links: Vec<String> = p
            .links
            .iter()
            .map(|l| {
                format!(
                    "{} > {} by {}",
                    model.state_name(&l.under),
                    model.state_name(&l.reaches),
                    by(&l.by)
                )
            })
            .collect();
        let gaps: Vec<String> = p.gaps.iter().map(|g| model.state_name(g)).collect();
        let waiting: Vec<String> = p
            .waiting
            .iter()
            .map(|(k, d)| format!("{} to {d}", model.state_name(k)))
            .collect();
        let got = json!({
            "wraps": wraps, "links": links, "gaps": gaps, "waiting": waiting,
            "heal": p.heal.map(|h| h.name()),
        });
        check(&format!("plan {key}"), got, &checkpoint["plan"][key]);
    }
    // Entitlement, over every rotation of the view and the current state;
    // for the grant graph, over grant rotations and the grant state.
    let mut states: BTreeSet<RotationSet> = graph
        .events()
        .iter()
        .copied()
        .filter(|&i| graph.is_rotation(i, Kind::Content))
        .map(RotationSet::single)
        .collect();
    states.insert(content.clone());
    let mut entitlement = serde_json::Map::new();
    for member in graph.members(Kind::Content).keys() {
        let mut row: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for (kind, key) in [(Kind::Content, "content"), (Kind::Grant, "grant")] {
            for state in &states {
                let grant_state = *state == grant
                    || (state.len() == 1 && graph.is_rotation(state.ids()[0], Kind::Grant));
                if kind == Kind::Grant && !grant_state {
                    continue;
                }
                if !graph.entitled(member, state, kind) {
                    continue;
                }
                if graph.restored_pending(member, state, kind, timed_out) {
                    row.entry("pending_stability")
                        .or_default()
                        .push(format!("{key} {}", model.state_name(state)));
                } else {
                    row.entry(key).or_default().push(model.state_name(state));
                }
            }
        }
        if !row.is_empty() {
            let mut value = serde_json::Map::new();
            for key in ["content", "grant", "pending_stability"] {
                value.insert(key.into(), json!(row.remove(key).unwrap_or_default()));
            }
            entitlement.insert(model.member_name(member), Json::Object(value));
        }
    }
    check(
        "entitlement",
        Json::Object(entitlement),
        &checkpoint["entitlement"],
    );
    // The stated reach queries.
    for query in checkpoint["reaches"].as_array().unwrap() {
        let kind = match text(query, "kind") {
            "content" => Kind::Content,
            _ => Kind::Grant,
        };
        let devices: Vec<String> = query["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap().to_owned())
            .collect();
        let state = model.state(text(query, "state"));
        let holdings = Holdings::new(&graph, &artifacts, kind);
        check(
            &format!("reaches {query}"),
            Json::Bool(holdings.reaches(&devices, &state)),
            &query["result"],
        );
    }
    out
}

#[test]
fn histories() {
    let mut failures = Vec::new();
    for history in family("histories").as_array().unwrap() {
        let name = text(history, "name");
        for checkpoint in history["checkpoints"].as_array().unwrap() {
            let model = Model::new(history, checkpoint);
            assert_eq!(
                model.key_graph().events().len(),
                checkpoint["events"].as_array().unwrap().len()
            );
            let label = format!("{name} / {}", text(checkpoint, "name"));
            failures.extend(check_checkpoint(&model, checkpoint, &label));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A checkpoint of a history, by their names.
fn checkpoint<'h>(histories: &'h Json, history: &str, name: &str) -> (&'h Json, &'h Json) {
    let history = histories
        .as_array()
        .unwrap()
        .iter()
        .find(|h| text(h, "name") == history)
        .unwrap();
    let checkpoint = history["checkpoints"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| text(c, "name") == name)
        .unwrap();
    (history, checkpoint)
}

/// keys.md, "Deliveries": a rotation's own delivery wraps for every device
/// of the merged roster and its author, as the heal of a cross-removal
/// did; "Healing": a guest may heal the content key but never the grant
/// key.
#[test]
fn own_deliveries_and_healers() {
    let histories = family("histories");
    let (history, cp) = checkpoint(
        &histories,
        "a cross-removal",
        "after the first informed writer heals",
    );
    let model = Model::new(history, cp);
    let graph = model.key_graph();
    let heal = model.state("heal-1");
    for kind in [Kind::Content, Kind::Grant] {
        let made: Vec<String> = model
            .artifacts(&cp["artifacts"])
            .into_iter()
            .filter_map(|a| match a {
                Artifact::Wrap {
                    kind: k,
                    state,
                    device,
                } if k == kind && state == heal => Some(device),
                _ => None,
            })
            .collect();
        let own = own_delivery(&graph, &"P1".to_owned(), kind);
        assert_eq!(own.devices, made, "{kind:?}");
        assert!(own.principals.is_empty());
    }
    let (history, cp) = checkpoint(
        &histories,
        "a guest heals; the grant key waits for a member that propagates",
        "only the guest has met both rooms",
    );
    let model = Model::new(history, cp);
    let graph = model.key_graph();
    let guest = "G1".to_owned();
    assert!(heal_candidates(&graph, Kind::Content).contains(&guest));
    assert!(!heal_candidates(&graph, Kind::Grant).contains(&guest));
    assert!(
        own_delivery(&graph, &guest, Kind::Content)
            .devices
            .contains(&guest)
    );
    assert!(
        !own_delivery(&graph, &guest, Kind::Grant)
            .devices
            .contains(&guest)
    );
}

/// A checkpoint's view whose granted space reports some named events as it
/// holds them: `Some(false)` held and no valid rotation, `None` not held.
struct Named<'m> {
    model: &'m Model,
    events: BTreeMap<EventId, Option<bool>>,
}

impl History for Named<'_> {
    type Device = String;
    type Member = String;

    fn space(&self) -> EventId {
        History::space(self.model)
    }
    fn genesis(&self) -> EventId {
        self.model.genesis()
    }
    fn events(&self) -> BTreeSet<EventId> {
        History::events(self.model)
    }
    fn facts(&self, id: EventId) -> &EventFacts<String, String> {
        self.model.facts(id)
    }
    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        self.model.precedes(earlier, later)
    }
    fn roster(&self, place: &BTreeSet<EventId>) -> BTreeMap<String, Membership> {
        self.model.roster(place)
    }
    fn devices(&self, member: &String) -> Vec<String> {
        self.model.devices(member)
    }
    fn space_of(&self, member: &String) -> Option<EventId> {
        self.model.space_of(member)
    }
    fn voiders(&self, valid: &BTreeSet<EventId>, removal: EventId) -> Vec<EventId> {
        self.model.voiders(valid, removal)
    }
    fn stable(&self, valid: &BTreeSet<EventId>, removal: EventId) -> bool {
        self.model.stable(valid, removal)
    }
    fn grantee_le(&self, space: EventId, earlier: EventId, rotation: EventId) -> Option<bool> {
        self.model.grantee_le(space, earlier, rotation)
    }
    fn grantee_rotation(&self, space: EventId, event: EventId) -> Option<bool> {
        match self.events.get(&event) {
            Some(&held) => held,
            None => self.model.grantee_rotation(space, event),
        }
    }
    fn principal_devices(&self, space: EventId, rotation: EventId) -> Vec<String> {
        self.model.principal_devices(space, rotation)
    }
    fn grantee_current(&self, space: EventId) -> Option<BTreeSet<String>> {
        self.model.grantee_current(space)
    }
    fn admits(&self, event: EventId, notice: &NoticeFacts) -> bool {
        self.model.admits(event, notice)
    }
}

/// keys.md, "Notices and space principals": only valid rotations of T that
/// sealed refs name put a principal out of force. A named event this
/// replica holds that is no valid rotation leaves T@T0 in force; one it
/// does not hold may be a rotation, so every principal of T stays out of
/// force until it holds it.
#[test]
fn only_named_rotations_put_a_principal_out_of_force() {
    let histories = family("histories");
    let (history, cp) = checkpoint(
        &histories,
        "space principals: a grant, notices, a principal out of force, cascades, a break and refused notices",
        "T removes b; the response puts T@T0 out of force and admits T@T1",
    );
    let model = Model::new(history, cp);
    let t1 = EventId(common::named("granted rotation/T1"));
    let principals = |held: Option<bool>| -> Vec<String> {
        let view = Named {
            model: &model,
            events: BTreeMap::from([(t1, held)]),
        };
        KeyGraph::new(&view, model.key_graph().valid().clone())
            .members(Kind::Content)
            .keys()
            .filter(|m| matches!(m, Member::Principal(_)))
            .map(|m| model.member_name(m))
            .collect()
    };
    assert_eq!(principals(Some(true)), ["T@T1"]);
    assert!(principals(None).is_empty());
    assert_eq!(principals(Some(false)), ["T@T0", "T@T1"]);
}
