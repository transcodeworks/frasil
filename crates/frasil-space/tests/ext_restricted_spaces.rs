//! ext-restricted-spaces.json's families of the roster and the key graph,
//! with feature `ext-restricted-spaces`:
//!
//! - `restricted_parent` ("The parent of a restricted space"): a
//!   restricted space's log judged under a parent whose genesis is held,
//!   not held, and restricted;
//! - `restricted_membership` ("Membership of a restricted space"): the
//!   reference deployment's F, its own membership, P's, and F's narrowed;
//! - `restricted_rotations` ("Keys of a restricted space"): for seven
//!   changes, whether F rotates, by its own membership before and after,
//!   and through keys.md's cascades;
//! - `carve_out` ("Creating a carve-out"): P's grant key, N's three roster
//!   events resolved, a member of P opening N's genesis, the guest's wrap
//!   found by trial, each member of P's level in N, N's effective
//!   membership, and the document's new stream and move record.

#![cfg(feature = "ext-restricted-spaces")]

mod common;

use common::named;
use common::space::StandIn;
use frasil_base::cbor;
use frasil_base::errors::Class;
use frasil_crypto::primitives::sha256;
use frasil_events::{EventId, Log, Ref, decode};
use frasil_keys::body::VisiblePart;
use frasil_keys::derive::{GrantKey, body_commitment, body_key};
use frasil_keys::wraps::{find_own_wrap, open_space_wrap};
use frasil_keys::{KeyName, RotationSet, SelfRef};
use frasil_space::ext_restricted_spaces::{Rotation, carve_out_levels, own_membership, rotation};
use frasil_space::graph::{
    GrantInForce, GrantTarget, Reach, SpaceGrants, edge_verdicts, effective,
};
use frasil_space::keygraph::{Cascade, ChangeKind, cascade};
use frasil_space::{
    Descriptor, DescriptorKind, GrantedSpace, KeyEventChecks, Keyring, Level, Limits, MemberRef,
    MemberType, Options, OtherLogs, Space, Twins,
};
use frasil_testkit::hex;
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

const FILE: &str = "ext-restricted-spaces.json";

fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

fn text(value: &Json) -> &str {
    value.as_str().unwrap()
}

fn id(value: &Json) -> EventId {
    EventId(hex::decode_array(text(value)).unwrap())
}

// -- restricted_parent

/// A space whose genesis this replica holds, and nothing else of it: all
/// that the parent's verdict reads.
struct HeldGenesis {
    id: EventId,
    restricted: bool,
    others: OtherLogs<'static>,
    keys: frasil_crypto::device::KeyRing,
}

impl GrantedSpace for HeldGenesis {
    fn space_id(&self) -> EventId {
        self.id
    }

    fn holds(&self, event: EventId) -> bool {
        event == self.id
    }

    fn precedes(&self, _earlier: EventId, _later: EventId) -> bool {
        false
    }

    fn is_restricted(&self) -> bool {
        self.restricted
    }

    fn other_logs(&self) -> &OtherLogs<'_> {
        &self.others
    }

    fn keys(&self) -> &frasil_crypto::device::KeyRing {
        &self.keys
    }

    fn names(&self, _device: &frasil_crypto::device::DeviceId) -> bool {
        false
    }

    fn effective(
        &self,
        _depth: usize,
        _seen: &[EventId],
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        BTreeMap::new()
    }

    fn reach(
        &self,
        _device: &[u8; 32],
        _paths: frasil_space::PathsFor,
    ) -> Option<frasil_space::graph::Reach> {
        None
    }

    fn propagating_writers(&self) -> BTreeSet<[u8; 32]> {
        BTreeSet::new()
    }

    fn unwaiting_writers(&self) -> BTreeSet<[u8; 32]> {
        BTreeSet::new()
    }

    fn ends(&self, _device: &[u8; 32]) -> Vec<Ref> {
        Vec::new()
    }
}

#[test]
fn restricted_parent() {
    let cases = family("restricted_parent");
    for case in cases.as_array().unwrap() {
        let name = text(&case["name"]);
        let mut names = BTreeMap::new();
        let mut events = Vec::new();
        for entry in case["log"].as_array().unwrap() {
            let event = decode(&hex::decode(text(&entry["signed"])).unwrap()).unwrap();
            names.insert(text(&entry["name"]).to_owned(), event.id());
            events.push(event);
        }
        let mut log = Log::new(events[0].clone()).unwrap();
        for event in &events[1..] {
            log.place(event.clone()).unwrap();
        }
        let mut keys = Keyring::default();
        for (event, key) in case["rotation_content_keys"].as_object().unwrap() {
            keys.rotations.insert(
                names[event],
                Zeroizing::new(hex::decode_array(text(key)).unwrap()),
            );
        }
        let held: Vec<HeldGenesis> = case["held_geneses"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(space, kind)| HeldGenesis {
                id: EventId(hex::decode_array(space).unwrap()),
                restricted: text(kind) == DescriptorKind::Restricted.name(),
                others: OtherLogs::none(),
                keys: frasil_crypto::device::KeyRing::new(),
            })
            .collect();
        let others = held
            .iter()
            .fold(OtherLogs::none(), |others, space| others.with_space(space));
        let options = Options {
            keys: &keys,
            limits: Limits::PROTOCOL,
            others: &others,
            units: &StandIn,
            twins: Twins::Assumed,
            key_checks: KeyEventChecks::Context,
            notices: None,
        };
        let got: BTreeMap<String, String> = match Space::resolve(&log, None, options) {
            Ok(space) => names
                .iter()
                .map(|(n, &i)| {
                    let status = space.status(i).unwrap();
                    let shown = status.class().map_or("valid", Class::name);
                    (n.clone(), shown.to_owned())
                })
                .collect(),
            // A replica that cannot judge the genesis judges no event of
            // the space.
            Err(class) => names
                .keys()
                .map(|n| (n.clone(), class.name().to_owned()))
                .collect(),
        };
        let want: BTreeMap<String, String> = case["events"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(n, v)| (n.clone(), text(v).to_owned()))
            .collect();
        assert_eq!(got, want, "{name}");
    }
}

// -- The reference deployment

/// The deployment's spaces by ID, with their names, and its persons.
#[derive(Clone)]
struct Deployment {
    spaces: BTreeMap<EventId, SpaceGrants>,
    ids: BTreeMap<String, EventId>,
    persons: BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    devices: BTreeMap<[u8; 32], String>,
}

impl Deployment {
    fn new(f: &Json) -> Self {
        let list = f["spaces"].as_array().unwrap();
        let ids: BTreeMap<String, EventId> = list
            .iter()
            .map(|s| (text(&s["name"]).to_owned(), id(&s["id"])))
            .collect();
        let mut out = Self {
            spaces: BTreeMap::new(),
            ids,
            persons: BTreeMap::new(),
            devices: BTreeMap::new(),
        };
        for (person, devices) in f["persons"].as_object().unwrap() {
            out.set_person(person, devices.as_array().unwrap().iter().map(text));
        }
        for s in list {
            let grants = s["grants"]
                .as_array()
                .unwrap()
                .iter()
                .map(|g| {
                    let target = text(&g["target"]);
                    GrantInForce {
                        event: id(&g["event"]),
                        target: match text(&g["kind"]) {
                            "device" => {
                                out.devices.insert(named(target), target.to_owned());
                                GrantTarget::Device(named(target))
                            }
                            "person" => GrantTarget::Person(named(target)),
                            "space" => GrantTarget::Space(out.ids[target]),
                            other => panic!("{other}"),
                        },
                        level: Level::from_name(text(&g["level"])).unwrap(),
                        session: g["session"].as_bool().unwrap(),
                        capabilities: Vec::new(),
                    }
                })
                .collect();
            let kind = match text(&s["kind"]) {
                "space" => DescriptorKind::Space,
                "restricted" => DescriptorKind::Restricted,
                _ => DescriptorKind::CarveOut,
            };
            out.spaces.insert(
                out.ids[text(&s["name"])],
                SpaceGrants {
                    kind,
                    parent: s["parent"].as_str().map(|p| out.ids[p]),
                    grants,
                },
            );
        }
        out
    }

    fn set_person<'n>(&mut self, person: &str, devices: impl Iterator<Item = &'n str>) {
        let devices: Vec<[u8; 32]> = devices
            .map(|d| {
                self.devices.insert(named(d), d.to_owned());
                named(d)
            })
            .collect();
        self.persons.insert(named(person), devices);
    }

    fn space(&self, name: &str) -> EventId {
        self.ids[name]
    }

    fn grants(&mut self, space: &str) -> &mut Vec<GrantInForce> {
        let id = self.ids[space];
        &mut self.spaces.get_mut(&id).unwrap().grants
    }

    /// The grant of `space` whose target is named so.
    fn grant_to(&mut self, space: &str, target: &str) -> &mut GrantInForce {
        let wanted = [
            GrantTarget::Device(named(target)),
            GrantTarget::Person(named(target)),
        ];
        let space_target = self.ids.get(target).copied().map(GrantTarget::Space);
        self.grants(space)
            .iter_mut()
            .find(|g| wanted.contains(&g.target) || Some(g.target) == space_target)
            .unwrap()
    }

    fn drop_grant(&mut self, space: &str, target: &str) {
        let event = self.grant_to(space, target).event;
        self.grants(space).retain(|g| g.event != event);
    }

    /// Adds a space that grants these persons.
    fn add_space(&mut self, name: &str, grants: &[(&str, Level)]) {
        let id = EventId(named(&format!("space/{name}")));
        self.ids.insert(name.to_owned(), id);
        let grants = grants
            .iter()
            .map(|&(person, level)| GrantInForce {
                event: EventId(named(&format!("{name}/{person}"))),
                target: GrantTarget::Person(named(person)),
                level,
                session: false,
                capabilities: Vec::new(),
            })
            .collect();
        self.spaces.insert(
            id,
            SpaceGrants {
                kind: DescriptorKind::Space,
                parent: None,
                grants,
            },
        );
    }

    fn effective(&self, space: &str) -> BTreeMap<[u8; 32], Reach> {
        let verdicts = edge_verdicts(&self.spaces);
        effective(&self.spaces, &self.persons, self.space(space), &verdicts).unwrap()
    }

    fn own(&self, space: &str) -> BTreeMap<[u8; 32], Reach> {
        let verdicts = edge_verdicts(&self.spaces);
        own_membership(&self.spaces, &self.persons, self.space(space), &verdicts).unwrap()
    }

    /// A membership as the vectors write it: level and propagation by
    /// device name.
    fn show(&self, members: &BTreeMap<[u8; 32], Reach>) -> BTreeMap<String, (String, bool)> {
        members
            .iter()
            .map(|(d, r)| {
                (
                    self.devices[d].clone(),
                    (r.level.name().to_owned(), r.propagates),
                )
            })
            .collect()
    }

    fn names(&self, devices: &[[u8; 32]]) -> Vec<String> {
        let mut out: Vec<String> = devices.iter().map(|d| self.devices[d].clone()).collect();
        out.sort();
        out
    }
}

fn members(value: &Json) -> BTreeMap<String, (String, bool)> {
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(d, m)| {
            (
                d.clone(),
                (
                    text(&m["level"]).to_owned(),
                    m["propagates"].as_bool().unwrap(),
                ),
            )
        })
        .collect()
}

// -- restricted_membership

#[test]
fn restricted_membership() {
    let f = family("restricted_membership");
    let d = Deployment::new(&f);
    assert_eq!(d.show(&d.own("F")), members(&f["F_own_roster"]));
    assert_eq!(d.show(&d.effective("P")), members(&f["P"]));
    assert_eq!(d.show(&d.effective("F")), members(&f["F_effective"]));
    let own = d.own("F");
    let parent = d.effective("P");
    let outside: Vec<[u8; 32]> = own
        .keys()
        .filter(|k| !parent.contains_key(*k))
        .copied()
        .collect();
    let want: Vec<String> = f["not_in_P"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| text(v).to_owned())
        .collect();
    assert_eq!(d.names(&outside), want);
    // No grant of F counts: Q's is refused.
    let verdicts = edge_verdicts(&d.spaces);
    assert!(
        verdicts
            .iter()
            .any(|(edge, verdict)| edge.to == d.space("F")
                && verdict.err().map(Class::name) == Some("GrantOfRestricted"))
    );
    // Without P's roster, F's membership cannot be computed.
    let mut without = d.spaces.clone();
    without.remove(&d.space("P"));
    assert_eq!(
        effective(&without, &d.persons, d.space("F"), &edge_verdicts(&without))
            .map_err(Class::name)
            .err(),
        Some("UnknownSpace")
    );
}

// -- restricted_rotations

fn shown(rotation: &Rotation, d: &Deployment) -> String {
    match rotation {
        Rotation::Loses(lost) => format!("rotates: loses {}", d.names(lost).join(", ")),
        Rotation::Lowers(lowered) => {
            format!("rotates: lowers {} to read", d.names(lowered).join(", "))
        }
        Rotation::KeepsItsKey => "keeps its key".to_owned(),
    }
}

#[test]
fn restricted_rotations() {
    let f = family("restricted_rotations");
    let membership = family("restricted_membership");
    // The deployment, with a space S that grants frank and that F grants at
    // read.
    let mut base = Deployment::new(&membership);
    base.add_space("S", &[("frank", Level::Write)]);
    let s = base.space("S");
    base.grants("F").push(GrantInForce {
        event: EventId(named("F/S")),
        target: GrantTarget::Space(s),
        level: Level::Read,
        session: false,
        capabilities: Vec::new(),
    });
    for (index, row) in f.as_array().unwrap().iter().enumerate() {
        let change = text(&row["change"]);
        let mut before = base.clone();
        let mut after = base.clone();
        // Each change, and the space it is a change of.
        let changed = match index {
            0 => {
                after.drop_grant("F", "dave");
                Some("F")
            }
            1 => {
                after.grant_to("F", "bob").level = Level::Read;
                Some("F")
            }
            2 => {
                before.set_person("bob", ["b-laptop", "b-old-phone"].into_iter());
                None
            }
            3 => {
                after.drop_grant("S", "frank");
                Some("S")
            }
            4 => {
                after.drop_grant("P", "erin");
                Some("P")
            }
            5 => {
                after.drop_grant("T", "bob");
                Some("T")
            }
            6 => {
                after.grant_to("P", "T").level = Level::Read;
                Some("P")
            }
            _ => panic!("an unexpected row: {change}"),
        };
        let own_before = before.own("F");
        let own_after = after.own("F");
        assert_eq!(
            before.show(&own_before),
            members(&row["F_own_before"]),
            "{change}"
        );
        assert_eq!(
            after.show(&own_after),
            members(&row["F_own_after"]),
            "{change}"
        );
        let got = rotation(&own_before, &own_after);
        assert_eq!(shown(&got, &before), text(&row["F"]), "{change}");
        // A change of another space reaches F through keys.md's cascade,
        // over F's own membership.
        if changed != Some("F") {
            let verdicts = cascade(
                &before.spaces,
                &after.spaces,
                &before.persons,
                &after.persons,
                changed.map(|name| after.space(name)),
                ChangeKind::Removal,
            )
            .unwrap();
            let f_verdict = &verdicts[&after.space("F")];
            match &got {
                Rotation::Loses(lost) => {
                    assert_eq!(f_verdict, &Cascade::Rotates(lost.clone()), "{change}")
                }
                _ => assert_eq!(f_verdict, &Cascade::KeepsItsKey, "{change}"),
            }
        }
    }
    // A carve-out of P at write: each member of P's level there.
    let levels = carve_out_levels(&base.effective("P"), Level::Write);
    assert!(levels.values().all(|&level| level <= Level::Write));
}

// -- carve_out

fn bytes(value: &Json) -> Vec<u8> {
    hex::decode(text(value)).unwrap()
}

fn array<const N: usize>(value: &Json) -> [u8; N] {
    hex::decode_array(text(value)).unwrap()
}

#[test]
fn carve_out() {
    let f = family("carve_out");
    let p = &f["parent"];
    let p_id = id(&p["id"]);
    let p_rotation = id(&p["grant_rotation"]);
    // P's grant key, from its grant seed.
    let grant = GrantKey::derive(&array(&p["grant_seed"]));
    assert_eq!(*grant.xwing_seed, array(&p["grant_key"]["xwing_seed"]));
    assert_eq!(grant.public.to_vec(), bytes(&p["grant_key"]["public"]));
    assert_eq!(grant.commitment(false), array(&p["grant_commitment"]));

    let c = &f["carve_out"];
    let n_id = id(&c["id"]);
    let descriptor = Descriptor::read(&bytes(&c["descriptor"])).unwrap();
    assert_eq!(descriptor.kind, DescriptorKind::CarveOut);
    assert_eq!(descriptor.parent, Some(p_id.0));
    assert_eq!(descriptor.encode(), bytes(&c["descriptor"]));
    let admin = frasil_crypto::device::DeviceId(array(&c["creator"]["device_id"]));
    let guest = frasil_crypto::device::DeviceId(array(&c["guest"]["device_id"]));
    for who in ["creator", "guest"] {
        let seed: [u8; 32] = array(&c[who]["identity_seed"]);
        assert_eq!(
            frasil_crypto::fixtures::FixtureKeys::from_identity_seed(&seed)
                .device_id()
                .0,
            array::<32>(&c[who]["device_id"]),
            "{who}"
        );
    }

    // N's log: its genesis, the update that grants P and admits the guest,
    // and the guest's removal, each sealed under its own rotation.
    let mut events = Vec::new();
    for entry in c["log"].as_array().unwrap() {
        let event = decode(&bytes(&entry["signed"])).unwrap();
        assert_eq!(event.id(), id(&entry["id"]));
        assert_eq!(event.seq(), entry["seq"].as_u64().unwrap());
        assert_eq!(event.unverified_body(), bytes(&entry["body"]).as_slice());
        events.push(event);
    }
    assert_eq!(events[0].id(), n_id);
    let payloads = ["genesis", "admit", "leave"];
    let mut keys = Keyring::default();
    for (event, payload) in events.iter().zip(payloads) {
        assert_eq!(
            event.unverified_body(),
            bytes(&c["payloads"][payload]).as_slice()
        );
        keys.rotations.insert(
            event.id(),
            Zeroizing::new(array(&c["secrets"][payload]["content"])),
        );
    }
    let mut log = Log::new(events[0].clone()).unwrap();
    for event in &events[1..] {
        log.place(event.clone()).unwrap();
    }
    let others = OtherLogs::none();
    let options = Options {
        keys: &keys,
        limits: Limits::PROTOCOL,
        others: &others,
        units: &StandIn,
        twins: Twins::Assumed,
        key_checks: KeyEventChecks::Context,
        notices: None,
    };
    let n = Space::resolve(&log, None, options).unwrap();
    assert_eq!(c["valid_by_roster_py"], true);
    for event in &events {
        assert!(n.is_valid(event.id()), "{:?}", n.status(event.id()));
    }
    assert_eq!(n.rotations(), vec![events[2].id()]);
    let space_member = MemberRef {
        kind: MemberType::Space,
        id: p_id.0,
    };
    let p_grant = n.roster().state(&space_member).unwrap();
    assert_eq!(p_grant.level, Level::Write);
    assert!(n.roster().state(&MemberRef::device(guest)).is_none());
    assert_eq!(
        n.roster().state(&MemberRef::device(admin)).unwrap().level,
        Level::Administer
    );

    // A member of P opens N's genesis through the second delivery's space
    // wrap of {genesis}.
    let opens = &c["p_member_opens_genesis"];
    let genesis_name = KeyName::Set(RotationSet::single(n_id));
    let bundle = open_space_wrap(
        &bytes(&opens["space_wrap"]),
        n_id.as_bytes(),
        Some(&genesis_name),
        Some(&genesis_name),
        &p_id,
        &p_rotation,
        &grant.xwing_seed,
    )
    .unwrap();
    assert_eq!(
        bundle.content(),
        Some(&array(&opens["genesis_content_key"]))
    );
    let nonce: [u8; 16] = array(&c["genesis_nonce"]);
    let genesis_key = body_key(bundle.content().unwrap(), &nonce, &admin, 1);
    assert_eq!(*genesis_key, array(&opens["genesis_body_key"]));
    assert_eq!(
        body_commitment(&genesis_key),
        array(&opens["genesis_commitment"])
    );
    let visible = VisiblePart::read(events[0].unverified_body(), &admin, 1).unwrap();
    assert!(visible.open(&genesis_key, &nonce, &admin, 1).is_ok());
    let admit = VisiblePart::read(events[1].unverified_body(), &admin, 2).unwrap();
    let second = admit
        .deliveries
        .iter()
        .find(|d| d.key_name == Some(genesis_name.clone()))
        .expect("a delivery of the genesis's state");
    assert!(second.space_wraps.contains(&bytes(&opens["space_wrap"])));

    // The guest finds its wrap by trial: no grant seed.
    let trial = &f["guest_wrap_by_trial"];
    let own = KeyName::SelfRef(SelfRef::new(admin, 2));
    let delivery = &admit.deliveries[usize::try_from(trial["delivery"].as_u64().unwrap()).unwrap()];
    let (index, bundle) = find_own_wrap(
        &delivery.wraps,
        n_id.as_bytes(),
        Some(&own),
        Some(&own),
        &guest,
        &array(&c["guest"]["hybrid_seed"]),
    )
    .unwrap();
    assert_eq!(index as u64, trial["index"].as_u64().unwrap());
    let holds: Vec<&str> = [
        bundle.content().map(|_| "content"),
        bundle.grant().map(|_| "grant"),
        bundle.upload().map(|_| "upload"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let want: Vec<&str> = trial["bundle_holds"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    assert_eq!(holds, want);
    assert_eq!(bundle.content(), Some(&array(&trial["content"])));

    // Each member of P's level in N through its grant of P at write, and
    // N's effective membership, over the reference deployment.
    let d = Deployment::new(&family("restricted_membership"));
    let levels: BTreeMap<String, String> = carve_out_levels(&d.effective("P"), Level::Write)
        .into_iter()
        .map(|(device, level)| (d.devices[&device].clone(), level.name().to_owned()))
        .collect();
    let want: BTreeMap<String, String> = f["levels_through_the_grant_of_P_at_write"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(device, level)| (device.clone(), text(level).to_owned()))
        .collect();
    assert_eq!(levels, want);
    let in_n = d.effective("N");
    for (device, reach) in f["effective_in_N"].as_object().unwrap() {
        let got = &in_n[&named(device)];
        assert_eq!(got.level.name(), text(&reach["level"]), "{device}");
        assert_eq!(
            got.propagates,
            reach["propagates"].as_bool().unwrap(),
            "{device}"
        );
        assert_eq!(
            got.depth as u64,
            reach["depth"].as_u64().unwrap(),
            "{device}"
        );
    }
    assert_eq!(in_n.len(), f["effective_in_N"].as_object().unwrap().len());

    // The document's new stream in N, its move record and P's pointer.
    let document = &f["document"];
    let type_ = text(&document["stream_type"]);
    let salt = bytes(&document["stream_salt"]);
    let digest = sha256(&[
        frasil_crypto::labels::STREAM_ID,
        &[u8::try_from(type_.len()).unwrap()],
        type_.as_bytes(),
        &salt,
    ]);
    assert_eq!(digest[..16], bytes(&document["stream_in_N"])[..]);
    assert_eq!(document["pointer_entry"], document["move_record"]);
    let record = cbor::decode(&bytes(&document["move_record"])).unwrap();
    let record = record.as_map().unwrap();
    assert_eq!(record[&1].as_unsigned(), Ok(1));
    assert_eq!(record[&2].as_bytes().unwrap(), n_id.as_bytes());
    assert_eq!(record[&3].as_bytes().unwrap(), &digest[..16]);
}
