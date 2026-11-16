//! ext-invite-links.json's families of the link, the drop and the
//! claimant, with feature `ext-invite-links` (ext-invite-links.md):
//!
//! - `derivations` and `links` ("The secret, its keys and the link");
//! - `drops` ("The drop and its messages", "Making an invite and keeping
//!   drops"): a drop sealed and opened, refused drops, the messages of kind
//!   4 and a peer's drop store;
//! - `histories` ("Invites in the roster", "Raced claims"): the histories
//!   admission.py builds, rebuilt here byte for byte by its builder's
//!   conventions (`common::history`), and those roster.py builds, given
//!   byte for byte;
//! - `claims` ("Claiming"): the claimant's walk, from fragment to roster;
//! - `expiry` ("Claiming", step 10; "Administering devices").

#![cfg(feature = "ext-invite-links")]

mod common;

use common::history::{History, Recipient};
use common::{example, h};
use frasil_admission::ext_invite_links::{
    InviteKeys, check_claimable, check_invite_entry, drop_aad, drop_address, drop_key, invite_drop,
    link_fragment, locator, open_drop, open_drop_wrap, read_fragment, seal_drop_with,
};
use frasil_admission::snapshot::snapshot_body_keys;
use frasil_base::errors::Class;
use frasil_base::time::Reading;
use frasil_crypto::device::DeviceId;
use frasil_crypto::primitives::sha256;
use frasil_events::{Event, EventId, Log, decode};
use frasil_keys::derive::read_credential;
use frasil_peers::ext_invite_links::DropStore;
use frasil_space::ext_invite_links::{
    CLAIMS_PERSON, InviteClass, act_delay, check_claim_expiry, invite_expiry, invite_grant,
    revoke_invite, successor,
};
use frasil_space::{
    CapabilityMode, Change, HistoryMode, KeyEventChecks, Keyring, Level, Limits, MemberRef,
    MemberType, Options, OtherLogs, Space, Standing, Status, Twins, UnitBodies, UnitBody, Valid,
    Via,
};
use frasil_testkit::hex;
use frasil_transport::ext_invite_links::{DropPut, MailboxDelete};
use frasil_transport::frame::{ConnectionKind, Extensions, Message, StreamClass, read_message};
use frasil_transport::mailbox::MailboxPut;
use serde_json::{Map, Value as Json, json};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

const FILE: &str = "ext-invite-links.json";

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

fn outcome<T, C: Class>(result: Result<T, C>) -> &'static str {
    match result {
        Ok(_) => "accepted",
        Err(class) => class.name(),
    }
}

/// admission.py's `INVITE_EXPIRES`.
const INVITE_EXPIRES: u64 = 1_760_604_800;

/// The link's secret the vectors use.
fn secret() -> [u8; 32] {
    example("admission/invite/secret")
}

fn bob() -> [u8; 32] {
    example("admission/person/bob")
}

fn carol() -> [u8; 32] {
    example("admission/person/carol")
}

fn dan() -> [u8; 32] {
    example("admission/person/dan")
}

// -- The invite's history, by admission.py's builder

/// admission.py's `_invite_base`: A grants B administer, then invites by
/// link "from now on", a break that delivers to the invite key; the
/// participant `invite` signs as the key, with A's view.
struct Base {
    r: History,
    entry: EventId,
    keys: InviteKeys,
}

fn invite_base() -> Base {
    let keys = InviteKeys::derive(&secret());
    let mut r = History::new("A", "admission/invites");
    let grant_b = Change::grant_administrator(
        r.device_keys("B"),
        frasil_space::change::MAX_RANK,
        HistoryMode::WithHistory,
        Via::Code,
    );
    r.rotate("A", vec![grant_b], "A grants B administer");
    r.sync(&["A", "B"]);
    let mut grant = invite_grant(
        keys.device_id().0,
        keys.device_keys(),
        Level::Write,
        HistoryMode::FromNowOn,
        INVITE_EXPIRES,
        CLAIMS_PERSON,
    );
    grant.label = Some("Invited".into());
    let entry = r.admit_with(
        "A",
        vec![grant],
        "A invites by link",
        true,
        true,
        &[Recipient {
            keys: keys.device_keys(),
            writes: true,
        }],
    );
    r.sync(&["A", "B"]);
    r.seeds.insert(
        "invite".into(),
        (*keys.identity_seed, *keys.mldsa_seed, *keys.xwing_seed),
    );
    let view = r.view["A"].clone();
    r.view.insert("invite".into(), view);
    Base { r, entry, keys }
}

/// A claim by a person: the invite key's successor naming it.
fn claim(r: &mut History, who: [u8; 32], label: &str) -> EventId {
    r.roster_event(
        "invite",
        vec![successor(MemberRef::person(who), None)],
        label,
    )
}

/// Resolves a whole history with every rotation's key.
fn resolve<'a>(r: &'a History, keys: &'a Keyring, others: &'a OtherLogs<'a>) -> Space<'a> {
    r.resolve(None, keys, others)
}

/// The names admission.py's summary gives members.
fn member_name(r: &History, base: &Base, member: &MemberRef) -> String {
    let named = [
        (base.keys.device_id().0, "invite"),
        (bob(), "Bob"),
        (carol(), "Carol"),
        (dan(), "Dan"),
    ];
    if let Some((_, name)) = named.iter().find(|(id, _)| *id == member.id) {
        return (*name).to_owned();
    }
    for device in ["A", "B", "D"] {
        if r.device(device).0 == member.id {
            return device.to_owned();
        }
    }
    hex::encode(member.id)[..12].to_owned()
}

fn type_name(kind: MemberType) -> &'static str {
    kind.name()
}

/// admission.py's `summary`: each event's status and the roster, `out`
/// for a member removed.
fn summary(r: &History, base: &Base, space: &Space<'_>) -> Json {
    let events: Map<String, Json> = r
        .events(space)
        .into_iter()
        .map(|(k, v)| (k, Json::from(v)))
        .collect();
    let mut roster = Map::new();
    for (member, standing) in space.roster().iter() {
        let name = member_name(r, base, member);
        let entry = match standing {
            Standing::Out { .. } => json!("out"),
            Standing::In(s) => {
                let mut e = Map::new();
                e.insert("type".into(), json!(type_name(member.kind)));
                e.insert("level".into(), json!(s.level.name()));
                e.insert("history".into(), json!(s.history.name()));
                e.insert("via".into(), json!(s.via.name()));
                if let Some(session) = s.session {
                    e.insert("session".into(), json!(hex::encode(session)));
                }
                if let Some(label) = &s.label {
                    e.insert("label".into(), json!(label));
                }
                if !s.capabilities.is_empty() {
                    let caps: Vec<Json> = s
                        .capabilities
                        .iter()
                        .map(|c| {
                            let mode = match c.mode {
                                CapabilityMode::Extends => "extends",
                                CapabilityMode::Narrows => "narrows",
                            };
                            json!([c.name, mode])
                        })
                        .collect();
                    e.insert("capabilities".into(), Json::Array(caps));
                }
                Json::Object(e)
            }
        };
        roster.insert(name, entry);
    }
    json!({"events": events, "roster": roster})
}

/// The cases admission.py builds, by name.
fn built_case(name: &str) -> Option<(Base, Option<&'static str>)> {
    let mut base = invite_base();
    let r = &mut base.r;
    let key = base.keys.device_id().0;
    let v0 = r.view["invite"].clone();
    let mut claimable = None;
    match name {
        "one claim" => {
            claim(r, bob(), "Bob claims");
            claimable = Some("claimable");
        }
        "two concurrent claims" => {
            claim(r, bob(), "Bob claims");
            r.view.insert("invite".into(), v0);
            claim(r, carol(), "Carol claims");
            claimable = Some("claimable");
        }
        "a claim after a claim" => {
            claim(r, bob(), "Bob claims");
            claim(r, carol(), "Carol claims after");
        }
        "a claim after a race" => {
            claim(r, bob(), "Bob claims");
            r.view.insert("invite".into(), v0);
            claim(r, carol(), "Carol claims");
            let all: BTreeSet<EventId> = r.log.canonical().into_iter().collect();
            r.view.insert("invite".into(), all);
            claim(r, dan(), "Dan claims after the race");
        }
        "a claim concurrent with the revocation" => {
            let va = r.view["A"].clone();
            r.rotate_with(
                "A",
                vec![revoke_invite(key)],
                "A revokes the invite at its expiry",
                true,
            );
            r.view.insert("invite".into(), va);
            claim(r, bob(), "Bob claims");
        }
        "a claim after the revocation" => {
            r.rotate_with("A", vec![revoke_invite(key)], "A revokes the invite", true);
            r.sync(&["A", "invite"]);
            claim(r, bob(), "Bob claims");
            claimable = Some("claimable");
        }
        "a claim and its close" => {
            claim(r, bob(), "Bob claims");
            r.sync(&["A", "invite"]);
            // A close takes nothing from anyone: it need not rotate.
            r.roster_event("A", vec![revoke_invite(key)], "A closes the invite");
        }
        "a claimant already in" => {
            let grant = Change::grant(
                MemberRef::person(bob()),
                Level::Read,
                HistoryMode::WithHistory,
                Via::Code,
            );
            r.rotate("A", vec![grant], "A grants Bob read");
            r.sync(&["A", "invite"]);
            claim(r, bob(), "Bob claims");
        }
        "a claimant of the wrong type" => {
            let d = r.device("D");
            let keys = r.device_keys("D");
            r.roster_event(
                "invite",
                vec![successor(MemberRef::device(d), Some(keys))],
                "a device claims",
            );
        }
        "op 4 by an administrator" => {
            r.roster_event(
                "B",
                vec![successor(MemberRef::person(bob()), None)],
                "B signs a successor",
            );
        }
        "a used invite granted again" => {
            claim(r, bob(), "Bob claims");
            r.sync(&["A", "invite"]);
            let again = invite_grant(
                key,
                base.keys.device_keys(),
                Level::Read,
                HistoryMode::FromNowOn,
                1_760_700_000,
                CLAIMS_PERSON,
            );
            r.admit_with(
                "A",
                vec![again],
                "A grants the used invite again",
                true,
                true,
                &[],
            );
        }
        "a successor that rotates" => {
            r.rotate(
                "invite",
                vec![successor(MemberRef::person(bob()), None)],
                "a rotating claim",
            );
        }
        "a successor with two changes" => {
            let b = r.device("B");
            r.roster_event(
                "invite",
                vec![
                    successor(MemberRef::person(bob()), None),
                    Change::remove(MemberRef::device(b)),
                ],
                "a claim with two changes",
            );
        }
        _ => return None,
    }
    Some((base, claimable))
}

// -- The histories roster.py builds, given byte for byte

/// units.md's reading of a unit, as the reference stands in for it: no
/// unit of these histories carries refs or fails to open.
struct NoRefs;

impl UnitBodies for NoRefs {
    fn open(&self, _unit: &Event) -> UnitBody {
        UnitBody::Opened(Vec::new())
    }
}

/// A history roster.py built, with its prefix: the events, the log, and
/// their names.
struct Given {
    log: Log,
    keys: Keyring,
    names: BTreeMap<EventId, String>,
    members: BTreeMap<MemberRef, String>,
}

impl Given {
    fn new(prefix: &str, events: &[Json], extra_key: Option<[u8; 32]>) -> Self {
        let decoded: Vec<(String, Event)> = events
            .iter()
            .map(|e| {
                let event = decode(&bytes(e, "signed")).unwrap();
                if let Some(id) = e.get("id").and_then(Json::as_str) {
                    assert_eq!(hex::encode(event.id().0), id);
                }
                (text(e, "name").to_owned(), event)
            })
            .collect();
        let mut log = Log::new(decoded[0].1.clone()).unwrap();
        for (_, event) in &decoded[1..] {
            log.place(event.clone()).unwrap();
        }
        let genesis = &decoded[0].1;
        let visible = frasil_keys::body::VisiblePart::read(
            genesis.unverified_body(),
            genesis.author(),
            genesis.seq(),
        )
        .unwrap();
        assert_eq!(
            visible.nonce.map(|n| n.to_vec()),
            Some(example(&format!("{prefix}/nonce"))[..16].to_vec()),
            "{prefix}: the genesis's nonce"
        );
        let mut keys = Keyring::default();
        let mut names = BTreeMap::new();
        let mut members = BTreeMap::new();
        for (index, ((name, event), json)) in decoded.iter().zip(events).enumerate() {
            let label = if index == 0 { "genesis" } else { name.as_str() };
            let own = example(&format!("{prefix}/{label}/content-key"));
            for candidate in std::iter::once(own).chain(extra_key) {
                let read = frasil_keys::body::VisiblePart::read(
                    event.unverified_body(),
                    event.author(),
                    event.seq(),
                )
                .ok()
                .and_then(|v| v.rotation().map(|r| r.read));
                if event.kind() == frasil_events::kind::SPACE
                    && read == Some(read_credential(&candidate).public)
                {
                    keys.rotations.insert(event.id(), Zeroizing::new(candidate));
                    break;
                }
            }
            names.insert(event.id(), name.clone());
            members.insert(
                MemberRef::device(*event.author()),
                text(json, "author").to_owned(),
            );
        }
        Self {
            log,
            keys,
            names,
            members,
        }
    }

    fn id(&self, name: &str) -> EventId {
        *self
            .names
            .iter()
            .find(|(_, n)| *n == name)
            .unwrap_or_else(|| panic!("no event {name}"))
            .0
    }

    fn resolve<'a>(
        &'a self,
        view: Option<&BTreeSet<EventId>>,
        others: &'a OtherLogs<'a>,
    ) -> Space<'a> {
        let options = Options {
            keys: &self.keys,
            limits: Limits::PROTOCOL,
            others,
            units: &NoRefs,
            twins: Twins::Assumed,
            key_checks: KeyEventChecks::Context,
            notices: None,
        };
        Space::resolve(&self.log, view, options).unwrap()
    }

    fn name(&self, id: EventId) -> String {
        self.names[&id].clone()
    }

    fn member(&self, member: &MemberRef) -> String {
        if let Some(name) = self.members.get(member) {
            return name.clone();
        }
        let invite = MemberRef {
            kind: MemberType::Device,
            id: member.id,
        };
        if let Some(name) = self.members.get(&invite) {
            return name.clone();
        }
        for person in ["bob", "carol", "mallory"] {
            if member.id == example(&format!("roster/{person}")) {
                let mut name = person.to_owned();
                name[..1].make_ascii_uppercase();
                return name;
            }
        }
        hex::encode(member.id)[..12].to_owned()
    }

    fn show(&self, status: &Status) -> String {
        match status {
            Status::Valid(Valid::Agreed) => "valid (agreed)".into(),
            Status::Valid(Valid::Seniority) => "valid (seniority)".into(),
            Status::Valid(Valid::Kept) => "valid (kept)".into(),
            Status::Valid(_) => "valid".into(),
            Status::Void { class, by } => match by {
                Some(by) => format!("{} by {}", class.name(), self.name(*by)),
                None => class.name().to_owned(),
            },
        }
    }

    /// roster.py's `summary`, with its extras.
    fn summary(&self, space: &Space<'_>) -> Json {
        let order = self.log.canonical_in(space.view());
        let genesis = self.log.id();
        let events: Map<String, Json> = order
            .iter()
            .filter(|&&id| id != genesis)
            .map(|&id| (self.name(id), json!(self.show(space.status(id).unwrap()))))
            .collect();
        let mut roster = Map::new();
        for (member, standing) in space.roster().iter() {
            let entry = match standing {
                Standing::Out { .. } => json!("removed"),
                Standing::In(s) => {
                    let mut e = Map::new();
                    e.insert("type".into(), json!(member.kind.name()));
                    e.insert("level".into(), json!(s.level.name()));
                    e.insert("history".into(), json!(s.history.name()));
                    e.insert("seniority".into(), json!(hex::encode(s.seniority.hash)));
                    if let Some(rank) = s.rank {
                        e.insert("rank".into(), json!(rank));
                    }
                    if let Some(label) = &s.label {
                        e.insert("label".into(), json!(label));
                    }
                    if let Some(session) = s.session {
                        e.insert("session".into(), json!(hex::encode(session)));
                    }
                    Json::Object(e)
                }
            };
            roster.insert(self.member(member), entry);
        }
        let rotations: Vec<String> = space
            .rotations()
            .into_iter()
            .map(|id| self.name(id))
            .collect();
        let mut out = Map::new();
        out.insert("events".into(), Json::Object(events));
        out.insert("roster".into(), Json::Object(roster));
        out.insert("rotations_maximal".into(), json!(rotations));
        let voided: Map<String, Json> = order
            .iter()
            .filter_map(|&id| {
                let voiders = space.voiders(id);
                (!voiders.is_empty()).then(|| {
                    let names: Vec<String> = voiders.into_iter().map(|v| self.name(v)).collect();
                    (self.name(id), json!(names))
                })
            })
            .collect();
        if !voided.is_empty() {
            out.insert("voided_by".into(), Json::Object(voided));
        }
        if !space.forks().is_empty() {
            let forked: Map<String, Json> = space
                .forks()
                .iter()
                .map(|(author, seq)| (self.member(&MemberRef::device(*author)), json!(seq)))
                .collect();
            out.insert("forked".into(), Json::Object(forked));
        }
        let frontiers = space.frontiers();
        if !frontiers.is_empty() {
            let all: Map<String, Json> = frontiers
                .into_iter()
                .map(|(x, heads)| {
                    let heads: Map<String, Json> = heads
                        .into_iter()
                        .map(|(d, i)| {
                            (
                                self.member(&MemberRef::device(DeviceId(d))),
                                json!(self.name(i)),
                            )
                        })
                        .collect();
                    (self.name(x), json!({ "heads": heads }))
                })
                .collect();
            out.insert("frontiers".into(), Json::Object(all));
        }
        let resubmit = space.resubmissions();
        if !resubmit.is_empty() {
            let map: Map<String, Json> = resubmit
                .into_iter()
                .map(|(d, ids)| {
                    let names: Vec<String> = ids.into_iter().map(|i| self.name(i)).collect();
                    (self.member(&MemberRef::device(DeviceId(d))), json!(names))
                })
                .collect();
            out.insert("resubmit".into(), Json::Object(map));
        }
        Json::Object(out)
    }
}

/// The prefix roster.py built each of its invite histories under.
fn roster_prefix(name: &str) -> &'static str {
    match name {
        "a late claim after a close" => "roster/invite-closed",
        "a late claim before any close" => "roster/invite-raced",
        "re-submission through a raced claim" => "roster/invite-resubmit",
        other => panic!("no prefix for {other}"),
    }
}

/// The keys of a view's summary the vectors give.
fn compared(want: &Json, got: &Json) -> Vec<String> {
    let mut out = Vec::new();
    let keys: BTreeSet<&String> = want
        .as_object()
        .unwrap()
        .keys()
        .chain(got.as_object().unwrap().keys())
        .filter(|k| !["holds", "name", "note"].contains(&k.as_str()))
        .collect();
    for key in keys {
        if want[key.as_str()] != got[key.as_str()] {
            out.push(format!(
                "{key}\n  want {}\n  got  {}",
                want[key.as_str()],
                got[key.as_str()]
            ));
        }
    }
    out
}

#[test]
fn histories() {
    let cases = family("histories");
    let mut failures = Vec::new();
    let mut names = Vec::new();
    for case in cases.as_array().unwrap() {
        let name = text(case, "name");
        names.push(name.to_owned());
        if let Some((base, claimable)) = built_case(name) {
            let keys = base.r.keyring();
            let others = OtherLogs::default();
            let space = resolve(&base.r, &keys, &others);
            let mut got = summary(&base.r, &base, &space);
            if claimable.is_some() {
                let verdict = check_claimable(&space, base.entry, &base.keys.device_id());
                got["claimable"] = json!(match verdict {
                    Ok(()) => "Open",
                    Err(class) => class.name(),
                });
            }
            for line in compared(case, &got) {
                failures.push(format!("{name}: {line}"));
            }
            continue;
        }
        if let Some(error) = case.get("error") {
            // An event refused at its place, over roster.json's base.
            let mut events: Vec<Json> = case["base"].as_array().unwrap().clone();
            events.push(json!({"name": "bad", "author": text(case, "by"),
                               "signed": text(case, "event")}));
            let updates = "roster/neg";
            let given = Given::new(updates, &events, Some(example("roster/neg/content-key")));
            let others = OtherLogs::default();
            let space = given.resolve(None, &others);
            let status = space.status(given.id("bad")).unwrap();
            assert_eq!(status.class().map(Class::name), error.as_str(), "{name}");
            continue;
        }
        let prefix = roster_prefix(name);
        let given = Given::new(prefix, case["events"].as_array().unwrap(), None);
        let others = OtherLogs::default();
        for (view_name, view) in case["views"].as_object().unwrap() {
            let held = match &view["holds"] {
                Json::String(every) => {
                    assert_eq!(every, "every event");
                    None
                }
                Json::Array(list) => Some(
                    list.iter()
                        .map(|n| given.id(n.as_str().unwrap()))
                        .collect::<BTreeSet<_>>(),
                ),
                other => panic!("{other}"),
            };
            let space = given.resolve(held.as_ref(), &others);
            for line in compared(view, &given.summary(&space)) {
                failures.push(format!("{name} / {view_name}: {line}"));
            }
        }
    }
    assert_eq!(names.len(), 17, "every case is met");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// -- encodings, rebuilt

/// The rebuilt history's invite grant and successor are the encodings'
/// bytes: the builder follows admission.py exactly.
#[test]
fn the_rebuilt_history_is_byte_for_byte() {
    let e = family("encodings");
    let (mut base, _) = built_case("one claim").unwrap();
    let invite = decode(&bytes(&e, "invite_event")).unwrap();
    assert_eq!(base.r.log.event(base.entry), Some(&invite));
    assert_eq!(hex::encode(base.entry.0), text(&e, "invite_event_id"));
    assert_eq!(hex::encode(base.r.id().0), text(&e, "space"));
    let successor = base
        .r
        .names
        .iter()
        .find(|(_, n)| *n == "Bob claims")
        .unwrap()
        .0;
    assert_eq!(hex::encode(successor.0), text(&e, "successor_id"));
    // The derivations' entry and space are this history's.
    let d = family("derivations");
    assert_eq!(text(&d, "invite_entry"), text(&e, "invite_event_id"));
    assert_eq!(text(&d, "space"), text(&e, "space"));
    let _ = &mut base;
}

// -- derivations and links

#[test]
fn derivations() {
    let d = family("derivations");
    let secret: [u8; 32] = array(&d, "secret");
    assert_eq!(secret, self::secret());
    let keys = InviteKeys::derive(&secret);
    let k = &d["keys"];
    assert_eq!(h(*keys.identity_seed), text(k, "identity_seed"));
    assert_eq!(h(keys.identity_key().0), text(k, "identity"));
    assert_eq!(h(keys.signer.kc().0), text(k, "kc"));
    assert_eq!(h(keys.device_id().0), text(k, "device_id"));
    assert_eq!(keys.device_keys().device_id(), keys.device_id());
    assert_eq!(h(*keys.xwing_seed), text(k, "xwing_seed"));
    assert_eq!(h(&keys.xwing[..]), text(k, "xwing"));
    assert_eq!(h(*keys.mldsa_seed), text(k, "mldsa_seed"));
    assert_eq!(
        h(sha256(&[keys.signer.mldsa_public()])),
        text(k, "mldsa_public_sha256")
    );
    assert_eq!(h(locator(&secret)), text(&d, "locator"));
    assert_eq!(h(*drop_key(&secret)), text(&d, "drop_key"));
    assert_eq!(h(drop_address(&secret)), text(&d, "drop_address"));
    let entry = EventId(array(&d, "invite_entry"));
    let space = EventId(array(&d, "space"));
    let fragment = link_fragment(&secret, &entry, &space);
    assert_eq!(fragment, text(&d, "fragment"));
    assert_eq!(
        fragment.len() as u64,
        d["fragment_characters"].as_u64().unwrap()
    );
    assert_eq!(
        frasil_admission::ext_invite_links::LINK_BYTES as u64,
        d["fragment_bytes"].as_u64().unwrap()
    );
    let link = read_fragment(&fragment).unwrap();
    assert_eq!(*link.secret, secret);
    assert_eq!(link.entry, entry);
    assert_eq!(link.space, space);
}

#[test]
fn links() {
    for case in family("links").as_array().unwrap() {
        let got = outcome(read_fragment(text(case, "fragment")));
        assert_eq!(got, text(case, "class"), "{}", text(case, "name"));
    }
}

// -- drops

/// A peer's control message, with this extension.
fn at_peer(payload: &[u8], invite_links: bool) -> Result<Message, &'static str> {
    let extensions = Extensions {
        invite_links,
        ..Extensions::NONE
    };
    read_message(
        payload,
        StreamClass::Control,
        ConnectionKind::DeviceToPeer,
        extensions,
    )
    .map(Option::unwrap)
    .map_err(Class::name)
}

/// A peer's answer to a `MailboxPut` of kind 4: its shape (steps 1 and 2),
/// then its drop store (steps 3 to 5).
fn put_answer(
    store: &mut DropStore,
    message: &[u8],
    entry: Option<[u8; 32]>,
    quota: u64,
) -> String {
    let put = match at_peer(message, true).and_then(|m| DropPut::read(&m).map_err(Class::name)) {
        Ok(put) => put,
        Err(class) => return class.to_owned(),
    };
    match store.put(&put.placed(), entry, quota, 0) {
        Ok(()) => "stored".into(),
        Err(refusal) => refusal.name().into(),
    }
}

#[test]
fn drops() {
    let f = family("drops");
    let s = &f["sealed"];
    let secret: [u8; 32] = array(s, "secret");
    assert_eq!(h(locator(&secret)), text(s, "locator"));
    assert_eq!(h(*drop_key(&secret)), text(s, "drop_key"));
    assert_eq!(h(drop_aad(&secret)), text(s, "associated_data"));
    let nonce: [u8; 24] = array(s, "nonce");
    let plaintext = bytes(s, "plaintext");
    let drop = seal_drop_with(&secret, &plaintext, &nonce);
    assert_eq!(h(&drop), text(s, "drop"));
    let opened = open_drop(&secret, &drop).unwrap();
    let o = &s["opened"];
    assert_eq!(h(&opened.key_name), text(o, "key_name"));
    assert_eq!(h(&opened.grant_key_name), text(o, "grant_key_name"));
    assert_eq!(h(&opened.wrap), text(o, "wrap"));
    assert_eq!(json!(opened.peers), o["peer_hints"]);
    assert_eq!(opened.encode(), plaintext, "one encoding");
    assert_eq!(
        s["drop_bytes"],
        json!([
            frasil_admission::ext_invite_links::DROP_MIN_BYTES,
            frasil_admission::ext_invite_links::DROP_MAX_BYTES
        ])
    );
    // Refused drops.
    for case in f["refused_drops"].as_array().unwrap() {
        let key: [u8; 32] = array(case, "secret");
        let data = match case.get("drop") {
            Some(_) => bytes(case, "drop"),
            None => {
                let mut data = bytes(case, "drop_prefix");
                data.resize(case["drop_bytes"].as_u64().unwrap() as usize, 0);
                data
            }
        };
        let got = outcome(open_drop(&key, &data));
        assert_eq!(got, text(case, "class"), "{}", text(case, "name"));
    }
    // The messages of kind 4.
    let address: [u8; 32] = array(&f, "address");
    assert_eq!(
        frasil_transport::ext_invite_links::drop_address(&array(&f, "locator")),
        address
    );
    let space: [u8; 32] = array(&f, "space");
    let drop = bytes(&f, "drop");
    let lifetime = f["lifetime"].as_u64().unwrap();
    let put = DropPut {
        request: 2,
        address,
        drop: drop.clone(),
        space,
        lifetime,
    };
    assert_eq!(h(put.encode()), text(&f, "mailbox_put"));
    assert_eq!(
        DropPut::read(&at_peer(&put.encode(), true).unwrap()),
        Ok(put.clone())
    );
    let delete = MailboxDelete {
        request: 3,
        address,
        space,
    };
    assert_eq!(h(delete.encode()), text(&f, "mailbox_delete"));
    assert_eq!(
        MailboxDelete::read(&at_peer(&delete.encode(), true).unwrap()),
        Ok(delete)
    );
    // A core peer refuses kind 4.
    let core = at_peer(&put.encode(), false).unwrap();
    assert_eq!(
        outcome(MailboxPut::read(&core, Extensions::NONE)),
        text(&f["core_peer"], "error")
    );
    // Refused puts.
    let entry_a = example("transport/upload entry A");
    let entry_b = example("transport/upload entry B");
    for case in f["mailbox_put_refusals"].as_array().unwrap() {
        let description = text(case, "description");
        let message = match case.get("message") {
            Some(_) => bytes(case, "message"),
            None => {
                let big = DropPut {
                    drop: vec![0; frasil_admission::ext_invite_links::DROP_MAX_BYTES + 1],
                    ..put.clone()
                };
                let message = big.encode();
                assert_eq!(h(sha256(&[&message])), text(case, "message_sha256"));
                message
            }
        };
        let (entry, quota) = match description {
            "a connection without the store right for the space" => (None, u64::MAX),
            "a space over its quota" => (Some(entry_a), drop.len() as u64 - 1),
            _ => (Some(entry_a), u64::MAX),
        };
        let got = put_answer(&mut DropStore::new(), &message, entry, quota);
        assert_eq!(got, text(case, "error"), "{description}");
    }
    // A peer's drop store.
    let mut store = DropStore::new();
    let again = DropPut {
        drop: [&drop[..], b"x"].concat(),
        ..put.clone()
    };
    let delete_with = |store: &mut DropStore, entry: Option<&[u8; 32]>| {
        let message = MailboxDelete::read(&at_peer(&delete.encode(), true).unwrap()).unwrap();
        match store.delete(&message.address, &message.space, entry, 0) {
            Ok(()) => "deleted".to_owned(),
            Err(refusal) => refusal.name().to_owned(),
        }
    };
    let steps: Vec<(&str, String)> = vec![
        (
            "a drop placed under upload entry A",
            put_answer(&mut store, &put.encode(), Some(entry_a), u64::MAX),
        ),
        (
            "a second drop at the same address, under entry B",
            put_answer(&mut store, &again.encode(), Some(entry_b), u64::MAX),
        ),
        (
            "a MailboxDelete under entry B",
            delete_with(&mut store, Some(&entry_b)),
        ),
        (
            "a MailboxDelete with no upload entry",
            delete_with(&mut store, None),
        ),
        (
            "the placer's MailboxDelete, under entry A",
            delete_with(&mut store, Some(&entry_a)),
        ),
        (
            "a MailboxDelete of an address that holds no drop",
            delete_with(&mut store, Some(&entry_a)),
        ),
        (
            "a drop at the address again, now free, under entry B",
            put_answer(&mut store, &put.encode(), Some(entry_b), u64::MAX),
        ),
    ];
    let got: Vec<Json> = steps
        .into_iter()
        .map(|(step, result)| json!({"step": step, "result": result}))
        .collect();
    assert_eq!(Json::Array(got), f["drop_store"]);
}

// -- claims

#[test]
fn claims() {
    let c = family("claims");
    let base = invite_base();
    let r = &base.r;
    let space = r.id();
    let secret = secret();
    // 1. The fragment.
    let fragment = link_fragment(&secret, &base.entry, &space);
    assert_eq!(fragment, text(&c, "fragment"));
    let link = read_fragment(&fragment).unwrap();
    assert_eq!(link.entry, base.entry);
    assert_eq!(link.space, space);
    let keys = InviteKeys::derive(&link.secret);
    // The inviter's drop: K's own wrap in the invite entry, with a peer hint.
    let entry_event = r.log.event(base.entry).unwrap();
    let visible = frasil_keys::body::VisiblePart::read(
        entry_event.unverified_body(),
        entry_event.author(),
        entry_event.seq(),
    )
    .unwrap();
    let delivery = &visible.deliveries[0];
    let (index, _) = frasil_keys::wraps::find_own_wrap(
        &delivery.wraps,
        space.as_bytes(),
        delivery.key_name.as_ref(),
        delivery.grant_name.as_ref(),
        &keys.device_id(),
        &keys.xwing_seed,
    )
    .unwrap();
    assert_eq!(index as u64, c["own_wrap_index"].as_u64().unwrap());
    let plain = invite_drop(entry_event, &keys, vec!["https://peer.example".into()]).unwrap();
    assert_eq!(plain.wrap, delivery.wraps[index], "only K's own wrap");
    let mut nonce = [0; 24];
    nonce.copy_from_slice(&example("admission/invite/drop-nonce")[..24]);
    let drop = seal_drop_with(&secret, &plain.encode(), &nonce);
    assert_eq!(h(&drop), text(&c, "drop"));
    // 2. and 3. The drop opens, and its wrap.
    let opened = open_drop(&link.secret, &drop).unwrap();
    let bundle = open_drop_wrap(&opened, &link.space, &keys);
    assert_eq!(outcome(bundle.clone()), text(&c, "drop_wrap_opens"));
    let bundle = bundle.unwrap();
    let mut holds: Vec<&str> = [
        ("content", bundle.content().is_some()),
        ("upload", bundle.upload().is_some()),
        ("grant", bundle.grant().is_some()),
    ]
    .into_iter()
    .filter(|(_, on)| *on)
    .map(|(name, _)| name)
    .collect();
    holds.sort_unstable();
    assert_eq!(json!(holds), c["bundle_holds"]);
    let content = *bundle.content().unwrap();
    assert_eq!(h(content), text(&c, "content_key"));
    assert_eq!(
        h(read_credential(&content).public),
        text(&c, "read_credential")
    );
    assert_eq!(h(link.entry.0), text(&c, "invite_entry"));
    // 5. The fetched entry holds the drop's wrap, and the bundle matches.
    assert_eq!(
        check_invite_entry(entry_event, &link.space, &opened, &bundle, |id| r
            .log
            .event(*id)),
        Ok(())
    );
    // 6. Without the snapshot's body keys the space is unusable.
    let others = OtherLogs::default();
    let mut only = Keyring::default();
    only.rotations.insert(link.entry, Zeroizing::new(content));
    let options = |keys| Options {
        keys,
        limits: Limits::PROTOCOL,
        others: &others,
        units: &NoRefs,
        twins: Twins::Assumed,
        key_checks: KeyEventChecks::StaleSeal,
        notices: None,
    };
    let without = Space::resolve(&r.log, None, options(&only)).map(|_| ());
    assert_eq!(
        without.err().map(Class::name),
        c["with_no_body_keys"].as_str()
    );
    // The snapshot's body keys, from a replica that holds every key.
    let all = r.keyring();
    let full = r.resolve(None, &all, &others);
    let body_keys = snapshot_body_keys(&full, &BTreeSet::from([link.entry]));
    let named: Map<String, Json> = body_keys
        .iter()
        .map(|(id, key)| (r.names[id].clone(), json!(h(&key[..]))))
        .collect();
    assert_eq!(Json::Object(named), c["body_keys"]);
    let mut newcomer = only.clone();
    for (id, key) in &body_keys {
        newcomer.bodies.insert(*id, vec![key.clone()]);
    }
    let space_now = Space::resolve(&r.log, None, options(&newcomer)).unwrap();
    assert_eq!(summary(r, &base, &space_now), c["with_the_body_keys"]);
    // 7. and 9.
    let claimable = match check_claimable(&space_now, link.entry, &keys.device_id()) {
        Ok(()) => "Open",
        Err(class) => class.name(),
    };
    assert_eq!(claimable, text(&c, "claimable"));
}

// -- expiry

fn reading(value: &Json) -> Reading {
    Reading {
        timeline: value["timeline"].as_u64().unwrap(),
        wall: value["wall"].as_u64(),
        run: value["run"].as_u64().unwrap(),
    }
}

#[test]
fn expiry() {
    let e = family("expiry");
    assert_eq!(
        e["link_lifetime_max"].as_u64(),
        Some(frasil_space::ext_invite_links::LINK_LIFETIME_MAX)
    );
    assert_eq!(
        e["link_skew"].as_u64(),
        Some(frasil_space::ext_invite_links::LINK_SKEW)
    );
    for case in e["invite_expiry"].as_array().unwrap() {
        let got = invite_expiry(
            case["expires_at"].as_u64().unwrap(),
            &reading(&case["first_sight"]),
            &reading(&case["now"]),
        );
        assert_eq!(got.name(), text(case, "outcome"), "{case}");
    }
    for case in e["claimant_check"].as_array().unwrap() {
        assert_eq!(case["lifetime"].as_u64(), e["link_lifetime_max"].as_u64());
        assert_eq!(case["skew"].as_u64(), e["link_skew"].as_u64());
        let got = match check_claim_expiry(
            case["expires_at"].as_u64().unwrap(),
            case["now_wall"].as_u64(),
        ) {
            Ok(()) => "ok",
            Err(class) => class.name(),
        };
        assert_eq!(got, text(case, "outcome"), "{}", text(case, "case"));
    }
    for act in e["delays"].as_array().unwrap() {
        let space = EventId(array(act, "space"));
        let trigger = EventId(array(act, "trigger"));
        let step = act["rotation_step"].as_u64().unwrap();
        let devices = act["devices"].as_array().unwrap();
        let administering: Vec<[u8; 32]> = devices.iter().map(|d| array(d, "device_id")).collect();
        for device in devices {
            let identity: [u8; 32] = array(device, "device_id");
            // The inviter's client closes at once.
            let at_once = text(act, "act") == "the close" && text(device, "device") == "A";
            let position = frasil_space::keygraph::rank_order(
                space.as_bytes(),
                trigger.as_bytes(),
                &administering,
            )
            .iter()
            .position(|d| *d == identity)
            .unwrap();
            assert_eq!(position as u64, device["position"].as_u64().unwrap());
            let got = act_delay(&space, &trigger, &administering, &identity, at_once, step);
            assert_eq!(got, device["delay_seconds"].as_u64(), "{act}");
        }
    }
}

// -- An invite that does not rotate, and a closed claim

/// "Claiming", step 5, for an invite "with history", which need not
/// rotate: its delivery wraps the state the inviter held, and that state's
/// rotation commits to the bundle.
#[test]
fn an_invite_that_does_not_rotate_checks_against_its_state() {
    let keys = InviteKeys::derive(&secret());
    let mut r = History::new("A", "admission/invites/no-rotation");
    let grant = invite_grant(
        keys.device_id().0,
        keys.device_keys(),
        Level::Write,
        HistoryMode::WithHistory,
        INVITE_EXPIRES,
        CLAIMS_PERSON,
    );
    let entry = r.roster_event_delivering(
        "A",
        vec![grant],
        "A invites by link, with history",
        &[Recipient {
            keys: keys.device_keys(),
            writes: true,
        }],
    );
    let space = r.id();
    let event = r.log.event(entry).unwrap();
    let plain = invite_drop(event, &keys, Vec::new()).unwrap();
    let bundle = open_drop_wrap(&plain, &space, &keys).unwrap();
    // The delivery names the genesis's state, not the entry's own.
    assert_eq!(
        check_invite_entry(event, &space, &plain, &bundle, |id| r.log.event(*id)),
        Ok(())
    );
    // Without the rotation it names, or with a key that rotation does not
    // commit to, the entry is not the link's.
    assert_eq!(
        check_invite_entry(event, &space, &plain, &bundle, |_| None),
        Err(InviteClass::WrongInvite)
    );
    let forged = frasil_keys::bundle::Bundle::new(Some([9; 32]), None, None).unwrap();
    assert_eq!(
        check_invite_entry(event, &space, &plain, &forged, |id| r.log.event(*id)),
        Err(InviteClass::WrongInvite)
    );
}

/// "Claiming", step 9, in its order: a valid successor makes the invite
/// used, even once a close removed its key.
#[test]
fn a_closed_claim_is_used() {
    let (base, _) = built_case("a claim and its close").unwrap();
    let keys = base.r.keyring();
    let others = OtherLogs::default();
    let space = resolve(&base.r, &keys, &others);
    assert_eq!(
        check_claimable(&space, base.entry, &base.keys.device_id()),
        Err(InviteClass::InviteUsed)
    );
}
